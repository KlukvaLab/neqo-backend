//! C ABI (см. ffi/neqo_backend.h).
//!
//! Правила:
//!  * дескрипторы — указатели на Box<T>; NULL недопустим;
//!  * отрицательный возврат — код ошибки из `ErrorCode`;
//!    детали — nb_last_error_message();
//!  * строки — UTF-8 с завершающим NUL, валидны до следующего вызова
//!    библиотеки в этом потоке.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::time::Duration;

use neqo_transport::StreamId;

use crate::error::{set_last_error, set_last_error_str, Error, ErrorCode};
use crate::fingerprint::Profile;
use crate::http1;
use crate::quic::{H3ConnectParams, H3Connection};
use crate::tls::{ConnectParams as TlsConnectParams, TlsStream};
use crate::ws::{Opcode, WsStream};

/// Opaque-типы для заголовка.
pub struct NbTls {
    inner: TlsStream,
}
pub struct NbWs {
    inner: WsStream,
}
pub struct NbH3 {
    inner: H3Connection,
}
pub struct NbH3Request {
    conn: *mut NbH3,
    stream_id: u64,
}
pub struct NbHttpResponse {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

/// Параметры подключения (общие для TLS/H3/WSS).
#[repr(C)]
pub struct NbConnectOptions {
    /// Имя хоста (SNI, проверка сертификата). UTF-8.
    pub host: *const c_char,
    /// Предварительно разрешённый IP (Kotlin делает DNS); NULL → резолвим.
    pub ip: *const c_char,
    pub port: u16,
    /// ALPN для TLS-ветки, wire-строка вида "h2,http/1.1"; NULL → нет ALPN.
    pub alpn: *const c_char,
    /// ECHConfigList (сырые байты из DNS HTTPS-записи); NULL → без ECH.
    pub ech_config_list: *const u8,
    pub ech_config_list_len: u32,
    /// Токен resumption QUIC (nb_h3_take_resumption_token).
    pub resumption_token: *const u8,
    pub resumption_token_len: u32,
    /// Таймаут connect+handshake, мс.
    pub timeout_ms: u32,
    /// 0 = firefox-desktop, 1 = firefox-android.
    pub profile: u8,
    /// Зарезервировано.
    pub reserved: [u8; 7],
}

#[repr(C)]
pub struct NbHeader {
    pub name: *const c_char,
    pub value: *const u8,
    pub value_len: u32,
}

// --- инфраструктура ------------------------------------------------------------

fn err_code(e: &Error) -> c_int {
    set_last_error(e);
    -(e.code as c_int)
}

fn check_ptr<T>(p: *const T) -> Result<(), Error> {
    if p.is_null() {
        Err(Error::invalid_arg("нулевой указатель"))
    } else {
        Ok(())
    }
}

unsafe fn cstr<'a>(p: *const c_char) -> Result<&'a str, Error> {
    if p.is_null() {
        return Err(Error::invalid_arg("нулевая строка"));
    }
    CStr::from_ptr(p).to_str().map_err(|_| Error::invalid_arg("не UTF-8"))
}

unsafe fn blob<'a>(p: *const u8, len: u32) -> Option<&'a [u8]> {
    if p.is_null() || len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(p, len as usize))
    }
}

fn dur(ms: u32) -> Duration {
    Duration::from_millis(ms.max(1) as u64)
}

// --- init / версии ---------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nb_init(pem_roots: *const u8, pem_roots_len: u32) -> c_int {
    let roots = blob(pem_roots, pem_roots_len);
    match crate::init::init(roots) {
        Ok(()) => 0,
        Err(e) => err_code(&e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_shutdown() -> c_int {
    crate::init::shutdown();
    0
}

#[no_mangle]
pub unsafe extern "C" fn nb_last_error_message() -> *const c_char {
    nb_last_error_message_impl()
}

/// Код последней ошибки в этом потоке: 1..=12 (ErrorCode) или 0, если
/// ошибки не было. Для функций, возвращающих указатель (NULL при ошибке):
/// вызывайте ДО nb_last_error_message — тот очищает слот.
#[no_mangle]
pub unsafe extern "C" fn nb_last_error_code() -> c_int {
    crate::error::last_error_code()
}

#[no_mangle]
pub unsafe extern "C" fn nb_version() -> *const c_char {
    thread_local! {
        static V: CString = CString::new(crate::version_string()).unwrap();
    }
    V.with(|v| v.as_ptr())
}

// --- TLS ------------------------------------------------------------------------

unsafe fn connect_options_parse(
    o: *const NbConnectOptions,
) -> Result<(String, Option<std::net::SocketAddr>, Option<Vec<String>>, Option<Vec<u8>>, Option<Vec<u8>>, u32, u16, Profile), Error> {
    check_ptr(o)?;
    let o = &*o;
    let host = cstr(o.host)?.to_string();
    // ip — голый адрес ("127.0.0.1"/"::1"); порт берём из o.port.
    let ip = if o.ip.is_null() {
        None
    } else {
        let s = cstr(o.ip)?;
        let addr: std::net::IpAddr = s
            .parse()
            .map_err(|_| Error::invalid_arg("не удалось разобрать ip"))?;
        Some(std::net::SocketAddr::new(addr, o.port))
    };
    let alpn = if o.alpn.is_null() {
        None
    } else {
        let s = cstr(o.alpn)?;
        Some(
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>(),
        )
    };
    let ech = blob(o.ech_config_list, o.ech_config_list_len).map(<[u8]>::to_vec);
    let token = blob(o.resumption_token, o.resumption_token_len).map(<[u8]>::to_vec);
    Ok((
        host,
        ip,
        alpn,
        ech,
        token,
        o.timeout_ms,
        o.port,
        Profile::from_u8(o.profile),
    ))
}

#[no_mangle]
pub unsafe extern "C" fn nb_tls_connect(
    opts: *const NbConnectOptions,
) -> *mut NbTls {
    let parsed = match connect_options_parse(opts) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&e);
            return ptr::null_mut();
        }
    };
    let (host, ip, alpn, ech, _token, timeout_ms, port, profile) = parsed;
    let alpn_refs: Option<Vec<&str>> = alpn.as_ref().map(|v| v.iter().map(String::as_str).collect());
    let p = TlsConnectParams {
        host: &host,
        addr: ip,
        port,
        alpn: alpn_refs.as_deref(),
        ech_config_list: ech.as_deref(),
        profile,
        timeout: dur(timeout_ms),
    };
    match TlsStream::connect(&p) {
        Ok(s) => Box::into_raw(Box::new(NbTls { inner: s })),
        Err(e) => {
            set_last_error(&e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_tls_read(
    s: *mut NbTls,
    buf: *mut u8,
    len: u32,
    timeout_ms: u32,
) -> c_int {
    let s = match s.as_mut() {
        Some(s) => s,
        None => {
            set_last_error_str("nb_tls_read: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    if buf.is_null() && len > 0 {
        return -(ErrorCode::InvalidArgument as c_int);
    }
    let out = std::slice::from_raw_parts_mut(buf, len as usize);
    match s.inner.read(out, dur(timeout_ms)) {
        Ok(n) => n as c_int,
        Err(e) => err_code(&e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_tls_write(
    s: *mut NbTls,
    buf: *const u8,
    len: u32,
    timeout_ms: u32,
) -> c_int {
    let s = match s.as_mut() {
        Some(s) => s,
        None => {
            set_last_error_str("nb_tls_write: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    let data = match blob(buf, len) {
        Some(d) => d,
        None => return 0,
    };
    match s.inner.write_all(data, dur(timeout_ms)) {
        Ok(()) => data.len() as c_int,
        Err(e) => err_code(&e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_tls_alpn(
    s: *mut NbTls,
    out: *mut c_char,
    out_cap: u32,
) -> c_int {
    let s = match s.as_ref() {
        Some(s) => s,
        None => {
            set_last_error_str("nb_tls_alpn: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    match s.inner.negotiated_alpn() {
        Ok(Some(proto)) => {
            let b = proto.as_bytes();
            if (b.len() + 1) > out_cap as usize {
                return -((b.len() + 1) as c_int); // сколько нужно
            }
            ptr::copy_nonoverlapping(b.as_ptr(), out as *mut u8, b.len());
            *out.add(b.len()) = 0;
            b.len() as c_int
        }
        Ok(None) => 0,
        Err(e) => err_code(&e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_tls_ech_retry_configs(
    s: *mut NbTls,
    out: *mut u8,
    out_cap: u32,
) -> c_int {
    let s = match s.as_ref() {
        Some(s) => s,
        None => {
            set_last_error_str("nb_tls_ech_retry_configs: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    match s.inner.ech_retry_configs() {
        Ok(cfg) => {
            if cfg.len() > out_cap as usize {
                return -((cfg.len() + 1) as c_int);
            }
            if !cfg.is_empty() {
                ptr::copy_nonoverlapping(cfg.as_ptr(), out, cfg.len());
            }
            cfg.len() as c_int
        }
        Err(e) => err_code(&e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_tls_close(s: *mut NbTls) {
    if let Some(s) = s.as_mut() {
        s.inner.close();
        drop(Box::from_raw(s));
    }
}

// --- HTTP/1.1 поверх TLS -----------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nb_http1_fetch(
    s: *mut NbTls,
    method: *const c_char,
    target: *const c_char,
    headers: *const NbHeader,
    nheaders: u32,
    body: *const u8,
    body_len: u32,
    timeout_ms: u32,
) -> *mut NbHttpResponse {
    let s = match s.as_mut() {
        Some(s) => s,
        None => {
            set_last_error_str("nb_http1_fetch: NULL");
            return ptr::null_mut();
        }
    };
    let mut run = || -> Result<NbHttpResponse, Error> {
        let method = cstr(method)?;
        let target = cstr(target)?;
        let mut hdrs: Vec<(String, String)> = Vec::new();
        if !headers.is_null() {
            for i in 0..nheaders as usize {
                let h = &*headers.add(i);
                let name = cstr(h.name)?;
                let value = blob(h.value, h.value_len)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                hdrs.push((name.to_string(), value));
            }
        }
        let authority = http_authority(s.inner.host(), 443);
        let req = http1::Request {
            method,
            target,
            authority: &authority,
            headers: &hdrs,
            body: blob(body, body_len),
            connection: http1::ConnectionHeader::Close,
        };
        let timeout = dur(timeout_ms);
        let mut resp = http1::send_request_and_read_head(&mut s.inner, &req, timeout)?;
        http1::read_body(&mut s.inner, &mut resp, timeout)?;
        Ok(NbHttpResponse {
            status: resp.status,
            headers: resp
                .headers
                .into_iter()
                .map(|(n, v)| (n, v.into_bytes()))
                .collect(),
            body: resp.body,
        })
    };
    match run() {
        Ok(r) => Box::into_raw(Box::new(r)),
        Err(e) => {
            set_last_error(&e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_http1_response_status(r: *const NbHttpResponse) -> c_int {
    match r.as_ref() {
        Some(r) => r.status as c_int,
        None => -(ErrorCode::InvalidArgument as c_int),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_http1_response_header_count(r: *const NbHttpResponse) -> c_int {
    match r.as_ref() {
        Some(r) => r.headers.len() as c_int,
        None => -(ErrorCode::InvalidArgument as c_int),
    }
}

/// Копирует i-й заголовок; возвращает длину value (для буферов — сколько
/// нужно, если capacity не хватило: отрицательное значение = -(need+1)).
#[no_mangle]
pub unsafe extern "C" fn nb_http1_response_header(
    r: *const NbHttpResponse,
    index: c_int,
    name_buf: *mut c_char,
    name_cap: u32,
    value_buf: *mut u8,
    value_cap: u32,
) -> c_int {
    let r = match r.as_ref() {
        Some(r) => r,
        None => {
            set_last_error_str("nb_http1_response_header: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    if index < 0 || index as usize >= r.headers.len() {
        return -(ErrorCode::InvalidArgument as c_int);
    }
    let (name, value) = &r.headers[index as usize];
    if (name.len() + 1) > name_cap as usize {
        return -((name.len() + 1) as c_int);
    }
    if (value.len() + 1) > value_cap as usize {
        return -((value.len() + 1) as c_int); // нужно value.len()+1 (с NUL)
    }
    ptr::copy_nonoverlapping(name.as_ptr(), name_buf as *mut u8, name.len());
    *name_buf.add(name.len()) = 0;
    ptr::copy_nonoverlapping(value.as_ptr(), value_buf, value.len());
    // NUL-терминация value для удобства C-вызовов printf/strcmp.
    *value_buf.add(value.len()) = 0;
    value.len() as c_int
}

#[no_mangle]
pub unsafe extern "C" fn nb_http1_response_body(
    r: *const NbHttpResponse,
    out: *mut u8,
    out_cap: u32,
) -> c_int {
    let r = match r.as_ref() {
        Some(r) => r,
        None => {
            set_last_error_str("nb_http1_response_body: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    if r.body.len() > out_cap as usize {
        return -((r.body.len() + 1) as c_int);
    }
    if !r.body.is_empty() {
        ptr::copy_nonoverlapping(r.body.as_ptr(), out, r.body.len());
    }
    r.body.len() as c_int
}

#[no_mangle]
pub unsafe extern "C" fn nb_http1_response_free(r: *mut NbHttpResponse) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

// --- WSS ------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nb_ws_connect(
    opts: *const NbConnectOptions,
    path: *const c_char,
    headers: *const NbHeader,
    nheaders: u32,
) -> *mut NbWs {
    let parsed = match connect_options_parse(opts) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&e);
            return ptr::null_mut();
        }
    };
    let (host, ip, alpn, ech, _token, timeout_ms, port, profile) = parsed;
    let path = match cstr(path) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(&e);
            return ptr::null_mut();
        }
    };
    let mut hdrs: Vec<(String, Vec<u8>)> = Vec::new();
    if !headers.is_null() {
        for i in 0..nheaders as usize {
            let h = &*headers.add(i);
            match cstr(h.name) {
                Ok(n) => hdrs.push((
                    n.to_string(),
                    blob(h.value, h.value_len).map(<[u8]>::to_vec).unwrap_or_default(),
                )),
                Err(e) => {
                    set_last_error(&e);
                    return ptr::null_mut();
                }
            }
        }
    }
    let hdrs_str: Vec<(String, String)> = hdrs
        .into_iter()
        .map(|(n, v)| (n, String::from_utf8_lossy(&v).into_owned()))
        .collect();
    let alpn_refs: Option<Vec<&str>> =
        alpn.as_ref().map(|v| v.iter().map(String::as_str).collect());
    let p = TlsConnectParams {
        host: &host,
        addr: ip,
        port,
        // По умолчанию WSS предлагает [h2, http/1.1] (как Firefox), но
        // пользовательский список из NbConnectOptions.alpn имеет приоритет
        // (например "http/1.1" для гарантии WSS на h2-серверах).
        alpn: alpn_refs.as_deref(),
        ech_config_list: ech.as_deref(),
        profile,
        timeout: dur(timeout_ms),
    };
    match WsStream::connect(&p, path, &hdrs_str, dur(timeout_ms)) {
        Ok(w) => Box::into_raw(Box::new(NbWs { inner: w })),
        Err(e) => {
            set_last_error(&e);
            ptr::null_mut()
        }
    }
}

/// opcode: 1=text, 2=binary, 9=ping.
#[no_mangle]
pub unsafe extern "C" fn nb_ws_send(
    w: *mut NbWs,
    opcode: u8,
    data: *const u8,
    len: u32,
    timeout_ms: u32,
) -> c_int {
    let w = match w.as_mut() {
        Some(w) => w,
        None => {
            set_last_error_str("nb_ws_send: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    let op = match opcode {
        1 => Opcode::Text,
        2 => Opcode::Binary,
        9 => Opcode::Ping,
        _ => {
            set_last_error_str("nb_ws_send: opcode должен быть 1, 2 или 9");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    let payload = blob(data, len).unwrap_or(&[]);
    match w.inner.send(op, payload, dur(timeout_ms)) {
        Ok(()) => payload.len() as c_int,
        Err(e) => err_code(&e),
    }
}

/// Ждёт сообщение. Возвращает длину payload (≥0) или код ошибки (<0).
/// opcode_out: 1=text, 2=binary, 8=close, 10=pong.
#[no_mangle]
pub unsafe extern "C" fn nb_ws_recv(
    w: *mut NbWs,
    opcode_out: *mut u8,
    buf: *mut u8,
    buf_cap: u32,
    timeout_ms: u32,
) -> c_int {
    let w = match w.as_mut() {
        Some(w) => w,
        None => {
            set_last_error_str("nb_ws_recv: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    match w.inner.recv(dur(timeout_ms)) {
        Ok(msg) => {
            if !opcode_out.is_null() {
                *opcode_out = msg.opcode as u8;
            }
            if msg.payload.len() > buf_cap as usize {
                return -((msg.payload.len() + 1) as c_int);
            }
            if !msg.payload.is_empty() {
                ptr::copy_nonoverlapping(msg.payload.as_ptr(), buf, msg.payload.len());
            }
            msg.payload.len() as c_int
        }
        Err(e) => err_code(&e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_ws_close(
    w: *mut NbWs,
    code: u16,
    reason: *const c_char,
    timeout_ms: u32,
) -> c_int {
    let w = match w.as_mut() {
        Some(w) => w,
        None => {
            set_last_error_str("nb_ws_close: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    let reason = if reason.is_null() {
        String::new()
    } else {
        CStr::from_ptr(reason).to_string_lossy().into_owned()
    };
    let rv = w.inner.close(code, &reason, dur(timeout_ms));
    drop(Box::from_raw(w));
    match rv {
        Ok(()) => 0,
        Err(e) => err_code(&e),
    }
}

// --- HTTP/3 ----------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nb_h3_connect(opts: *const NbConnectOptions) -> *mut NbH3 {
    let parsed = match connect_options_parse(opts) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&e);
            return ptr::null_mut();
        }
    };
    let (host, ip, _alpn, ech, token, timeout_ms, port, _profile) = parsed;
    let p = H3ConnectParams {
        host: &host,
        addr: ip,
        port,
        ech_config_list: ech.as_deref(),
        resumption_token: token.as_deref(),
        timeout: dur(timeout_ms),
    };
    match H3Connection::connect(&p) {
        Ok(c) => Box::into_raw(Box::new(NbH3 { inner: c })),
        Err(e) => {
            set_last_error(&e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_h3_fetch(
    h: *mut NbH3,
    method: *const c_char,
    target: *const c_char,
    headers: *const NbHeader,
    nheaders: u32,
    body: *const u8,
    body_len: u32,
    timeout_ms: u32,
) -> *mut NbH3Request {
    let h = match h.as_mut() {
        Some(h) => h,
        None => {
            set_last_error_str("nb_h3_fetch: NULL");
            return ptr::null_mut();
        }
    };
    let mut run = || -> Result<NbH3Request, Error> {
        let method = cstr(method)?;
        let target = cstr(target)?;
        let mut hdrs: Vec<(String, Vec<u8>)> = Vec::new();
        if !headers.is_null() {
            for i in 0..nheaders as usize {
                let hd = &*headers.add(i);
                hdrs.push((
                    cstr(hd.name)?.to_string(),
                    blob(hd.value, hd.value_len).map(<[u8]>::to_vec).unwrap_or_default(),
                ));
            }
        }
        let stream_id = h.inner.fetch(
            method,
            target,
            &hdrs,
            blob(body, body_len),
            dur(timeout_ms),
        )?;
        Ok(NbH3Request {
            conn: h,
            stream_id: stream_id.as_u64(),
        })
    };
    match run() {
        Ok(r) => Box::into_raw(Box::new(r)),
        Err(e) => {
            set_last_error(&e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_h3_req_status(r: *mut NbH3Request) -> c_int {
    let r = match r.as_ref() {
        Some(r) => r,
        None => return -(ErrorCode::InvalidArgument as c_int),
    };
    let h = match r.conn.as_ref() {
        Some(h) => h,
        None => return -(ErrorCode::InvalidArgument as c_int),
    };
    match h.inner.request(StreamId::from(r.stream_id)) {
        Some(st) => st.status.map(i32::from).unwrap_or(-1),
        None => -(ErrorCode::InvalidArgument as c_int),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_h3_req_header_count(r: *mut NbH3Request) -> c_int {
    let r = match r.as_ref() {
        Some(r) => r,
        None => return -(ErrorCode::InvalidArgument as c_int),
    };
    let h = match r.conn.as_ref() {
        Some(h) => h,
        None => return -(ErrorCode::InvalidArgument as c_int),
    };
    match h.inner.request(StreamId::from(r.stream_id)) {
        Some(st) => st.headers.len() as c_int,
        None => -(ErrorCode::InvalidArgument as c_int),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_h3_req_header(
    r: *mut NbH3Request,
    index: c_int,
    name_buf: *mut c_char,
    name_cap: u32,
    value_buf: *mut u8,
    value_cap: u32,
) -> c_int {
    let r = match r.as_ref() {
        Some(r) => r,
        None => {
            set_last_error_str("nb_h3_req_header: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    let h = match r.conn.as_ref() {
        Some(h) => h,
        None => {
            set_last_error_str("nb_h3_req_header: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    let st = match h.inner.request(StreamId::from(r.stream_id)) {
        Some(st) => st,
        None => return -(ErrorCode::InvalidArgument as c_int),
    };
    if index < 0 || index as usize >= st.headers.len() {
        return -(ErrorCode::InvalidArgument as c_int);
    }
    let (name, value) = &st.headers[index as usize];
    if (name.len() + 1) > name_cap as usize {
        return -((name.len() + 1) as c_int);
    }
    if (value.len() + 1) > value_cap as usize {
        return -((value.len() + 1) as c_int); // нужно value.len()+1 (с NUL)
    }
    ptr::copy_nonoverlapping(name.as_ptr(), name_buf as *mut u8, name.len());
    *name_buf.add(name.len()) = 0;
    ptr::copy_nonoverlapping(value.as_ptr(), value_buf, value.len());
    *value_buf.add(value.len()) = 0;
    value.len() as c_int
}

#[no_mangle]
pub unsafe extern "C" fn nb_h3_req_read(
    r: *mut NbH3Request,
    buf: *mut u8,
    buf_cap: u32,
    timeout_ms: u32,
) -> c_int {
    let r = match r.as_mut() {
        Some(r) => r,
        None => {
            set_last_error_str("nb_h3_req_read: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    let h = match r.conn.as_mut() {
        Some(h) => h,
        None => {
            set_last_error_str("nb_h3_req_read: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    if buf.is_null() && buf_cap > 0 {
        return -(ErrorCode::InvalidArgument as c_int);
    }
    let mut out = std::slice::from_raw_parts_mut(buf, buf_cap as usize);
    match h
        .inner
        .read_body(StreamId::from(r.stream_id), &mut out, dur(timeout_ms))
    {
        Ok(n) => n as c_int,
        Err(e) => err_code(&e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_h3_req_free(r: *mut NbH3Request) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_h3_take_resumption_token(
    h: *mut NbH3,
    out: *mut u8,
    out_cap: u32,
) -> c_int {
    let h = match h.as_mut() {
        Some(h) => h,
        None => {
            set_last_error_str("nb_h3_take_resumption_token: NULL");
            return -(ErrorCode::InvalidArgument as c_int);
        }
    };
    match h.inner.take_resumption_token() {
        Some(t) => {
            if t.len() > out_cap as usize {
                return -((t.len() + 1) as c_int);
            }
            ptr::copy_nonoverlapping(t.as_ptr(), out, t.len());
            t.len() as c_int
        }
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn nb_h3_close(h: *mut NbH3) {
    if let Some(h) = h.as_mut() {
        h.inner.close();
        drop(Box::from_raw(h));
    }
}

fn http_authority(host: &str, port: u16) -> String {
    let default = port == 443;
    if host.contains(':') && !host.starts_with('[') {
        if default {
            format!("[{host}]")
        } else {
            format!("[{host}]:{port}")
        }
    } else if default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

thread_local! {
    static MSG: std::cell::RefCell<CString> =
        std::cell::RefCell::new(CString::new("нет ошибки").unwrap());
}

/// Записать сообщение последней ошибки (для nb_last_error_message).
pub fn nb_last_error_message_impl() -> *const c_char {
    let taken = crate::error::take_last_error().unwrap_or_else(|| "нет ошибки".into());
    MSG.with(|m| {
        *m.borrow_mut() = CString::new(taken).unwrap_or_else(|_| CString::new("?").unwrap());
        m.borrow().as_ptr()
    })
}
