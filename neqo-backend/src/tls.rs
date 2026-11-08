//! TLS-соединения на NSPR/NSS сокетах.
//!
//! Жизненный цикл (то же, что у nsSSLIOLayer в Firefox):
//!  1. `PR_NewTCPSocket` → `SSL_ImportFD` (надеваем SSL-слой);
//!  2. профиль Firefox (`fingerprint::configure_socket`);
//!  3. non-blocking + `PR_Connect` с дедлайном через `PR_Poll`;
//!  4. `SSL_ResetHandshake(client)` + `SSL_SetURL`;
//!  5. `SSL_ForceHandshake` в цикле — ГЛАВНАЯ ЛОВУШКА NSS:
//!     `PR_Connect` НЕ запускает TLS-handshake, без ForceHandshake
//!     первый PR_Write просто уедет в сеть открытым текстом (см.
//!     docs/PITFALLS.md);
//!  6. read/write через PR_Read/PR_Write с PR_Poll на WOULD_BLOCK.

use std::cell::RefCell;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::raw::{c_int, c_short, c_uint, c_void};
use std::time::{Duration, Instant};

use crate::error::{Error, ErrorCode, Result};
use crate::fingerprint::{self, Profile, TlsOptions};
use crate::nssx;
use crate::verify;

// Статусы/константы из биндингов (constified-имена).
use nssx::PRStatus_PR_SUCCESS as PR_SUCCESS;
use nssx::SSLNextProtoState_SSL_NEXT_PROTO_NEGOTIATED as NEXT_PROTO_NEGOTIATED;
use nssx::SSLNextProtoState_SSL_NEXT_PROTO_SELECTED as NEXT_PROTO_SELECTED;
use nssx::_SECStatus_SECFailure as SECFailure;
use nssx::_SECStatus_SECSuccess as SECSuccess;

/// Параметры подключения.
pub struct ConnectParams<'a> {
    /// Имя хоста: SNI + проверка сертификата.
    pub host: &'a str,
    /// Адрес; `None` → резолвим `host:port` через getaddrinfo.
    pub addr: Option<SocketAddr>,
    pub port: u16,
    /// Список ALPN (например ["h2", "http/1.1"]); `None` — не предлагать.
    pub alpn: Option<&'a [&'a str]>,
    /// ECHConfigList (байты ech= из DNS HTTPS-записи).
    pub ech_config_list: Option<&'a [u8]>,
    pub profile: Profile,
    pub timeout: Duration,
}

impl<'a> ConnectParams<'a> {
    fn resolve(&self) -> Result<SocketAddr> {
        if let Some(a) = self.addr {
            return Ok(a);
        }
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        match (host, self.port).to_socket_addrs() {
            Ok(mut addrs) => addrs
                .next()
                .ok_or_else(|| Error::new(ErrorCode::DnsFailure, "адрес не разрешён")),
            Err(e) => Err(Error::new(
                ErrorCode::DnsFailure,
                format!("DNS {host}: {e}"),
            )),
        }
    }
}

struct AuthContext {
    host: String,
    /// Ошибка из колбэка верификации (проявится после ForceHandshake).
    cert_error: RefCell<Option<Error>>,
}

pub struct TlsStream {
    fd: *mut nssx::PRFileDesc,
    host: String,
    closed: bool,
}

impl TlsStream {
    /// Установить TLS-соединение с профилем Firefox.
    pub fn connect(p: &ConnectParams<'_>) -> Result<TlsStream> {
        let _ = crate::init::global()?;
        let addr = p.resolve()?;
        let deadline = Instant::now() + p.timeout;

        unsafe {
            // 1. TCP-сокет и SSL-слой.
            let tcp = nssx::PR_NewTCPSocket();
            if tcp.is_null() {
                return Err(Error::new(ErrorCode::Generic, "PR_NewTCPSocket"));
            }
            let fd = nssx::SSL_ImportFD(std::ptr::null_mut(), tcp);
            if fd.is_null() {
                nssx::PR_Close(tcp);
                return Err(Error::new(ErrorCode::Generic, "SSL_ImportFD"));
            }

            // 2. Профиль Firefox ДО handshake.
            let tls_opts = TlsOptions {
                ech_config_list: p.ech_config_list,
            };
            if let Err(e) = fingerprint::configure_socket(fd, p.profile, &tls_opts) {
                nssx::PR_Close(fd);
                return Err(e);
            }

            // 3. Non-blocking + connect с дедлайном.
            if let Err(e) = set_nonblocking(fd, true) {
                nssx::PR_Close(fd);
                return Err(e);
            }
            let netaddr = netaddr_from(&addr);
            let mut rv = nssx::PR_Connect(fd, &netaddr, nssx::PR_INTERVAL_NO_TIMEOUT);
            if rv != PR_SUCCESS {
                let err = nssx::PR_GetError();
                if err != nssx::PR_IN_PROGRESS_ERROR {
                    nssx::PR_Close(fd);
                    return Err(pr_error(ErrorCode::ConnectFailed, err, "PR_Connect"));
                }
                // Ждём завершения connect.
                if let Err(e) = poll_status(
                    fd,
                    PR_POLL_WRITE | PR_POLL_EXCEPT,
                    deadline,
                    "connect",
                ) {
                    nssx::PR_Close(fd);
                    return Err(e);
                }
                rv = nssx::PR_ConnectContinue(fd, PR_POLL_WRITE as c_short);
                if rv != PR_SUCCESS {
                    let err = nssx::PR_GetError();
                    if err != nssx::PR_IS_CONNECTED_ERROR {
                        nssx::PR_Close(fd);
                        return Err(pr_error(ErrorCode::ConnectFailed, err, "PR_ConnectContinue"));
                    }
                }
            }

            // 4. Клиентский handshake.
            if nssx::SSL_ResetHandshake(fd, 0) != SECSuccess {
                let err = nssx::PR_GetError();
                nssx::PR_Close(fd);
                return Err(pr_error(ErrorCode::HandshakeFailed, err, "SSL_ResetHandshake"));
            }
            let chost = std::ffi::CString::new(p.host)
                .map_err(|_| Error::invalid_arg("host содержит NUL"))?;
            if nssx::SSL_SetURL(fd, chost.as_ptr()) != SECSuccess {
                let err = nssx::PR_GetError();
                nssx::PR_Close(fd);
                return Err(pr_error(ErrorCode::HandshakeFailed, err, "SSL_SetURL"));
            }

            // 5. ALPN (SSL_SetNextProtoNego — это и есть ALPN-API NSS).
            if let Some(list) = p.alpn {
                let wire = alpn_wire(list);
                if nssx::SSL_SetNextProtoNego(fd, wire.as_ptr(), wire.len() as c_uint)
                    != SECSuccess
                {
                    let err = nssx::PR_GetError();
                    nssx::PR_Close(fd);
                    return Err(pr_error(ErrorCode::HandshakeFailed, err, "SSL_SetNextProtoNego"));
                }
            }

            // 6. Колбэк верификации сертификата (как PSM в Firefox).
            let auth_ctx = Box::new(AuthContext {
                host: p.host.to_string(),
                cert_error: RefCell::new(None),
            });
            let ctx_ptr = Box::into_raw(auth_ctx) as *mut c_void;
            if nssx::SSL_AuthCertificateHook(fd, Some(auth_certificate_cb), ctx_ptr)
                != SECSuccess
            {
                drop(Box::from_raw(ctx_ptr as *mut AuthContext));
                nssx::PR_Close(fd);
                return Err(Error::new(ErrorCode::Generic, "SSL_AuthCertificateHook"));
            }

            // 7. ForceHandshake — см. docs/PITFALLS.md.
            loop {
                if Instant::now() >= deadline {
                    drop(Box::from_raw(ctx_ptr as *mut AuthContext));
                    nssx::PR_Close(fd);
                    return Err(Error::timeout("handshake: таймаут"));
                }
                let rv = nssx::SSL_ForceHandshake(fd);
                if rv == SECSuccess {
                    break;
                }
                let err = nssx::PR_GetError();
                if err == nssx::PR_WOULD_BLOCK_ERROR {
                    // SSL хочет читать ИЛИ писать — опрашиваем оба.
                    if let Err(e) =
                        poll_status(fd, PR_POLL_READ | PR_POLL_WRITE, deadline, "handshake")
                    {
                        drop(Box::from_raw(ctx_ptr as *mut AuthContext));
                        nssx::PR_Close(fd);
                        return Err(e);
                    }
                    continue;
                }
                let ctx = Box::from_raw(ctx_ptr as *mut AuthContext);
                nssx::PR_Close(fd);
                // Ошибка верификации важнее транспортной.
                if let Some(cert_err) = ctx.cert_error.borrow_mut().take() {
                    return Err(cert_err);
                }
                if err == nssx::SSLErrorCodes_SSL_ERROR_ECH_RETRY_WITH_ECH as i32 {
                    return Err(Error::new(
                        ErrorCode::EchRetryWithEch,
                        "сервер отклонил ECH и вернул новые конфиги (nb_tls_ech_retry_configs)",
                    ));
                }
                return Err(pr_error(ErrorCode::HandshakeFailed, err, "SSL_ForceHandshake"));
            }

            let ctx = Box::from_raw(ctx_ptr as *mut AuthContext);
            if let Some(cert_err) = ctx.cert_error.borrow_mut().take() {
                nssx::PR_Close(fd);
                return Err(cert_err);
            }

            Ok(TlsStream {
                fd,
                host: p.host.to_string(),
                closed: false,
            })
        }
    }

    /// Прочитать до `buf.len()` байт; 0 = EOF (чистое закрытие).
    pub fn read(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        self.check_alive()?;
        let deadline = Instant::now() + timeout;
        unsafe {
            loop {
                let n = nssx::PR_Read(self.fd, buf.as_mut_ptr().cast(), buf.len() as c_int);
                if n > 0 {
                    return Ok(n as usize);
                }
                if n == 0 {
                    self.closed = true;
                    return Ok(0);
                }
                let err = nssx::PR_GetError();
                if err == nssx::PR_WOULD_BLOCK_ERROR {
                    poll_status(self.fd, PR_POLL_READ, deadline, "read")?;
                    continue;
                }
                self.closed = true;
                return Err(pr_error(ErrorCode::Generic, err, "PR_Read"));
            }
        }
    }

    /// Записать весь буфер (частичная запись — продолжаем в цикле).
    pub fn write_all(&mut self, buf: &[u8], timeout: Duration) -> Result<()> {
        self.check_alive()?;
        let deadline = Instant::now() + timeout;
        let mut off = 0usize;
        unsafe {
            while off < buf.len() {
                let n = nssx::PR_Write(
                    self.fd,
                    buf[off..].as_ptr().cast(),
                    (buf.len() - off) as c_int,
                );
                if n >= 0 {
                    off += n as usize;
                    continue;
                }
                let err = nssx::PR_GetError();
                if err == nssx::PR_WOULD_BLOCK_ERROR {
                    poll_status(self.fd, PR_POLL_WRITE, deadline, "write")?;
                    continue;
                }
                self.closed = true;
                return Err(pr_error(ErrorCode::Generic, err, "PR_Write"));
            }
        }
        Ok(())
    }

    /// Согласованный ALPN, если был.
    pub fn negotiated_alpn(&self) -> Result<Option<String>> {
        self.check_alive()?;
        unsafe {
            let mut state: nssx::SSLNextProtoState = std::mem::zeroed();
            let mut out = [0u8; 255];
            let mut out_len: c_uint = 0;
            let rv = nssx::SSL_GetNextProto(
                self.fd,
                &mut state,
                out.as_mut_ptr(),
                &mut out_len,
                out.len() as c_uint,
            );
            if rv != SECSuccess {
                return Ok(None);
            }
            match state {
                NEXT_PROTO_NEGOTIATED | NEXT_PROTO_SELECTED => {
                    let s = String::from_utf8_lossy(&out[..out_len as usize]).into_owned();
                    Ok(Some(s))
                }
                _ => Ok(None),
            }
        }
    }

    /// ECHConfigList для ретрая (после ErrorCode::EchRetryWithEch).
    pub fn ech_retry_configs(&self) -> Result<Vec<u8>> {
        unsafe {
            let get: Option<
                unsafe extern "C" fn(*mut nssx::PRFileDesc, *mut *mut nssx::SECItem) -> c_int,
            > = resolve_experimental(c"SSL_GetEchRetryConfigs");
            let f = get.ok_or_else(|| {
                Error::new(ErrorCode::Unsupported, "ECH не поддерживается сборкой NSS")
            })?;
            let mut item: *mut nssx::SECItem = std::ptr::null_mut();
            if f(self.fd, &mut item) != SECSuccess {
                return Err(pr_error(ErrorCode::Generic, nssx::PR_GetError(), "EchRetryConfigs"));
            }
            if item.is_null() || (*item).data.is_null() {
                return Ok(Vec::new());
            }
            let bytes =
                std::slice::from_raw_parts((*item).data, (*item).len as usize).to_vec();
            nssx::SECITEM_FreeItem(item, 1);
            Ok(bytes)
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    fn check_alive(&self) -> Result<()> {
        if self.closed {
            return Err(Error::new(ErrorCode::Closed, "соединение закрыто"));
        }
        Ok(())
    }

    /// Аккуратное закрытие: close_notify + free.
    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            unsafe {
                // PR_Close на SSL-дескрипторе отправляет close_notify.
                nssx::PR_Close(self.fd);
            }
        }
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        self.close();
    }
}

// --- Вспомогательное ------------------------------------------------------------

const PR_POLL_READ: i16 = 0x1;
const PR_POLL_WRITE: i16 = 0x4;
const PR_POLL_EXCEPT: i16 = 0x2;

unsafe fn set_nonblocking(fd: *mut nssx::PRFileDesc, on: bool) -> Result<()> {
    let mut opt: nssx::PRSocketOptionData = std::mem::zeroed();
    opt.option = nssx::PRSockOption_PR_SockOpt_Nonblocking;
    // Именованное поле union `value`, ветка `non_blocking` (PRBool).
    opt.value.non_blocking = on as i32;
    if nssx::PR_SetSocketOption(fd, &opt) == PR_SUCCESS {
        Ok(())
    } else {
        Err(pr_error(ErrorCode::Generic, nssx::PR_GetError(), "PR_SetSocketOption"))
    }
}

/// Ждать готовности (флаги PR_POLL_*) до дедлайна.
unsafe fn poll_status(
    fd: *mut nssx::PRFileDesc,
    flags: i16,
    deadline: Instant,
    what: &str,
) -> Result<()> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::timeout(format!("{what}: таймаут")));
        }
        let ms = ((deadline - now).as_millis().min(u32::MAX as u128 - 1) as u32 + 1)
            .min(60_000);
        let mut pfd = nssx::PRPollDesc {
            fd,
            in_flags: flags,
            out_flags: 0,
        };
        let n = nssx::PR_Poll(&mut pfd, 1, nssx::PR_MillisecondsToInterval(ms));
        if n > 0 {
            return Ok(());
        }
        if n == 0 {
            continue; // истёк наш под-таймаут — проверяем дедлайн
        }
        let err = nssx::PR_GetError();
        if err == nssx::PR_PENDING_INTERRUPT_ERROR {
            continue;
        }
        return Err(pr_error(ErrorCode::Generic, err, "PR_Poll"));
    }
}

/// PRNetAddr из SocketAddr. Раскладка PRNetAddr стабильна десятилетиями:
/// [0..2) family (u16, host order), [2..4) port (u16, network order),
/// v4: [4..8) ip; v6: [4..8) flowinfo, [8..24) addr, [24..28) scope_id.
fn netaddr_from(addr: &SocketAddr) -> nssx::PRNetAddr {
    let mut buf = [0u8; 28];
    match addr {
        SocketAddr::V4(a) => {
            buf[0..2].copy_from_slice(&(nssx::PR_AF_INET as u16).to_le_bytes());
            buf[2..4].copy_from_slice(&a.port().to_be_bytes());
            buf[4..8].copy_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            buf[0..2].copy_from_slice(&(nssx::PR_AF_INET6 as u16).to_le_bytes());
            buf[2..4].copy_from_slice(&a.port().to_be_bytes());
            buf[4..8].copy_from_slice(&0u32.to_le_bytes()); // flowinfo
            buf[8..24].copy_from_slice(&a.ip().octets());
            buf[24..28].copy_from_slice(&a.scope_id().to_le_bytes());
        }
    }
    unsafe { std::ptr::read(buf.as_ptr() as *const nssx::PRNetAddr) }
}

/// ALPN-список в wire-формате: длина-байт + протокол.
fn alpn_wire(list: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in list {
        let b = p.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out
}

/// Колбэк верификации для NSS (аналог AuthCertificate в PSM).
unsafe extern "C" fn auth_certificate_cb(
    arg: *mut c_void,
    fd: *mut nssx::PRFileDesc,
    _checksig: c_int,
    _is_server: c_int,
) -> c_int {
    let ctx = &*(arg as *const AuthContext);
    match peer_chain(fd) {
        Ok(chain) => match verify::verify_server_chain(&chain, &ctx.host) {
            Ok(()) => SECSuccess,
            Err(e) => {
                *ctx.cert_error.borrow_mut() = Some(e);
                nssx::PR_SetError(nssx::SSLErrorCodes_SSL_ERROR_BAD_CERTIFICATE as i32, 0);
                SECFailure
            }
        },
        Err(e) => {
            *ctx.cert_error.borrow_mut() = Some(e);
            nssx::PR_SetError(nssx::SSLErrorCodes_SSL_ERROR_BAD_CERTIFICATE as i32, 0);
            SECFailure
        }
    }
}

/// Снять цепочку сертификатов собеседника (DER-список).
/// SSL_PeerCertificateChainDER — экспериментальный API (макрос).
unsafe fn peer_chain(fd: *mut nssx::PRFileDesc) -> Result<Vec<Vec<u8>>> {
    let get_chain: Option<
        unsafe extern "C" fn(*mut nssx::PRFileDesc, *mut *mut nssx::SECItemArray) -> c_int,
    > = resolve_experimental(c"SSL_PeerCertificateChainDER");
    let get_chain = get_chain.ok_or_else(|| {
        Error::new(ErrorCode::Unsupported, "NSS без SSL_PeerCertificateChainDER")
    })?;
    let mut arr: *mut nssx::SECItemArray = std::ptr::null_mut();
    if get_chain(fd, &mut arr) != SECSuccess {
        return Err(pr_error(
            ErrorCode::HandshakeFailed,
            nssx::PR_GetError(),
            "SSL_PeerCertificateChainDER",
        ));
    }
    if arr.is_null() {
        return Err(Error::new(
            ErrorCode::HandshakeFailed,
            "сервер не предоставил цепочку сертификатов",
        ));
    }
    let items = std::slice::from_raw_parts((*arr).items, (*arr).len as usize);
    let mut chain = Vec::with_capacity(items.len());
    for it in items {
        if !it.data.is_null() {
            chain.push(std::slice::from_raw_parts(it.data, it.len as usize).to_vec());
        }
    }
    nssx::SECITEM_FreeArray(arr, 1);
    Ok(chain)
}

/// Ошибка NSPR → Error.
unsafe fn pr_error(code: ErrorCode, pr: i32, what: &str) -> Error {
    let p = nssx::PR_ErrorToString(pr, nssx::PR_LANGUAGE_I_DEFAULT);
    let msg = if p.is_null() {
        format!("{what}: NSPR/{pr}")
    } else {
        format!(
            "{what}: {} (NSPR/{pr})",
            std::ffi::CStr::from_ptr(p).to_string_lossy()
        )
    };
    Error::new(code, msg)
}

/// Разрешение экспериментального API NSS по имени.
unsafe fn resolve_experimental<F: Copy>(name: &std::ffi::CStr) -> Option<F> {
    let p = nssx::SSL_GetExperimentalAPI(name.as_ptr());
    if p.is_null() {
        return None;
    }
    let raw: unsafe extern "C" fn() = std::mem::transmute(p);
    Some(unsafe { std::mem::transmute_copy::<_, F>(&raw) })
}
