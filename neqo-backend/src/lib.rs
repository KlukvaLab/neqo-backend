#![allow(
    clippy::disallowed_methods,
    clippy::missing_safety_doc,
    clippy::cargo_common_metadata
)]

pub mod crypto;
pub mod mimicry;
pub mod nss_sys;
pub mod quic;
pub mod tls;
pub mod ws;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, OnceLock, RwLock};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::runtime::Runtime;

use crate::crypto::ensure_nss_initialized;
use crate::quic::QuicStream;
use crate::tls::TlsTransport;
use crate::ws::{TcpTransport, WebSocketStream, WireTransport};

/// Return codes for `ffx_stream_read` beyond the byte count:
/// * `-2` unknown handle
/// * `-3` stream error (see `ffx_get_last_error`)
/// * `-100` read timed out (stream remains usable — retry)
pub const FFX_READ_TIMEOUT: i64 = -100;

/// Default ALPN for the WS-over-TLS path, matching Firefox's offer.
pub const DEFAULT_WS_ALPN: [&str; 2] = ["h2", "http/1.1"];

#[async_trait::async_trait]
pub trait FirefoxStream: Send + Sync {
    async fn read(&self, buf: &mut [u8]) -> Result<usize, String>;
    async fn write(&self, buf: &[u8]) -> Result<usize, String>;
    /// Half-closes the sending side (stream FIN). No-op for transports
    /// without half-close semantics (e.g. WebSocket).
    async fn finish(&self) -> Result<(), String> {
        Ok(())
    }
    fn close(&self);
}

#[async_trait::async_trait]
impl FirefoxStream for WebSocketStream {
    async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        self.read(buf).await
    }
    async fn write(&self, buf: &[u8]) -> Result<usize, String> {
        self.write(buf).await
    }
    fn close(&self) {
        self.close();
    }
}

#[async_trait::async_trait]
impl FirefoxStream for QuicStream {
    async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        self.read(buf).await
    }
    async fn write(&self, buf: &[u8]) -> Result<usize, String> {
        self.write(buf).await
    }
    async fn finish(&self) -> Result<(), String> {
        self.finish().await
    }
    fn close(&self) {
        self.close();
    }
}

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static STREAMS: LazyLock<Mutex<HashMap<u64, Arc<dyn FirefoxStream>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LAST_ERROR: RwLock<String> = RwLock::new(String::new());

fn set_last_error(msg: String) {
    if let Ok(mut lock) = LAST_ERROR.write() {
        *lock = msg;
    }
}

fn get_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("Failed to initialize Tokio runtime")
    })
}

// =========================================================================
// C-ABI EXPORTS (Zero Neqo/NSS leaks across boundary)
// =========================================================================

/// Backend identification string (static, no freeing required).
#[unsafe(no_mangle)]
pub extern "C" fn ffx_version() -> *const c_char {
    // Static C string; lives for the whole process.
    static VERSION: &[u8] = b"neqo-backend 0.1.0 (neqo 0.34.0, NSS socket TLS)\0";
    VERSION.as_ptr().cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn ffx_init() -> i32 {
    let _ = env_logger::try_init();
    match ensure_nss_initialized() {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

/// Adds a trusted root CA (DER-encoded X.509) used alongside the built-in
/// Mozilla root store. Use this to pin your own proxy CA or a test CA.
///
/// # Safety
/// `der` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffx_add_root_ca(der: *const u8, len: usize) -> i32 {
    if der.is_null() || len == 0 {
        set_last_error("ffx_add_root_ca: null/empty DER".to_string());
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(der, len) };
    match crate::crypto::add_root_ca(slice) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffx_connect_ws(
    host: *const c_char,
    port: u16,
    path: *const c_char,
    headers_str: *const c_char,
    probing_marker: *const c_char,
    use_tls: c_int,
    alpn: *const c_char,
    out_handle: *mut u64,
) -> i32 {
    if host.is_null() || out_handle.is_null() {
        set_last_error("Null pointer passed to ffx_connect_ws".to_string());
        return -1;
    }

    let host_str = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            set_last_error(format!("Invalid host UTF-8: {e}"));
            return -1;
        }
    };

    let path_str = if path.is_null() {
        "/".to_string()
    } else {
        unsafe { CStr::from_ptr(path) }
            .to_string_lossy()
            .to_string()
    };

    let marker_str = if probing_marker.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(probing_marker) }
                .to_string_lossy()
                .to_string(),
        )
    };

    let mut headers_map = HashMap::new();
    if !headers_str.is_null() {
        let raw_headers = unsafe { CStr::from_ptr(headers_str) }.to_string_lossy();
        for line in raw_headers.lines() {
            if let Some((k, v)) = line.split_once(':') {
                headers_map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }

    let alpn_list: Vec<String> = if alpn.is_null() {
        DEFAULT_WS_ALPN.iter().map(ToString::to_string).collect()
    } else {
        unsafe { CStr::from_ptr(alpn) }
            .to_str()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect()
    };

    // 1. Establish the wire transport.
    //    TLS: NSS socket SSL on a dedicated I/O thread (genuine Firefox
    //    ClientHello). Plaintext TCP is only for local tests.
    let transport: Arc<dyn WireTransport> = if use_tls != 0 {
        let refs: Vec<&str> = alpn_list.iter().map(String::as_str).collect();
        match TlsTransport::connect(&host_str, port, &refs, Duration::from_secs(15)) {
            Ok(t) => {
                if t.negotiated_alpn == "h2" {
                    return {
                        set_last_error(
                            "Server selected ALPN h2; WebSocket upgrade requires http/1.1 \
                             (RFC 8441 WebSockets-over-h2 is not implemented yet)"
                                .to_string(),
                        );
                        -3
                    };
                }
                Arc::new(t)
            }
            Err(e) => {
                set_last_error(e);
                return -2;
            }
        }
    } else {
        let rt = get_runtime();
        match rt.block_on(TcpTransport::connect(&host_str, port)) {
            Ok(t) => Arc::new(t),
            Err(e) => {
                set_last_error(e);
                return -2;
            }
        }
    };

    // 2. WebSocket handshake over the transport.
    let rt = get_runtime();
    let res = rt.block_on(WebSocketStream::connect(
        transport,
        &host_str,
        port,
        &path_str,
        headers_map,
        marker_str.as_deref(),
    ));

    match res {
        Ok(stream) => {
            let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
            STREAMS.lock().insert(handle, Arc::new(stream));
            unsafe { *out_handle = handle };
            0
        }
        Err(e) => {
            set_last_error(e);
            -3
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffx_connect_quic(
    host: *const c_char,
    port: u16,
    alpn: *const c_char,
    out_handle: *mut u64,
) -> i32 {
    if host.is_null() || out_handle.is_null() {
        set_last_error("Null pointer passed to ffx_connect_quic".to_string());
        return -1;
    }

    let host_str = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            set_last_error(format!("Invalid host UTF-8: {e}"));
            return -1;
        }
    };

    let alpn_list: Vec<String> = if alpn.is_null() {
        vec!["h3".to_string(), "hq-interop".to_string()]
    } else {
        unsafe { CStr::from_ptr(alpn) }
            .to_str()
            .unwrap_or("h3")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect()
    };
    let alpn_refs: Vec<&str> = alpn_list.iter().map(String::as_str).collect();

    let rt = get_runtime();
    let res = rt.block_on(async move { QuicStream::connect(&host_str, port, &alpn_refs).await });

    match res {
        Ok(stream) => {
            let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
            STREAMS.lock().insert(handle, Arc::new(stream));
            unsafe { *out_handle = handle };
            0
        }
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

/// Reads up to `len` bytes from the stream into `buf`.
///
/// Returns the byte count (0 = EOF), or:
/// * `-2` unknown handle
/// * `-3` stream error (`ffx_get_last_error` for details)
/// * `-100` timed out after `timeout_ms` — the stream stays usable, retry
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffx_stream_read(
    handle: u64,
    buf: *mut u8,
    len: usize,
    timeout_ms: u32,
) -> i64 {
    if buf.is_null() || len == 0 {
        return -1;
    }

    let stream = {
        let guard = STREAMS.lock();
        match guard.get(&handle).cloned() {
            Some(s) => s,
            None => {
                set_last_error(format!("Stream handle {handle} not found"));
                return -2;
            }
        }
    };

    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    let rt = get_runtime();

    let future = async {
        if timeout_ms > 0 {
            match tokio::time::timeout(
                Duration::from_millis(u64::from(timeout_ms)),
                stream.read(slice),
            )
            .await
            {
                Ok(res) => res,
                Err(_) => return Err(FFX_READ_TIMEOUT.to_string()),
            }
        } else {
            stream.read(slice).await
        }
    };

    match rt.block_on(future) {
        Ok(n) => n as i64,
        Err(e) => {
            if e == FFX_READ_TIMEOUT.to_string() {
                set_last_error(e);
                FFX_READ_TIMEOUT
            } else {
                set_last_error(e);
                -3
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffx_stream_write(handle: u64, buf: *const u8, len: usize) -> i64 {
    if buf.is_null() || len == 0 {
        return 0;
    }

    let stream = {
        let guard = STREAMS.lock();
        match guard.get(&handle).cloned() {
            Some(s) => s,
            None => {
                set_last_error(format!("Stream handle {handle} not found"));
                return -2;
            }
        }
    };

    let slice = unsafe { std::slice::from_raw_parts(buf, len) };
    let rt = get_runtime();

    match rt.block_on(stream.write(slice)) {
        Ok(n) => n as i64,
        Err(e) => {
            set_last_error(e);
            -3
        }
    }
}

/// Half-closes the stream's sending side (QUIC stream FIN). No-op for
/// WebSocket streams.
#[unsafe(no_mangle)]
pub extern "C" fn ffx_stream_finish(handle: u64) -> i32 {
    let stream = {
        let guard = STREAMS.lock();
        match guard.get(&handle).cloned() {
            Some(s) => s,
            None => {
                set_last_error(format!("Stream handle {handle} not found"));
                return -2;
            }
        }
    };
    let rt = get_runtime();
    match rt.block_on(stream.finish()) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(e);
            -3
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ffx_stream_close(handle: u64) -> i32 {
    let stream = {
        let mut guard = STREAMS.lock();
        guard.remove(&handle)
    };

    if let Some(s) = stream {
        s.close();
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffx_get_last_error(buf: *mut c_char, max_len: usize) -> i32 {
    if buf.is_null() || max_len == 0 {
        return -1;
    }

    let err = LAST_ERROR.read().map(|g| g.clone()).unwrap_or_default();
    let cstr = match CString::new(err) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let bytes = cstr.as_bytes_with_nul();
    let to_copy = std::cmp::min(bytes.len(), max_len);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, to_copy);
        if to_copy < max_len {
            *buf.add(to_copy) = 0;
        } else {
            *buf.add(max_len - 1) = 0;
        }
    }

    to_copy as i32
}
