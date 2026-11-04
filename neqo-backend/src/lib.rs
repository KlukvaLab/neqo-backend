#![allow(
    clippy::disallowed_methods,
    clippy::missing_safety_doc,
    clippy::cargo_common_metadata
)]

pub mod crypto;
pub mod mimicry;
pub mod quic;
pub mod ws;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, OnceLock, RwLock};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::runtime::Runtime;

use crate::crypto::ensure_nss_initialized;
use crate::quic::QuicStream;
use crate::ws::WebSocketStream;

#[async_trait::async_trait]
pub trait FirefoxStream: Send + Sync {
    async fn read(&self, buf: &mut [u8]) -> Result<usize, String>;
    async fn write(&self, buf: &[u8]) -> Result<usize, String>;
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
// C-ABI EXPORTS (Zero Neqo/NSS Leaks across boundary)
// =========================================================================

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffx_connect_ws(
    host: *const c_char,
    port: u16,
    path: *const c_char,
    headers_str: *const c_char,
    probing_marker: *const c_char,
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

    let rt = get_runtime();
    let res = rt.block_on(async move {
        WebSocketStream::connect(
            &host_str,
            port,
            &path_str,
            headers_map,
            marker_str.as_deref(),
        )
        .await
    });

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

    let alpn_list: Vec<&str> = if alpn.is_null() {
        vec!["h3", "hq-interop"]
    } else {
        unsafe { CStr::from_ptr(alpn) }
            .to_str()
            .unwrap_or("h3")
            .split(',')
            .map(str::trim)
            .collect()
    };

    let rt = get_runtime();
    let res = rt.block_on(async move { QuicStream::connect(&host_str, port, &alpn_list).await });

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
            tokio::time::timeout(Duration::from_millis(timeout_ms as u64), stream.read(slice))
                .await
                .map_err(|_| "Read timeout".to_string())?
        } else {
            stream.read(slice).await
        }
    };

    match rt.block_on(future) {
        Ok(n) => n as i64,
        Err(e) => {
            set_last_error(e);
            -3
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
