//! TLS-over-TCP transport backed by the NSS socket-level SSL API — the same
//! code path Firefox itself uses for `https://` connections. This is what
//! produces a *genuine* Firefox TLS fingerprint (ClientHello, extension order,
//! cipher list, record layer behaviour) with zero synthetic emulation.
//!
//! ## Threading model
//!
//! * `TlsTransport::connect` performs DNS resolution, TCP connect and the full
//!   TLS handshake (including certificate verification) on the calling
//!   thread, in **nonblocking** mode driven by `PR_Poll` with an overall
//!   deadline. This is the textbook NSS nonblocking client pattern:
//!   `PR_Connect` → `PR_Poll` → `PR_ConnectContinue`, then
//!   `SSL_ForceHandshake` → `PR_Poll` → retry.
//! * Afterwards the `PRFileDesc` is owned exclusively by one dedicated I/O
//!   thread running a `PR_Poll` event loop. The async side talks to it over
//!   channels plus a TCP-socketpair wakeup (NSPR pipes do not support
//!   `PR_Poll`), so there is no cross-thread `PRFileDesc` access and no
//!   close/IO race conditions.
//!
//! ## NSS gotchas encoded here (verified against NSS 3.132)
//!
//! * `PR_SetSocketOption(Nonblocking)` must be called on the **plain TCP fd
//!   before `SSL_ImportFD`** — after import, the option lands on the SSL
//!   layer's private struct and never reaches the OS socket.
//! * The TLS handshake does NOT happen inside `PR_Connect`; it must be forced
//!   with `SSL_ForceHandshake` (which on a blocking socket would stall the
//!   whole thread; nonblocking + poll is used instead).
//! * `SSL_SetNextProtoNego` rotates the protocol list (first entry moves to
//!   the end, NPN legacy), so we pass the list REVERSED to keep the wire
//!   order equal to the caller's preference order.

use std::ffi::CString;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::raw::{c_int, c_uint};
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};
use std::{ptr, thread};

use async_trait::async_trait;
use tokio::sync::{Mutex, mpsc};

use crate::crypto::{ensure_nss_initialized, verify_chain};
use crate::mimicry::StreamReadBuffer;
use crate::nss_sys::*;
use crate::ws::WireTransport;

/// Commands for the I/O thread.
enum IoCmd {
    Write(Vec<u8>),
    Shutdown,
}

/// Context passed through the auth-certificate hook.
struct AuthCtx {
    host: String,
}

/// # Safety
/// `PRFileDesc` pointers are only dereferenced on the owning thread; the
/// socketpair write end is used from any thread, which NSPR permits.
struct SendFd(*mut PRFileDesc);
unsafe impl Send for SendFd {}
unsafe impl Sync for SendFd {}

/// Async TLS transport (NSS socket SSL) with a dedicated I/O thread.
pub struct TlsTransport {
    cmd_tx: std_mpsc::Sender<IoCmd>,
    wake: SendFd,
    rx: Mutex<StreamReadBuffer>,
    /// ALPN protocol negotiated with the server (empty = none).
    pub negotiated_alpn: String,
}

impl TlsTransport {
    /// Connects to `host:port`, performs the Firefox-shaped TLS handshake and
    /// returns a transport.
    ///
    /// `alpn` is in *client preference order* (e.g. `["h2", "http/1.1"]`);
    /// the ClientHello advertises exactly this order on the wire.
    pub fn connect(
        host: &str,
        port: u16,
        alpn: &[&str],
        connect_timeout: Duration,
    ) -> Result<Self, String> {
        ensure_nss_initialized()?;

        let addr = resolve(host, port)?;
        let addr_pr = match addr {
            SocketAddr::V4(v4) => PRNetAddr::ipv4(v4.ip().octets(), port),
            SocketAddr::V6(v6) => PRNetAddr::ipv6(v6.ip().octets(), port),
        };
        let deadline = Instant::now() + connect_timeout;

        // --- Socket + SSL layer setup -----------------------------------
        let af = if addr.is_ipv4() {
            PR_AF_INET as PRIntn
        } else {
            PR_AF_INET6 as PRIntn
        };
        let fd = unsafe { PR_OpenTCPSocket(af) };
        if fd.is_null() {
            return Err("PR_OpenTCPSocket failed".to_string());
        }

        // CRITICAL: set nonblocking on the plain TCP fd BEFORE SSL_ImportFD
        // (see module docs). It stays nonblocking for its whole life.
        set_nonblocking(fd)?;

        let ssl_fd = unsafe { SSL_ImportFD(ptr::null_mut(), fd) };
        if ssl_fd.is_null() {
            unsafe { PR_Close(fd) };
            return Err("SSL_ImportFD failed".to_string());
        }

        // Configure the TLS profile the way Firefox (PSM) does:
        // security on, client role, session tickets enabled (present in the
        // Firefox ClientHello), TLS 1.2..1.3, SNI from the host name.
        unsafe {
            if SSL_OptionSet(ssl_fd, SSL_SECURITY, PR_TRUE) != SECSuccess
                || SSL_OptionSet(ssl_fd, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE) != SECSuccess
                || SSL_OptionSet(ssl_fd, SSL_ENABLE_SESSION_TICKETS, PR_TRUE) != SECSuccess
            {
                close_quietly(ssl_fd);
                return Err("SSL_OptionSet failed".to_string());
            }

            let range = SSLVersionRange {
                min: SSL_LIBRARY_VERSION_TLS_1_2,
                max: SSL_LIBRARY_VERSION_TLS_1_3,
            };
            if SSL_VersionRangeSet(ssl_fd, &range) != SECSuccess {
                close_quietly(ssl_fd);
                return Err("SSL_VersionRangeSet failed".to_string());
            }

            let url = CString::new(host).map_err(|_| "host contains NUL byte".to_string())?;
            if SSL_SetURL(ssl_fd, url.as_ptr()) != SECSuccess {
                close_quietly(ssl_fd);
                return Err(format!("SSL_SetURL({host}) failed"));
            }

            // ALPN (see module docs about list rotation).
            if !alpn.is_empty() {
                let mut wire = Vec::new();
                for p in alpn.iter().rev() {
                    let bytes = p.as_bytes();
                    if bytes.is_empty() || bytes.len() > 255 {
                        close_quietly(ssl_fd);
                        return Err(format!("Invalid ALPN protocol: {p:?}"));
                    }
                    wire.push(bytes.len() as u8);
                    wire.extend_from_slice(bytes);
                }
                if SSL_SetNextProtoNego(ssl_fd, wire.as_ptr(), wire.len() as c_uint) != SECSuccess {
                    close_quietly(ssl_fd);
                    return Err("SSL_SetNextProtoNego failed".to_string());
                }
            }

            // Certificate verification hook — strict, no bypasses.
            let ctx = Box::into_raw(Box::new(AuthCtx {
                host: host.to_string(),
            }));
            if SSL_AuthCertificateHook(ssl_fd, Some(auth_certificate_hook), ctx.cast())
                != SECSuccess
            {
                drop(Box::from_raw(ctx));
                close_quietly(ssl_fd);
                return Err("SSL_AuthCertificateHook failed".to_string());
            }

            // --- Nonblocking TCP connect (PR_Connect / poll / continue) --
            if PR_Connect(ssl_fd, &addr_pr, PR_INTERVAL_NO_TIMEOUT) != PR_SUCCESS {
                let err = PR_GetError();
                if err != PR_IN_PROGRESS_ERROR {
                    drop(Box::from_raw(ctx));
                    close_quietly(ssl_fd);
                    return Err(format!(
                        "TCP connect to {host}:{port} failed: {}",
                        nspr_error_name(err)
                    ));
                }
                loop {
                    if Instant::now() >= deadline {
                        drop(Box::from_raw(ctx));
                        close_quietly(ssl_fd);
                        return Err(format!("TCP connect to {host}:{port} timed out"));
                    }
                    let mut pfd = PRPollDesc {
                        fd: ssl_fd,
                        in_flags: (PR_POLL_WRITE | PR_POLL_EXCEPT) as i16,
                        out_flags: 0,
                    };
                    let n = PR_Poll(&raw mut pfd, 1, poll_timeout_until(deadline));
                    if n < 0 {
                        let e = PR_GetError();
                        drop(Box::from_raw(ctx));
                        close_quietly(ssl_fd);
                        return Err(format!(
                            "PR_Poll during connect failed: {}",
                            nspr_error_name(e)
                        ));
                    }
                    if PR_ConnectContinue(ssl_fd, pfd.out_flags) == PR_SUCCESS {
                        break;
                    }
                    let e = PR_GetError();
                    if e != PR_IN_PROGRESS_ERROR && e != PR_WOULD_BLOCK_ERROR {
                        drop(Box::from_raw(ctx));
                        close_quietly(ssl_fd);
                        return Err(format!(
                            "TCP connect to {host}:{port} failed: {}",
                            nspr_error_name(e)
                        ));
                    }
                }
            }

            // --- TLS handshake (ForceHandshake / poll / retry) -----------
            loop {
                let rv = SSL_ForceHandshake(ssl_fd);
                if rv == SECSuccess {
                    break;
                }
                let err = PR_GetError();
                if err != PR_WOULD_BLOCK_ERROR {
                    drop(Box::from_raw(ctx));
                    close_quietly(ssl_fd);
                    return Err(format!(
                        "TLS handshake with {host}:{port} failed: {} (strict certificate verification is enforced)",
                        nspr_error_name(err)
                    ));
                }
                if Instant::now() >= deadline {
                    drop(Box::from_raw(ctx));
                    close_quietly(ssl_fd);
                    return Err(format!("TLS handshake with {host}:{port} timed out"));
                }
                let mut pfd = PRPollDesc {
                    fd: ssl_fd,
                    in_flags: (PR_POLL_READ | PR_POLL_WRITE) as i16,
                    out_flags: 0,
                };
                let n = PR_Poll(&raw mut pfd, 1, poll_timeout_until(deadline));
                if n < 0 {
                    let e = PR_GetError();
                    drop(Box::from_raw(ctx));
                    close_quietly(ssl_fd);
                    return Err(format!(
                        "PR_Poll during handshake failed: {}",
                        nspr_error_name(e)
                    ));
                }
            }
            drop(Box::from_raw(ctx));

            // Which ALPN protocol did the server pick?
            let mut state: c_int = 0;
            let mut proto_buf = [0u8; 255];
            let mut proto_len: c_uint = 0;
            let mut negotiated = String::new();
            if SSL_GetNextProto(
                ssl_fd,
                &raw mut state,
                proto_buf.as_mut_ptr(),
                &raw mut proto_len,
                proto_buf.len() as c_uint,
            ) == SECSuccess
                && proto_len > 0
            {
                negotiated = String::from_utf8_lossy(&proto_buf[..proto_len as usize]).to_string();
            }
            log::info!(
                "[TLS] Connected to {host}:{port}; TLS handshake OK; ALPN = {:?}",
                if negotiated.is_empty() {
                    "(none)"
                } else {
                    &negotiated
                }
            );

            // Wakeup channel: TCP socketpair (NSPR pipes don't support poll).
            let mut pair: [*mut PRFileDesc; 2] = [ptr::null_mut(); 2];
            if PR_NewTCPSocketPair(pair.as_mut_ptr()) != PR_SUCCESS {
                close_quietly(ssl_fd);
                return Err("PR_NewTCPSocketPair failed".to_string());
            }
            let (wake_read, wake_write) = (pair[0], pair[1]);
            set_nonblocking(wake_read)?;

            let (cmd_tx, cmd_rx) = std_mpsc::channel::<IoCmd>();
            let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(256);

            let io_fd = SendFd(ssl_fd);
            let io_wake = SendFd(wake_read);
            thread::Builder::new()
                .name("nss-tls-io".to_string())
                .spawn(move || {
                    io_loop(io_fd, io_wake, cmd_rx, data_tx);
                })
                .map_err(|e| {
                    close_quietly(ssl_fd);
                    PR_Close(wake_read);
                    PR_Close(wake_write);
                    format!("Failed to spawn TLS I/O thread: {e}")
                })?;

            Ok(Self {
                cmd_tx,
                wake: SendFd(wake_write),
                rx: Mutex::new(StreamReadBuffer::new(data_rx)),
                negotiated_alpn: negotiated,
            })
        }
    }

    fn wake_io_thread(&self) {
        // One byte wakes the poll loop; the loop drains the socketpair.
        let byte: u8 = 1;
        let fd = self.wake.0;
        let _ = unsafe { PR_Write(fd, (&byte as *const u8).cast(), 1) };
    }
}

#[async_trait]
impl WireTransport for TlsTransport {
    async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut rx = self.rx.lock().await;
        rx.read(buf).await
    }

    async fn write_all(&self, buf: &[u8]) -> Result<(), String> {
        self.cmd_tx
            .send(IoCmd::Write(buf.to_vec()))
            .map_err(|_| "TLS I/O thread terminated".to_string())?;
        self.wake_io_thread();
        Ok(())
    }

    fn shutdown(&self) {
        if self.cmd_tx.send(IoCmd::Shutdown).is_ok() {
            self.wake_io_thread();
        }
    }
}

impl Drop for TlsTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The single-owner I/O event loop for one TLS connection.
///
/// `fd_wrapper` / `wake_wrapper` exist so raw pointers cross the thread
/// boundary inside a `Send`-asserting newtype (edition-2024 closures would
/// otherwise capture the raw field itself).
fn io_loop(
    fd_wrapper: SendFd,
    wake_wrapper: SendFd,
    cmd_rx: std_mpsc::Receiver<IoCmd>,
    data_tx: mpsc::Sender<Vec<u8>>,
) {
    let fd = fd_wrapper.0;
    let wake_read = wake_wrapper.0;
    let mut out_buf: Vec<u8> = Vec::new();
    let mut shutting_down = false;
    let mut poll_fds: [PRPollDesc; 2] = [PRPollDesc {
        fd: ptr::null_mut(),
        in_flags: 0,
        out_flags: 0,
    }; 2];

    loop {
        poll_fds[0].fd = fd;
        poll_fds[0].in_flags = PR_POLL_READ as i16
            | if out_buf.is_empty() {
                0
            } else {
                PR_POLL_WRITE as i16
            };
        poll_fds[0].out_flags = 0;
        poll_fds[1].fd = wake_read;
        poll_fds[1].in_flags = PR_POLL_READ as i16;
        poll_fds[1].out_flags = 0;

        let n = unsafe { PR_Poll(poll_fds.as_mut_ptr(), 2, PR_MillisecondsToInterval(250)) };
        if n < 0 {
            break; // poll error — fatal
        }

        // 1. Wakeup socketpair: drain it, then drain the command queue.
        if poll_fds[1].out_flags & (PR_POLL_READ as i16) != 0 {
            let mut drain = [0u8; 64];
            unsafe {
                // wake_read is nonblocking: read until it would block.
                while PR_Read(wake_read, drain.as_mut_ptr().cast(), drain.len() as PRInt32) > 0 {}
            }
        }
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                IoCmd::Write(data) => {
                    out_buf.extend_from_slice(&data);
                    if out_buf.len() > 64 * 1024 * 1024 {
                        // Backstop against an unbounded write backlog.
                        log::error!("[TLS] Write backlog exceeded 64 MiB, closing connection");
                        shutting_down = true;
                        out_buf.clear();
                        break;
                    }
                }
                IoCmd::Shutdown => {
                    shutting_down = true;
                    break;
                }
            }
        }
        if shutting_down && out_buf.is_empty() {
            break;
        }

        // 2. Flush pending outbound bytes. Attempted whenever out_buf is
        //    non-empty (the socket is nonblocking, would-block is benign) —
        //    the poll WRITE flag may be stale for data queued this iteration.
        if !out_buf.is_empty() {
            loop {
                if out_buf.is_empty() {
                    break;
                }
                let chunk_len = out_buf.len().min(64 * 1024) as PRInt32;
                let written = unsafe { PR_Write(fd, out_buf.as_ptr().cast(), chunk_len) };
                if written > 0 {
                    out_buf.drain(..written as usize);
                } else {
                    break; // would-block or error; retry on the next iteration
                }
            }
            if out_buf.is_empty() && shutting_down {
                break;
            }
            if out_buf.is_empty() {
                continue; // re-poll without the WRITE flag
            }
        }

        // 3. Socket readable: read and forward upstream.
        if poll_fds[0].out_flags & (PR_POLL_READ as i16) != 0 {
            loop {
                let mut chunk = vec![0u8; 64 * 1024];
                let nread =
                    unsafe { PR_Read(fd, chunk.as_mut_ptr().cast(), chunk.len() as PRInt32) };
                if nread > 0 {
                    chunk.truncate(nread as usize);
                    if data_tx.blocking_send(chunk).is_err() {
                        // Consumer dropped: remote close.
                        shutting_down = true;
                        out_buf.clear();
                        break;
                    }
                } else if nread == 0 {
                    // EOF
                    shutting_down = true;
                    out_buf.clear();
                    break;
                } else {
                    let err = unsafe { PR_GetError() };
                    if err == PR_WOULD_BLOCK_ERROR {
                        break; // drained for now
                    }
                    shutting_down = true;
                    out_buf.clear();
                    break;
                }
            }
            if shutting_down && out_buf.is_empty() {
                break;
            }
        }
    }

    // Owned exclusively by this thread: closing here is race-free.
    // (wake_write belongs to TlsTransport and is closed when it drops.)
    unsafe {
        PR_Shutdown(fd, PR_SHUTDOWN_BOTH);
        PR_Close(fd);
        PR_Close(wake_read);
    }
    // Dropping data_tx closes the mpsc → reader sees EOF.
    drop(data_tx);
}

/// Strict certificate verification hook (runs during the TLS handshake).
unsafe extern "C" fn auth_certificate_hook(
    arg: *mut std::ffi::c_void,
    fd: *mut PRFileDesc,
    _checksig: PRBool,
    _is_server: PRBool,
) -> SECStatus {
    let ctx = unsafe { &*(arg.cast::<AuthCtx>()) };
    let chain = unsafe { peer_certificate_chain_der(fd) };
    if verify_chain(&chain, &ctx.host) {
        SECSuccess
    } else {
        // Rejected: bad/missing chain, untrusted root or SAN mismatch.
        SECFailure
    }
}

fn set_nonblocking(fd: *mut PRFileDesc) -> Result<(), String> {
    let mut opt = PRSocketOptionData {
        option: PR_SockOpt_Nonblocking,
        value_nonblocking: PR_TRUE,
    };
    if unsafe { PR_SetSocketOption(fd, &raw mut opt) } != PR_SUCCESS {
        unsafe { PR_Close(fd) };
        Err("PR_SetSocketOption(Nonblocking) failed".to_string())
    } else {
        Ok(())
    }
}

fn close_quietly(fd: *mut PRFileDesc) {
    unsafe { PR_Close(fd) };
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addr_str = format!("{host}:{port}");
    addr_str
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {addr_str}: {e}"))?
        .next()
        .ok_or_else(|| format!("No addresses for {addr_str}"))
}

/// Remaining poll timeout in NSPR interval units, capped at 250ms slices so
/// the deadline is re-checked.
fn poll_timeout_until(deadline: Instant) -> PRIntervalTime {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let ms = remaining.as_millis().min(250) as u32;
    if ms == 0 {
        PR_INTERVAL_NO_WAIT
    } else {
        unsafe { PR_MillisecondsToInterval(ms) }
    }
}

fn nspr_error_name(code: PRInt32) -> String {
    let name = match code {
        PR_WOULD_BLOCK_ERROR => "PR_WOULD_BLOCK_ERROR",
        PR_IO_TIMEOUT_ERROR => "PR_IO_TIMEOUT_ERROR",
        PR_CONNECT_REFUSED_ERROR => "PR_CONNECT_REFUSED_ERROR",
        PR_NETWORK_UNREACHABLE_ERROR => "PR_NETWORK_UNREACHABLE_ERROR",
        PR_CONNECT_TIMEOUT_ERROR => "PR_CONNECT_TIMEOUT_ERROR",
        PR_CONNECT_RESET_ERROR => "PR_CONNECT_RESET_ERROR",
        PR_IN_PROGRESS_ERROR => "PR_IN_PROGRESS_ERROR",
        _ => "PR error",
    };
    format!("{name} ({code})")
}
