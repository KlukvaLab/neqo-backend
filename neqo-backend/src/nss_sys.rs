//! Minimal hand-written bindings to the NSPR socket API and the NSS socket-level
//! SSL API (TLS over TCP).
//!
//! ## Why this exists (and why it does not use `nss-rs`)
//!
//! `nss-rs` only exposes the QUIC-style "agent" API (`Agent`, `handshake_raw`,
//! `RecordList`), where the caller implements the record layer. That is what
//! neqo uses for QUIC. For TLS over TCP we need the socket-based SSL API
//! (`SSL_ImportFD`, `PR_Connect`, `PR_Read`, `PR_Write`) — the very API Firefox
//! itself uses for `https://` — which produces a genuine Firefox ClientHello
//! and gives us the battle-tested NSS record layer (key updates, close_notify,
//! fragmentation) instead of a hand-rolled one.
//!
//! The NSS public C API is stable (backwards compatible within 3.x, guaranteed
//! by Mozilla), so this small surface is safe to bind by hand. All numeric
//! option values below were verified against the NSS 3.132 headers shipped in
//! `../nss` (`lib/ssl/ssl.h`, `lib/util/seccomon.h`) and NSPR 4.x
//! (`/usr/include/nspr/{prio.h,prnetdb.h,prinrval.h}`).
//!
//! **When bumping NSS**: re-verify the `SSL_*` option constants and struct
//! layouts in this file against the new headers. They change rarely, but they
//! are not ABI-guaranteed.

#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    clippy::upper_case_acronyms
)]
// non_upper_case_globals: constants mirror the C spelling of the NSS/NSPR
// headers they were verified against; renaming them invites transcription
// mistakes on the next NSS bump.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::OnceLock;

// =========================================================================
// Base types (prtypes.h / seccomon.h)
// =========================================================================

pub type PRStatus = c_int; // PR_FAILURE = -1, PR_SUCCESS = 0
pub const PR_SUCCESS: PRStatus = 0;
pub const PR_FAILURE: PRStatus = -1;

pub type PRBool = c_int; // PR_TRUE = 1, PR_FALSE = 0
pub const PR_TRUE: PRBool = 1;

pub type PRIntn = c_int;
pub type PRInt32 = c_int;
pub type PRUint16 = u16;
pub type PRUint32 = u32;
pub type PRIntervalTime = PRUint32;

pub const PR_INTERVAL_NO_WAIT: PRIntervalTime = 0;
pub const PR_INTERVAL_NO_TIMEOUT: PRIntervalTime = 0xFFFF_FFFF;

pub type SECStatus = c_int; // SECFailure = -1, SECSuccess = 0
pub const SECSuccess: SECStatus = 0;
pub const SECFailure: SECStatus = -1;

/// Opaque NSPR file descriptor.
#[repr(C)]
pub struct PRFileDesc {
    _private: [u8; 0],
}

// =========================================================================
// PRNetAddr (prnetdb.h) — union of 108 bytes on Unix/Windows.
//
// We model the first two fields explicitly (family, port) and keep the rest
// as an opaque byte area filled per address family:
//   IPv4: family@0, port@2, ip@4..8, pad@8..16  (total 16)
//   IPv6: family@0, port@2, flowinfo@4..8, ip@8..24, scope_id@24..28
// =========================================================================

pub const PR_AF_INET: PRUint16 = 2;
pub const PR_AF_INET6: PRUint16 = 10;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PRNetAddr {
    pub family: PRUint16,
    /// Network byte order (big-endian).
    pub port: PRUint16,
    /// `ip` (v4) / `flowinfo`+`ip`+`scope_id` (v6), laid out per family.
    pub rest: [u8; 104],
}

impl PRNetAddr {
    #[must_use]
    pub fn ipv4(octets: [u8; 4], port: u16) -> Self {
        let mut addr = Self {
            family: PR_AF_INET,
            port: port.to_be(),
            rest: [0; 104],
        };
        addr.rest[..4].copy_from_slice(&octets);
        addr
    }

    #[must_use]
    pub fn ipv6(octets: [u8; 16], port: u16) -> Self {
        let mut addr = Self {
            family: PR_AF_INET6,
            port: port.to_be(),
            rest: [0; 104],
        };
        // rest[0..4] = flowinfo (0), rest[4..20] = ip, rest[20..24] = scope_id
        addr.rest[4..20].copy_from_slice(&octets);
        addr
    }
}

// =========================================================================
// PRPollDesc (prio.h)
// =========================================================================

pub const PR_POLL_READ: PRIntn = 0x1;
pub const PR_POLL_WRITE: PRIntn = 0x2;
pub const PR_POLL_EXCEPT: PRIntn = 0x4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PRPollDesc {
    pub fd: *mut PRFileDesc,
    pub in_flags: i16,
    pub out_flags: i16,
}

// =========================================================================
// PRSocketOptionData (prio.h) — only the `Nonblocking` member is modelled.
// =========================================================================

pub const PR_SockOpt_Nonblocking: PRIntn = 0;

#[repr(C)]
pub struct PRSocketOptionData {
    pub option: PRIntn,
    /// Union member `value.nonblocking`.
    pub value_nonblocking: PRIntn,
}

// =========================================================================
// SECItem / SECItemArray (seccomon.h)
// =========================================================================

#[repr(C)]
pub struct SECItem {
    pub kind: c_uint,
    pub data: *mut u8,
    pub len: c_uint,
}

#[repr(C)]
pub struct SECItemArray {
    pub items: *mut SECItem,
    pub len: c_uint,
}

// =========================================================================
// SSL types (ssl.h / sslt.h)
// =========================================================================

pub const SSL_LIBRARY_VERSION_TLS_1_2: PRUint16 = 0x0303;
pub const SSL_LIBRARY_VERSION_TLS_1_3: PRUint16 = 0x0304;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SSLVersionRange {
    pub min: PRUint16,
    pub max: PRUint16,
}

// SSL option values — verified against NSS 3.132 lib/ssl/ssl.h.
// These are enum positions, NOT ABI-guaranteed: re-check on NSS bump.
pub const SSL_SECURITY: PRInt32 = 1;
pub const SSL_HANDSHAKE_AS_CLIENT: PRInt32 = 5;
pub const SSL_NO_CACHE: PRInt32 = 9;
pub const SSL_ENABLE_SESSION_TICKETS: PRInt32 = 18;
pub const SSL_ENABLE_ALPN: PRInt32 = 26;

/// `SECStatus (*)(void *arg, PRFileDesc *fd, PRBool checksig, PRBool isServer)`
pub type SSLAuthCertificate = Option<
    unsafe extern "C" fn(
        arg: *mut c_void,
        fd: *mut PRFileDesc,
        checksig: PRBool,
        is_server: PRBool,
    ) -> SECStatus,
>;

// =========================================================================
// Imported functions
// =========================================================================

// --- NSPR (libnspr4) ---
unsafe extern "C" {
    pub fn PR_OpenTCPSocket(af: PRIntn) -> *mut PRFileDesc;
    pub fn PR_Connect(
        fd: *mut PRFileDesc,
        addr: *const PRNetAddr,
        timeout: PRIntervalTime,
    ) -> PRStatus;
    pub fn PR_Read(fd: *mut PRFileDesc, buf: *mut c_void, amount: PRInt32) -> PRInt32;
    pub fn PR_Write(fd: *mut PRFileDesc, buf: *const c_void, amount: PRInt32) -> PRInt32;
    pub fn PR_Close(fd: *mut PRFileDesc) -> PRStatus;
    pub fn PR_Shutdown(fd: *mut PRFileDesc, how: PRIntn) -> PRStatus;
    pub fn PR_Poll(pds: *mut PRPollDesc, npds: PRIntn, timeout: PRIntervalTime) -> PRIntn;
    /// Continues a nonblocking connect after `PR_Poll` (out_flags from the
    /// poll descriptor). See prio.h: PR_Connect → PR_IN_PROGRESS_ERROR →
    /// poll(WRITE|EXCEPT) → PR_ConnectContinue → repeat.
    pub fn PR_ConnectContinue(fd: *mut PRFileDesc, out_flags: i16) -> PRStatus;
    pub fn PR_GetError() -> PRInt32;
    pub fn PR_MillisecondsToInterval(ms: PRUint32) -> PRIntervalTime;
    pub fn PR_SetSocketOption(fd: *mut PRFileDesc, data: *mut PRSocketOptionData) -> PRStatus;
    /// Creates a pair of connected TCP sockets — used as a pollable wakeup
    /// channel (NSPR pipes do not support `PR_Poll`).
    pub fn PR_NewTCPSocketPair(fds: *mut *mut PRFileDesc) -> PRStatus;
}

pub const PR_SHUTDOWN_BOTH: PRIntn = 2;

// --- NSS SSL (libssl3) ---
unsafe extern "C" {
    pub fn SSL_ImportFD(model: *mut PRFileDesc, fd: *mut PRFileDesc) -> *mut PRFileDesc;
    pub fn SSL_OptionSet(fd: *mut PRFileDesc, option: PRInt32, on: PRBool) -> SECStatus;
    pub fn SSL_SetURL(fd: *mut PRFileDesc, url: *const c_char) -> SECStatus;
    pub fn SSL_VersionRangeSet(fd: *mut PRFileDesc, range: *const SSLVersionRange) -> SECStatus;
    pub fn SSL_AuthCertificateHook(
        fd: *mut PRFileDesc,
        cb: SSLAuthCertificate,
        arg: *mut c_void,
    ) -> SECStatus;
    /// `data` is wire-format, 8-bit length-prefixed protocol names.
    /// NOTE: NSS rotates the list (first protocol moves to the end) for NPN
    /// legacy reasons, so pass protocols in REVERSE preference order.
    pub fn SSL_SetNextProtoNego(fd: *mut PRFileDesc, data: *const u8, len: c_uint) -> SECStatus;
    /// Returns the negotiated ALPN protocol (empty = none). Valid after
    /// handshake. `state` may be null.
    pub fn SSL_GetNextProto(
        fd: *mut PRFileDesc,
        state: *mut c_int,
        buf: *mut u8,
        len: *mut c_uint,
        buf_len: c_uint,
    ) -> SECStatus;
    /// Resolves an experimental NSS API by name to a function pointer.
    /// Needed for `SSL_PeerCertificateChainDER`, which is NOT exported as a
    /// plain symbol (see the `peer_certificate_chain_der` helper below).
    pub fn SSL_GetExperimentalAPI(name: *const c_char) -> *mut c_void;
    /// Forces the TLS handshake to complete on a connected socket. On a
    /// blocking socket this runs the full handshake (including the
    /// certificate-authentication hook). NSS does NOT do this in
    /// `PR_Connect` — the handshake is otherwise deferred to the first
    /// `PR_Read`/`PR_Write`.
    pub fn SSL_ForceHandshake(fd: *mut PRFileDesc) -> SECStatus;
}

// --- NSS util (libnssutil3 / libnss3) ---
unsafe extern "C" {
    pub fn SECITEM_FreeArray(arr: *mut SECItemArray, free_it: PRBool);
}

// NSPR error codes (prerr.h) — stable literal values, part of the NSPR ABI.
pub const PR_WOULD_BLOCK_ERROR: PRInt32 = -5998;
pub const PR_IO_TIMEOUT_ERROR: PRInt32 = -5990;
pub const PR_CONNECT_REFUSED_ERROR: PRInt32 = -5981;
pub const PR_NETWORK_UNREACHABLE_ERROR: PRInt32 = -5980;
pub const PR_CONNECT_TIMEOUT_ERROR: PRInt32 = -5979;
pub const PR_CONNECT_RESET_ERROR: PRInt32 = -5961;
pub const PR_IN_PROGRESS_ERROR: PRInt32 = -5934;

type SslPeerCertChainDerFn =
    unsafe extern "C" fn(fd: *mut PRFileDesc, out: *mut *mut SECItemArray) -> SECStatus;

/// Cached `SSL_PeerCertificateChainDER` function pointer, resolved through
/// `SSL_GetExperimentalAPI` (the symbol itself is not exported from
/// libssl3.so; nss-rs uses the same mechanism).
static PEER_CERT_CHAIN_DER: OnceLock<Option<SslPeerCertChainDerFn>> = OnceLock::new();

fn peer_cert_chain_der_fn() -> Option<SslPeerCertChainDerFn> {
    *PEER_CERT_CHAIN_DER.get_or_init(|| {
        let name = c"SSL_PeerCertificateChainDER";
        let ptr = unsafe { SSL_GetExperimentalAPI(name.as_ptr()) };
        if ptr.is_null() {
            log::error!("SSL_GetExperimentalAPI(SSL_PeerCertificateChainDER) returned null");
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut c_void, SslPeerCertChainDerFn>(ptr) })
        }
    })
}

/// Fetches the peer certificate chain as DER blobs. Returns an empty vector
/// if the peer did not supply a certificate.
///
/// # Safety
/// `fd` must be a valid SSL socket with a completed or in-progress handshake.
pub unsafe fn peer_certificate_chain_der(fd: *mut PRFileDesc) -> Vec<Vec<u8>> {
    let Some(f) = peer_cert_chain_der_fn() else {
        return Vec::new();
    };
    unsafe {
        let mut arr: *mut SECItemArray = std::ptr::null_mut();
        if f(fd, &raw mut arr) != SECSuccess || arr.is_null() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let len = (*arr).len as usize;
        for i in 0..len {
            let item = (*arr).items.add(i);
            if (*item).data.is_null() {
                continue;
            }
            let slice = std::slice::from_raw_parts((*item).data, (*item).len as usize);
            out.push(slice.to_vec());
        }
        SECITEM_FreeArray(arr, PR_TRUE);
        out
    }
}
