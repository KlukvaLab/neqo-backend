//! # neqo-backend
//!
//! Сетевой бэкенд с TLS-отпечатком Firefox для прокси Gorynych.
//! Три пути:
//!  * HTTPS over TLS — TLS-сокеты NSS (1.2/1.3) + минимальный HTTP/1.1;
//!  * HTTPS over QUIC — HTTP/3 на стеке neqo (как в Firefox);
//!  * WSS — WebSocket (RFC 6455) поверх TLS-сокета.
//!
//! Внешний контракт — C ABI (см. `ffi/neqo_backend.h` и модуль [`ffi`]).
//! Rust-слой изолирует приложение от изменений API NSS/neqo.

#![allow(clippy::missing_safety_doc)] // FFI-функции: безопасность описана в .h

pub mod error;
pub mod ffi;
pub mod fingerprint;
pub mod http1;
pub mod init;
pub mod quic;
pub mod sha1;
pub mod tls;
pub mod verify;
pub mod ws;

/// Сгенерированные биндинги к NSPR/SSL (всё, чего не экспортирует nss-rs).
#[allow(
    dead_code,
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    unused_qualifications,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction
)]
pub mod nssx {
    include!(concat!(env!("OUT_DIR"), "/nss_extra.rs"));
}

pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"));
pub const NEQO_VERSION: &str = "0.34.0";
pub const NSS_RS_VERSION: &str = "0.16.3";

/// Строка версий для nb_version().
pub fn version_string() -> String {
    format!(
        "neqo-backend {} (neqo {}, nss-rs {}, pinned NSS: см. docs/BUILDING.md)",
        VERSION, NEQO_VERSION, NSS_RS_VERSION
    )
}
