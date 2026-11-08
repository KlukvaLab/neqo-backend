//! Инициализация NSS и глобального верификатора сертификатов.
//!
//! Схема повторяет Firefox:
//!  * NSS инициализируется в режиме NoDB (`NSS_NoDB_Init` + domestic policy)
//!    через `nss_rs::init()` — никаких записей на диск;
//!  * корневые центры сертификации НЕ берутся из NSS (в NoDB их нет) —
//!    они загружаются в верификатор rustls-webpki либо из PEM, переданного
//!    приложением (Android: доверенное хранилище ОС отдаёт Kotlin-слой),
//!    либо из системного хранилища (desktop Linux/Windows);
//!  * проверка цепочек (path building, сроков, SAN, EKU) делает
//!    `WebPkiServerVerifier` — на wire-отпечаток это не влияет.

use std::sync::OnceLock;

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;

use crate::error::{Error, ErrorCode, Result};

pub struct GlobalContext {
    pub verifier: std::sync::Arc<WebPkiServerVerifier>,
}

static GLOBAL: OnceLock<std::result::Result<GlobalContext, String>> = OnceLock::new();

/// Инициализировать библиотеку.
///
/// `pem_roots`:
///  * `Some(bytes)` — PEM-блоки `-----BEGIN CERTIFICATE-----` с корневыми
///    (и, при необходимости, промежуточными) сертификатами;
///  * `None` — загрузить корни из хранилища ОС (только desktop).
pub fn init(pem_roots: Option<&[u8]>) -> Result<()> {
    let res = GLOBAL.get_or_init(|| match init_inner(pem_roots) {
        Ok(ctx) => Ok(ctx),
        Err(e) => Err(e.to_string()),
    });
    match res {
        Ok(_) => Ok(()),
        Err(msg) => Err(Error::new(ErrorCode::NotInitialized, msg.clone())),
    }
}

/// Доступ к верификатору (после успешного `init`).
pub fn global() -> Result<&'static GlobalContext> {
    let res = GLOBAL.get_or_init(|| Err("nb_init не был вызван".to_string()));
    match res {
        Ok(ctx) => Ok(ctx),
        Err(msg) => Err(Error::new(ErrorCode::NotInitialized, msg.clone())),
    }
}

fn init_inner(pem_roots: Option<&[u8]>) -> Result<GlobalContext> {
    // 1. NSS (NSS_NoDB_Init + NSS_SetDomesticPolicy + проверка версии).
    //    Тот же вызов делает neqo для QUIC-пути — двойная инициализация
    //    безопасна (nss-rs использует OnceLock, NSS_IsInitialized).
    nss::init().map_err(|e| Error::new(ErrorCode::Generic, format!("NSS init: {e:?}")))?;

    // 2. Корневые сертификаты.
    let mut roots = RootCertStore::empty();
    let mut loaded = 0usize;
    if let Some(pem) = pem_roots {
        for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(pem)) {
            let cert = cert.map_err(|e| {
                Error::new(ErrorCode::InvalidArgument, format!("PEM parse: {e}"))
            })?;
            roots
                .add(cert)
                .map_err(|e| Error::new(ErrorCode::InvalidArgument, format!("root CA: {e}")))?;
            loaded += 1;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        if let Some(err) = native.errors.first() {
            return Err(Error::new(
                ErrorCode::Generic,
                format!("system roots: {err}"),
            ));
        }
        for cert in native.certs {
            if roots.add(cert).is_ok() {
                loaded += 1;
            }
        }
    }
    if loaded == 0 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "не загружено ни одного корневого сертификата",
        ));
    }

    // 3. Верификатор цепочек (алгоритмы подписей из ring-провайдера rustls).
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiServerVerifier::builder_with_provider(
        std::sync::Arc::new(roots),
        provider,
    )
    .build()
    .map_err(|e| Error::new(ErrorCode::Generic, format!("verifier: {e}")))?;

    Ok(GlobalContext {
        verifier,
    })
}

/// Освобождение ресурсов (сейчас — no-op; NSS остаётся инициализированным
/// до конца процесса, как это делает Firefox). Предоставлено для стабильности ABI.
pub fn shutdown() {}
