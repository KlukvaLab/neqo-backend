//! Проверка цепочек сертификатов сервера.
//!
//! Firefox не доверяет NSS проверять сертификаты: PSM снимает цепочку
//! с сокета и проверяет её собственным верификатором. Мы делаем то же:
//! цепочка DER-блокаов уходит в `WebPkiServerVerifier` (rustls-webpki:
//! построение пути, подписи, сроки, SAN, EKU TLS-сервера).

use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::error::{Error, ErrorCode, Result};
use crate::init;

/// Проверить цепочку (chain[0] — сертификат сервера) против имени `host`.
pub fn verify_server_chain(chain: &[Vec<u8>], host: &str) -> Result<()> {
    if chain.is_empty() {
        return Err(Error::new(
            ErrorCode::CertificateInvalid,
            "сервер не предоставил сертификат",
        ));
    }
    let ctx = init::global()?;

    let end_entity = CertificateDer::from(chain[0].clone());
    let intermediates: Vec<CertificateDer<'_>> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();

    let name = ServerName::try_from(host.to_string()).map_err(|e| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("некорректное имя хоста {host:?}: {e}"),
        )
    })?;

    ctx.verifier
        .verify_server_cert(&end_entity, &intermediates, &name, &[], UnixTime::now())
        .map(|_| ())
        .map_err(|e| {
            Error::new(
                ErrorCode::CertificateInvalid,
                format!("проверка сертификата для {host} не пройдена: {e}"),
            )
        })
}
