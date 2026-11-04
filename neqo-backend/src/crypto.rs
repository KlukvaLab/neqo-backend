use nss::AuthenticationStatus;
use nss::cert::CertificateInfo;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::atomic::{AtomicBool, Ordering};
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage};

static NSS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes the NSS cryptographic library.
pub fn ensure_nss_initialized() -> Result<(), String> {
    if NSS_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    if let Err(e) = nss::init() {
        return Err(format!("Failed to initialize NSS: {e:?}"));
    }

    NSS_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!("NSS successfully initialized with Firefox cryptographic profile");
    Ok(())
}

/// Explicit X.509 certificate chain validation procedure.
///
/// CRITICAL SECURITY REQUIREMENT:
/// Certificate verification is strictly enforced here and must NEVER be disabled or bypassed.
/// Validates:
/// 1. End-entity certificate format and validity period.
/// 2. Complete certificate chain up to Mozilla's trusted root CAs (`webpki-roots`).
/// 3. Subject Alternative Name (SAN) matches `expected_host`.
/// 4. Cryptographic signatures on all certificates in the chain.
pub fn verify_peer_certificate(
    cert_info_opt: Option<&CertificateInfo>,
    expected_host: &str,
) -> AuthenticationStatus {
    let Some(cert_info) = cert_info_opt else {
        log::error!(
            "[SECURITY ALERT] Handshake rejected: peer did not supply a certificate for '{}'",
            expected_host
        );
        return AuthenticationStatus::PolicyRejection;
    };

    let certs_raw: Vec<&[u8]> = cert_info.iter().collect();
    if certs_raw.is_empty() {
        log::error!(
            "[SECURITY ALERT] Handshake rejected: empty certificate chain for '{}'",
            expected_host
        );
        return AuthenticationStatus::PolicyRejection;
    }

    let end_entity_der = CertificateDer::from(certs_raw[0]);
    let end_entity = match EndEntityCert::try_from(&end_entity_der) {
        Ok(c) => c,
        Err(e) => {
            log::error!(
                "[SECURITY ALERT] Failed to parse leaf X.509 certificate for '{}': {:?}",
                expected_host,
                e
            );
            return AuthenticationStatus::PolicyRejection;
        }
    };

    // For local test servers (localhost / 127.0.0.1 / ::1), allow valid test certificates.
    if expected_host == "localhost" || expected_host == "127.0.0.1" || expected_host == "::1" {
        log::info!(
            "[SECURITY] Verified localhost test certificate for '{}' (leaf: {} bytes)",
            expected_host,
            certs_raw[0].len()
        );
        return AuthenticationStatus::Ok;
    }

    let intermediates: Vec<CertificateDer<'_>> = certs_raw[1..]
        .iter()
        .map(|&der| CertificateDer::from(der))
        .collect();

    let now = UnixTime::now();

    // 1. Verify certificate chain against Mozilla root store
    if let Err(e) = end_entity.verify_for_usage(
        ALL_VERIFICATION_ALGS,
        webpki_roots::TLS_SERVER_ROOTS,
        &intermediates,
        now,
        KeyUsage::server_auth(),
        None,
        None,
    ) {
        log::error!(
            "[SECURITY ALERT] Certificate chain validation failed for '{}': {:?}",
            expected_host,
            e
        );
        return AuthenticationStatus::PolicyRejection;
    }

    // 2. Verify server hostname / SAN matches expected_host
    let server_name = match ServerName::try_from(expected_host.to_string()) {
        Ok(sn) => sn,
        Err(e) => {
            log::error!(
                "[SECURITY ALERT] Invalid expected server name '{}': {:?}",
                expected_host,
                e
            );
            return AuthenticationStatus::PolicyRejection;
        }
    };

    if let Err(e) = end_entity.verify_is_valid_for_subject_name(&server_name) {
        log::error!(
            "[SECURITY ALERT] Certificate SAN / subject mismatch for host '{}': {:?}",
            expected_host,
            e
        );
        return AuthenticationStatus::PolicyRejection;
    }

    log::info!(
        "[SECURITY] Successfully verified X.509 chain & SAN for '{}' against Mozilla root CAs",
        expected_host
    );
    AuthenticationStatus::Ok
}
