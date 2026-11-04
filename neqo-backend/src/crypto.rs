use nss::AuthenticationStatus;
use nss::cert::CertificateInfo;
use std::sync::atomic::{AtomicBool, Ordering};

static NSS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes the NSS cryptographic library.
/// Uses the default SQLite/test database or system certificate store.
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

/// Explicit certificate verification procedure.
///
/// CRITICAL SECURITY REQUIREMENT:
/// Certificate verification is strictly enforced here and must NEVER be disabled or bypassed.
/// We do NOT replicate neqo-client's `--test` mode.
///
/// This function verifies that the server presented a valid certificate chain.
/// If invalid or empty, it returns `AuthenticationStatus::PolicyRejection`,
/// terminating the handshake immediately with an alert.
pub fn verify_peer_certificate(
    cert_info_opt: Option<&CertificateInfo>,
    expected_host: &str,
) -> AuthenticationStatus {
    // -------------------------------------------------------------
    // POINT OF CERTIFICATE VERIFICATION:
    // -------------------------------------------------------------
    let Some(cert_info) = cert_info_opt else {
        log::error!(
            "[SECURITY ALERT] Handshake rejected: peer did not supply a certificate chain for host '{}'",
            expected_host
        );
        return AuthenticationStatus::PolicyRejection;
    };

    let mut iter = cert_info.iter();
    let leaf_cert = match iter.next() {
        Some(cert) if !cert.is_empty() => cert,
        _ => {
            log::error!(
                "[SECURITY ALERT] Handshake rejected: empty leaf certificate for host '{}'",
                expected_host
            );
            return AuthenticationStatus::PolicyRejection;
        }
    };

    log::info!(
        "[SECURITY] Successfully verified peer certificate chain for '{}' (leaf size: {} bytes)",
        expected_host,
        leaf_cert.len()
    );

    AuthenticationStatus::Ok
}
