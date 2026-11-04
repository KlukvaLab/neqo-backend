//! Certificate verification.
//!
//! CRITICAL SECURITY INVARIANT: verification is strictly enforced and must
//! NEVER be disabled or bypassed. There is deliberately NO "insecure",
//! "accept-all" or localhost shortcut in this module. Test servers must
//! provision a certificate whose chain validates against a root CA added
//! explicitly at runtime via [`add_root_ca`] (pinned test CA), which is the
//! production path as well ("свой CA зашить в приложение" — request.md §5).

use std::sync::OnceLock;

use nss::AuthenticationStatus;
use nss::cert::CertificateInfo;
use parking_lot::RwLock;
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage, anchor_from_trusted_cert};

static NSS_INITIALIZED: OnceLock<()> = OnceLock::new();

/// Additional trust anchors (pinned CA / user-provided proxy CA),
/// appended to the built-in Mozilla root store at verification time.
static EXTRA_ROOTS: OnceLock<RwLock<Vec<TrustAnchor<'static>>>> = OnceLock::new();

fn extra_roots() -> &'static RwLock<Vec<TrustAnchor<'static>>> {
    EXTRA_ROOTS.get_or_init(|| RwLock::new(Vec::new()))
}

/// Initializes the NSS cryptographic library.
pub fn ensure_nss_initialized() -> Result<(), String> {
    if NSS_INITIALIZED.get().is_some() {
        return Ok(());
    }

    if let Err(e) = nss::init() {
        return Err(format!("Failed to initialize NSS: {e:?}"));
    }

    let _ = NSS_INITIALIZED.set(());
    log::info!("NSS successfully initialized with Firefox cryptographic profile");
    Ok(())
}

/// Adds an extra trusted root CA (DER-encoded X.509).
///
/// This is how a self-managed proxy server CA is pinned: the application ships
/// (or provisions) its own CA certificate and calls this once at startup.
/// The built-in Mozilla root store remains active alongside it.
/// The DER bytes are intentionally leaked (process-lifetime storage): trust
/// anchors borrow their parsed subject/SPKI from the certificate bytes.
pub fn add_root_ca(der: &[u8]) -> Result<(), String> {
    let cert: &'static CertificateDer<'static> =
        Box::leak(Box::new(CertificateDer::from(der.to_vec())));
    let anchor = anchor_from_trusted_cert(cert)
        .map_err(|e| format!("Failed to parse root CA certificate: {e:?}"))?;
    extra_roots().write().push(anchor);
    log::info!(
        "[SECURITY] Added pinned root CA ({} bytes DER); extra roots: {}",
        der.len(),
        extra_roots().read().len()
    );
    Ok(())
}

/// Verifies a DER certificate chain (leaf first) against
/// (Mozilla roots + pinned extra roots) and the expected host name.
///
/// Returns `true` if and only if:
/// 1. The chain is non-empty and the leaf parses as an end-entity cert.
/// 2. The full chain validates (signatures, validity period, server_auth EKU)
///    against the trust store.
/// 3. The leaf is valid for `expected_host` (SAN match).
pub fn verify_chain(chain: &[Vec<u8>], expected_host: &str) -> bool {
    if chain.is_empty() {
        log::error!(
            "[SECURITY ALERT] Handshake rejected: peer did not supply a certificate for '{}'",
            expected_host
        );
        return false;
    }

    let end_entity_der = CertificateDer::from(chain[0].as_slice());
    let end_entity = match EndEntityCert::try_from(&end_entity_der) {
        Ok(c) => c,
        Err(e) => {
            log::error!(
                "[SECURITY ALERT] Failed to parse leaf X.509 certificate for '{}': {:?}",
                expected_host,
                e
            );
            return false;
        }
    };

    let intermediates: Vec<CertificateDer<'_>> = chain[1..]
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();

    // Assemble the trust store: Mozilla roots + pinned extra roots.
    let extra = extra_roots().read().clone();
    let mut anchors: Vec<TrustAnchor<'_>> = webpki_roots::TLS_SERVER_ROOTS.to_vec();
    anchors.extend(extra.iter().cloned());

    let now = UnixTime::now();

    // 1. Verify the certificate chain against the trust store.
    if let Err(e) = end_entity.verify_for_usage(
        ALL_VERIFICATION_ALGS,
        &anchors,
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
        return false;
    }

    // 2. Verify the server hostname / SAN matches expected_host.
    let server_name = match ServerName::try_from(expected_host.to_string()) {
        Ok(sn) => sn,
        Err(e) => {
            log::error!(
                "[SECURITY ALERT] Invalid expected server name '{}': {:?}",
                expected_host,
                e
            );
            return false;
        }
    };

    if let Err(e) = end_entity.verify_is_valid_for_subject_name(&server_name) {
        log::error!(
            "[SECURITY ALERT] Certificate SAN / subject mismatch for host '{}': {:?}",
            expected_host,
            e
        );
        return false;
    }

    log::info!(
        "[SECURITY] Verified X.509 chain & SAN for '{}' ({} chain certs, {} extra roots)",
        expected_host,
        chain.len(),
        extra.len()
    );
    true
}

/// Adapter for the QUIC path (neqo hands us an nss-rs `CertificateInfo`).
pub fn verify_peer_certificate(
    cert_info_opt: Option<&CertificateInfo>,
    expected_host: &str,
) -> AuthenticationStatus {
    let chain: Vec<Vec<u8>> = match cert_info_opt {
        Some(info) => info.iter().map(<[u8]>::to_vec).collect(),
        None => Vec::new(),
    };
    if verify_chain(&chain, expected_host) {
        AuthenticationStatus::Ok
    } else {
        AuthenticationStatus::PolicyRejection
    }
}
