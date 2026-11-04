//! End-to-end integration test: WebSocket over real NSS TLS.
//!
//! Covers the three critical acceptance criteria from request.md:
//! 1. TLS handshake with the genuine NSS socket API (Firefox TLS stack).
//! 2. Strict certificate verification: an unpinned self-signed CA is
//!    REJECTED; pinning the test CA via `add_root_ca` makes it pass.
//! 3. The ClientHello ALPN order matches Firefox (`h2, http/1.1`).

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use neqo_backend::crypto::{add_root_ca, ensure_nss_initialized};
use neqo_backend::tls::TlsTransport;
use neqo_backend::ws::WebSocketStream;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn gen_certs() {
    let status = Command::new("bash")
        .arg(fixtures_dir().join("gen_certs.sh"))
        .status()
        .expect("failed to run gen_certs.sh");
    assert!(status.success(), "certificate generation failed");
}

/// Spawns the TLS echo server; returns (port, guard).
fn start_server() -> (u16, ServerGuard) {
    let mut child = Command::new("python3")
        .arg(fixtures_dir().join("echo_server_tls.py"))
        .arg(fixtures_dir().join("server.crt"))
        .arg(fixtures_dir().join("server.key"))
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn TLS echo server");

    let stdout = child.stdout.take().expect("no stdout");
    let mut reader = BufReader::new(stdout);

    // Read the PORT= line with a bounded wait.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut port: Option<u16> = None;
    while std::time::Instant::now() < deadline {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if let Some(rest) = line.strip_prefix("PORT=") {
                    port = rest.trim().parse().ok();
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let port = port.expect("server did not report its port");

    // Keep reading stdout on a background thread so the pipe never fills.
    std::thread::spawn(move || {
        for line in reader.lines().flatten() {
            println!("[srvout] {line}");
        }
    });

    (port, ServerGuard(child))
}

#[test]
fn ws_over_tls_end_to_end() {
    let _ = env_logger::builder().is_test(true).try_init();
    gen_certs();
    ensure_nss_initialized().expect("NSS init failed");
    let (port, _guard) = start_server();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    // ------------------------------------------------------------------
    // 1) NEGATIVE: the server certificate chains to our test CA, which is
    //    NOT in the Mozilla root store. Verification must fail the handshake.
    // ------------------------------------------------------------------
    let refused = TlsTransport::connect(
        "localhost",
        port,
        &["h2", "http/1.1"],
        Duration::from_secs(10),
    );
    assert!(
        refused.is_err(),
        "handshake must FAIL before the test CA is pinned (got: {:?})",
        refused.map(|t| t.negotiated_alpn.clone())
    );
    let err = refused.err().unwrap();
    assert!(
        err.contains("certificate")
            || err.contains("Certificate")
            || err.contains("TLS handshake")
            || err.contains("TLS connect"),
        "unexpected error text: {err}"
    );

    // ------------------------------------------------------------------
    // 2) PIN the test CA — this is the production mechanism for trusting
    //    your own proxy server CA.
    // ------------------------------------------------------------------
    let ca_der = std::fs::read(fixtures_dir().join("ca.der")).expect("ca.der");
    add_root_ca(&ca_der).expect("pinned CA must parse");

    // ------------------------------------------------------------------
    // 3) POSITIVE: full connect + WS handshake + large echo round-trip,
    //    with a fingerprint assertion on the offered ALPN order.
    // ------------------------------------------------------------------
    rt.block_on(async move {
        let result = tokio::time::timeout(Duration::from_secs(30), ws_echo_round_trip(port)).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("echo round-trip failed: {e}"),
            Err(_) => panic!("echo round-trip timed out"),
        }
    });

    // ------------------------------------------------------------------
    // 4) FINGERPRINT PROBE: parse our raw ClientHello and assert the ALPN
    //    extension lists protocols in Firefox order: h2, http/1.1.
    // ------------------------------------------------------------------
    let offered = probe_offered_alpn();
    assert_eq!(
        offered,
        Some("h2,http/1.1".to_string()),
        "ClientHello ALPN order must match Firefox (h2, http/1.1)"
    );
}

/// Spawns the sniffer, lets one TLS connect attempt hit it, and returns the
/// offered ALPN list as a comma-joined string.
fn probe_offered_alpn() -> Option<String> {
    use std::io::Read;

    let mut child = Command::new("python3")
        .arg(fixtures_dir().join("echo_server_tls.py"))
        .arg("sniff")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn sniffer");
    let mut stdout = child.stdout.take().expect("no sniffer stdout");
    let mut reader = BufReader::new(&mut stdout);

    let mut line = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut port: Option<u16> = None;
    while std::time::Instant::now() < deadline {
        let mut l = String::new();
        if reader.read_line(&mut l).unwrap_or(0) == 0 {
            break;
        }
        if let Some(rest) = l.strip_prefix("PORT=") {
            port = rest.trim().parse().ok();
            break;
        }
        line.push_str(&l);
    }
    let port = port.expect("sniffer did not report its port");

    // Fire one TLS connection at the sniffer; it will die after reading the
    // ClientHello, so the connect is expected to fail (any result is fine).
    let _ = TlsTransport::connect(
        "localhost",
        port,
        &["h2", "http/1.1"],
        Duration::from_secs(5),
    );

    // Read the sniffer's verdict.
    let mut verdict: Option<String> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let mut l = String::new();
        if reader.read_line(&mut l).unwrap_or(0) == 0 {
            break;
        }
        if let Some(rest) = l.strip_prefix("OFFERED_ALPN=") {
            verdict = Some(rest.trim().to_string());
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = stdout.read(&mut [0u8; 64]); // drain
    verdict
}

async fn ws_echo_round_trip(port: u16) -> Result<(), String> {
    let transport = TlsTransport::connect(
        "localhost",
        port,
        &["h2", "http/1.1"],
        Duration::from_secs(10),
    )?;
    assert_eq!(
        transport.negotiated_alpn, "http/1.1",
        "server must select http/1.1 for the WS upgrade"
    );

    let ws = WebSocketStream::connect(
        Arc::new(transport),
        "localhost",
        port,
        "/",
        Default::default(),
        None,
    )
    .await?;

    // Large payload: exercises chunked frames + StreamReadBuffer reassembly.
    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    ws.write(&payload).await?;

    let expected_prefix = b"ALPN=http/1.1;ECHO:";
    let mut got = Vec::with_capacity(payload.len() + 64);
    let mut buf = vec![0u8; 65536];
    while got.len() < expected_prefix.len() + payload.len() {
        let n = ws.read(&mut buf).await?;
        if n == 0 {
            return Err("EOF before full echo received".to_string());
        }
        got.extend_from_slice(&buf[..n]);
    }

    assert_eq!(
        &got[..expected_prefix.len()],
        expected_prefix,
        "server must select http/1.1 and echo it in the first response"
    );
    assert_eq!(
        &got[expected_prefix.len()..],
        &payload[..],
        "echoed payload must match (chunked reassembly)"
    );

    // Small second message: keep-alive / channel reuse sanity.
    ws.write(b"second-flight").await?;
    let mut buf2 = [0u8; 4096];
    let mut got2 = Vec::new();
    while got2.len() < b"second-flight".len() {
        let n = ws.read(&mut buf2).await?;
        if n == 0 {
            break;
        }
        got2.extend_from_slice(&buf2[..n]);
    }
    assert!(
        got2.ends_with(b"second-flight"),
        "second echo incomplete: {got2:?}"
    );

    ws.close();
    Ok(())
}
