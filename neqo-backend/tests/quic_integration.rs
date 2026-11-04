//! QUIC integration test: our backend against the stock `neqo-server`.
//!
//! Acceptance criteria covered (request.md §6):
//! * connects to the upstream neqo-server over QUIC,
//! * data flows in both directions on a stream (HTTP/0.9 over hq-interop),
//! * certificate verification is enforced: the connection only succeeds
//!   after the server certificate is pinned via `add_root_ca`
//!   (the bundled neqo test cert expired in 2019 — strict verification
//!   rejects it, which is exactly what we want).

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use neqo_backend::crypto::{add_root_ca, ensure_nss_initialized};
use neqo_backend::quic::QuicStream;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn cargo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn gen_neqo_db() {
    let status = Command::new("bash")
        .arg(fixtures_dir().join("gen_neqo_db.sh"))
        .status()
        .expect("failed to run gen_neqo_db.sh");
    assert!(status.success(), "neqo-server DB generation failed");
}

fn start_neqo_server(port: u16) -> ServerGuard {
    let server_bin = cargo_root()
        .join("target")
        .join("debug")
        .join("neqo-server");
    assert!(
        server_bin.exists(),
        "neqo-server not built: {}",
        server_bin.display()
    );

    let db = fixtures_dir().join("neqo-db");
    let mut child = Command::new(server_bin)
        .arg(format!("127.0.0.1:{port}"))
        .arg("-a")
        .arg("hq-interop")
        .arg("-d")
        .arg(db.display().to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(
            std::fs::File::create("/tmp/neqo-server-test.log").unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create("/tmp/neqo-server-test.err").unwrap(),
        ))
        .spawn()
        .expect("failed to spawn neqo-server");
    std::thread::sleep(Duration::from_millis(800));
    ServerGuard(child)
}

#[test]
fn quic_against_neqo_server() {
    let _ = env_logger::builder().is_test(true).try_init();
    gen_neqo_db();
    ensure_nss_initialized().expect("NSS init failed");

    let port = 4451u16;
    let _guard = start_neqo_server(port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async move {
        // 1) NEGATIVE: without pinning, verification must reject the
        //    self-signed neqo-server certificate.
        let refused = QuicStream::connect("127.0.0.1", port, &["hq-interop"]).await;
        assert!(
            refused.is_err(),
            "QUIC handshake must fail before pinning the server cert"
        );

        // 2) Pin the server certificate (same mechanism as a proxy CA).
        let ca = std::fs::read(fixtures_dir().join("neqo-server-ca.der")).expect("ca der");
        add_root_ca(&ca).expect("pin server cert");

        // 3) POSITIVE: connect and exchange data (HTTP/0.9 request/response).
        let result = tokio::time::timeout(Duration::from_secs(30), quic_round_trip(port)).await;
        match result {
            Ok(Ok(n)) => assert!(n > 0, "server must send a non-empty response"),
            Ok(Err(e)) => panic!("QUIC round-trip failed: {e}"),
            Err(_) => panic!("QUIC round-trip timed out"),
        }
    });
}

async fn quic_round_trip(port: u16) -> Result<usize, String> {
    let stream = QuicStream::connect("127.0.0.1", port, &["hq-interop"]).await?;

    // neqo-server HTTP/0.9 wire format (see neqo-bin/src/{client,server}/http09.rs):
    // the request is "GET /<n>\r\n" followed by a stream half-close; the
    // response is <n> zero bytes.
    let request = b"GET /2000\r\n";
    stream.write(request).await?;
    stream.finish().await?;

    let mut buf = vec![0u8; 65536];
    let mut total = 0usize;
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n;
        if total >= 2000 {
            break; // got the full response
        }
    }
    stream.close();
    Ok(total)
}
