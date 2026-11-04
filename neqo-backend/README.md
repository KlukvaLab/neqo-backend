# neqo-backend

Isolated Rust transport backend providing genuine Mozilla Firefox network fingerprints via [NSS](https://hg.mozilla.org/projects/nss) (TLS) and [Neqo](https://github.com/mozilla/neqo) (QUIC / HTTP3).

Created for [KlukvaLab](https://github.com/KlukvaLab).

## Features

- **Genuine Firefox TLS fingerprint**: the WebSocket transport runs over the NSS *socket-level* SSL API (`SSL_ImportFD`, `SSL_ForceHandshake`, …) — the same code path Firefox itself uses for `https://`. ClientHello, extension order and record-layer behaviour are Firefox-native, with zero synthetic emulation.
- **Genuine Firefox QUIC**: raw QUIC streams via neqo (the Firefox QUIC stack), Firefox-shaped transport parameters and keepalive.
- **WebSocket (RFC 6455)** with strict Firefox JA4H header order, `permessage-deflate` (RFC 7692) always offered like real Firefox, polite Close frames, and DPI-evasion behaviours (first-flight Ping noise, jittered keepalive, randomized chunking).
- **Strict certificate verification** — never bypassed. Mozilla root store (webpki-roots) plus runtime-pinned CAs for your own proxy server (`ffx_add_root_ca`). No insecure mode exists.
- **Active probing defense**: first-flight auth marker (`X-Probe-Auth`) support.
- **C-ABI boundary**: clean C-compatible FFI with stream handles (`uint64_t`), consumed via JNA by the Kotlin Multiplatform layer (Desktop JVM now, Android later).
- **ALPN in Firefox order** (`h2, http/1.1`), asserted by a ClientHello-sniffing integration test.

## NSS/NSPR API notes (read before bumping NSS)

All verified against NSS 3.132 / NSPR 4.x; see `src/nss_sys.rs` for details:

- TLS handshake does NOT run inside `PR_Connect` — call `SSL_ForceHandshake` explicitly.
- Set `PR_SockOpt_Nonblocking` on the TCP fd **before** `SSL_ImportFD`.
- `SSL_PeerCertificateChainDER` is an experimental API: resolve it via `SSL_GetExperimentalAPI`.
- `SSL_SetNextProtoNego` rotates the list (first → last); pass reversed for wire-order.
- NSPR pipes don't support `PR_Poll` — a TCP socketpair is used as the wakeup channel.

## Building

Requires: clang/LLVM, NSS ≥ 3.126 dev libraries (or a local build via `NSS_DIR`/pkg-config), NSPR dev, Rust stable (edition 2024).

```bash
cargo build --release -p neqo-backend
```

Output: `target/release/libneqo_backend.so` (Linux), `neqo_backend.dll` (Windows), `libneqo_backend.dylib` (macOS).

## Testing

```bash
cargo test -p neqo-backend
```

Runs 14 unit tests plus two end-to-end integration tests (a local TLS echo server with a pinned test CA, and the stock `neqo-server` over QUIC). Test fixtures (certificates, NSS DB) are generated automatically by scripts in `tests/fixtures/`.

## C-ABI summary

| Function | Purpose |
|---|---|
| `ffx_init()` | Initialize NSS (idempotent) |
| `ffx_add_root_ca(der, len)` | Pin an additional trusted root CA (your proxy CA / test CA) |
| `ffx_connect_ws(host, port, path, headers, marker, use_tls, alpn, out)` | WebSocket over NSS TLS (or plaintext TCP for local tests) |
| `ffx_connect_quic(host, port, alpn, out)` | Raw QUIC stream (neqo) |
| `ffx_stream_read(h, buf, len, timeout_ms)` | Read; `0` = EOF, `-100` = timeout (retry), `-3` = error |
| `ffx_stream_write(h, buf, len)` | Write |
| `ffx_stream_finish(h)` | Half-close (QUIC stream FIN; no-op for WS) |
| `ffx_stream_close(h)` | Close and free the handle |
| `ffx_get_last_error(buf, len)` | Last error text |

## License

Apache License 2.0.
