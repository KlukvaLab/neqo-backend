# neqo-backend

Isolated Rust transport backend providing genuine Mozilla Firefox network fingerprints via [NSS](https://hg.mozilla.org/projects/nss) (TLS) and [Neqo](https://github.com/mozilla/neqo) (QUIC / HTTP3).

Created for [KlukvaLab](https://github.com/KlukvaLab).

## Features

- **Genuine Firefox Fingerprint**: Uses Mozilla's own NSS cryptography engine and Neqo QUIC stack (zero synthetic emulation like uTLS).
- **C-ABI Boundary**: Clean C-compatible FFI with stream handles (`uint64_t`), easily consumed by Kotlin Multiplatform (JNA/JNI), Python, Go, or C/C++.
- **WebSocket over TLS**: RFC 6455 framing with strict Firefox JA4H header order.
- **Active Probing Defense**: Support for probing authorization markers in first flight payloads.
- **Strict Certificate Verification**: Peer certificates are validated; no silent bypass.

## Building

Requires:
- Clang / LLVM
- NSS ≥ 3.126 development libraries
- Rust (stable 2024 edition)

```bash
cargo build --release -p neqo-backend
```

The resulting library will be located at:
- `target/release/libneqo_backend.so` (Linux)
- `target/release/libneqo_backend.dylib` (macOS)
- `target/release/neqo_backend.dll` (Windows)

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).
