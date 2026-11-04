# neqo-backend (Workspace)

Self-contained workspace for building `neqo-backend` — an isolated Mozilla Neqo & NSS network transport layer.

Maintained by [KlukvaLab](https://github.com/KlukvaLab).

## Architecture

This workspace includes Mozilla Neqo (v0.34.0) and the `neqo-backend` C-ABI bridge crate.

- **`neqo-backend/`**: C-ABI bridge exposing WebSocket and QUIC transports with authentic Firefox TLS/QUIC fingerprints.
- **`neqo-transport/`**, **`neqo-common/`**, etc.: Mozilla's official IETF QUIC implementation in Rust.

## Prerequisites

```bash
sudo apt update && sudo apt install -y build-essential clang pkg-config cmake ninja-build libnss3-dev libnspr4-dev
```

If your distribution has NSS older than 3.126, build NSS from source (see `scripts/build_nss.sh`).

## Quick Start

```bash
# Build release library
./build.sh --release
```

Library output: `target/release/libneqo_backend.so`

## Exported C-ABI Functions

- `ffx_init() -> int32_t`
- `ffx_connect_ws(host, port, path, headers, probing_marker, out_handle) -> int32_t`
- `ffx_connect_quic(host, port, alpn, out_handle) -> int32_t`
- `ffx_stream_read(handle, buf, len, timeout_ms) -> int64_t`
- `ffx_stream_write(handle, buf, len) -> int64_t`
- `ffx_stream_close(handle) -> int32_t`
- `ffx_get_last_error(buf, max_len) -> int32_t`

## License

Apache License 2.0. See [LICENSE](LICENSE).
