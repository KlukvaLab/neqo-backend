#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

MODE="${1:---release}"

# Auto-detect local custom NSS build if present
NSS_LOCAL="${SCRIPT_DIR}/../dist/Release/lib"
if [ -d "${NSS_LOCAL}" ]; then
    export PKG_CONFIG_PATH="${NSS_LOCAL}/pkgconfig:${PKG_CONFIG_PATH:-}"
    export LD_LIBRARY_PATH="${NSS_LOCAL}:${LD_LIBRARY_PATH:-}"
fi

echo "==> Building neqo-backend (${MODE})..."
# opt-level=2 avoids rustc 1.99.1 ICE with serde_core
RUSTFLAGS="${RUSTFLAGS:-} -C opt-level=2" cargo build ${MODE} -p neqo-backend

TARGET_DIR="debug"
if [ "${MODE}" = "--release" ]; then
    TARGET_DIR="release"
fi

OUTPUT_LIB="${SCRIPT_DIR}/target/${TARGET_DIR}/libneqo_backend.so"
if [ -f "${OUTPUT_LIB}" ]; then
    echo "==> Build successful!"
    echo "    Output: ${OUTPUT_LIB} ($(ls -lh "${OUTPUT_LIB}" | awk '{print $5}'))"
fi
