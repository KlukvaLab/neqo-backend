#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

MODE="${1:---release}"

# NSS 3.130 (пиннинг), собранный neqo-backend/scripts/fetch_nss.sh.
# nss-rs и build.rs neqo-backend сами находят dist рядом с NSS_DIR.
NSS_DEPS="${NSS_DEPS:-$HOME/gorynych/nss-deps}"
if [ -d "${NSS_DEPS}/nss-3.130/dist/Release/lib" ] && [ -z "${NSS_DIR:-}" ]; then
    export NSS_DIR="${NSS_DEPS}/nss-3.130/nss"
    export NSS_PREBUILT=1
fi

export PATH="$HOME/.cargo/bin:$PATH"

echo "==> Building neqo-backend (${MODE})..."
# opt-level=2 avoids rustc 1.99.1 ICE with serde_core
RUSTFLAGS="${RUSTFLAGS:-} -C opt-level=2" cargo build ${MODE} -p neqo-backend

TARGET_DIR="debug"
if [ "${MODE}" = "--release" ]; then
    TARGET_DIR="release"
fi

# NSS runtime рядом с библиотекой (rpath=$ORIGIN вшит через build.rs):
# без этого libnss3 найдёт СИСТЕМНЫЙ softokn и упадёт (SEC_ERROR_NO_TOKEN).
if [ -n "${NSS_DIR:-}" ]; then
    NSS_LIB="${NSS_DEPS}/nss-3.130/dist/Release/lib"
    for lib in libnss3.so libnssutil3.so libssl3.so libnspr4.so \
               libplc4.so libplds4.so libfreebl3.so libfreeblpriv3.so \
               libsoftokn3.so libsqlite3.so; do
        [ -f "${NSS_LIB}/${lib}" ] && \
            cp -L "${NSS_LIB}/${lib}" "target/${TARGET_DIR}/"
    done
fi

OUTPUT_LIB="${SCRIPT_DIR}/target/${TARGET_DIR}/libneqo_backend.so"
if [ -f "${OUTPUT_LIB}" ]; then
    echo "==> Build successful!"
    echo "    Output: ${OUTPUT_LIB} ($(ls -lh "${OUTPUT_LIB}" | awk '{print $5}'))"
    echo "    Header: neqo-backend/ffi/neqo_backend.h"
fi
