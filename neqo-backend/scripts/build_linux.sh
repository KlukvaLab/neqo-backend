#!/usr/bin/env bash
# Сборка neqo-backend для Desktop Linux.
# Запускать из любого места; скрипт сам находит корень workspace.
# Использование: neqo-backend/scripts/build_linux.sh [x86_64|i686|aarch64]
#
# Выход: neqo-backend/dist/linux-<arch>/libneqo_backend.so (+ NSS-библиотеки
#        рядом, rpath=$ORIGIN вшит через build.rs) и libneqo_backend.a.
set -euo pipefail

ARCH="${1:-x86_64}"
PKG="$(cd "$(dirname "$0")/.." && pwd)"   # каталог пакета neqo-backend
ROOT="$(cd "$PKG/.." && pwd)"             # корень workspace (клон neqo)
NSS_DEPS="${NSS_DEPS:-$HOME/gorynych/nss-deps}"
NSS_DIR="${NSS_DIR:-$NSS_DEPS/nss-3.130/nss}"

case "$ARCH" in
    x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
    i686)   TARGET="i686-unknown-linux-gnu" ;;
    aarch64)
        TARGET="aarch64-unknown-linux-gnu"
        dpkg -s gcc-aarch64-linux-gnu >/dev/null 2>&1 || {
            echo "!! нужен кросс-компилятор: sudo apt install gcc-aarch64-linux-gnu" >&2
            exit 1
        }
        export CROSS_COMPILE=aarch64-linux-gnu-
        ;;
    *) echo "_usage: $0 [x86_64|i686|aarch64]" >&2; exit 1 ;;
esac

# NSS 3.130, собранный fetch_nss.sh; nss-rs и build.rs найдут dist рядом.
[ -d "$NSS_DIR/../dist/Release/lib" ] || {
    echo "!! NSS 3.130 не найден: запустите neqo-backend/scripts/fetch_nss.sh" >&2
    exit 1
}
export NSS_DIR
export NSS_PREBUILT=1
export PATH="$HOME/.cargo/bin:$PATH"

command -v cargo >/dev/null || { echo "!! cargo не найден" >&2; exit 1; }
rustup target add "$TARGET" 2>/dev/null || true

cd "$ROOT"
echo ">> cargo build --release ($TARGET)"
# opt-level=2: обход ICE rustc 1.99.1 в serde_core (см. корневой build.sh)
RUSTFLAGS="${RUSTFLAGS:-} -C opt-level=2" cargo build --release --target "$TARGET" -p neqo-backend

OUT="$PKG/dist/linux-$ARCH"
mkdir -p "$OUT"
cp "$ROOT/target/$TARGET/release/libneqo_backend.so" "$OUT/"
[ -f "$ROOT/target/$TARGET/release/libneqo_backend.a" ] && \
    cp "$ROOT/target/$TARGET/release/libneqo_backend.a" "$OUT/"

# NSS runtime: кладём собранные нами .so рядом с библиотекой (rpath=$ORIGIN),
# чтобы не зависеть от системного NSS (обычно старее пинна).
if [ "$ARCH" = "x86_64" ]; then
    NSS_LIB="$NSS_DEPS/nss-3.130/dist/Release/lib"
    for lib in libnss3.so libnssutil3.so libssl3.so libnspr4.so \
                libplc4.so libplds4.so libfreebl3.so libfreeblpriv3.so \
                libsoftokn3.so libsqlite3.so; do
        [ -f "$NSS_LIB/$lib" ] && cp -L "$NSS_LIB/$lib" "$OUT/"
    done
    chmod +x "$OUT"/*.so
fi
# Для кросс-таргетов NSS-библиотеки нужно собрать отдельно тем же скриптом
# с CC/CXX/AR кросс-тулчейна — см. docs/BUILDING.md «Кросс-сборка NSS».

cp "$PKG/ffi/neqo_backend.h" "$OUT/"

echo ">> Готово: $OUT"
ls -la "$OUT"
