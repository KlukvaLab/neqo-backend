#!/usr/bin/env bash
# Сборка neqo-backend для Desktop Linux.
# Использование: scripts/build_linux.sh [x86_64|i686|aarch64]
#
# Выход: dist/linux-<arch>/libneqo_backend.so (+ NSS-библиотеки рядом,
#        rpath=$ORIGIN) и libneqo_backend.a.
set -euo pipefail

ARCH="${1:-x86_64}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
export NSS_DEPS="${NSS_DEPS:-$HOME/gorynych/nss-deps}"
# nss-rs (и наш build.rs) ищут NSS в $NSS_DIR/../dist — каталог nss/
# может не существовать при NSS_PREBUILT=1, важен именно родитель.
export NSS_DIR="${NSS_DIR:-$NSS_DEPS/nss-3.130/nss}"

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

export NSS_PREBUILT=1
export PATH="$HOME/.cargo/bin:$PATH"

command -v "cargo" >/dev/null || { echo "!! cargo не найден" >&2; exit 1; }
rustup target add "$TARGET" 2>/dev/null || true

cd "$HERE"
echo ">> cargo build --release ($TARGET)"
cargo build --release --target "$TARGET"

OUT="$HERE/dist/linux-$ARCH"
mkdir -p "$OUT"
cp "target/$TARGET/release/libneqo_backend.so" "$OUT/"
[ -f "target/$TARGET/release/libneqo_backend.a" ] && \
    cp "target/$TARGET/release/libneqo_backend.a" "$OUT/"

# NSS runtime: кладём собранные нами .so рядом и ставим rpath=$ORIGIN,
# чтобы не зависеть от системного NSS (обычно старее пинна).
NSS_LIB="$NSS_DEPS/nss-3.130/dist/Release/lib"
if [ "$ARCH" = "x86_64" ]; then
    for lib in libnss3.so libnssutil3.so libssl3.so libnspr4.so \
                libplc4.so libplds4.so libfreebl3.so libfreeblpriv3.so \
                libsoftokn3.so libsqlite3.so; do
        [ -f "$NSS_LIB/$lib" ] && cp -L "$NSS_LIB/$lib" "$OUT/"
    done
    chmod +x "$OUT"/*.so

    # rpath=$ORIGIN нужен ВСЕМ .so: libnss3 сам dlopen'ит libsoftokn3 —
    # без rpath он найдёт СИСТЕМНЫЙ softokn и упадёт (SEC_ERROR_NO_TOKEN).
    PATCHELF="$(command -v patchelf || true)"
    if [ -z "$PATCHELF" ] && [ -x "$HOME/.local/bin/patchelf" ]; then
        PATCHELF="$HOME/.local/bin/patchelf"
    fi
    if [ -z "$PATCHELF" ]; then
        echo ">> patchelf не найден — ставлю статический в ~/.local/bin"
        mkdir -p "$HOME/.local/bin" /tmp/pe-$$
        curl -sSL -o /tmp/pe-$$/pe.tar.gz \
            https://github.com/NixOS/patchelf/releases/download/0.18.0/patchelf-0.18.0-x86_64.tar.gz
        tar xzf /tmp/pe-$$/pe.tar.gz -C /tmp/pe-$$ 2>/dev/null
        cp /tmp/pe-$$/bin/patchelf "$HOME/.local/bin/patchelf" && chmod +x "$HOME/.local/bin/patchelf"
        rm -rf /tmp/pe-$$
        PATCHELF="$HOME/.local/bin/patchelf"
    fi
    for so in "$OUT"/*.so; do
        "$PATCHELF" --set-rpath '$ORIGIN' "$so"
    done
fi
# Для кросс-таргетов NSS-библиотеки нужно собрать отдельно тем же скриптом
# с CC/CXX/AR кросс-тулчейна — см. docs/BUILDING.md «Кросс-сборка NSS».

cp "$HERE/ffi/neqo_backend.h" "$OUT/"

echo ">> Готово: $OUT"
ls -la "$OUT"
