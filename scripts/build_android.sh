#!/usr/bin/env bash
# Сборка neqo-backend для Android (arm64-v8a / armeabi-v7a).
#
# Требуется: Android NDK r26+ (переменная ANDROID_NDK_HOME или ~/Android/Sdk/ndk/*).
# Скрипт:
#   1) кросс-собирает NSS clang'ом из NDK в отдельный dist_android/<abi>;
#   2) собирает cdylib через cargo с --target ...-android;
#   3) кладёт результат в dist/android-<abi>/ (для jniLibs).
#
# Выход: libneqo_backend.so (+ NSS .so рядом; грузите их все в jniLibs/<abi>).
set -euo pipefail

ABI="${1:-arm64}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
NSS_DEPS="${NSS_DEPS:-$HOME/gorynych/nss-deps}"
API=24

# --- NDK ---
NDK="${ANDROID_NDK_HOME:-}"
if [ -z "$NDK" ]; then
    for d in "$HOME/Android/Sdk/ndk"/*; do
        [ -d "$d" ] && NDK="$d"
    done
fi
[ -n "${NDK:-}" ] && [ -d "$NDK" ] || { echo "!! NDK не найден (ANDROID_NDK_HOME?)" >&2; exit 1; }
echo ">> NDK: $NDK"

case "$ABI" in
    arm64)
        TRIPLE="aarch64-linux-android"
        NSS_TARGET="--target=arm64" ;;
    arm32)
        TRIPLE="armv7a-linux-androideabi"
        NSS_TARGET="--target=arm" ;;
    *) echo "_usage: $0 [arm64|arm32]" >&2; exit 1 ;;
esac

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
CC="$TOOLCHAIN/${TRIPLE}${API}-clang"
CXX="$TOOLCHAIN/${TRIPLE}${API}-clang++"
AR="$TOOLCHAIN/llvm-ar"
for t in "$CC" "$CXX" "$AR"; do
    [ -x "$t" ] || { echo "!! нет $t" >&2; exit 1; }
done

# --- 1. Кросс-сборка NSS ---------------------------------------------------
NSS_SRC="$NSS_DEPS/nss-3.130"
if [ ! -d "$NSS_SRC/dist_android_$ABI/lib" ]; then
    echo ">> Кросс-сборка NSS для $ABI"
    # Отдельный dist для Android: собираем в клоне, чтобы не затирать host-dist.
    if [ ! -d "$NSS_DEPS/nss-android-$ABI" ]; then
        mkdir -p "$NSS_DEPS/nss-android-$ABI"
        cp -a "$NSS_SRC/nss" "$NSS_DEPS/nss-android-$ABI/nss"
        cp -a "$NSS_SRC/nspr" "$NSS_DEPS/nss-android-$ABI/nspr"
    fi
    export PATH="$HOME/.local/bin:$TOOLCHAIN:$PATH"
    (cd "$NSS_DEPS/nss-android-$ABI/nss" && \
        env CC="$CC" CXX="$CXX" AR="$AR" \
        ./build.sh -Ddisable_tests=1 -Ddisable_dbm=1 -Ddisable_libpkix=1 \
        -Ddisable_ckbi=1 -Ddisable_fips=1 --opt --static "$NSS_TARGET")
    # build.sh кладёт вывод в ../dist — переносим в dist_android_$ABI
    mv "$NSS_DEPS/nss-android-$ABI/dist" "$NSS_SRC/dist_android_$ABI" 2>/dev/null || true
fi
NSS_ANDROID_DIR="$NSS_SRC/nss-android-$ABI/nss"
[ -d "$NSS_SRC/dist_android_$ABI/lib" ] || { echo "!! NSS android dist не найден" >&2; exit 1; }

# --- 2. cargo ---------------------------------------------------------------
export NSS_DIR="$NSS_ANDROID_DIR"
export NSS_PREBUILT=1
# nss-rs ищет заголовки в $NSS_DIR/../dist — у нас он в nss-android-<abi>/dist
# (build.rs build_nss кладёт именно туда; для prebuilt они уже там).
export PATH="$HOME/.cargo/bin:$PATH"
TARGET_RUST="${TRIPLE/armv7a-/armv7a-}"
case "$ABI" in
    arm64) RUST_TARGET="aarch64-linux-android" ;;
    arm32) RUST_TARGET="armv7-linux-androideabi" ;;
esac
rustup target add "$RUST_TARGET" 2>/dev/null || true

# Крейты с C-кодом (zstd и т.п.) собираются NDK-clang'ом:
export CC_"${TRIPLE//-/_}"="$CC"
export CXX_"${TRIPLE//-/_}"="$CXX"
export AR_"${TRIPLE//-/_}"="$AR"
export RANLIB_"${TRIPLE//-/_}"="$TOOLCHAIN/llvm-ranlib"

echo ">> cargo build --release ($RUST_TARGET)"
cd "$HERE"
cargo build --release --target "$RUST_TARGET"

OUT="$HERE/dist/android-$ABI"
mkdir -p "$OUT"
cp "target/$RUST_TARGET/release/libneqo_backend.so" "$OUT/"
for lib in libnss3.so libnssutil3.so libssl3.so libnspr4.so \
            libplc4.so libplds4.so libfreebl3.so libfreeblpriv3.so \
            libsoftokn3.so libsqlite3.so; do
    [ -f "$NSS_SRC/dist_android_$ABI/lib/$lib" ] && \
        cp -L "$NSS_SRC/dist_android_$ABI/lib/$lib" "$OUT/"
done
cp "$HERE/ffi/neqo_backend.h" "$OUT/"

echo ">> Готово: $OUT (скопируйте .so в app/src/main/jniLibs/$ABI/)"
ls -la "$OUT"
