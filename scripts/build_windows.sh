#!/usr/bin/env bash
# Сборка neqo-backend для Desktop Windows (MSVC).
# Запускать из окружения MSVC (x64 Native Tools Command Prompt) или WSL с
# установленным cargo-xwin; здесь вариант с cargo-xwin (кросс-сборка из Linux).
#
# Использование: scripts/build_windows.sh [x64|x32]
#
# Требуется: cargo-xwin (cargo install cargo-xwin), clang+libclang.
# NSS для Windows собирается СТАТИЧЕСКИ (так делает и nss-rs: Windows ->
# static_link), поэтому никаких NSS .dll таскать не нужно.
set -euo pipefail

ARCH="${1:-x64}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
export NSS_DEPS="${NSS_DEPS:-$HOME/gorynych/nss-deps}"
# nss-rs (и наш build.rs) ищут NSS в $NSS_DIR/../dist; экспортировать
# обязательно — иначе провалимся в pkg-config и найдём системный NSS.
export NSS_DIR="${NSS_DIR:-$NSS_DEPS/nss-3.130/nss}"

case "$ARCH" in
    x64) TARGET="x86_64-pc-windows-msvc" ;;
    x32) TARGET="i686-pc-windows-msvc" ;;
    *) echo "_usage: $0 [x64|x32]" >&2; exit 1 ;;
esac

export NSS_PREBUILT=1
export PATH="$HOME/.cargo/bin:$PATH"
command -v cargo-xwin >/dev/null 2>&1 || CARGO=xwin || CARGO=cargo
rustup target add "$TARGET" 2>/dev/null || true

cd "$HERE"
echo ">> Сборка $TARGET"
if command -v cargo-xwin >/dev/null 2>&1; then
    cargo xwin build --release --target "$TARGET"
else
    cargo build --release --target "$TARGET"
fi

OUT="$HERE/dist/windows-$ARCH"
mkdir -p "$OUT"
cp "target/$TARGET/release/neqo_backend.dll" "$OUT/" 2>/dev/null || true
cp "target/$TARGET/release/neqo_backend.dll.lib" "$OUT/" 2>/dev/null || \
    cp "target/$TARGET/release/neqo_backend.lib" "$OUT/" 2>/dev/null || true
cp "$HERE/ffi/neqo_backend.h" "$OUT/"
echo ">> Готово: $OUT"
ls -la "$OUT"
