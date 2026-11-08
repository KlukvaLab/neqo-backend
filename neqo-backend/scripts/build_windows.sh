#!/usr/bin/env bash
# Сборка neqo-backend для Desktop Windows (MSVC).
# Запускать из любого места; скрипт сам находит корень workspace.
# Запускать из окружения MSVC (x64 Native Tools Command Prompt) или WSL с
# установленным cargo-xwin; здесь вариант с cargo-xwin (кросс-сборка из Linux).
#
# Использование: neqo-backend/scripts/build_windows.sh [x64|x32]
#
# Требуется: cargo-xwin (cargo install cargo-xwin), clang+libclang.
# NSS для Windows собирается СТАТИЧЕСКИ (так делает и nss-rs: Windows ->
# static_link), поэтому никаких NSS .dll таскать не нужно.
set -euo pipefail

ARCH="${1:-x64}"
PKG="$(cd "$(dirname "$0")/.." && pwd)"   # каталог пакета neqo-backend
ROOT="$(cd "$PKG/.." && pwd)"             # корень workspace (клон neqo)
NSS_DEPS="${NSS_DEPS:-$HOME/gorynych/nss-deps}"
NSS_DIR="${NSS_DIR:-$NSS_DEPS/nss-3.130/nss}"

case "$ARCH" in
    x64) TARGET="x86_64-pc-windows-msvc" ;;
    x32) TARGET="i686-pc-windows-msvc" ;;
    *) echo "_usage: $0 [x64|x32]" >&2; exit 1 ;;
esac

[ -d "$NSS_DIR/../dist/Release/lib" ] || {
    echo "!! NSS 3.130 не найден: запустите neqo-backend/scripts/fetch_nss.sh" >&2
    exit 1
}
export NSS_DIR
export NSS_PREBUILT=1
export PATH="$HOME/.cargo/bin:$PATH"
rustup target add "$TARGET" 2>/dev/null || true

cd "$ROOT"
echo ">> Сборка $TARGET"
if command -v cargo-xwin >/dev/null 2>&1; then
    cargo xwin build --release --target "$TARGET" -p neqo-backend
else
    RUSTFLAGS="${RUSTFLAGS:-} -C opt-level=2" \
        cargo build --release --target "$TARGET" -p neqo-backend
fi

OUT="$PKG/dist/windows-$ARCH"
mkdir -p "$OUT"
cp "$ROOT/target/$TARGET/release/neqo_backend.dll" "$OUT/" 2>/dev/null || true
cp "$ROOT/target/$TARGET/release/neqo_backend.dll.lib" "$OUT/" 2>/dev/null || \
    cp "$ROOT/target/$TARGET/release/neqo_backend.lib" "$OUT/" 2>/dev/null || true
cp "$PKG/ffi/neqo_backend.h" "$OUT/"
echo ">> Готово: $OUT"
ls -la "$OUT"
