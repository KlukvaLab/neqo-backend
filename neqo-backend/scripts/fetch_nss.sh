#!/usr/bin/env bash
# Скачать и собрать пиннованный NSS (+NSPR) для neqo-backend.
#
# Результат:
#   $NSS_DEPS/nss-3.130/nss       -> NSS_DIR
#   $NSS_DEPS/nss-3.130/dist/...  -> заголовки и библиотеки
#
# Зависимости: build-essential, ninja|ninja-build, python3, pip (gyp-next),
#              clang+libclang (для bindgen на этапе cargo).
set -euo pipefail

NSS_DEPS="${NSS_DEPS:-$HOME/gorynych/nss-deps}"
NSS_VERSION="3.130"
NSPR_VERSION="4.39"
TARBALL="nss-${NSS_VERSION}-with-nspr-${NSPR_VERSION}.tar.gz"
URL="https://ftp.mozilla.org/pub/security/nss/releases/NSS_${NSS_VERSION//./_}_RTM/src/${TARBALL}"
SHA256="d122bd039416254567f2dfe7f4c9b6ed4d202d8c6a3ed91332da0d514d0974c0"

mkdir -p "$NSS_DEPS"
cd "$NSS_DEPS"

if [ ! -d "nss-${NSS_VERSION}/dist/Release/lib" ]; then
    if [ ! -f "$TARBALL" ]; then
        echo ">> Скачиваю ${URL}"
        curl -fSL --retry 3 -o "$TARBALL" "$URL"
    fi
    echo ">> Проверяю sha256"
    echo "${SHA256}  ${TARBALL}" | sha256sum -c -

    echo ">> Распаковываю"
    tar xf "$TARBALL"

    echo ">> Собираю NSS (opt + static)"
    # gyp нужен в PATH (pip3 install --user gyp-next)
    export PATH="$HOME/.local/bin:$PATH"
    command -v gyp >/dev/null || {
        echo "!! gyp не найден. Установите: pip3 install --user gyp-next" >&2
        exit 1
    }
    (cd "nss-${NSS_VERSION}/nss" && ./build.sh \
        -Ddisable_tests=1 -Ddisable_dbm=1 -Ddisable_libpkix=1 \
        -Ddisable_ckbi=1 -Ddisable_fips=1 --opt --static)
fi

echo ">> NSS готов: ${NSS_DEPS}/nss-${NSS_VERSION}/nss"
echo "   Используйте: NSS_DIR=${NSS_DEPS}/nss-${NSS_VERSION}/nss NSS_PREBUILT=1"
