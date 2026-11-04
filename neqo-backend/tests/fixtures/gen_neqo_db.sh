#!/usr/bin/env bash
# Generates a fresh NSS database with a valid (non-expired) certificate for
# neqo-server, used by the QUIC integration tests. The bundled neqo test
# certificate expired in 2019 and strict verification (correctly) rejects it.
#
# The cert is created with openssl (so the SAN can carry a proper IP entry,
# which certutil -8 cannot express) and imported into the NSS DB with
# pk12util under the nickname "key" (neqo-server's default).
#
# Outputs:
#   neqo-db/            — NSS database with the cert+key pair
#   neqo-server-ca.der  — DER form of that certificate, for ffx_add_root_ca
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB="$DIR/neqo-db"
CA_DER="$DIR/neqo-server-ca.der"

if [ -f "$CA_DER" ] && [ -f "$DB/cert9.db" ] && certutil -L -d "sql:$DB" -n "key" >/dev/null 2>&1; then
    exit 0
fi

rm -rf "$DB"
mkdir -p "$DB"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. Certificate with a proper SAN (DNS + IP) via openssl.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TMP/server.key" -out "$TMP/server.crt" \
    -subj "/CN=localhost" -days 730 \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "keyUsage=digitalSignature,keyEncipherment" 1>&2

# 2. Import into the NSS database as "key".
openssl pkcs12 -export -name "key" \
    -inkey "$TMP/server.key" -in "$TMP/server.crt" \
    -passout pass: -out "$TMP/server.p12" 1>&2

certutil -N -d "sql:$DB" --empty-password 1>&2
pk12util -i "$TMP/server.p12" -d "sql:$DB" -W '' 1>&2
certutil -M -n "key" -t "CT,C,C" -d "sql:$DB" 1>&2

# 3. DER form for clients pinning the certificate.
openssl x509 -in "$TMP/server.crt" -outform DER -out "$CA_DER" 1>&2

echo "fresh neqo-server NSS DB generated in $DB" 1>&2
