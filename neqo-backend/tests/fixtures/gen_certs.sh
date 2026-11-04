#!/usr/bin/env bash
# Generates the test CA and server certificate used by the TLS integration
# tests. Idempotent: skips regeneration if ca.crt already exists.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$DIR/ca.crt" ] && [ -f "$DIR/ca.der" ] && [ -f "$DIR/server.crt" ] && [ -f "$DIR/server.key" ]; then
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$DIR/ca.key" -out "$DIR/ca.crt" \
    -subj "/CN=neqo-backend test CA" -days 3650 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 1>&2

openssl req -newkey rsa:2048 -nodes -keyout "$DIR/server.key" -out "$DIR/server.csr" \
    -subj "/CN=localhost" 1>&2

openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
    -CAcreateserial -out "$DIR/server.crt" -days 3650 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n") 1>&2

# DER form of the CA cert for clients that pin it via ffx_add_root_ca.
openssl x509 -in "$DIR/ca.crt" -outform DER -out "$DIR/ca.der" 1>&2

echo "test certificates generated in $DIR" 1>&2
