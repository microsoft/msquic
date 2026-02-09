#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Generates a self-signed test certificate chain (Root CA → Intermediate CA →
# Leaf) and bundles them into a PKCS#12 (.pfx) file for MsQuic tests.
#
# Bash replacement for install-test-certificates.ps1.
#
# Usage:
#   ./scripts/install-test-certificates.sh <output.pfx>

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <output-pfx-path>" >&2
    exit 1
fi

OUTPUT_FILE="$1"
PASSWORD="PLACEHOLDER"
DAYS_VALID=365

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# ── Root CA ─────────────────────────────────────────────────────────────────
openssl req -x509 -new -newkey rsa:2048 -nodes \
    -keyout "$WORK_DIR/root.key" \
    -out "$WORK_DIR/root.crt" \
    -subj "/CN=MsQuicPkcs12Root" \
    -days "$DAYS_VALID" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,digitalSignature,keyCertSign" \
    2>/dev/null

# ── Intermediate CA ─────────────────────────────────────────────────────────
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$WORK_DIR/intermediate.key" \
    -out "$WORK_DIR/intermediate.csr" \
    -subj "/CN=MsQuicPkcs12Intermediate" \
    2>/dev/null

openssl x509 -req \
    -in "$WORK_DIR/intermediate.csr" \
    -CA "$WORK_DIR/root.crt" \
    -CAkey "$WORK_DIR/root.key" \
    -CAcreateserial \
    -out "$WORK_DIR/intermediate.crt" \
    -days "$DAYS_VALID" \
    -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,digitalSignature,keyCertSign") \
    2>/dev/null

# ── Leaf certificate ────────────────────────────────────────────────────────
cat > "$WORK_DIR/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EOF

openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$WORK_DIR/leaf.key" \
    -out "$WORK_DIR/leaf.csr" \
    -subj "/CN=localhost" \
    2>/dev/null

openssl x509 -req \
    -in "$WORK_DIR/leaf.csr" \
    -CA "$WORK_DIR/intermediate.crt" \
    -CAkey "$WORK_DIR/intermediate.key" \
    -CAcreateserial \
    -out "$WORK_DIR/leaf.crt" \
    -days "$DAYS_VALID" \
    -extfile "$WORK_DIR/leaf.ext" \
    2>/dev/null

# ── Bundle into PKCS#12 (.pfx) ─────────────────────────────────────────────
# Include leaf + intermediate + root in the chain
cat "$WORK_DIR/intermediate.crt" "$WORK_DIR/root.crt" > "$WORK_DIR/chain.crt"

openssl pkcs12 -export \
    -out "$OUTPUT_FILE" \
    -inkey "$WORK_DIR/leaf.key" \
    -in "$WORK_DIR/leaf.crt" \
    -certfile "$WORK_DIR/chain.crt" \
    -passout "pass:$PASSWORD" \
    2>/dev/null

echo "Generated $OUTPUT_FILE"
