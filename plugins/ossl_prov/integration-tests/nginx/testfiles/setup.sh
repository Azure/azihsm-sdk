#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Setup script for NGINX integration tests.
#
# Generates all key material (credentials, OBK, POTA, masked TLS key,
# self-signed certificate) directly into the directory passed as $1.
# This mirrors the self-contained approach used by the CLI (env.sh) and
# CAPI (generate_dev_key_material) test suites.
#
# Prerequisites:
#   - OPENSSL_BIN set to the OpenSSL 3.x binary
#   - PROVIDER_PATH set to the directory containing azihsm_provider.so
#   - LD_LIBRARY_PATH set (if needed) for the OpenSSL binary to find libcrypto
#   - AZIHSM_CREDENTIALS_ID, AZIHSM_CREDENTIALS_PIN set
#
# OPENSSL_CONF is unset because genpkey/req use explicit -provider flags.
# If OPENSSL_CONF were set, the provider would be loaded twice (from config
# AND from CLI flags) causing conflicts.

set -euo pipefail
unset OPENSSL_CONF

KEYMAT_DIR="${1:?Usage: setup.sh <keymat-directory>}"
mkdir -p "$KEYMAT_DIR"

OSSL="${OPENSSL_BIN:?OPENSSL_BIN must be set to the OpenSSL 3.x binary}"
if [[ ! -x "$OSSL" ]]; then
    echo "ERROR: OPENSSL_BIN does not exist or is not executable: $OSSL" >&2
    exit 1
fi

PROV_PATH="${PROVIDER_PATH:?PROVIDER_PATH must be set}"
PROV="-provider-path $PROV_PATH -provider default -provider azihsm_provider"

# --- Generate base key material (same as CLI env.sh / CAPI harness) ---

# Credential binary files
if [[ ! -f "$KEYMAT_DIR/credentials_id.bin" ]]; then
    printf '\x70\xFC\xF7\x30\xB8\x76\x42\x38\xB8\x35\x80\x10\xCE\x8A\x3F\x76' > "$KEYMAT_DIR/credentials_id.bin"
    chmod 600 "$KEYMAT_DIR/credentials_id.bin"
fi
if [[ ! -f "$KEYMAT_DIR/credentials_pin.bin" ]]; then
    printf '\xDB\x3D\xC7\x7F\xC2\x2E\x43\x00\x80\xD4\x1B\x31\xB6\xF0\x48\x00' > "$KEYMAT_DIR/credentials_pin.bin"
    chmod 600 "$KEYMAT_DIR/credentials_pin.bin"
fi

# OBK — 48-byte random owner backup key
if [[ ! -f "$KEYMAT_DIR/obk.bin" ]]; then
    $OSSL rand -out "$KEYMAT_DIR/obk.bin" 48
    chmod 600 "$KEYMAT_DIR/obk.bin"
fi

# POTA — P-384 key pair
if [[ ! -f "$KEYMAT_DIR/pota_private_key.der" ]]; then
    $OSSL ecparam -name secp384r1 -genkey -noout \
        | $OSSL ec -outform DER -out "$KEYMAT_DIR/pota_private_key.der" 2>/dev/null
    $OSSL ec -in "$KEYMAT_DIR/pota_private_key.der" -inform DER \
        -pubout -outform DER -out "$KEYMAT_DIR/pota_public_key.der" 2>/dev/null
    chmod 600 "$KEYMAT_DIR/pota_private_key.der" "$KEYMAT_DIR/pota_public_key.der"
fi

# --- Generate TLS key + certificate ---

echo "Generating P-384 masked key..."
$OSSL genpkey $PROV \
    -propquery "?provider=azihsm" \
    -algorithm EC \
    -pkeyopt group:P-384 \
    -pkeyopt "azihsm.masked_key:$KEYMAT_DIR/masked_key_p384.bin" \
    -outform DER -out /dev/null

echo "Generating self-signed certificate..."
$OSSL req -new -x509 $PROV \
    -propquery "?provider=azihsm" \
    -key "azihsm://$KEYMAT_DIR/masked_key_p384.bin;type=ec" \
    -subj "/CN=localhost" \
    -days 365 -sha384 \
    -out "$KEYMAT_DIR/server.crt"

echo "NGINX test setup complete.  Key material in: $KEYMAT_DIR"
