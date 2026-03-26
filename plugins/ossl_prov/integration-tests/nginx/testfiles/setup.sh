#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Setup script for NGINX integration tests.
# Generates credential files, a P-384 masked key, and a self-signed
# certificate using explicit provider flags, then installs all key material
# to the system paths expected by the provider config.
#
# Prerequisites (handled by CI before this script runs):
#   - Provider .so installed at PROVIDER_PATH
#   - Config files deployed to /etc/azihsm/
#   - Base key material (OBK, POTA) generated in CWD (workspace root)
#   - OPENSSL_BIN, LD_LIBRARY_PATH, AZIHSM_CREDENTIALS_ID, AZIHSM_CREDENTIALS_PIN set
#
# IMPORTANT: OPENSSL_CONF must NOT be set when running genpkey/req with
# explicit -provider flags.  If set, the provider is loaded twice (once from
# config, once from CLI), and the CLI-loaded instance uses CWD-relative
# defaults while the config-loaded instance may conflict.  We unset it here
# and use explicit -provider/-propquery flags instead.

set -euo pipefail
unset OPENSSL_CONF

# --- Validate environment ---------------------------------------------------
OSSL="${OPENSSL_BIN:?OPENSSL_BIN must be set to the OpenSSL 3.x binary}"
if [[ ! -x "$OSSL" ]]; then
    echo "ERROR: OPENSSL_BIN does not exist or is not executable: $OSSL" >&2
    exit 1
fi

PROV_PATH="${PROVIDER_PATH:-/usr/lib/x86_64-linux-gnu/ossl-modules}"
PROV="-provider-path $PROV_PATH -provider default -provider azihsm_provider"

# --- Ensure credential binary files exist in CWD ----------------------------
# The provider needs these files to enumerate HSM partitions.  The CI
# "Generate dev key material" step creates them, but we regenerate here to
# be self-contained (matching what the capi test harness does).
CRED_ID="${AZIHSM_CREDENTIALS_ID:-70fcf730b8764238b8358010ce8a3f76}"
CRED_PIN="${AZIHSM_CREDENTIALS_PIN:-db3dc77fc22e430080d41b31b6f04800}"

if [[ ! -f credentials_id.bin ]]; then
    echo "Generating credentials_id.bin..."
    printf '\x70\xFC\xF7\x30\xB8\x76\x42\x38\xB8\x35\x80\x10\xCE\x8A\x3F\x76' > credentials_id.bin
    chmod 600 credentials_id.bin
fi
if [[ ! -f credentials_pin.bin ]]; then
    echo "Generating credentials_pin.bin..."
    printf '\xDB\x3D\xC7\x7F\xC2\x2E\x43\x00\x80\xD4\x1B\x31\xB6\xF0\x48\x00' > credentials_pin.bin
    chmod 600 credentials_pin.bin
fi

# --- Diagnostics -------------------------------------------------------------
echo "CWD: $(pwd)"
echo "Key material files in CWD:"
ls -la credentials_id.bin credentials_pin.bin obk.bin pota_private_key.der pota_public_key.der 2>&1 || true
echo "OPENSSL_CONF=${OPENSSL_CONF:-<unset>}"
echo "AZIHSM_CREDENTIALS_ID=${CRED_ID}"
echo "AZIHSM_CREDENTIALS_PIN=${CRED_PIN}"
echo "PROVIDER_PATH=$PROV_PATH"
echo "Provider .so exists:"
ls -la "$PROV_PATH/azihsm_provider.so" 2>&1 || true
echo "libazihsm_api_native.so:"
ldconfig -p | grep azihsm || true
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-<unset>}"

# --- Fix LD_LIBRARY_PATH ----------------------------------------------------
# nextest prepends test-binary paths to LD_LIBRARY_PATH which can cause the
# provider to load a different (non-mock or stale) libazihsm_api_native.so
# from target/debug/deps/.  Reset to just the OpenSSL lib dir.
OPENSSL_LIB_DIR="${OPENSSL_LIB:-/opt/openssl-3.0.3/lib}"
export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR"
echo "LD_LIBRARY_PATH (fixed)=$LD_LIBRARY_PATH"

# --- Generate P-384 masked key ----------------------------------------------
# Uses explicit -provider flags.  The provider finds key material (obk.bin,
# pota keys, credentials) in CWD (the workspace root, set by the Rust harness).
echo "Generating P-384 masked key..."
$OSSL genpkey $PROV \
    -propquery "?provider=azihsm" \
    -algorithm EC \
    -pkeyopt group:P-384 \
    -pkeyopt "azihsm.masked_key:/etc/azihsm/masked_key_p384.bin" \
    -outform DER -out /dev/null

# --- Generate self-signed certificate ---------------------------------------
echo "Generating self-signed certificate..."
$OSSL req -new -x509 $PROV \
    -propquery "?provider=azihsm" \
    -key "azihsm:///etc/azihsm/masked_key_p384.bin;type=ec" \
    -subj "/CN=localhost" \
    -days 365 -sha384 \
    -out /etc/azihsm/server.crt

# --- Install all key material to /var/lib/azihsm ----------------------------
# Base material (obk, pota) from CWD + derived material (bmk, muk) generated
# by the provider during genpkey.
echo "Installing key material to /var/lib/azihsm/..."
cp bmk.bin muk.bin obk.bin pota_private_key.der pota_public_key.der /var/lib/azihsm/
chmod 600 /var/lib/azihsm/*.bin /var/lib/azihsm/*.der

echo "NGINX test setup complete."
