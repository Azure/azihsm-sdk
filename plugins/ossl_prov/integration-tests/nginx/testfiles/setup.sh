#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Setup script for NGINX integration tests.
#
# Unlike the cli/capi test suites (which generate key material under
# target/test-keymat/), the NGINX suite deploys to system paths
# (/etc/azihsm/, /var/lib/azihsm/) to mirror a production deployment.
#
# Prerequisites (handled by CI before this script runs):
#   - Provider .so installed at PROVIDER_PATH
#   - Config files deployed to /etc/azihsm/
#   - Base key material (OBK, POTA) generated in CWD (workspace root)
#   - OPENSSL_BIN, LD_LIBRARY_PATH, AZIHSM_CREDENTIALS_ID, AZIHSM_CREDENTIALS_PIN set
#
# OPENSSL_CONF is unset because genpkey/req use explicit -provider flags.
# If OPENSSL_CONF were set, the provider would be loaded twice (from config
# AND from CLI flags) causing conflicts.

set -euo pipefail
unset OPENSSL_CONF

OSSL="${OPENSSL_BIN:?OPENSSL_BIN must be set to the OpenSSL 3.x binary}"
if [[ ! -x "$OSSL" ]]; then
    echo "ERROR: OPENSSL_BIN does not exist or is not executable: $OSSL" >&2
    exit 1
fi

PROV_PATH="${PROVIDER_PATH:-/usr/lib/x86_64-linux-gnu/ossl-modules}"
PROV="-provider-path $PROV_PATH -provider default -provider azihsm_provider"

# The provider needs credential binary files to enumerate HSM partitions.
if [[ ! -f credentials_id.bin ]]; then
    printf '\x70\xFC\xF7\x30\xB8\x76\x42\x38\xB8\x35\x80\x10\xCE\x8A\x3F\x76' > credentials_id.bin
    chmod 600 credentials_id.bin
fi
if [[ ! -f credentials_pin.bin ]]; then
    printf '\xDB\x3D\xC7\x7F\xC2\x2E\x43\x00\x80\xD4\x1B\x31\xB6\xF0\x48\x00' > credentials_pin.bin
    chmod 600 credentials_pin.bin
fi

# nextest may prepend target/debug/deps/ to LD_LIBRARY_PATH, causing the
# provider to load a stale libazihsm_api_native.so.  Reset to just the
# custom OpenSSL lib dir needed by $OSSL.
OPENSSL_LIB_DIR="${OPENSSL_LIB:-/opt/openssl-3.0.3/lib}"
export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR"

echo "Generating P-384 masked key..."
$OSSL genpkey $PROV \
    -propquery "?provider=azihsm" \
    -algorithm EC \
    -pkeyopt group:P-384 \
    -pkeyopt "azihsm.masked_key:/etc/azihsm/masked_key_p384.bin" \
    -outform DER -out /dev/null

echo "Generating self-signed certificate..."
$OSSL req -new -x509 $PROV \
    -propquery "?provider=azihsm" \
    -key "azihsm:///etc/azihsm/masked_key_p384.bin;type=ec" \
    -subj "/CN=localhost" \
    -days 365 -sha384 \
    -out /etc/azihsm/server.crt

echo "Installing key material to /var/lib/azihsm/..."
cp bmk.bin muk.bin obk.bin pota_private_key.der pota_public_key.der /var/lib/azihsm/
chmod 600 /var/lib/azihsm/*.bin /var/lib/azihsm/*.der

echo "NGINX test setup complete."
