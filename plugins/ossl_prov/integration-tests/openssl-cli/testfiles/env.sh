# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Common environment setup for integration test scripts.
#
# Source this file from each test script:
#   source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"  (depth-3 scripts)
#   source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"     (depth-2 scripts)

# Derive repo root from env.sh location
# (testfiles/ -> openssl-cli/ -> integration-tests/ -> ossl_prov/ -> plugins/ -> repo root)
TESTFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TESTFILES_DIR/../../../../.." && pwd)"

# --- Required environment variables ---

if [ -z "$OPENSSL_BIN" ]; then
    echo "ERROR: OPENSSL_BIN is not set." >&2
    echo "" >&2
    echo "Required environment variables for integration tests:" >&2
    echo "  OPENSSL_BIN    Path to OpenSSL 3.x binary (required)" >&2
    echo "                 e.g. export OPENSSL_BIN=/opt/openssl-3.0.3/bin/openssl" >&2
    echo "" >&2
    echo "Optional (have sensible defaults):" >&2
    echo "  PROVIDER_PATH  Dir containing azihsm_provider.so (default: target/debug)" >&2
    echo "  OPENSSL_LIB    Dir with OpenSSL shared libs, sets LD_LIBRARY_PATH (default: empty)" >&2
    echo "  PROPQUERY      Provider query string (default: ?provider=azihsm)" >&2
    exit 1
fi

if [ ! -x "$OPENSSL_BIN" ]; then
    echo "ERROR: OPENSSL_BIN is not executable: $OPENSSL_BIN" >&2
    exit 1
fi

# --- Optional environment variables (sensible defaults) ---

test -z "$PROVIDER_PATH" && PROVIDER_PATH="$REPO_ROOT/target/debug"
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"

# OPENSSL_LIB: distinguish "unset" from "set to empty" (CI sets OPENSSL_LIB="")
if [ -z "${OPENSSL_LIB+x}" ]; then
    OPENSSL_LIB=""
fi

export LD_LIBRARY_PATH="$OPENSSL_LIB"

# --- Credentials via hex env vars (preferred) ---
# The provider reads credentials from these env vars first, falling back to
# default files in CWD if unset.  Values match the mock HSM's test credentials.
export AZIHSM_CREDENTIALS_ID="${AZIHSM_CREDENTIALS_ID:-70fcf730b8764238b8358010ce8a3f76}"
export AZIHSM_CREDENTIALS_PIN="${AZIHSM_CREDENTIALS_PIN:-db3dc77fc22e430080d41b31b6f04800}"

# --- Isolated key material directory ---
# All key material is generated in target/test-keymat/cli/ to avoid polluting
# the workspace root or package directory.  The xtask cleans this directory
# before each integration test run for fresh-per-run isolation.

AZIHSM_KEY_DIR="$REPO_ROOT/target/test-keymat/cli"
mkdir -p "$AZIHSM_KEY_DIR"

# --- Generate dev key material if not present ---
# Credential files are kept as fallback for any path that unsets the env vars.
# OBK and POTA files are always required.

if [ ! -f "$AZIHSM_KEY_DIR/credentials_id.bin" ]; then
    printf '\x70\xFC\xF7\x30\xB8\x76\x42\x38\xB8\x35\x80\x10\xCE\x8A\x3F\x76' > "$AZIHSM_KEY_DIR/credentials_id.bin"
    chmod 600 "$AZIHSM_KEY_DIR/credentials_id.bin"
fi

if [ ! -f "$AZIHSM_KEY_DIR/credentials_pin.bin" ]; then
    printf '\xDB\x3D\xC7\x7F\xC2\x2E\x43\x00\x80\xD4\x1B\x31\xB6\xF0\x48\x00' > "$AZIHSM_KEY_DIR/credentials_pin.bin"
    chmod 600 "$AZIHSM_KEY_DIR/credentials_pin.bin"
fi

if [ ! -f "$AZIHSM_KEY_DIR/obk.bin" ]; then
    "$OPENSSL_BIN" rand -out "$AZIHSM_KEY_DIR/obk.bin" 48
    chmod 600 "$AZIHSM_KEY_DIR/obk.bin"
fi

if [ ! -f "$AZIHSM_KEY_DIR/pota_private_key.der" ]; then
    "$OPENSSL_BIN" ecparam -name secp384r1 -genkey -noout \
        | "$OPENSSL_BIN" ec -outform DER -out "$AZIHSM_KEY_DIR/pota_private_key.der" 2>/dev/null
    "$OPENSSL_BIN" ec -in "$AZIHSM_KEY_DIR/pota_private_key.der" -inform DER \
        -pubout -outform DER -out "$AZIHSM_KEY_DIR/pota_public_key.der" 2>/dev/null
    chmod 600 "$AZIHSM_KEY_DIR/pota_private_key.der" "$AZIHSM_KEY_DIR/pota_public_key.der"
fi

# --- Generate openssl.cnf with absolute paths ---
# The config auto-loads the default and azihsm providers and provides
# absolute paths to all key material files (matching the README format).

PROVIDER_SO="$(cd "$PROVIDER_PATH" && pwd)/azihsm_provider.so"

cat > "$AZIHSM_KEY_DIR/openssl.cnf" << EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
azihsm = azihsm_sect

[default_sect]
activate = 1

[azihsm_sect]
module = $PROVIDER_SO
activate = 1
azihsm-bmk-path = $AZIHSM_KEY_DIR/bmk.bin
azihsm-muk-path = $AZIHSM_KEY_DIR/muk.bin
azihsm-obk-path = $AZIHSM_KEY_DIR/obk.bin
azihsm-mobk-path = $AZIHSM_KEY_DIR/mobk.bin
azihsm-obk-source = caller
azihsm-pota-source = caller
azihsm-pota-private-key-path = $AZIHSM_KEY_DIR/pota_private_key.der
azihsm-pota-public-key-path = $AZIHSM_KEY_DIR/pota_public_key.der
azihsm-api-revision = 1.0
EOF

export OPENSSL_CONF="$AZIHSM_KEY_DIR/openssl.cnf"

# --- Version gating helpers ---
# Skip the test if OpenSSL is older than the given <major>.<minor>.  Used by
# lit .sh scripts that exercise features only available in newer OpenSSL.
# Exits 0 (lit treats this as a passing skip) so the rest of the suite
# continues.
#
#   require_ossl_version 3 5
require_ossl_version() {
    local req_major=$1 req_minor=$2
    local ver
    ver=$("$OPENSSL_BIN" version | awk '{print $2}')
    local cur_major cur_minor
    cur_major=$(echo "$ver" | cut -d. -f1)
    cur_minor=$(echo "$ver" | cut -d. -f2)
    if [ "$cur_major" -lt "$req_major" ] || \
       { [ "$cur_major" -eq "$req_major" ] && [ "$cur_minor" -lt "$req_minor" ]; }; then
        echo "SKIP: requires OpenSSL >= $req_major.$req_minor (have $ver)"
        exit 0
    fi
}

# Convenience: skip the test unless OpenSSL is at least 3.5.
skip_below_ossl_3_5() { require_ossl_version 3 5; }
