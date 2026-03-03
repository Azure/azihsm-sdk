# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Common environment setup for integration test scripts.
#
# Source this file from each test script:
#   source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"  (depth-3 scripts)
#   source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"     (depth-2 scripts)

# Derive repo root from env.sh location (testfiles/ -> integration-tests/ -> repo root)
TESTFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TESTFILES_DIR/../.." && pwd)"

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
