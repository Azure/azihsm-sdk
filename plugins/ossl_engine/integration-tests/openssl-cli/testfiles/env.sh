# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Shared setup for the engine CLI integration tests, sourced by each script.
# Provisions the keymat both the masked-key generator and the engine-loading
# openssl process share (OBK, POTA keypair, resiliency storage), and writes an
# openssl.cnf that loads the engine by id "azihsm" from $ENGINE_SO.
set -eu

: "${OPENSSL_BIN:?OPENSSL_BIN must point to the OpenSSL 1.1.x openssl binary}"
: "${ENGINE_SO:?ENGINE_SO must point to libazihsm_ossl_engine.so}"
: "${MASKED_KEYGEN:?MASKED_KEYGEN must point to the masked-keygen helper}"

# Owner-only, set before any key material or config is created below.
umask 0077

# Isolated keymat dir (xtask wipes target/test-keymat before a run).
# The runner passes each suite's keydir as the script's first argument (lit's
# @keydir constant); the env var / default remain for manual invocations.
KEYDIR="${1:-${AZIHSM_ENGINE_TEST_KEYDIR:-$PWD/target/test-keymat/engine-cli}}"
mkdir -p "$KEYDIR"
install -d -m 700 "$KEYDIR/res"

# OBK (48 random bytes = BK3) and the caller POTA P-384 keypair, normalized to
# unencrypted PKCS#8 DER (what azihsm_crypto's key parser expects). Generated
# once per keydir so the generator and the engine share them.
[ -f "$KEYDIR/obk.bin" ] || "$OPENSSL_BIN" rand -out "$KEYDIR/obk.bin" 48
if [ ! -f "$KEYDIR/pota_priv.der" ]; then
    "$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
        -out "$KEYDIR/pota.pem"
    "$OPENSSL_BIN" pkcs8 -topk8 -nocrypt -in "$KEYDIR/pota.pem" -outform DER \
        -out "$KEYDIR/pota_priv.der"
    "$OPENSSL_BIN" pkey -in "$KEYDIR/pota_priv.der" -inform DER -pubout -outform DER \
        -out "$KEYDIR/pota_pub.der"
fi

# Environment the generator and the engine both read (see EngineData::open_hsm_from_env).
# Credentials are left unset so the mock's built-in test credentials are used on
# both sides.
export AZIHSM_RESILIENCY_ENABLED=1
export AZIHSM_RESILIENCY_STORAGE_DIR="$KEYDIR/res"
export AZIHSM_OBK_SOURCE=caller
export AZIHSM_OBK_PATH="$KEYDIR/obk.bin"
export AZIHSM_MOBK_PATH="$KEYDIR/mobk.bin"
export AZIHSM_POTA_SOURCE=caller
export AZIHSM_POTA_PRIVATE_KEY_PATH="$KEYDIR/pota_priv.der"
export AZIHSM_POTA_PUBLIC_KEY_PATH="$KEYDIR/pota_pub.der"

# openssl.cnf that dynamically loads the engine so `-engine azihsm` resolves.
cat > "$KEYDIR/openssl.cnf" <<EOF
openssl_conf = openssl_init
[openssl_init]
engines = engine_section
[engine_section]
azihsm = azihsm_engine
[azihsm_engine]
dynamic_path = $ENGINE_SO
init = 1
EOF
export OPENSSL_CONF="$KEYDIR/openssl.cnf"
