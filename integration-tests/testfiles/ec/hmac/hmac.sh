# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
dgst_bits=$2
dgst="sha"$dgst_bits""
cleanup=$3

keyfile_priv=./hmac_peer_ec_"$curve"_priv.pem
keyfile_pub=./hmac_peer_ec_"$curve"_pub.pem
maskedkeyfile=./hmac_masked_"$curve"_imported.bin
shared_secret=./hmac_shared_secret_"$curve".bin
hmac_derivation_output=./hmac_"$curve"_"$dgst".bin
testdata=./hmac_testdata_"$curve"_"$dgst".bin
hmac_output=./hmac_output_"$curve"_"$dgst".bin

"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt azihsm.key_usage:keyAgreement \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" \
    -outform DER \
    -out /dev/null

"$OPENSSL_BIN" genpkey \
    -algorithm EC \
    -pkeyopt "ec_paramgen_curve:$curve" \
    -out "$keyfile_priv"

"$OPENSSL_BIN" pkey -in "$keyfile_priv" \
        -pubout -out "$keyfile_pub" \
        2>/dev/null

"$OPENSSL_BIN" pkeyutl \
    -derive \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -inkey "azihsm://$maskedkeyfile;type=ec" \
    -peerkey "$keyfile_pub" \
    -pkeyopt "output_file:$shared_secret"

"$OPENSSL_BIN" kdf \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -keylen 4096 \
    -kdfopt "digest:$dgst" \
    -kdfopt "azihsm.ikm_file:$shared_secret" \
    -kdfopt "output_file:$hmac_derivation_output" \
    -kdfopt derived_key_type:hmac \
    -kdfopt "derived_key_bits:$dgst_bits" \
    -binary -out /dev/null \
    HKDF

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

"$OPENSSL_BIN" mac -digest "$dgst" \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -macopt "key:$hmac_derivation_output" \
    -in "$testdata" \
    -binary \
    -out "$hmac_output" \
    HMAC

#CHECK: file created
if [[ -f "$hmac_output" && -s "$hmac_output" ]]; then
  echo "file created"
fi

if [[ "$cleanup" == "true" ]]; then
    rm -f "$keyfile_priv" "$keyfile_pub" "$maskedkeyfile" "$shared_secret" \
        "$hmac_derivation_output" "$testdata" "$hmac_output"
fi
