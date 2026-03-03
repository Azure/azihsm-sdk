# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @hexsalt @cleanup

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

curve=P-$1
dgst_bits=$2
dgst="sha"$dgst_bits""
hexsalt=$3
cleanup=$4
keyfile_priv=./hmac_derivation_peer_ec_"$curve"_priv.pem
keyfile_pub=./hmac_derivation_peer_ec_"$curve"_pub.pem
maskedkeyfile=./hmac_derivation_masked_"$curve"_imported.bin
shared_secret=./hmac_derivation_shared_secret_"$curve".bin
hmac_derivation_output=./hmac_derivation_aes_"$curve"_"$dgst".bin

if [[ "$hexsalt" == "true" ]]; then
    saltopts="-kdfopt hexsalt:000102030405060708090a0b0c -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9"
else
    saltopts=""
fi

"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
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
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -inkey "azihsm://$maskedkeyfile;type=ec" \
    -peerkey "$keyfile_pub" \
    -pkeyopt "output_file:$shared_secret"

"$OPENSSL_BIN" kdf \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -keylen 4096 \
    -kdfopt "digest:$dgst" \
    -kdfopt "azihsm.ikm_file:$shared_secret" \
    -kdfopt "output_file:$hmac_derivation_output" \
    -kdfopt derived_key_type:hmac \
    -kdfopt "derived_key_bits:$dgst_bits" \
    $saltopts \
    -binary -out /dev/null \
    HKDF

#CHECK: file created
if [[ -f "$hmac_derivation_output" && -s "$hmac_derivation_output" ]]; then
  echo "file created"
fi

if [[ "$cleanup" == "true" ]]; then
    rm "$keyfile_priv"
    rm "$keyfile_pub"
    rm "$maskedkeyfile"
    rm "$shared_secret"
    rm "$hmac_derivation_output"
fi
