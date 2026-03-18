# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @hexsalt @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
dgst_bits=$2
dgst="sha"$dgst_bits""
hexsalt=$3
cleanup=$4
keyfile_priv=./hkdf_peer_ec_"$curve"_priv.pem
keyfile_pub=./hkdf_peer_ec_"$curve"_pub.pem
maskedkeyfile=./hkdf_masked_"$curve"_imported.bin
shared_secret=./hkdf_shared_secret_"$curve".bin
hkdf_output=hkdf_aes_"$curve"_"$dgst".bin

if [[ "$hexsalt" == "true" ]]; then
    saltopts="-kdfopt hexsalt:000102030405060708090a0b0c -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9"
else
    saltopts=""
fi

"$OPENSSL_BIN" genpkey \
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
    -propquery "$PROPQUERY" \
    -inkey "azihsm://$maskedkeyfile;type=ec" \
    -peerkey "$keyfile_pub" \
    -pkeyopt "output_file:$shared_secret"

"$OPENSSL_BIN" kdf \
    -propquery "$PROPQUERY" \
    -keylen 4096 \
    -kdfopt "digest:$dgst" \
    -kdfopt "azihsm.ikm_file:$shared_secret" \
    -kdfopt "output_file:$hkdf_output" \
    -kdfopt derived_key_type:aes \
    -kdfopt derived_key_bits:256 \
    $saltopts \
    -binary -out /dev/null \
    HKDF

#CHECK: file created
if [[ -f "$hkdf_output" && -s "$hkdf_output" ]]; then
  echo "file created"
fi

if [[ "$cleanup" == "true" ]]; then
    rm -f "$keyfile_priv" "$keyfile_pub" "$maskedkeyfile" "$shared_secret" \
        "$hkdf_output"
fi
