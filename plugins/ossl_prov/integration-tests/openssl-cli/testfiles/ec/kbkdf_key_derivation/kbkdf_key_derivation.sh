# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @withcontext @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
dgst_bits=$2
dgst="sha"$dgst_bits""
withcontext=$3
cleanup=$4
keyfile_priv=./kbkdf_peer_ec_"$curve"_priv.pem
keyfile_pub=./kbkdf_peer_ec_"$curve"_pub.pem
maskedkeyfile=./kbkdf_masked_"$curve"_imported.bin
shared_secret=./kbkdf_shared_secret_"$curve".bin
kbkdf_output=kbkdf_aes_"$curve"_"$dgst".bin

# The azihsm provider maps the standard OSSL_KDF_PARAM_SALT/INFO parameters to the
# SP 800-108 Label/Context inputs. At least one of Label/Context must be present, so a
# Label (hexsalt) is always supplied; the Context (hexinfo) is optional.
if [[ "$withcontext" == "true" ]]; then
    kdfopts="-kdfopt hexsalt:000102030405060708090a0b0c -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9"
else
    kdfopts="-kdfopt hexsalt:000102030405060708090a0b0c"
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
    -kdfopt mode:counter \
    -kdfopt "azihsm.ikm_file:$shared_secret" \
    -kdfopt "output_file:$kbkdf_output" \
    -kdfopt derived_key_type:aes \
    -kdfopt derived_key_bits:256 \
    $kdfopts \
    -binary -out /dev/null \
    KBKDF

#CHECK: file created
if [[ -f "$kbkdf_output" && -s "$kbkdf_output" ]]; then
  echo "file created"
fi

if [[ "$cleanup" == "true" ]]; then
    rm -f "$keyfile_priv" "$keyfile_pub" "$maskedkeyfile" "$shared_secret" \
        "$kbkdf_output"
fi
