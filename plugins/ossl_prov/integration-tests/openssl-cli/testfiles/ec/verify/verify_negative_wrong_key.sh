# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
dgst=$2
cleanup=$3
testdata=testdata_verify.bin
maskedkeyfile=./masked_verify_negative_false_key_"$curve"_"$dgst".bin
wrongkey=./masked_verify_negative_false_key_"$curve"_"$dgst"_wrongkey.bin
signature=testdata_verify.sig."$dgst"_"$curve"

# Generate a fresh key
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" \
    -pkeyopt azihsm.key_usage:digitalSignature

# Create and sign test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -sign "azihsm://$maskedkeyfile;type=ec" \
    -out "$signature" \
    "$testdata"

# Generate a new key that wont work
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt "azihsm.masked_key:$wrongkey" \
    -pkeyopt azihsm.key_usage:digitalSignature

# Verification should fail — use || true so -e doesn't abort the script
#CHECK: Verification failure
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -verify "azihsm://$wrongkey;type=ec" \
    -signature "$signature" \
    "$testdata" || true

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$signature" "$maskedkeyfile" "$wrongkey"
fi
