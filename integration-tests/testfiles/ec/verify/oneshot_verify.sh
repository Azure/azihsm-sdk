# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
dgst=$2
cleanup=$3
testdata=testdata_oneshot_verify.bin
testdata_hash=testdata_oneshot_verify."$dgst"
maskedkeyfile=./masked_oneshot_verify_"$curve"_"$dgst".bin
signature=testdata_oneshot_verify.sig."$dgst"_"$curve"

# Generate a fresh key
"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" \
    -pkeyopt azihsm.key_usage:digitalSignature

# Create test data and hash
dd if=/dev/urandom of="$testdata" bs=1024 count=1

"$OPENSSL_BIN" dgst -"$dgst" -binary -out "$testdata_hash" "$testdata"

# Sign with pkeyutl
"$OPENSSL_BIN" pkeyutl -sign \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -inkey "azihsm://$maskedkeyfile;type=ec" \
    -in "$testdata_hash" \
    -out "$signature"

# CHECK: Signature Verified Successfully
"$OPENSSL_BIN" pkeyutl -verify \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -inkey "azihsm://$maskedkeyfile;type=ec" \
    -in "$testdata_hash" \
    -sigfile "$signature"

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$testdata_hash" "$signature" "$maskedkeyfile"
fi
