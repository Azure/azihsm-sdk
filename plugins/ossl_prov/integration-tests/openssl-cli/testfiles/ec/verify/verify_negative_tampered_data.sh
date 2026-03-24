# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

# Checks if tampered data will fail to verify

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
dgst=$2
cleanup=$3
testdata=testdata_neg.bin
maskedkeyfile=./masked_neg_"$curve"_"$dgst".bin
signature=testdata_neg.sig."$dgst"_"$curve"
testdata_tampered=testdata_neg_tampered.bin

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

# Tamper with the data
cp "$testdata" "$testdata_tampered"
echo "tampered" >> "$testdata_tampered"

# Verification should fail — use || true so -e doesn't abort the script
#CHECK: Verification failure
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -verify "azihsm://$maskedkeyfile;type=ec" \
    -signature "$signature" \
    "$testdata_tampered" || true

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$signature" "$maskedkeyfile" "$testdata_tampered"
fi
