# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

parent_folder="$(dirname "$0")"
curve=P-$1
dgst=$2
cleanup=$3
testdata_folder="$parent_folder"/testdata
testdata="$testdata_folder"/testdata_"$curve"_"$dgst".bin
maskedkeyfile="$testdata_folder"/masked_"$curve".bin
keyfile="$testdata_folder"/ec_"$curve".der
signature_filename=testdata.sig."$dgst"_"$curve"
signature="$testdata_folder"/"$signature_filename"
testdata_hash="$testdata_folder"/testdata."$dgst"

mkdir -p "$testdata_folder"

"$OPENSSL_BIN" genpkey \
    -algorithm EC \
    -pkeyopt "ec_paramgen_curve:$curve" \
    -outform DER \
    -out "$keyfile"

"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -outform DER \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile"

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

"$OPENSSL_BIN" dgst -"$dgst" -binary -out "$testdata_hash" "$testdata"

"$OPENSSL_BIN" pkeyutl -sign \
    -propquery "$PROPQUERY" \
    -inkey "azihsm://$maskedkeyfile;type=ec" \
    -in "$testdata_hash" \
    -out "$signature"

# CHECK: file signed
if [[ -f "$signature" && -s "$signature" ]]; then
  echo "file signed"
fi

# CHECK: Signature Verified Successfully

"$OPENSSL_BIN" pkeyutl -verify \
    -propquery "$PROPQUERY" \
    -inkey "azihsm://$maskedkeyfile;type=ec" \
    -in "$testdata_hash" \
    -sigfile "$signature"

if [[ "$cleanup" == "true" ]]; then
    rm -f "$keyfile" "$testdata" "$signature" "$maskedkeyfile" "$testdata_hash"
    rmdir "$testdata_folder" 2>/dev/null || true
fi
