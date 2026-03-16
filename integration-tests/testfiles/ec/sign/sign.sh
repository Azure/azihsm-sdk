# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

parent_folder="$(dirname "$0")"
curve=P-$1
dgst=$2
cleanup=$3
testdata=testdata.bin
maskedkeyfile=./masked_sign_"$curve"_"$dgst".bin
signature=testdata.sig."$dgst"_"$curve"

# Generate a fresh signing key
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

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

"$OPENSSL_BIN" dgst -"$dgst" \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -sign "azihsm://$maskedkeyfile;type=ec" \
    -out "$signature" \
    "$testdata"

# CHECK: file signed
if [[ -f "$signature" && -s "$signature" ]]; then
  echo "file signed"
fi

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$signature" "$maskedkeyfile"
fi
