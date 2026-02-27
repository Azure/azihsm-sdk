# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

curve=P-$1
dgst=$2
cleanup=$3
testdata=testdata_verify.bin
maskedkeyfile=./masked_verify_"$curve"_"$dgst".bin
signature=testdata_verify.sig."$dgst"_"$curve"

# Generate a fresh key
"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt group:$curve \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt azihsm.masked_key:$maskedkeyfile \
    -pkeyopt azihsm.key_usage:digitalSignature

# Create and sign test data
dd if=/dev/urandom of=$testdata bs=1024 count=1

"$OPENSSL_BIN" dgst -$dgst \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -sign "azihsm://$maskedkeyfile;type=ec" \
    -out $signature \
    $testdata

#CHECK: Verified OK
"$OPENSSL_BIN" dgst -$dgst \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -verify "azihsm://$maskedkeyfile;type=ec" \
    -signature $signature \
    $testdata

if [[ "$cleanup" == "true" ]]; then
  rm -f $testdata $signature $maskedkeyfile
fi
