# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

parent_folder="$(dirname "$0")"
curve=P-$1
dgst=$2
cleanup=$3
testdata="$parent_folder"/testdata/testdata_"$curve"_"$dgst".bin
maskedkeyfile="$parent_folder"/testdata/masked_"$curve".bin
signature_filename=testdata.sig."$dgst"_"$curve"
signature="$parent_folder"/testdata/"$signature_filename"

mkdir -p "$parent_folder"/testdata

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

# Create test data
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
    rm $testdata
    rm $maskedkeyfile
    rm $signature
fi
