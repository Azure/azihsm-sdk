# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @algorithm @cleanup 

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

keybits=$1
algorithm=$2
cleanup=$3
keyfile=./no_file_there.der
maskedkeyfile=./should_not_exist_rsa_"$keybits"_"$algorithm"_imported.bin

# Unset -e and catch error output
set +e
# Try loading a keyfile that does not exist
output=$("$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -algorithm $algorithm \
    -pkeyopt rsa_keygen_bits:$keybits \
    -pkeyopt azihsm.session:false \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt azihsm.input_key:$keyfile \
    -pkeyopt azihsm.masked_key:$maskedkeyfile 2>&1)
exit_code=$?
set -e

#CHECK: Error generating $$algorithm key
echo $output

#CHECK: PASS - No file created
if [[ -f $maskedkeyfile ]]; then
    # Key file was unexpectedly created - this should not have occurred
    echo "FAIL"

    # remove the file in this case
    if [[ "$cleanup" == "true" ]]; then
        rm $maskedkeyfile
    fi
else 
    # No key file created (expected behaviour)
    echo "PASS - No file created"
fi

