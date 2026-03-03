# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @cleanup

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

curve=P-$1
cleanup=$2
maskedkeyfile=./masked_P-$1.bin

# Unset -e and catch error output
set +e
# Try loading a keyfile that does not exist
output=$("$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -outform DER \
    -pkeyopt azihsm.input_key:./not_an_actual_file.bin \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" 2>&1)
exit_code=$?
set -e

#CHECK: Error generating EC key
echo "$output"

#CHECK: PASS - No file created
if [[ -f "$maskedkeyfile" ]]; then
    # Key file was unexpectedly created - this should not have occurred
    echo "FAIL"

    # remove the file in this case
    if [[ "$cleanup" == "true" ]]; then
        rm "$maskedkeyfile"
    fi
else 
    # No key file created (expected behaviour)
    echo "PASS - No file created"
fi
