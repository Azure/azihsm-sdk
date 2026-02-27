# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @session_bool @cleanup

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

curve=P-999
session_bool=$2
maskedkeyfile=./masked_errorkey_"$curve".bin
cleanup=$3

set +e

output=$("$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt group:$curve \
    -pkeyopt azihsm.session:$session_bool \
    -outform DER \
    -pkeyopt azihsm.masked_key:$maskedkeyfile \
    -pkeyopt azihsm.key_usage:digitalSignature 2>&1)
exit_code=$?
set -e

#CHECK: Error setting group:P-999 parameter
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