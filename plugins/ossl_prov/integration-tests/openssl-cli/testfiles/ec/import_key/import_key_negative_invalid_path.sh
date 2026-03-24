# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
cleanup=$2
maskedkeyfile=./masked_P-$1.bin

# Unset -e and catch error output
set +e
# Try loading a keyfile that does not exist
output=$("$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -outform DER \
    -pkeyopt azihsm.input_key:./not_an_actual_file.bin \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" 2>&1)
exit_code=$?
if [ "$exit_code" -eq 0 ]; then
    echo "FAIL - expected non-zero exit code but got 0" >&2
    exit 1
fi
set -e

#CHECK: Error generating EC key
echo "$output"

#CHECK: PASS - No file created
if [[ -f "$maskedkeyfile" ]]; then
    # Key file was unexpectedly created - this should not have occurred
    echo "FAIL"

    # remove the file in this case
    if [[ "$cleanup" == "true" ]]; then
        rm -f "$maskedkeyfile"
    fi
else 
    # No key file created (expected behaviour)
    echo "PASS - No file created"
fi
