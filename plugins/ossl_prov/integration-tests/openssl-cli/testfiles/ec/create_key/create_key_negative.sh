# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @session_bool @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-999
session_bool=$2
maskedkeyfile=./masked_errorkey_"$curve".bin
cleanup=$3

set +e

output=$("$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt "azihsm.session:$session_bool" \
    -outform DER \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" \
    -pkeyopt azihsm.key_usage:digitalSignature 2>&1)
exit_code=$?
if [ "$exit_code" -eq 0 ]; then
    echo "FAIL - expected non-zero exit code but got 0" >&2
    exit 1
fi
set -e

#CHECK: Error setting group:P-999 parameter
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