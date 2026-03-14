# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @algorithm @cleanup 

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keybits=$1
algorithm=$2
cleanup=$3
keyfile=./no_file_there.der
maskedkeyfile=./should_not_exist_rsa_"$keybits"_"$algorithm"_imported.bin

# Unset -e and catch error output
set +e
# Try loading a keyfile that does not exist
output=$("$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm "$algorithm" \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -pkeyopt azihsm.session:false \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" 2>&1)
exit_code=$?
if [ "$exit_code" -eq 0 ]; then
    echo "FAIL - expected non-zero exit code but got 0" >&2
    exit 1
fi
set -e

#CHECK: Error generating $$algorithm key
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

