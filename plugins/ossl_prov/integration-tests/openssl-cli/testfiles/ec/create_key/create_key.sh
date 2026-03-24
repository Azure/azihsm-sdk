# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @session_bool @usage @cleanup

#CHECK: ==== Key Generation Details ====
#CHECK: provider             : $$provider
#CHECK: algorithm            : $$algo
#CHECK: curve                : P$$curve
#CHECK: session              : $$session
#CHECK: key usage            : $$usage

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
session_bool=$2
usage=$3
cleanup=$4

maskedkeyfile=./masked_P-$1.bin

"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt "azihsm.session:$session_bool" \
    -outform DER \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" \
    -pkeyopt "azihsm.key_usage:$usage" -text


#CHECK: keyfile created
if [[ -f "$maskedkeyfile" && -s "$maskedkeyfile" ]]; then
  echo "keyfile created"
fi

#CHECK: PASS
if [[ "$session_bool" == "false" ]]; then

    output=$("$OPENSSL_BIN" storeutl \
        -propquery "$PROPQUERY" \
        "azihsm://$maskedkeyfile;type=ec" 2>&1)

    if [[ "$output" == *"0: Pkey"* ]] && [[ "$output" == *"Total found: 1"* ]]; then
        echo "PASS"
    else
        echo "FAIL"
        echo "$output"
    fi
else
    echo "PASS"
fi


if [[ "$cleanup" == "true" ]]; then
  rm -f "$maskedkeyfile"
fi
