# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @session_bool @usage @cleanup

#CHECK: ==== Key Generation Details ====
#CHECK: provider             : $$provider
#CHECK: algorithm            : $$algo
#CHECK: curve                : P$$curve
#CHECK: session              : $$session
#CHECK: key usage            : $$usage

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

curve=P-$1
session_bool=$2
usage=$3
cleanup=$4

maskedkeyfile=./masked_P-$1.bin

"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt group:$curve \
    -pkeyopt azihsm.session:$session_bool \
    -outform DER \
    -pkeyopt azihsm.masked_key:$maskedkeyfile \
    -pkeyopt azihsm.key_usage:$usage -text


#CHECK: keyfile created
if [[ -f $maskedkeyfile && -s $maskedkeyfile ]]; then
  echo "keyfile created"
fi

#CHECK: PASS
if [[ "$session_bool" == "false" ]]; then

    output=$("$OPENSSL_BIN" storeutl \
        -provider-path "$PROVIDER_PATH" \
        -provider default \
        -provider azihsm_provider \
        -propquery "$PROPQUERY" \
        "azihsm://"$maskedkeyfile";type=ec" 2>&1)

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
  rm $maskedkeyfile
fi
