# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @sec_one @cleanup

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

curve=P-$1
sec_one=$2
cleanup=$3
keyfile=./ec_"$curve".der
maskedkeyfile=./masked_"$curve".bin


# Generate SEC1 DER key
"$OPENSSL_BIN" ecparam \
    -genkey -name "$sec_one" \
    -outform DER \
    -out "$keyfile"

"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -outform DER \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile"

#CHECK: keyfile created
if [[ -f "$maskedkeyfile" && -s "$maskedkeyfile" ]]; then
  echo "keyfile created"
fi

#CHECK: 0: Pkey
#CHECK: Total found: 1

"$OPENSSL_BIN" storeutl \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    "azihsm://$maskedkeyfile;type=ec"

if [[ "$cleanup" == "true" ]]; then
    rm "$keyfile"
    rm "$maskedkeyfile"
fi
