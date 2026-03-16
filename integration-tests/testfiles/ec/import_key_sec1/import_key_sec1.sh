# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @sec_one @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
sec_one=$2
cleanup=$3
keyfile=./ec_"$curve".der
maskedkeyfile=./masked_"$curve"_imported.bin


# Generate SEC1 DER key
"$OPENSSL_BIN" ecparam \
    -genkey -name "$sec_one" \
    -outform DER \
    -out "$keyfile"

"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
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
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    "azihsm://$maskedkeyfile;type=ec"

if [[ "$cleanup" == "true" ]]; then
    rm -f "$keyfile" "$maskedkeyfile"
fi
