# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @algorithm @cleanup 

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keybits=$1
algorithm=$2
cleanup=$3
keyfile=./rsa_"$keybits"_key.der
maskedkeyfile=./masked_rsa_"$keybits"_"$algorithm"_imported.bin

# Generate external RSA key first (HSM cannot generate RSA keys natively)
"$OPENSSL_BIN" genpkey \
    -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -outform DER \
    -out "$keyfile"

# Import the RSA key into HSM via the provider
"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -algorithm "$algorithm" \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile"

#CHECK: keyfile created
if [[ -f "$maskedkeyfile" && -s "$maskedkeyfile" ]]; then
  echo "keyfile created"
fi

# Verify the masked key can be loaded via store
# Use appropriate type based on algorithm
if [[ "$algorithm" == "RSA-PSS" ]]; then
    keytype="rsa-pss"
else
    keytype="rsa"
fi


#CHECK: 0: Pkey
#CHECK: Total found: 1

"$OPENSSL_BIN" storeutl \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    "azihsm://$maskedkeyfile;type=$keytype"

if [[ "$cleanup" == "true" ]]; then
    rm -f "$keyfile" "$maskedkeyfile"
fi