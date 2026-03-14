# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @algorithm @cleanup 

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keybits=$1
algorithm=$2
cleanup=$3

keyfile=./rsa_pkcs1_encrypt_"$keybits"_key.der
maskedkeyfile=./masked_rsa_pkcs1_encrypt_"$keybits"_"$algorithm"_imported.bin
encrypted_data=encrypted_data_pkcs1_encrypt_"$keybits"_"$algorithm".bin

# Generate external RSA key first (HSM cannot generate RSA keys natively)
"$OPENSSL_BIN" genpkey \
    -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -outform DER \
    -out "$keyfile"

# Import the RSA key into HSM via the provider
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm "$algorithm" \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt azihsm.key_usage:keyEncipherment \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile"

# Use appropriate type based on algorithm
if [[ "$algorithm" == "RSA-PSS" ]]; then
    keytype="rsa-pss"
else
    keytype="rsa"
fi

echo -n "Hello PKCS1" | "$OPENSSL_BIN" pkeyutl \
    -propquery "$PROPQUERY" \
    -encrypt \
    -inkey "azihsm://$maskedkeyfile;type=$keytype" \
    -pkeyopt rsa_padding_mode:pkcs1 \
    -out "$encrypted_data"

# CHECK: data encrypted
if [[ -f "$encrypted_data" && -s "$encrypted_data" ]]; then
  echo "data encrypted"
fi

# CHECK: Hello PKCS1
"$OPENSSL_BIN" pkeyutl \
    -propquery "$PROPQUERY" \
    -decrypt \
    -inkey "azihsm://$maskedkeyfile;type=$keytype" \
    -pkeyopt rsa_padding_mode:pkcs1 \
    -in "$encrypted_data"

if [[ "$cleanup" == "true" ]]; then
  rm -f "$encrypted_data" "$maskedkeyfile" "$keyfile"
fi
