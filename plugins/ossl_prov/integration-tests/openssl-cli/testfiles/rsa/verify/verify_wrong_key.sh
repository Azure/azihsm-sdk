# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @algorithm @dgst @cleanup 

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keybits=$1
algorithm=$2
dgst=$3
cleanup=$4
keyfile=./wrongkey_rsa_"$keybits"_goodkey.der
wrongkey=./wrongkey_rsa_"$keybits"_wrongkey.der
maskedkeyfile=./wrongkey_masked_rsa_"$keybits"_"$algorithm"_imported.bin
wrongkeyfile=./wrongkey_masked_rsa_"$keybits"_"$algorithm"_imported_wrong.bin
testdata=testdata_wrongkey_"$keybits"_"$algorithm".bin
signature=testdata_wrongkey.sig."$keybits"_"$algorithm"_"$dgst"

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
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile"

# Use appropriate type based on algorithm
if [[ "$algorithm" == "RSA-PSS" ]]; then
    keytype="rsa-pss"
else
    keytype="rsa"
fi

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

# Sign test data
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -sign "azihsm://$maskedkeyfile;type=$keytype" \
    -out "$signature" \
    "$testdata"

# Generate and import a fresh key that wont work
"$OPENSSL_BIN" genpkey \
    -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -outform DER \
    -out "$wrongkey"

"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm "$algorithm" \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt "azihsm.input_key:$wrongkey" \
    -pkeyopt "azihsm.masked_key:$wrongkeyfile"

# Verification should fail — use || true so -e doesn't abort the script
#CHECK: Verification failure
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -verify "azihsm://$wrongkeyfile;type=$keytype" \
    -signature "$signature" \
    "$testdata" || true

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$signature" "$maskedkeyfile" "$keyfile" "$wrongkey" "$wrongkeyfile"
fi
