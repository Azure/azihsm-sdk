# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @algorithm @dgst @cleanup 

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keybits=$1
algorithm=$2
dgst=$3
cleanup=$4
keyfile=./rsa_"$keybits"_key.der
maskedkeyfile=./masked_rsa_tampered_"$keybits"_"$algorithm"_imported.bin
testdata=testdata_tampered_"$keybits"_"$algorithm".bin
testdata_tampered=tampereddata_tampered_"$keybits"_"$algorithm".bin
signature=testdata_tampered.sig."$keybits"_"$algorithm"_"$dgst"

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

# Create test signature
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -sign "azihsm://$maskedkeyfile;type=$keytype" \
    -out "$signature" \
    "$testdata"

# Tamper with the data
cp "$testdata" "$testdata_tampered"
echo "tampered" >> "$testdata_tampered"

# Verification should fail — use || true so -e doesn't abort the script
#CHECK: Verification failure
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -verify "azihsm://$maskedkeyfile;type=$keytype" \
    -signature "$signature" \
    "$testdata_tampered" || true

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$testdata_tampered" "$signature" "$maskedkeyfile" "$keyfile"
fi
