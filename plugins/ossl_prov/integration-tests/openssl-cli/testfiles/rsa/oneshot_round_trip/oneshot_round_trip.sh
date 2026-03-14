# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @algorithm @dgst @cleanup 

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keybits=$1
algorithm=$2
dgst=$3
cleanup=$4
keyfile=./rsa_"$keybits"_key.der
maskedkeyfile=./masked_rsa_"$keybits"_"$algorithm"_imported.bin
testdata=testdata_oneshot_roundtrip_"$keybits"_"$algorithm".bin
testdata_hash=testdata_oneshot_roundtrip_hash."$keybits"_"$algorithm"_"$dgst"
signature=testdata_oneshot_roundtrip.sig."$keybits"_"$algorithm"_"$dgst"

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

#CHECK: keyfile created
if [[ -f "$maskedkeyfile" && -s "$maskedkeyfile" ]]; then
  echo "keyfile created"
fi

# Use appropriate type based on algorithm
if [[ "$algorithm" == "RSA-PSS" ]]; then
    keytype="rsa-pss"
else
    keytype="rsa"
fi

#CHECK: 0: Pkey
#CHECK: Total found: 1

"$OPENSSL_BIN" storeutl \
    -propquery "$PROPQUERY" \
    "azihsm://$maskedkeyfile;type=$keytype"

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

# Pre-hash the data with different algorithms
"$OPENSSL_BIN" dgst -"$dgst" -binary -out "$testdata_hash" "$testdata"

# Sign pre-hashed data
"$OPENSSL_BIN" pkeyutl -sign \
    -propquery "$PROPQUERY" \
    -inkey "azihsm://$maskedkeyfile;type=$keytype" \
    -pkeyopt digest:"$dgst" \
    -in "$testdata_hash" \
    -out "$signature"

# CHECK: file signed
if [[ -f "$signature" && -s "$signature" ]]; then
  echo "file signed"
fi

# CHECK: Signature Verified Successfully
"$OPENSSL_BIN" pkeyutl -verify \
    -propquery "$PROPQUERY" \
    -inkey "azihsm://$maskedkeyfile;type=$keytype" \
    -pkeyopt digest:"$dgst" \
    -in "$testdata_hash" \
    -sigfile "$signature"

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$testdata_hash" "$signature" "$maskedkeyfile" "$keyfile"
fi
