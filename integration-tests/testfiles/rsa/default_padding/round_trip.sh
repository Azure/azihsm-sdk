# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keybits=$1
dgst=$2
cleanup=$3
keyfile=./rsa_defpad_"$keybits"_key.der
maskedkeyfile=./masked_rsa_defpad_"$keybits"_imported.bin
testdata=testdata_defpad_"$keybits".bin
signature=testdata_defpad.sig."$keybits"_"$dgst"

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
    -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile"

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

# Sign without explicit padding options (defaults to PKCS#1 v1.5)
"$OPENSSL_BIN" dgst -"$dgst" \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -sign "azihsm://$maskedkeyfile;type=rsa" \
    -out "$signature" \
    "$testdata"

# CHECK: file signed
if [[ -f "$signature" && -s "$signature" ]]; then
  echo "file signed"
fi

#CHECK: Verified OK
"$OPENSSL_BIN" dgst -"$dgst" \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -verify "azihsm://$maskedkeyfile;type=rsa" \
    -signature "$signature" \
    "$testdata"

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$signature" "$maskedkeyfile" "$keyfile"
fi
