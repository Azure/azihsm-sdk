# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keybits=$1
dgst=$2
cleanup=$3
keyfile=./rsa_pss_defpad_"$keybits"_key.der
maskedkeyfile=./masked_rsa_pss_defpad_"$keybits"_imported.bin
testdata=testdata_pss_defpad_"$keybits".bin
signature=testdata_pss_defpad.sig."$keybits"_"$dgst"

# Generate external RSA key first (HSM cannot generate RSA keys natively)
"$OPENSSL_BIN" genpkey \
    -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -outform DER \
    -out "$keyfile"

# Import the RSA key into HSM via the provider as RSA-PSS
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm rsa-pss \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile"

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

# Sign without explicit padding options (PSS key auto-selects PSS padding)
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -sign "azihsm://$maskedkeyfile;type=rsa-pss" \
    -out "$signature" \
    "$testdata"

# CHECK: file signed
if [[ -f "$signature" && -s "$signature" ]]; then
  echo "file signed"
fi

#CHECK: Verified OK
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -verify "azihsm://$maskedkeyfile;type=rsa-pss" \
    -signature "$signature" \
    "$testdata"

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$signature" "$maskedkeyfile" "$keyfile"
fi
