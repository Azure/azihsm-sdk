# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @saltlength @dgst @explicit_mgfone @cleanup 

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keybits=$1
saltlength=$2
dgst=$3
explicit_mgf1=$4
cleanup=$5
keyfile=./rsa_"$keybits"_key.der
maskedkeyfile=./masked_rsa_verify_"$keybits"_"rsa-pss"_imported.bin
testdata=testdata_verify_"$keybits"_rsa-pss_"$saltlength".bin
signature=testdata_verify.sig."$keybits"_rsa-pss_"$saltlength"_"$dgst"

if [[ "$explicit_mgf1" == "true" ]]; then
    mgf1="-sigopt rsa_mgf1_md:$dgst"
else
    mgf1=""
fi

# Generate external RSA key first (HSM cannot generate RSA keys natively)
"$OPENSSL_BIN" genpkey \
    -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -outform DER \
    -out "$keyfile"

# Import the RSA key into HSM via the provider
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm rsa \
    -pkeyopt "rsa_keygen_bits:$keybits" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile"

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -sigopt rsa_padding_mode:pss \
    -sigopt "rsa_pss_saltlen:$saltlength" \
    $mgf1 \
    -sign "azihsm://$maskedkeyfile;type=rsa" \
    -out "$signature" \
    "$testdata"

#CHECK: Verified OK
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -sigopt rsa_padding_mode:pss \
    -sigopt "rsa_pss_saltlen:$saltlength" \
    $mgf1 \
    -verify "azihsm://$maskedkeyfile;type=rsa" \
    -signature "$signature" \
    "$testdata"

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata" "$signature" "$maskedkeyfile" "$keyfile"
fi
