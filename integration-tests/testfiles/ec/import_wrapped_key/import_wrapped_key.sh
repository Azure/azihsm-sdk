# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
dgst=$2
cleanup=$3
wrapping_pub=./wrapping_pub_"$curve".pem
keyfile_pem=./ec_"$curve"_to_wrap.pem
wrapped_blob=./wrapped_ec_"$curve".bin
maskedkeyfile=./masked_"$curve"_wrapped_import.bin
testdata=./testdata_wrapped_"$curve".bin
signature=./signature_wrapped_"$curve"_"$dgst".sig
pkcs8_der=./ec_"$curve"_pkcs8.der
kek_bin=./kek_ec_"$curve".bin
encrypted_kek=./encrypted_kek_ec_"$curve".bin
wrapped_payload=./wrapped_payload_ec_"$curve".bin

# Step 1: Export the HSM's RSA wrapping public key
"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -algorithm RSA \
    -pkeyopt azihsm.key_usage:keyWrapping \
    -outform PEM \
    -out "$wrapping_pub"

#CHECK: wrapping key exported
if [[ -f "$wrapping_pub" && -s "$wrapping_pub" ]]; then
    echo "wrapping key exported"
fi

# Step 2: Generate an external EC key
"$OPENSSL_BIN" genpkey \
    -algorithm EC \
    -pkeyopt "ec_paramgen_curve:$curve" \
    -out "$keyfile_pem"

# Step 3: Wrap the key using RSA-AES Key Wrap (RSA-OAEP + AES-KWP)
# 3a: Normalize to PKCS#8 DER
"$OPENSSL_BIN" pkcs8 -topk8 -nocrypt -in "$keyfile_pem" -outform DER -out "$pkcs8_der"

# 3b: Generate random 256-bit AES KEK
"$OPENSSL_BIN" rand 32 > "$kek_bin"

# 3c: AES-KWP wrap the PKCS#8 key with the KEK (RFC 5649)
"$OPENSSL_BIN" enc -id-aes256-wrap-pad \
    -e \
    -K "$(xxd -p -c 256 "$kek_bin")" \
    -iv "A65959A6" \
    -in "$pkcs8_der" \
    -out "$wrapped_payload" \
    -nopad

# 3d: RSA-OAEP encrypt the KEK with the wrapping public key
"$OPENSSL_BIN" pkeyutl -encrypt \
    -pubin -inkey "$wrapping_pub" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -in "$kek_bin" \
    -out "$encrypted_kek"

# 3e: Concatenate [encrypted KEK] || [AES-KWP wrapped key]
cat "$encrypted_kek" "$wrapped_payload" > "$wrapped_blob"

#CHECK: wrapped key created
if [[ -f "$wrapped_blob" && -s "$wrapped_blob" ]]; then
    echo "wrapped key created"
fi

# Step 4: Import the wrapped key into HSM
"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt "azihsm.wrapped_key:$wrapped_blob" \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" \
    -outform DER \
    -out /dev/null

#CHECK: masked key created
if [[ -f "$maskedkeyfile" && -s "$maskedkeyfile" ]]; then
    echo "masked key created"
fi

# Step 5: Verify the masked key can be loaded via store
#CHECK: 0: Pkey
#CHECK: Total found: 1

"$OPENSSL_BIN" storeutl \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    "azihsm://$maskedkeyfile;type=ec"

# Step 6: Sign with the imported key
dd if=/dev/urandom of="$testdata" bs=1024 count=1 2>/dev/null

"$OPENSSL_BIN" dgst -"$dgst" \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -sign "azihsm://$maskedkeyfile;type=ec" \
    -out "$signature" \
    "$testdata"

#CHECK: file signed
if [[ -f "$signature" && -s "$signature" ]]; then
    echo "file signed"
fi

# Step 7: Verify the signature
#CHECK: Verified OK

"$OPENSSL_BIN" dgst -"$dgst" \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -verify "azihsm://$maskedkeyfile;type=ec" \
    -signature "$signature" \
    "$testdata"

if [[ "$cleanup" == "true" ]]; then
    rm -f "$wrapping_pub" "$keyfile_pem" "$wrapped_blob" "$maskedkeyfile" \
          "$testdata" "$signature" "$pkcs8_der" "$kek_bin" "$encrypted_kek" \
          "$wrapped_payload"
fi
