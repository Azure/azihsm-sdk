# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keykind @cleanup

# Exercise sign/verify and encrypt/decrypt against an imported key of an
# explicitly selected form, so both plain RSA and RSA-CRT are covered by a
# cryptographic operation rather than only by their stored metadata.  The rest
# of the RSA suite omits azihsm.key_kind and therefore runs the provider
# default (RSA-CRT); this test pins both forms independently of that default.

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

keykind=$1
cleanup=$2
tag=$(echo "$keykind" | tr '[:upper:]-' '[:lower:]_')

keyfile=./rsa_ops_"$tag"_input.der
masked_sign=./masked_rsa_ops_"$tag"_sign.bin
masked_enc=./masked_rsa_ops_"$tag"_enc.bin
pubkey=./rsa_ops_"$tag"_pub.pem
testdata=./rsa_ops_"$tag"_testdata.bin
signature=./rsa_ops_"$tag".sig
plaintext=./rsa_ops_"$tag"_plain.bin
ciphertext=./rsa_ops_"$tag"_cipher.bin
decrypted=./rsa_ops_"$tag"_decrypted.bin

# The DDI key type stored in the masked blob for each selectable form.
if [[ "$keykind" == "RSA-CRT" ]]; then
    expected_type=4
else
    expected_type=1
fi

# External RSA key (the HSM cannot generate RSA natively)
"$OPENSSL_BIN" genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -outform DER \
    -out "$keyfile"

"$OPENSSL_BIN" pkey -in "$keyfile" -inform DER -pubout -out "$pubkey"

# --- Signing key ---------------------------------------------------------
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt "azihsm.key_kind:$keykind" \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$masked_sign" \
    -outform DER > /dev/null

#CHECK: stored key type matches selection
if [[ "$(masked_key_type "$masked_sign")" == "$expected_type" ]]; then
    echo "stored key type matches selection"
fi

dd if=/dev/urandom of="$testdata" bs=1024 count=1 status=none

# Sign in the HSM through the reloaded masked key.
"$OPENSSL_BIN" pkeyutl \
    -propquery "$PROPQUERY" \
    -sign -rawin -digest sha256 \
    -inkey "azihsm://$masked_sign;type=rsa" \
    -in "$testdata" \
    -out "$signature"

# Verify in software against the input key's public half.
#CHECK: Signature Verified Successfully
"$OPENSSL_BIN" pkeyutl \
    -verify -rawin -digest sha256 \
    -pubin -inkey "$pubkey" \
    -in "$testdata" \
    -sigfile "$signature"

# A tampered message must not verify against the HSM signature.
#CHECK: tampered data rejected
printf 'tampered' >> "$testdata"
if ! "$OPENSSL_BIN" pkeyutl \
    -verify -rawin -digest sha256 \
    -pubin -inkey "$pubkey" \
    -in "$testdata" \
    -sigfile "$signature" > /dev/null 2>&1; then
    echo "tampered data rejected"
fi

# --- Encryption key ------------------------------------------------------
# keyEncipherment gives the private half decrypt rather than sign.
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt azihsm.key_usage:keyEncipherment \
    -pkeyopt "azihsm.key_kind:$keykind" \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$masked_enc" \
    -outform DER > /dev/null

echo -n "azihsm rsa key kind round trip" > "$plaintext"

# Encrypt in software with the public half, decrypt in the HSM.
"$OPENSSL_BIN" pkeyutl -encrypt \
    -pubin -inkey "$pubkey" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -in "$plaintext" \
    -out "$ciphertext"

"$OPENSSL_BIN" pkeyutl -decrypt \
    -propquery "$PROPQUERY" \
    -inkey "azihsm://$masked_enc;type=rsa" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -in "$ciphertext" \
    -out "$decrypted"

#CHECK: decrypted plaintext matches
if cmp -s "$plaintext" "$decrypted"; then
    echo "decrypted plaintext matches"
fi

if [[ "$cleanup" == "true" ]]; then
    rm -f "$keyfile" "$masked_sign" "$masked_enc" "$pubkey" "$testdata" \
        "$signature" "$plaintext" "$ciphertext" "$decrypted"
fi
