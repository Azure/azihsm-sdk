# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

cleanup=$1
keyfile=./rsa_key_type_input.der
masked_auto=./masked_rsa_key_type_auto.bin
masked_plain=./masked_rsa_key_type_plain.bin
masked_wrapped=./masked_rsa_key_type_wrapped.bin
wrapping_pub=./rsa_key_type_wrapping_pub.pem
kek_bin=./rsa_key_type_kek.bin
encrypted_kek=./rsa_key_type_encrypted_kek.bin
wrapped_payload=./rsa_key_type_wrapped_payload.bin
wrapped_blob=./rsa_key_type_wrapped.bin
testdata=./rsa_key_type_testdata.bin
signature=./rsa_key_type.sig
pubkey=./rsa_key_type_pub.pem

# The masked key blob metadata is plaintext: a 4-byte header, a 48-byte AES
# header (iv_len and post_iv_pad_len as LE u16 at offsets 4 and 6), the IV,
# padding, then the MBOR-encoded metadata whose second field (bytes 15..18,
# big-endian u32) is the DDI key type: 1 = RSA 2K private, 4 = RSA 2K
# private CRT.
masked_key_type() {
    local iv_len post_iv md_start
    iv_len=$(od -An -tu2 -j4 -N2 "$1" | tr -d ' ')
    post_iv=$(od -An -tu2 -j6 -N2 "$1" | tr -d ' ')
    md_start=$((4 + 48 + iv_len + post_iv))
    od -An -tu1 -j$((md_start + 18)) -N1 "$1" | tr -d ' '
}

# Generate an external RSA key; standard generation carries CRT components
"$OPENSSL_BIN" genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -outform DER \
    -out "$keyfile"

# Import without azihsm.key_type: the CRT form is auto-detected
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$masked_auto" \
    -outform DER > /dev/null

#CHECK: auto-detected key type: 4
echo "auto-detected key type: $(masked_key_type "$masked_auto")"

# Import with azihsm.key_type:rsa: forces the plain RSA form
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt azihsm.key_type:rsa \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -pkeyopt "azihsm.masked_key:$masked_plain" \
    -outform DER > /dev/null

#CHECK: forced-plain key type: 1
echo "forced-plain key type: $(masked_key_type "$masked_plain")"

# The masked CRT key must reload via store and sign; verify against the
# input key's public half using the default provider
echo "sign me" > "$testdata"
"$OPENSSL_BIN" pkeyutl \
    -propquery "$PROPQUERY" \
    -sign -rawin -digest sha256 \
    -inkey "azihsm://$masked_auto;type=rsa" \
    -in "$testdata" \
    -out "$signature"

"$OPENSSL_BIN" pkey -in "$keyfile" -inform DER -pubout -out "$pubkey"

#CHECK: Signature Verified Successfully
"$OPENSSL_BIN" pkeyutl \
    -verify -rawin -digest sha256 \
    -pubin -inkey "$pubkey" \
    -in "$testdata" \
    -sigfile "$signature"

# Wrapped-key import: the blob is opaque, so azihsm.key_type:rsa-crt
# declares the CRT form (RSA-AES Key Wrap as in import_wrapped_key.sh)
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm RSA \
    -pkeyopt azihsm.key_usage:keyWrapping \
    -outform PEM \
    -out "$wrapping_pub"

"$OPENSSL_BIN" rand 32 > "$kek_bin"

"$OPENSSL_BIN" enc -id-aes256-wrap-pad \
    -e \
    -K "$(xxd -p -c 256 "$kek_bin")" \
    -iv "A65959A6" \
    -in "$keyfile" \
    -out "$wrapped_payload" \
    -nopad

"$OPENSSL_BIN" pkeyutl -encrypt \
    -pubin -inkey "$wrapping_pub" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -in "$kek_bin" \
    -out "$encrypted_kek"

cat "$encrypted_kek" "$wrapped_payload" > "$wrapped_blob"

"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt azihsm.key_type:rsa-crt \
    -pkeyopt "azihsm.wrapped_key:$wrapped_blob" \
    -pkeyopt "azihsm.masked_key:$masked_wrapped" \
    -outform DER > /dev/null

#CHECK: wrapped-import key type: 4
echo "wrapped-import key type: $(masked_key_type "$masked_wrapped")"

# An unknown azihsm.key_type value must be rejected
#CHECK: invalid key type rejected
if ! "$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm RSA \
    -pkeyopt azihsm.key_type:bogus \
    -pkeyopt "azihsm.input_key:$keyfile" \
    -outform DER > /dev/null 2>&1; then
    echo "invalid key type rejected"
fi

if [[ "$cleanup" == "true" ]]; then
    rm -f "$keyfile" "$masked_auto" "$masked_plain" "$masked_wrapped" \
        "$wrapping_pub" "$kek_bin" "$encrypted_kek" "$wrapped_payload" \
        "$wrapped_blob" "$testdata" "$signature" "$pubkey"
fi
