# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# RSA decryption over the real CLI path: import an external software RSA key into
# the HSM with keyEncipherment usage (`genpkey -engine azihsm -algorithm RSA
# -pkeyopt azihsm.key_usage:keyEncipherment -pkeyopt azihsm.input_key`), load the
# masked blob through `ENGINE_load_private_key` (`azihsm://<blob>;type=rsa`), then
# decrypt with it on the HSM. Decryption reaches the engine's RSA EVP_PKEY_METHOD
# decrypt override via the standard asym-cipher parameters (rsa_padding_mode:oaep
# / pkcs1, rsa_oaep_md, rsa_mgf1_md, rsa_oaep_label); the HSM performs the raw
# private-key operation and the SDK removes the padding.
#
# Ciphertexts are produced in software (no engine) with the public half extracted
# through the engine — proving the loaded key decrypts what its public half
# encrypts. Covers OAEP across SHA-256/384/512, OAEP with a label, PKCS#1 v1.5,
# and a tampered-ciphertext negative check.
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

swpem="$KEYDIR/rsa_dec_sw.pem"
input="$KEYDIR/rsa_dec_input.der"
blob="$KEYDIR/rsa_dec_key.bin"
msg="$KEYDIR/rsa_dec_msg.txt"
pub="$KEYDIR/rsa_dec_pub.pem"
rm -f "$KEYDIR"/rsa_dec_*

uri="azihsm://$blob;type=rsa"

# External software RSA-2048 key, normalized to unencrypted PKCS#8 DER.
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$swpem"
"$OPENSSL_BIN" pkcs8 -topk8 -nocrypt -in "$swpem" -outform DER -out "$input"

# Import into the HSM with keyEncipherment usage (so the private half can decrypt),
# writing the masked blob.
"$OPENSSL_BIN" genpkey -engine azihsm -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:2048" \
    -pkeyopt "azihsm.input_key:$input" \
    -pkeyopt "azihsm.masked_key:$blob" \
    -pkeyopt "azihsm.key_kind:RSA-CRT" \
    -pkeyopt "azihsm.key_usage:keyEncipherment" || true
test -s "$blob"

printf 'engine rsa decryption over the CLI path' > "$msg"

# Public half through the engine load path, in a software-encryptable form.
"$OPENSSL_BIN" pkey -engine azihsm -inform engine -in "$uri" -pubout -out "$pub"

# OAEP across each supported digest: encrypt in software with the public half,
# decrypt on the HSM through the engine, and compare.
for md in sha256 sha384 sha512; do
    ct="$KEYDIR/rsa_dec_${md}.ct"
    pt="$KEYDIR/rsa_dec_${md}.pt"
    "$OPENSSL_BIN" pkeyutl -encrypt -pubin -inkey "$pub" \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt "rsa_oaep_md:$md" -pkeyopt "rsa_mgf1_md:$md" \
        -in "$msg" -out "$ct"
    "$OPENSSL_BIN" pkeyutl -decrypt -engine azihsm -keyform engine -inkey "$uri" \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt "rsa_oaep_md:$md" -pkeyopt "rsa_mgf1_md:$md" \
        -in "$ct" -out "$pt"
    cmp -s "$msg" "$pt" || { echo "OAEP $md decryption mismatch"; exit 1; }
done

# OAEP with an explicit label (SHA-256).
lct="$KEYDIR/rsa_dec_label.ct"
lpt="$KEYDIR/rsa_dec_label.pt"
label="00010203deadbeef"
"$OPENSSL_BIN" pkeyutl -encrypt -pubin -inkey "$pub" \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt "rsa_oaep_label:$label" \
    -in "$msg" -out "$lct"
"$OPENSSL_BIN" pkeyutl -decrypt -engine azihsm -keyform engine -inkey "$uri" \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt "rsa_oaep_label:$label" \
    -in "$lct" -out "$lpt"
cmp -s "$msg" "$lpt" || { echo "OAEP label decryption mismatch"; exit 1; }

# PKCS#1 v1.5.
pct="$KEYDIR/rsa_dec_pkcs1.ct"
ppt="$KEYDIR/rsa_dec_pkcs1.pt"
"$OPENSSL_BIN" pkeyutl -encrypt -pubin -inkey "$pub" \
    -pkeyopt rsa_padding_mode:pkcs1 -in "$msg" -out "$pct"
"$OPENSSL_BIN" pkeyutl -decrypt -engine azihsm -keyform engine -inkey "$uri" \
    -pkeyopt rsa_padding_mode:pkcs1 -in "$pct" -out "$ppt"
cmp -s "$msg" "$ppt" || { echo "PKCS#1 v1.5 decryption mismatch"; exit 1; }

# A tampered OAEP ciphertext must fail to decrypt. Flip the first byte (XOR 0xff)
# so the change is guaranteed regardless of its value, while preserving length.
bad="$KEYDIR/rsa_dec_bad.ct"
cp "$KEYDIR/rsa_dec_sha256.ct" "$bad"
b0=$(od -An -tu1 -N1 "$bad" | tr -d ' ')
printf "$(printf '\\%03o' $((b0 ^ 0xff)))" | dd of="$bad" bs=1 seek=0 count=1 conv=notrunc status=none
if "$OPENSSL_BIN" pkeyutl -decrypt -engine azihsm -keyform engine -inkey "$uri" \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -in "$bad" -out /dev/null 2>/dev/null; then
    echo "tampered ciphertext unexpectedly decrypted"
    exit 1
fi
echo "rsa decrypt round trip ok"

# CHECK: rsa decrypt round trip ok
