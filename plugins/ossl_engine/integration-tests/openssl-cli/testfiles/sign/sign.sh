# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Stage a masked EC key blob, sign through the engine (HSM ECDSA), and verify
# the signatures in software with the extracted public key. Covers both sign
# entry points: hash-and-sign (dgst -sign -> EVP_DigestSign) and pre-hashed
# (pkeyutl -sign -> EVP_PKEY_sign).
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

blob="$KEYDIR/ec_sign_key.bin"
msg="$KEYDIR/sign_msg.txt"
pub="$KEYDIR/sign_pub.pem"
sig="$KEYDIR/sign_sig.bin"
digest="$KEYDIR/sign_digest.bin"
psig="$KEYDIR/sign_pkeyutl_sig.bin"
rm -f "$blob" "$msg" "$msg.tampered" "$pub" "$sig" "$digest" "$psig"

uri="azihsm://$blob;type=ec"

# Generate the masked blob out-of-process (shares the keymat set above).
"$MASKED_KEYGEN" "$blob"

printf 'engine ecdsa signing over the CLI path' > "$msg"

# Extract the public half in a software-verifiable form.
"$OPENSSL_BIN" pkey -engine azihsm -inform engine -in "$uri" -pubout -out "$pub"

# Hash-and-sign through the engine (EVP_DigestSign -> the engine's sign_sig ->
# HSM), then verify in software (no engine): proves the HSM signed the digest
# with the key matching the public half.
"$OPENSSL_BIN" dgst -sha384 -engine azihsm -keyform engine -sign "$uri" -out "$sig" "$msg"
"$OPENSSL_BIN" dgst -sha384 -verify "$pub" -signature "$sig" "$msg"
# CHECK: Verified OK

# Pre-hashed path: sign the raw SHA-384 digest via pkeyutl (EVP_PKEY_sign),
# then verify it in software.
"$OPENSSL_BIN" dgst -sha384 -binary -out "$digest" "$msg"
"$OPENSSL_BIN" pkeyutl -sign -engine azihsm -keyform engine -inkey "$uri" \
    -in "$digest" -out "$psig"
"$OPENSSL_BIN" pkeyutl -verify -pubin -inkey "$pub" -sigfile "$psig" -in "$digest"
# CHECK: Signature Verified Successfully

# A tampered message must fail verification.
printf 'engine ecdsa signing over the CLI path?' > "$msg.tampered"
if "$OPENSSL_BIN" dgst -sha384 -verify "$pub" -signature "$sig" "$msg.tampered"; then
    echo "tampered message unexpectedly verified"
    exit 1
else
    echo "tampered message rejected"
fi
# CHECK: tampered message rejected
