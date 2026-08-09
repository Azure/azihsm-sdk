# RUN: @bash -ea @file
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# For each supported curve (with its conventional digest): stage a masked EC
# key blob, sign through the engine (HSM ECDSA), and verify the signatures in
# software with the extracted public key. Covers both sign entry points:
# hash-and-sign (dgst -sign -> EVP_DigestSign) and pre-hashed
# (pkeyutl -sign -> EVP_PKEY_sign).
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

for pair in "p256 sha256" "p384 sha384" "p521 sha512"; do
    read -r curve md <<< "$pair"
    blob="$KEYDIR/ec_sign_key_$curve.bin"
    msg="$KEYDIR/sign_msg_$curve.txt"
    pub="$KEYDIR/sign_pub_$curve.pem"
    sig="$KEYDIR/sign_sig_$curve.bin"
    digest="$KEYDIR/sign_digest_$curve.bin"
    psig="$KEYDIR/sign_pkeyutl_sig_$curve.bin"
    rm -f "$blob" "$msg" "$msg.tampered" "$pub" "$sig" "$digest" "$psig"

    uri="azihsm://$blob;type=ec"

    # Generate the masked blob out-of-process (shares the keymat set above).
    "$MASKED_KEYGEN" "$blob" "$curve"

    printf 'engine ecdsa signing over the CLI path (%s)' "$curve" > "$msg"

    # Extract the public half in a software-verifiable form.
    "$OPENSSL_BIN" pkey -engine azihsm -inform engine -in "$uri" -pubout -out "$pub"

    # Hash-and-sign through the engine (EVP_DigestSign -> the engine's
    # sign_sig -> HSM), then verify in software (no engine): proves the HSM
    # signed the digest with the key matching the public half.
    "$OPENSSL_BIN" dgst "-$md" -engine azihsm -keyform engine -sign "$uri" \
        -out "$sig" "$msg"
    "$OPENSSL_BIN" dgst "-$md" -verify "$pub" -signature "$sig" "$msg"

    # Pre-hashed path: sign the raw digest via pkeyutl (EVP_PKEY_sign), then
    # verify it in software.
    "$OPENSSL_BIN" dgst "-$md" -binary -out "$digest" "$msg"
    "$OPENSSL_BIN" pkeyutl -sign -engine azihsm -keyform engine -inkey "$uri" \
        -in "$digest" -out "$psig"
    "$OPENSSL_BIN" pkeyutl -verify -pubin -inkey "$pub" -sigfile "$psig" \
        -in "$digest"

    # A tampered message must fail verification.
    printf 'engine ecdsa signing over the CLI path (%s)?' "$curve" > "$msg.tampered"
    if "$OPENSSL_BIN" dgst "-$md" -verify "$pub" -signature "$sig" "$msg.tampered"; then
        echo "tampered message unexpectedly verified: $curve"
        exit 1
    fi
    echo "sign round trip ok: $curve"
done

# CHECK: sign round trip ok: p256
# CHECK: sign round trip ok: p384
# CHECK: sign round trip ok: p521
