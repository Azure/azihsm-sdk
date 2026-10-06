# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# RSA-PSS signing over the real CLI path, across all supported digests: import an
# external software RSA key into the HSM (`genpkey -engine azihsm -algorithm RSA
# -pkeyopt azihsm.input_key`), load the written masked blob through
# `ENGINE_load_private_key` (`azihsm://<blob>;type=rsa`), then PSS-sign with it.
# PSS reaches the engine's RSA EVP_PKEY_METHOD sign override via the standard
# signature parameters (rsa_padding_mode:pss, rsa_pss_saltlen, rsa_mgf1_md); the
# SDK builds the EMSA-PSS block host-side (MGF1 = signing digest) and the HSM
# performs the raw private-key operation. Signatures are verified in software (no
# engine) against the public half extracted through the engine.
#
# Covers both sign entry points — dgst -sign (EVP_DigestSign) and pkeyutl -sign
# (EVP_PKEY_sign) — for SHA-256/384/512, across salt lengths unset (= digest
# default), digest, explicit, and max, with an explicit rsa_pss_saltlen:auto
# rejected (matching the provider), a matching MGF1 accepted and a mismatched
# MGF1 rejected, zero-size signing (an empty message signs; a zero-length
# pre-hashed digest is rejected), plus a tampered-message negative check.
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

swpem="$KEYDIR/rsa_pss_sw.pem"
input="$KEYDIR/rsa_pss_input.der"
blob="$KEYDIR/rsa_pss_key.bin"
msg="$KEYDIR/rsa_pss_msg.txt"
pub="$KEYDIR/rsa_pss_pub.pem"
rm -f "$KEYDIR"/rsa_pss_*

uri="azihsm://$blob;type=rsa"

# External software RSA-2048 key, normalized to unencrypted PKCS#8 DER.
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$swpem"
"$OPENSSL_BIN" pkcs8 -topk8 -nocrypt -in "$swpem" -outform DER -out "$input"

# Import into the HSM, writing the masked blob (genpkey refuses to serialize the
# HSM private key afterwards — the blob is the persistent private form).
"$OPENSSL_BIN" genpkey -engine azihsm -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:2048" \
    -pkeyopt "azihsm.input_key:$input" \
    -pkeyopt "azihsm.masked_key:$blob" \
    -pkeyopt "azihsm.key_kind:RSA-CRT" || true
test -s "$blob"

printf 'engine rsa-pss signing over the CLI path' > "$msg"

# Public half through the engine load path, in a software-verifiable form.
"$OPENSSL_BIN" pkey -engine azihsm -inform engine -in "$uri" -pubout -out "$pub"

# Sign + software-verify under each supported digest, via both entry points and
# both the digest-default and max salt lengths (exercises per-digest size and
# HSM-parameter handling, not just the NID mapping).
for md in sha256 sha384 sha512; do
    sig="$KEYDIR/rsa_pss_${md}.sig"
    psig="$KEYDIR/rsa_pss_${md}_pkeyutl.sig"
    msig="$KEYDIR/rsa_pss_${md}_max.sig"
    dg="$KEYDIR/rsa_pss_${md}.dig"

    # dgst PSS sign (salt = digest length).
    "$OPENSSL_BIN" dgst "-$md" -engine azihsm -keyform engine \
        -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
        -sign "$uri" -out "$sig" "$msg"
    "$OPENSSL_BIN" dgst "-$md" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
        -verify "$pub" -signature "$sig" "$msg"

    # pkeyutl PSS sign (pre-hashed, salt = digest length).
    "$OPENSSL_BIN" dgst "-$md" -binary -out "$dg" "$msg"
    "$OPENSSL_BIN" pkeyutl -sign -engine azihsm -keyform engine -inkey "$uri" \
        -pkeyopt "digest:$md" -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:digest \
        -in "$dg" -out "$psig"
    "$OPENSSL_BIN" pkeyutl -verify -pubin -inkey "$pub" \
        -pkeyopt "digest:$md" -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:digest \
        -sigfile "$psig" -in "$dg"

    # dgst PSS sign (salt = max = modulus - digest - 2).
    "$OPENSSL_BIN" dgst "-$md" -engine azihsm -keyform engine \
        -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:max \
        -sign "$uri" -out "$msig" "$msg"
    "$OPENSSL_BIN" dgst "-$md" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:max \
        -verify "$pub" -signature "$msig" "$msg"
done

# Explicit salt length distinct from SHA-256's 32-byte digest default, so this
# covers the explicit path (not the digest default).
esig="$KEYDIR/rsa_pss_explicit.sig"
"$OPENSSL_BIN" dgst -sha256 -engine azihsm -keyform engine \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 \
    -sign "$uri" -out "$esig" "$msg"
"$OPENSSL_BIN" dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 \
    -verify "$pub" -signature "$esig" "$msg"

# An explicit MGF1 digest equal to the signing digest is accepted.
gsig="$KEYDIR/rsa_pss_mgf1.sig"
"$OPENSSL_BIN" dgst -sha256 -engine azihsm -keyform engine \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256 \
    -sign "$uri" -out "$gsig" "$msg"
"$OPENSSL_BIN" dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -sigopt rsa_mgf1_md:sha256 -verify "$pub" -signature "$gsig" "$msg"

# A MGF1 digest different from the signing digest must be rejected: the HSM PSS
# padding uses one hash for both.
if "$OPENSSL_BIN" dgst -sha256 -engine azihsm -keyform engine \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha512 \
    -sign "$uri" -out /dev/null "$msg" 2>/dev/null; then
    echo "mismatched MGF1 digest unexpectedly accepted"
    exit 1
fi

# An unset salt length defaults to the digest length (the provider's default).
dsig="$KEYDIR/rsa_pss_default.sig"
"$OPENSSL_BIN" dgst -sha256 -engine azihsm -keyform engine \
    -sigopt rsa_padding_mode:pss \
    -sign "$uri" -out "$dsig" "$msg"
"$OPENSSL_BIN" dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -verify "$pub" -signature "$dsig" "$msg"

# An explicit rsa_pss_saltlen:auto must be rejected (matching the provider; the
# HSM needs a concrete salt length).
if "$OPENSSL_BIN" dgst -sha256 -engine azihsm -keyform engine \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto \
    -sign "$uri" -out /dev/null "$msg" 2>/dev/null; then
    echo "explicit rsa_pss_saltlen:auto unexpectedly accepted"
    exit 1
fi

# Zero-size signing. An empty message is a valid input: its digest is still a
# full-length hash, so dgst -sign over an empty file signs and verifies.
empty="$KEYDIR/rsa_pss_empty.txt"
esig0="$KEYDIR/rsa_pss_empty.sig"
: > "$empty"
"$OPENSSL_BIN" dgst -sha256 -engine azihsm -keyform engine \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -sign "$uri" -out "$esig0" "$empty"
"$OPENSSL_BIN" dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -verify "$pub" -signature "$esig0" "$empty"

# A zero-length pre-hashed digest (pkeyutl -sign over empty input) must be
# rejected: its length does not match the signature digest.
if "$OPENSSL_BIN" pkeyutl -sign -engine azihsm -keyform engine -inkey "$uri" \
    -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:digest \
    -in "$empty" -out /dev/null 2>/dev/null; then
    echo "zero-length digest unexpectedly signed"
    exit 1
fi

# A tampered message must fail verification.
printf 'engine rsa-pss signing over the CLI path?' > "$msg.tampered"
if "$OPENSSL_BIN" dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -verify "$pub" -signature "$KEYDIR/rsa_pss_sha256.sig" "$msg.tampered"; then
    echo "tampered message unexpectedly verified"
    exit 1
fi
echo "rsa pss round trip ok"

# CHECK: rsa pss round trip ok
