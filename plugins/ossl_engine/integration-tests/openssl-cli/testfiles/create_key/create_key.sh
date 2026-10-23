# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# For each supported curve: generate a key on the HSM through
# `openssl genpkey -engine azihsm`, then prove the written masked blob is a
# usable private key by loading it in a fresh openssl process, signing, and
# verifying in software.
#
# genpkey cannot serialize its usual private-key output: an HSM-backed key
# has no private scalar to encode, so it prints "Error writing key" (and,
# depending on the 1.1.1 patch level, may or may not exit non-zero) — the
# masked blob is the persistent private form. (OpenSSL 3.x solves this with
# provider encoders; a custom ASN1 method emitting a loadable azihsm PEM is a
# possible engine follow-up.) The generation completes before that: the blob
# is on disk and usable, which is what this test asserts.
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

for entry in "p256 P-256 sha256" "p384 P-384 sha384" "p521 P-521 sha512"; do
    read -r tag curve md <<< "$entry"
    blob="$KEYDIR/created_ec_$tag.bin"
    msg="$KEYDIR/create_msg_$tag.txt"
    pub="$KEYDIR/create_pub_$tag.pem"
    sig="$KEYDIR/create_sig_$tag.bin"
    rm -f "$blob" "$msg" "$pub" "$sig"

    # -text prints the provider-parity info block (to the default stdout
    # output); the private-key write before it is refused with one clear
    # error on stderr.
    "$OPENSSL_BIN" genpkey -engine azihsm -algorithm EC \
        -pkeyopt "ec_paramgen_curve:$curve" \
        -pkeyopt "azihsm.masked_key:$blob" \
        -pkeyopt "azihsm.session:false" \
        -pkeyopt "azihsm.key_usage:digitalSignature" \
        -text || true

    # The generation itself succeeded: the masked blob is on disk...
    test -s "$blob"

    # ...and is a usable private key in a fresh process: load, sign, verify.
    uri="azihsm://$blob;type=ec"
    "$OPENSSL_BIN" pkey -engine azihsm -inform engine -in "$uri" -pubout -out "$pub"
    printf 'engine ecdsa signing with a CLI-generated key (%s)' "$tag" > "$msg"
    "$OPENSSL_BIN" dgst "-$md" -engine azihsm -keyform engine -sign "$uri" \
        -out "$sig" "$msg"
    "$OPENSSL_BIN" dgst "-$md" -verify "$pub" -signature "$sig" "$msg"
    echo "create key ok: $tag"
done

# One provider-parity block per curve, then the per-curve success markers.
# CHECK: ==== PrivateKeyInfo (PKCS#8) ====
# CHECK: create key ok: p256
# CHECK: ==== PrivateKeyInfo (PKCS#8) ====
# CHECK: create key ok: p384
# CHECK: ==== PrivateKeyInfo (PKCS#8) ====
# CHECK: create key ok: p521
