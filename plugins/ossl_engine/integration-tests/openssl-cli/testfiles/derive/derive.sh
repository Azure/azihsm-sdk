# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# For each supported curve: generate a keyAgreement key on the HSM, then run
# ECDH against a software peer through `openssl pkeyutl -derive`, loading the
# masked EC blob via azihsm://. The shared secret never leaves the HSM — the
# derive's output is the masked blob of the derived secret, written to the
# output_file path (file mode) or to -out (buffer mode).
# (lit treats an uppercase word followed by a colon as a directive — keep such
# tokens out of comments here.)
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

for entry in "p256 P-256" "p384 P-384" "p521 P-521"; do
    read -r tag curve <<< "$entry"
    blob="$KEYDIR/agree_ec_$tag.bin"
    peer_priv="$KEYDIR/derive_peer_$tag.pem"
    peer_pub="$KEYDIR/derive_peer_pub_$tag.pem"
    secret_file="$KEYDIR/derived_file_$tag.bin"
    secret_buf="$KEYDIR/derived_buf_$tag.bin"
    rm -f "$blob" "$peer_priv" "$peer_pub" "$secret_file" "$secret_buf"

    "$OPENSSL_BIN" genpkey -engine azihsm -algorithm EC \
        -pkeyopt "ec_paramgen_curve:$curve" \
        -pkeyopt "azihsm.masked_key:$blob" \
        -pkeyopt "azihsm.key_usage:keyAgreement" \
        -out /dev/null || true
    test -s "$blob"

    # Software peer key pair on the same curve.
    "$OPENSSL_BIN" genpkey -algorithm EC \
        -pkeyopt "ec_paramgen_curve:$curve" -out "$peer_priv"
    "$OPENSSL_BIN" pkey -in "$peer_priv" -pubout -out "$peer_pub"

    # File mode: masked blob of the derived secret to output_file.
    "$OPENSSL_BIN" pkeyutl -derive -engine azihsm -keyform engine \
        -inkey "azihsm://$blob;type=ec" \
        -peerkey "$peer_pub" \
        -pkeyopt "output_file:$secret_file"
    test -s "$secret_file"

    # Buffer mode: the blob lands in -out.
    "$OPENSSL_BIN" pkeyutl -derive -engine azihsm -keyform engine \
        -inkey "azihsm://$blob;type=ec" \
        -peerkey "$peer_pub" \
        -out "$secret_buf"
    test -s "$secret_buf"

    echo "derive ok: $tag"
done

# CHECK: derive ok: p256
# CHECK: derive ok: p384
# CHECK: derive ok: p521
