# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Chained ECDH → HKDF through the CLI. A keyAgreement key derives a masked
# shared secret against a software peer; pkeyutl's KDF mode then derives
# masked HMAC and AES keys from it on the device, across a matrix of digests
# and key sizes. Requires -engine_impl so pkeyutl resolves the KDF method
# through the engine. No secret bytes ever appear — every output is a masked
# blob.
# (lit treats an uppercase word followed by a colon as a directive — keep such
# tokens out of comments here.)
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

blob="$KEYDIR/hkdf_agree_ec.bin"
peer_priv="$KEYDIR/hkdf_peer.pem"
peer_pub="$KEYDIR/hkdf_peer_pub.pem"
secret="$KEYDIR/hkdf_shared_secret.bin"
rm -f "$blob" "$peer_priv" "$peer_pub" "$secret"

"$OPENSSL_BIN" genpkey -engine azihsm -algorithm EC \
    -pkeyopt "ec_paramgen_curve:P-384" \
    -pkeyopt "azihsm.masked_key:$blob" \
    -pkeyopt "azihsm.key_usage:keyAgreement" \
    -out /dev/null || true
test -s "$blob"

"$OPENSSL_BIN" genpkey -algorithm EC \
    -pkeyopt "ec_paramgen_curve:P-384" -out "$peer_priv"
"$OPENSSL_BIN" pkey -in "$peer_priv" -pubout -out "$peer_pub"

"$OPENSSL_BIN" pkeyutl -derive -engine azihsm -keyform engine \
    -inkey "azihsm://$blob;type=ec" \
    -peerkey "$peer_pub" \
    -pkeyopt "output_file:$secret"
test -s "$secret"

# Derive masked keys across digests and key sizes. HMAC's kind follows the
# digest (bits must match); AES key bits vary independently of the digest.
# output_file mode writes the masked blob to a file (kdflen 1 satisfies
# pkeyutl's positive-length requirement; no bytes come back in the buffer).
for cfg in \
    "hmac SHA256 256" \
    "hmac SHA384 384" \
    "hmac SHA512 512" \
    "aes SHA256 128" \
    "aes SHA256 192" \
    "aes SHA256 256"; do
    read -r ktype md bits <<< "$cfg"
    out="$KEYDIR/hkdf_${ktype}_${md}_${bits}.bin"
    rm -f "$out"
    "$OPENSSL_BIN" pkeyutl -kdf HKDF -kdflen 1 -engine azihsm -engine_impl \
        -pkeyopt "md:$md" \
        -pkeyopt "salt:cli-salt" \
        -pkeyopt "info:cli-info" \
        -pkeyopt "azihsm.ikm_file:$secret" \
        -pkeyopt "derived_key_type:$ktype" \
        -pkeyopt "derived_key_bits:$bits" \
        -pkeyopt "output_file:$out"
    test -s "$out"
    echo "hkdf ok: $ktype $md $bits"
done

# Buffer mode: the masked blob comes back in -out. kdflen must be at least the
# blob length; the armed size query reports MASKED_KEY_MAX_BUFFER (8192 bytes,
# the shared masked-blob buffer size), so pass that.
buf="$KEYDIR/hkdf_buffer_mode.bin"
rm -f "$buf"
"$OPENSSL_BIN" pkeyutl -kdf HKDF -kdflen 8192 -engine azihsm -engine_impl \
    -pkeyopt "md:SHA256" \
    -pkeyopt "azihsm.ikm_file:$secret" \
    -pkeyopt "derived_key_type:aes" \
    -pkeyopt "derived_key_bits:256" \
    -out "$buf"
test -s "$buf"
echo "hkdf ok: buffer-mode"

# CHECK: hkdf ok: hmac SHA256 256
# CHECK: hkdf ok: hmac SHA384 384
# CHECK: hkdf ok: hmac SHA512 512
# CHECK: hkdf ok: aes SHA256 128
# CHECK: hkdf ok: aes SHA256 192
# CHECK: hkdf ok: aes SHA256 256
# CHECK: hkdf ok: buffer-mode
