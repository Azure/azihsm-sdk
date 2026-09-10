# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Chained ECDH → HKDF through the CLI. A keyAgreement key derives a masked
# shared secret against a software peer; pkeyutl's KDF mode then derives
# masked AES and HMAC keys from it on the device. Requires -engine_impl so
# pkeyutl resolves the KDF method through the engine. No secret bytes ever
# appear — every output is a masked blob.
# (lit treats an uppercase word followed by a colon as a directive — keep such
# tokens out of comments here.)
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

blob="$KEYDIR/hkdf_agree_ec.bin"
peer_priv="$KEYDIR/hkdf_peer.pem"
peer_pub="$KEYDIR/hkdf_peer_pub.pem"
secret="$KEYDIR/hkdf_shared_secret.bin"
hmac_key="$KEYDIR/hkdf_hmac_key.bin"
aes_key="$KEYDIR/hkdf_aes_key.bin"
rm -f "$blob" "$peer_priv" "$peer_pub" "$secret" "$hmac_key" "$aes_key"

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

# HMAC-kind derived key, masked blob to output_file.
"$OPENSSL_BIN" pkeyutl -kdf HKDF -kdflen 1 -engine azihsm -engine_impl \
    -pkeyopt "md:SHA384" \
    -pkeyopt "salt:cli-salt" \
    -pkeyopt "info:cli-info" \
    -pkeyopt "azihsm.ikm_file:$secret" \
    -pkeyopt "derived_key_type:hmac" \
    -pkeyopt "derived_key_bits:384" \
    -pkeyopt "output_file:$hmac_key" \
    -out /dev/null
test -s "$hmac_key"
echo "hkdf hmac key ok"

# AES-kind derived key, masked blob into the output buffer.
"$OPENSSL_BIN" pkeyutl -kdf HKDF -kdflen 8192 -engine azihsm -engine_impl \
    -pkeyopt "md:SHA256" \
    -pkeyopt "azihsm.ikm_file:$secret" \
    -pkeyopt "derived_key_type:aes" \
    -pkeyopt "derived_key_bits:256" \
    -out "$aes_key"
test -s "$aes_key"
echo "hkdf aes key ok"

# CHECK: hkdf hmac key ok
# CHECK: hkdf aes key ok
