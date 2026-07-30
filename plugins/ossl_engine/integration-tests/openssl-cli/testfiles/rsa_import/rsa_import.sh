# RUN: @bash -ea @file
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Import an external RSA key into the HSM via the provisioning tool, then
# load the masked blob back through the engine's ENGINE_load_private_key
# path and check the public halves line up. (The wrapped-blob flow is
# covered by the in-crate Rust tests — OpenSSL 1.1's `enc` refuses AES
# key-wrap ciphers, so it cannot wrap here.)
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

key="$KEYDIR/rsa_import_input.der"
masked="$KEYDIR/rsa_key.bin"
pub="$KEYDIR/rsa_import_pub.der"
rm -f "$key" "$masked" "$pub"

# External RSA-2048 key as PKCS#8 DER (the HSM cannot generate RSA natively).
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -outform DER -out "$key"

"$MASKED_KEYGEN" rsa-import --input-key "$key" \
    --masked-out "$masked" --pubkey-out "$pub"

# CHECK: masked blob created
if [ -s "$masked" ]; then
    echo "masked blob created"
fi

# The exported public half must match the input key's.
# CHECK: public key matches input
"$OPENSSL_BIN" pkey -in "$key" -inform DER -pubout -outform DER \
    -out "$KEYDIR/rsa_import_expected_pub.der"
if cmp -s "$pub" "$KEYDIR/rsa_import_expected_pub.der"; then
    echo "public key matches input"
fi

# Load the masked key via the engine (real ENGINE_load_private_key) and
# emit the public key; it must equal the input key's public half.
# CHECK: loaded public key matches input
"$OPENSSL_BIN" pkey -engine azihsm -inform engine \
    -in "azihsm://$masked;type=rsa" -pubout -outform DER \
    -out "$KEYDIR/rsa_import_loaded_pub.der"
if cmp -s "$KEYDIR/rsa_import_loaded_pub.der" "$KEYDIR/rsa_import_expected_pub.der"; then
    echo "loaded public key matches input"
fi

# The wrapping public key exports as a parseable SPKI.
# CHECK: BEGIN PUBLIC KEY
"$MASKED_KEYGEN" wrapping-key --pubkey-out "$KEYDIR/wrapping_pub.der"
"$OPENSSL_BIN" pkey -pubin -inform DER -in "$KEYDIR/wrapping_pub.der" -pubout

rm -f "$key" "$masked" "$pub" "$KEYDIR/rsa_import_expected_pub.der" \
    "$KEYDIR/rsa_import_loaded_pub.der" "$KEYDIR/wrapping_pub.der"
