# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @cleanup

# End-to-end AES-CBC test via the OpenSSL CLI using an opaque, HSM-backed
# symmetric key (EVP_SKEY) - generate a masked key, then encrypt and decrypt.

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

# EVP_SKEY / opaque symmetric keys are OpenSSL 3.5+; on older OpenSSL this
# exits 0 (a passing skip).
skip_below_ossl_3_5

keybits=$1
cleanup=$2

keybytes=$((keybits / 8))
maskedkeyfile="./masked_aes_${keybits}_cbc.bin"
plaintext="./aes_cbc_pt_${keybits}.bin"
ciphertext="./aes_cbc_ct_${keybits}.bin"
decrypted="./aes_cbc_dec_${keybits}.bin"
iv="000102030405060708090a0b0c0d0e0f"

# Generate an opaque AES key inside the HSM and persist its masked blob.
"$OPENSSL_BIN" skeyutl -genkey \
    -skeymgmt AES \
    -skeyopt "key-length:$keybytes" \
    -skeyopt "azihsm.masked_key:$maskedkeyfile" \
    -propquery "$PROPQUERY"

if [[ ! -s "$maskedkeyfile" ]]; then
  echo "skeyutl produced no masked key blob"
  exit 1
fi

# Create some plaintext (size need not be block-aligned; padding handles it).
dd if=/dev/urandom of="$plaintext" bs=80 count=1 2>/dev/null

# Encrypt with the opaque key via openssl enc.
"$OPENSSL_BIN" enc -e "-aes-${keybits}-cbc" \
    -skeymgmt AES \
    -skeyopt "azihsm.masked_key:$maskedkeyfile" \
    -iv "$iv" \
    -in "$plaintext" -out "$ciphertext" \
    -propquery "$PROPQUERY"

# Decrypt with the same opaque key (re-imported from the same masked blob).
"$OPENSSL_BIN" enc -d "-aes-${keybits}-cbc" \
    -skeymgmt AES \
    -skeyopt "azihsm.masked_key:$maskedkeyfile" \
    -iv "$iv" \
    -in "$ciphertext" -out "$decrypted" \
    -propquery "$PROPQUERY"

# The recovered plaintext must match the original.
if ! cmp -s "$plaintext" "$decrypted"; then
  echo "aes-${keybits}-cbc opaque-key roundtrip mismatch"
  exit 1
fi

echo "aes-${keybits}-cbc opaque-key roundtrip ok"

if [[ "$cleanup" == "true" ]]; then
  rm -f "$maskedkeyfile" "$plaintext" "$ciphertext" "$decrypted"
fi
