# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# RSA import + load + sign over the real CLI path: import an external software
# RSA key into the HSM via `openssl genpkey -engine azihsm -algorithm RSA
# -pkeyopt azihsm.input_key:<der>`, then load the written masked blob through
# `ENGINE_load_private_key` (`azihsm://<blob>;type=rsa`) in fresh openssl
# processes and sign with it — reaching the engine's RSA_METHOD sign slot (HSM
# PKCS#1 v1.5, DigestInfo + padding host-side). Signatures are verified in
# software (no engine) with the public half extracted through the engine.
#
# Covers both sign entry points: dgst -sign (EVP_DigestSign) and pkeyutl -sign
# with a digest set (EVP_PKEY_sign). RSA signing requires a signature digest; a
# raw pkeyutl -sign with none routes to rsa_priv_enc (unsupported for HSM keys),
# so a digest is configured here. genpkey cannot serialize an HSM-backed private
# key, so the import prints one clear error after the blob is written — the blob
# is the persistent private form (as in create_key).
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

md=sha256
swpem="$KEYDIR/rsa_sw.pem"
input="$KEYDIR/rsa_input.der"
blob="$KEYDIR/rsa_sign_key.bin"
msg="$KEYDIR/rsa_sign_msg.txt"
pub="$KEYDIR/rsa_sign_pub.pem"
sig="$KEYDIR/rsa_sign_sig.bin"
digest="$KEYDIR/rsa_sign_digest.bin"
psig="$KEYDIR/rsa_sign_pkeyutl_sig.bin"
rm -f "$swpem" "$input" "$blob" "$msg" "$msg.tampered" "$pub" "$sig" "$digest" "$psig"

uri="azihsm://$blob;type=rsa"

# External software RSA-2048 key, normalized to unencrypted PKCS#8 DER (the form
# the HSM unwrap parser expects) for azihsm.input_key.
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$swpem"
"$OPENSSL_BIN" pkcs8 -topk8 -nocrypt -in "$swpem" -outform DER -out "$input"

# Import into the HSM (wrap the DER against the unwrapping key, unwrap it in),
# writing the masked blob. The private-key serialization genpkey attempts after
# is refused with one clear error; the blob is already on disk.
"$OPENSSL_BIN" genpkey -engine azihsm -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:2048" \
    -pkeyopt "azihsm.input_key:$input" \
    -pkeyopt "azihsm.masked_key:$blob" \
    -pkeyopt "azihsm.key_kind:RSA-CRT" || true
test -s "$blob"

printf 'engine rsa signing over the CLI path' > "$msg"

# Extract the public half through the engine load path (proves
# azihsm://…;type=rsa loads), in a software-verifiable form.
"$OPENSSL_BIN" pkey -engine azihsm -inform engine -in "$uri" -pubout -out "$pub"

# Hash-and-sign through the engine (EVP_DigestSign -> RSA_sign -> our sign slot
# -> HSM), then verify in software: proves the HSM signed with the key matching
# the public half.
"$OPENSSL_BIN" dgst "-$md" -engine azihsm -keyform engine -sign "$uri" \
    -out "$sig" "$msg"
"$OPENSSL_BIN" dgst "-$md" -verify "$pub" -signature "$sig" "$msg"

# Pre-hashed path: pkeyutl -sign with the digest set (EVP_PKEY_sign), then
# verify in software.
"$OPENSSL_BIN" dgst "-$md" -binary -out "$digest" "$msg"
"$OPENSSL_BIN" pkeyutl -sign -engine azihsm -keyform engine -inkey "$uri" \
    -pkeyopt "digest:$md" -in "$digest" -out "$psig"
"$OPENSSL_BIN" pkeyutl -verify -pubin -inkey "$pub" -pkeyopt "digest:$md" \
    -sigfile "$psig" -in "$digest"

# A tampered message must fail verification.
printf 'engine rsa signing over the CLI path?' > "$msg.tampered"
if "$OPENSSL_BIN" dgst "-$md" -verify "$pub" -signature "$sig" "$msg.tampered"; then
    echo "tampered message unexpectedly verified"
    exit 1
fi
echo "rsa sign round trip ok"

# CHECK: rsa sign round trip ok
