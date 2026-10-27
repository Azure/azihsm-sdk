# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# The RSA-PSS key type over the real CLI path: import an external software RSA
# key into the HSM as an RSA-PSS key (`genpkey -engine azihsm -algorithm RSA-PSS
# -pkeyopt azihsm.input_key`), load the masked blob back as RSA-PSS
# (`azihsm://<blob>;type=rsa-pss`), and sign with it. An RSA-PSS key signs PSS
# with no padding option (the key type's default) via dgst and pkeyutl, its
# public half exports as an RSA-PSS key, and a self-signed certificate carries an
# RSASSA-PSS signature; all verify in software. PKCS#1 v1.5 padding, decryption,
# and a keyEncipherment RSA-PSS import are rejected.
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

swpem="$KEYDIR/rsa_psskt_sw.pem"
input="$KEYDIR/rsa_psskt_input.der"
blob="$KEYDIR/rsa_psskt_key.bin"
msg="$KEYDIR/rsa_psskt_msg.txt"
pub="$KEYDIR/rsa_psskt_pub.pem"
rm -f "$KEYDIR"/rsa_psskt_*

uri="azihsm://$blob;type=rsa-pss"

# External software RSA-2048 key, normalized to unencrypted PKCS#8 DER.
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$swpem"
"$OPENSSL_BIN" pkcs8 -topk8 -nocrypt -in "$swpem" -outform DER -out "$input"

# Import as RSA-PSS, writing the masked blob (genpkey refuses to serialize the
# HSM private key afterwards — the blob is the persistent private form).
"$OPENSSL_BIN" genpkey -engine azihsm -algorithm RSA-PSS \
    -pkeyopt "rsa_keygen_bits:2048" \
    -pkeyopt "azihsm.input_key:$input" \
    -pkeyopt "azihsm.masked_key:$blob" || true
test -s "$blob"

# An RSA-PSS key only signs: a keyEncipherment import fails before writing a blob.
bad="$KEYDIR/rsa_psskt_bad.bin"
err="$KEYDIR/rsa_psskt_bad.err"
"$OPENSSL_BIN" genpkey -engine azihsm -algorithm RSA-PSS \
    -pkeyopt "rsa_keygen_bits:2048" \
    -pkeyopt "azihsm.input_key:$input" \
    -pkeyopt "azihsm.masked_key:$bad" \
    -pkeyopt "azihsm.key_usage:keyEncipherment" 2>"$err" || true
test ! -e "$bad"
grep -q "supports only azihsm.key_usage:digitalSignature" "$err"

printf 'engine rsa-pss key type over the CLI path' > "$msg"

# The public half exports as an RSA-PSS key.
"$OPENSSL_BIN" pkey -engine azihsm -inform engine -in "$uri" -pubout -out "$pub"
"$OPENSSL_BIN" pkey -pubin -in "$pub" -noout -text | grep -q "RSA-PSS Public-Key"

# PSS by default: no padding option, verified in software as PSS with a
# digest-length salt, via both sign entry points. (Digest and salt coverage of
# the shared PSS sign path lives in rsa_pss.sh.)
sig="$KEYDIR/rsa_psskt.sig"
psig="$KEYDIR/rsa_psskt_pkeyutl.sig"
dg="$KEYDIR/rsa_psskt.dig"
"$OPENSSL_BIN" dgst -sha256 -engine azihsm -keyform engine -sign "$uri" -out "$sig" "$msg"
"$OPENSSL_BIN" dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -verify "$pub" -signature "$sig" "$msg"
"$OPENSSL_BIN" dgst -sha256 -binary -out "$dg" "$msg"
"$OPENSSL_BIN" pkeyutl -sign -engine azihsm -keyform engine -inkey "$uri" \
    -pkeyopt digest:sha256 -in "$dg" -out "$psig"
"$OPENSSL_BIN" pkeyutl -verify -pubin -inkey "$pub" \
    -pkeyopt digest:sha256 -pkeyopt rsa_pss_saltlen:digest -sigfile "$psig" -in "$dg"

# PKCS#1 v1.5 padding is refused for an RSA-PSS key.
if "$OPENSSL_BIN" dgst -sha256 -engine azihsm -keyform engine \
    -sigopt rsa_padding_mode:pkcs1 -sign "$uri" -out /dev/null "$msg" 2>/dev/null; then
    echo "RSA-PSS key unexpectedly signed with PKCS#1 v1.5 padding"
    exit 1
fi

# An RSA-PSS key has no decrypt.
if "$OPENSSL_BIN" pkeyutl -decrypt -engine azihsm -keyform engine -inkey "$uri" \
    -in "$msg" -out /dev/null 2>/dev/null; then
    echo "RSA-PSS key unexpectedly decrypted"
    exit 1
fi

# A self-signed certificate signed on the HSM carries an RSASSA-PSS signature
# and verifies in software.
# (req reads its own -config; the engine still loads via OPENSSL_CONF.)
cert="$KEYDIR/rsa_psskt_cert.pem"
reqcnf="$KEYDIR/rsa_psskt_req.cnf"
printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = azihsm rsa-pss\n' > "$reqcnf"
"$OPENSSL_BIN" req -new -x509 -config "$reqcnf" -engine azihsm -keyform engine -key "$uri" \
    -sha256 -days 1 -out "$cert"
"$OPENSSL_BIN" x509 -in "$cert" -noout -text | grep -q "Signature Algorithm: rsassaPss"
"$OPENSSL_BIN" verify -CAfile "$cert" "$cert"
echo "rsa-pss key type ok"

# CHECK: rsa-pss key type ok
