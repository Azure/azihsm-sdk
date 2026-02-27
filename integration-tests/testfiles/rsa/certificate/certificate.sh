# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @keybits @dgst @cleanup 

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
# openssl req always tries to load a config file. When using a custom-built
# OpenSSL (e.g. CI) the default openssl.cnf may not exist. Setting
# OPENSSL_CONF=/dev/null skips config loading; -subj provides the subject directly.
test -z "$OPENSSL_CONF" && export OPENSSL_CONF=/dev/null
export LD_LIBRARY_PATH="$OPENSSL_LIB"

keybits=$1
dgst=$2
cleanup=$3

keyfile=./certificate_rsa_"$keybits"_key.der
maskedkeyfile=./certificate_masked_rsa_"$keybits"_imported.bin
certificate=./certtificate_certfile_"$keybits".pem

# Generate external RSA key first (HSM cannot generate RSA keys natively)
"$OPENSSL_BIN" genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:$keybits \
    -outform DER \
    -out $keyfile

# Import the RSA key into HSM via the provider
"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:$keybits \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt azihsm.input_key:$keyfile \
    -pkeyopt azihsm.masked_key:$maskedkeyfile

"$OPENSSL_BIN" req \
    -new \
    -x509 \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -key "azihsm://$maskedkeyfile;type=rsa" \
    -subj "/CN=test-$keybits" \
    -days 365 -"$dgst" \
    -out "$certificate"


#CHECK: certificate created
if [[ -f $certificate && -s $certificate ]]; then
  echo "certificate created"
fi

if [[ "$cleanup" == "true" ]]; then
  rm $maskedkeyfile
fi
