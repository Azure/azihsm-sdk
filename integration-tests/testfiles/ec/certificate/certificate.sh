# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
# openssl req always tries to load a config file. When using a custom-built
# OpenSSL (e.g. CI) the default openssl.cnf may not exist. Setting
# OPENSSL_CONF=/dev/null skips config loading; -subj provides the subject directly.
test -z "$OPENSSL_CONF" && export OPENSSL_CONF=/dev/null
export LD_LIBRARY_PATH="$OPENSSL_LIB"

curve=P-$1
dgst=$2
cleanup=$3

certificate=./cert_"$curve"_"$dgst".pem
maskedkeyfile=./cert_masked_"$curve".bin

"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt azihsm.session:false \
    -outform DER \
    -pkeyopt "azihsm.masked_key:$maskedkeyfile" \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -text

"$OPENSSL_BIN" req \
    -new \
    -x509 \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -key "azihsm://$maskedkeyfile;type=ec" \
    -subj "/CN=test-$curve" \
    -days 365 -"$dgst" \
    -out "$certificate"


#CHECK: certificate created
if [[ -f "$certificate" && -s "$certificate" ]]; then
  echo "certificate created"
fi

if [[ "$cleanup" == "true" ]]; then
  rm "$maskedkeyfile"
  rm "$certificate"
fi
