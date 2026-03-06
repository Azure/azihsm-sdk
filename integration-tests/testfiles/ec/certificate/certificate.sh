# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

# openssl req always tries to load a config file. When using a custom-built
# OpenSSL (e.g. CI) the default openssl.cnf may not exist. Setting
# OPENSSL_CONF=/dev/null skips config loading; -subj provides the subject directly.
test -z "$OPENSSL_CONF" && export OPENSSL_CONF=/dev/null

curve=P-$1
dgst=$2
cleanup=$3

certificate=./cert_"$curve"_"$dgst".pem
maskedkeyfile=./cert_masked_"$curve".bin

"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
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
    -propquery "$PROPQUERY" \
    -provider default \
    -provider azihsm_provider \
    -key "azihsm://$maskedkeyfile;type=ec" \
    -subj "/CN=test-$curve" \
    -days 365 -"$dgst" \
    -out "$certificate"


#CHECK: certificate created
if [[ -f "$certificate" && -s "$certificate" ]]; then
  echo "certificate created"
fi

if [[ "$cleanup" == "true" ]]; then
  rm -f "$maskedkeyfile" "$certificate"
fi
