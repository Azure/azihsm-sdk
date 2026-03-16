#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

AZIHSM_DIR="/etc/azihsm"
MASKED_KEY="${AZIHSM_DIR}/masked_key_p384.bin"
CERT="${AZIHSM_DIR}/server.crt"
NGINX_CONF="/etc/nginx/nginx.conf"

mkdir -p "${AZIHSM_DIR}"

export OPENSSL_CONF="/etc/azihsm/openssl-cli.cnf"

echo "==> Generating EC P-384 key pair in mock HSM ..."
openssl genpkey \
    -algorithm EC \
    -pkeyopt group:P-384 \
    -pkeyopt "azihsm.masked_key:${MASKED_KEY}" \
    -outform DER \
    -out /dev/null

echo "==> Generating self-signed certificate ..."
openssl req -new -x509 \
    -key "azihsm://${MASKED_KEY};type=ec" \
    -subj "/CN=localhost" \
    -days 365 \
    -sha384 \
    -out "${CERT}"

echo "==> Installing nginx configuration ..."
cp /etc/azihsm/nginx.conf.template "${NGINX_CONF}"

# nginx config: loads the provider without default_properties so that
# TLS-internal algorithms (HKDF, etc.) use the default provider.
export OPENSSL_CONF="/etc/azihsm/openssl-provider.cnf"

echo "==> Starting nginx on port 8443 ..."
exec nginx -g 'daemon off;' -c "${NGINX_CONF}"
