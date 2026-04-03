#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Negative test: verify that nginx cannot load its config when the provider
# is unavailable.

set -euo pipefail

PROVIDER_SO="${PROVIDER_SO:?PROVIDER_SO must be set to the path of azihsm_provider.so}"
NGINX_CONF="${NGINX_CONF:?NGINX_CONF must be set to the path of the generated nginx.conf}"

# Stop nginx (may already be stopped — ignore errors)
sudo nginx -s stop || true
sleep 1

# Temporarily hide the provider by renaming it
sudo mv "$PROVIDER_SO" "${PROVIDER_SO}.disabled"

# Ensure we always restore the provider, even if the test fails
restore_provider() {
    sudo mv "${PROVIDER_SO}.disabled" "$PROVIDER_SO"
}
trap restore_provider EXIT

# Attempt to validate the config without the provider.
OUTPUT=$(sudo env -u OPENSSL_CONF nginx -t -c /etc/nginx/nginx.conf 2>&1 || true)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "unregistered scheme"; then
    echo "Negative test passed: nginx correctly rejects config without provider."
else
    echo "ERROR: nginx did not report 'unregistered scheme' — provider may still be loaded." >&2
    exit 1
fi
