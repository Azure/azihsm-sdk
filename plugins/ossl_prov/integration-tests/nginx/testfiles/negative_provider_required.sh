#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Negative test: verify that nginx cannot load its config when the provider
# is unavailable.

set -euo pipefail

PROVIDER_SO="${PROVIDER_SO:?PROVIDER_SO must be set to the path of azihsm_provider.so}"
NGINX_CONF="${NGINX_CONF:?NGINX_CONF must be set to the path of the generated nginx.conf}"
NGINX_PREFIX="${NGINX_PREFIX:?NGINX_PREFIX must be set}"
NGINX_ERROR_LOG="${NGINX_ERROR_LOG:?NGINX_ERROR_LOG must be set}"

NGINX_FLAGS=(-p "$NGINX_PREFIX" -e "$NGINX_ERROR_LOG" -c "$NGINX_CONF")

# Stop nginx (may already be stopped — ignore errors)
nginx -s stop "${NGINX_FLAGS[@]}" || true
sleep 1

# Try to hide the provider by renaming it.  If the provider lives in a
# system directory (e.g. /usr/lib/ossl-modules) the mv will fail — fall
# back to unsetting OPENSSL_CONF which prevents the provider from loading.
if mv "$PROVIDER_SO" "${PROVIDER_SO}.disabled" 2>/dev/null; then
    trap 'mv "${PROVIDER_SO}.disabled" "$PROVIDER_SO"' EXIT
    OUTPUT=$(nginx -t "${NGINX_FLAGS[@]}" 2>&1 || true)
else
    OUTPUT=$(env -u OPENSSL_CONF nginx -t "${NGINX_FLAGS[@]}" 2>&1 || true)
fi

echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "unregistered scheme"; then
    echo "Negative test passed: nginx correctly rejects config without provider."
else
    echo "ERROR: nginx did not report 'unregistered scheme' — provider may still be loaded." >&2
    exit 1
fi
