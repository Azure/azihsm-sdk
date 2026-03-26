#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Negative test: verify that nginx cannot load its config when the provider
# is removed from the system path.  The store:azihsm:// URI scheme should
# fail with "unregistered scheme".

set -euo pipefail

# Stop nginx (may already be stopped — ignore errors)
sudo nginx -s stop || true
sleep 1

# Remove the provider from the system module path
sudo rm -f /usr/lib/x86_64-linux-gnu/ossl-modules/azihsm_provider.so

# Attempt to validate the config without the provider.
# nginx -t is EXPECTED to fail — capture its output, then check for the
# expected error message.  We cannot pipe directly because pipefail would
# abort on the non-zero exit from nginx -t.
OUTPUT=$(sudo env -u OPENSSL_CONF nginx -t -c /etc/nginx/nginx.conf 2>&1 || true)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "unregistered scheme"; then
    echo "Negative test passed: nginx correctly rejects config without provider."
else
    echo "ERROR: nginx did not report 'unregistered scheme' — provider may still be loaded." >&2
    exit 1
fi
