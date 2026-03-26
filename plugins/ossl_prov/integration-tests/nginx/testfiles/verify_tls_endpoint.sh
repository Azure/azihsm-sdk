#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Verify that nginx serves TLS using the azihsm provider.

set -euo pipefail

echo "Checking root endpoint..."
curl -fsk https://localhost:8443/ | grep "azihsm"

echo "Checking health endpoint..."
curl -fsk https://localhost:8443/health | grep "healthy"

echo "TLS endpoint verification passed."
