#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Verify that nginx serves TLS using the azihsm provider.

set -euo pipefail

curl -fsk https://localhost:8443/ | grep "azihsm"
curl -fsk https://localhost:8443/health | grep "healthy"
