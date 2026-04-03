#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Verify that the TLS certificate served by nginx has the expected properties:
# P-384 curve, ECDSA-SHA384 signature, secp384r1 OID, CN=localhost.

set -euo pipefail

CERT=$(echo | openssl s_client -connect localhost:8443 -servername localhost 2>/dev/null \
    | openssl x509 -noout -text)

echo "$CERT"
echo "$CERT" | grep -q "Signature Algorithm: ecdsa-with-SHA384"
echo "$CERT" | grep -q "NIST CURVE: P-384"
echo "$CERT" | grep -q "ASN1 OID: secp384r1"
echo "$CERT" | grep -q "Subject: CN.*=.*localhost"
