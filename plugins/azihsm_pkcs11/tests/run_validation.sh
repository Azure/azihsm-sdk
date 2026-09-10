#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Drives the module with the two validation tools: OpenSC pkcs11-tool (smoke)
# and, when present, Google pkcs11test (conformance). Builds the standalone
# no-device module for the tool-facing checks; if the mock-backed module has
# been built (cargo build -p azihsm_pkcs11 --features mock), it also runs the
# C_Login provisioning ceremony against the simulator.
#
# The tools are expected locally (extracted from distro packages / cloned, no
# system install). Point PKCS11_TESTING at that directory; it defaults to the
# repo-sibling layout with an env.sh that puts the tools on PATH.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$PLUGIN/../.." && pwd)"
PKCS11_TESTING="${PKCS11_TESTING:-$(cd "$REPO/.." && pwd)/pkcs11-testing}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== building standalone module (no device) =="
gcc -shared -fPIC -Wall -Wextra -Wno-unknown-pragmas \
    -I"$PLUGIN/include/pkcs11-v3.1" \
    "$PLUGIN"/src/*.c \
    -o "$WORK/azihsm_pkcs11.so" -lpthread
MOD="$WORK/azihsm_pkcs11.so"
echo "  built $MOD ; exported C_ symbols: $(nm -D "$MOD" | grep -c ' T C_')"

if [ -f "$PKCS11_TESTING/env.sh" ]; then
    # shellcheck disable=SC1091
    source "$PKCS11_TESTING/env.sh"
fi

echo; echo "== pkcs11-tool: show-info / slots / mechanisms =="
pkcs11-tool --module "$MOD" --show-info
pkcs11-tool --module "$MOD" --list-slots
pkcs11-tool --module "$MOD" --list-mechanisms | head -n 20

echo; echo "== pkcs11-tool: SHA-256('abc') must equal openssl (the demo op) =="
printf abc > "$WORK/msg"
pkcs11-tool --module "$MOD" --hash --mechanism SHA256 \
    --input-file "$WORK/msg" --output-file "$WORK/dig" 2>/dev/null
got="$(xxd -p -c64 "$WORK/dig")"
exp="$(printf abc | sha256sum | cut -d' ' -f1)"
echo "  module : $got"; echo "  openssl: $exp"
[ "$got" = "$exp" ] && echo "  *** DIGEST OK ***" || { echo "  MISMATCH"; exit 1; }

if [ -x "$PKCS11_TESTING/pkcs11test/pkcs11test" ]; then
    echo; echo "== pkcs11test: framework conformance subset =="
    ( cd "$PKCS11_TESTING/pkcs11test" && \
      ./pkcs11test -m "$(basename "$MOD")" -l "$(dirname "$MOD")" -s 0 \
        --gtest_filter='*Slot*:*Session*' 2>&1 \
        | grep -E 'PASSED|FAILED\]' | tail -n 4 ) || true
fi

# --- mock-backed C_Login ceremony (needs the integrated build + mock DDI) ----
HSMMOD="$REPO/target/debug/azihsm_pkcs11.so"
if [ -f "$HSMMOD" ]; then
    echo; echo "== mock-backed: C_Login provisioning ceremony =="
    echo "   (build it with: cargo build -p azihsm_pkcs11 --features mock)"
    AZIHSM_PKCS11_DEBUG=1 pkcs11-tool --module "$HSMMOD" --login --pin 1234 \
        --list-objects 2>&1 | sed 's/^/   /' || echo "   (login harness failed)"

    # The AES checks below are hard gates (real functionality, not the login
    # ceremony's best-effort diagnostic above), so announce a failure before the
    # pipefail/errexit abort rather than aborting the script silently.
    echo; echo "== mock-backed: AES keygen via pkcs11-tool =="
    # --sensitive is required: this token refuses non-sensitive HSM keys.
    if ! pkcs11-tool --module "$HSMMOD" --login --pin 1234 --keygen \
        --key-type aes:32 --label validation --sensitive 2>&1 | sed 's/^/   /'; then
        echo "   (AES keygen failed)"; exit 1
    fi

    echo; echo "== mock-backed: AES keygen + CBC round-trip harness =="
    gcc -Wall -Wextra -Werror -I"$PLUGIN/include/pkcs11-v3.1" -I"$PLUGIN/src" \
        "$PLUGIN/tests/aes_test.c" -o "$WORK/aes_test" -ldl
    "$WORK/aes_test" "$HSMMOD" || { echo "   (AES harness failed)"; exit 1; }
else
    echo; echo "== mock-backed C_Login skipped (no target/debug/azihsm_pkcs11.so) =="
fi

echo; echo "All validation steps completed."
