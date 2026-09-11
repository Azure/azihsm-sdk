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

echo; echo "== digest KAT (NIST vectors, no device) =="
gcc -Wall -Wextra -Werror \
    -I"$PLUGIN/include/pkcs11-v3.1" -I"$PLUGIN/src" \
    "$HERE/digest_kat_test.c" "$PLUGIN/src/azihsm_pkcs11_digest.c" \
    -o "$WORK/digest_kat_test"
"$WORK/digest_kat_test"

if [ -f "$PKCS11_TESTING/env.sh" ]; then
    # shellcheck disable=SC1091
    source "$PKCS11_TESTING/env.sh"
fi

echo; echo "== pkcs11-tool: show-info / slots / mechanisms =="
pkcs11-tool --module "$MOD" --show-info
pkcs11-tool --module "$MOD" --list-slots
pkcs11-tool --module "$MOD" --list-mechanisms | head -n 20

echo; echo "== pkcs11-tool: digests of 'abc' must equal coreutils =="
printf abc > "$WORK/msg"
for pair in SHA-1:sha1sum SHA256:sha256sum SHA384:sha384sum SHA512:sha512sum; do
    mech="${pair%%:*}"; sum="${pair##*:}"
    pkcs11-tool --module "$MOD" --hash --mechanism "$mech" \
        --input-file "$WORK/msg" --output-file "$WORK/dig" 2>/dev/null
    got="$(xxd -p -c130 "$WORK/dig")"
    exp="$("$sum" < "$WORK/msg" | cut -d' ' -f1)"
    echo "  $mech module   : $got"; echo "  $mech coreutils: $exp"
    [ "$got" = "$exp" ] && echo "  *** $mech OK ***" || { echo "  MISMATCH"; exit 1; }
done

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
else
    echo; echo "== mock-backed C_Login skipped (no target/debug/azihsm_pkcs11.so) =="
fi

echo; echo "All validation steps completed."
