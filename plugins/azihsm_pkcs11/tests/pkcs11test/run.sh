#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Conformance gate: builds Google pkcs11test at a pinned revision (with the
# login-profile fixture patch), runs it against the given module and requires
# every test named in include-list.txt to pass — and to have actually run.
# See README.md alongside.
#
#   run.sh <module.so> [work-dir]
#
# work-dir (default: $RUNNER_TEMP or $TMPDIR or /tmp, plus azihsm-pkcs11test)
# keeps the clone between runs; the build itself is always from clean.
# Environment overrides:
#   PKCS11TEST_REPO / PKCS11TEST_REV   clone source and pinned commit
#   AZIHSM_PKCS11_TEST_PIN             user PIN (default: simulator 1234)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOD="${1:?usage: $0 <module.so> [work-dir]}"
WORK="${2:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/azihsm-pkcs11test}"
REPO="${PKCS11TEST_REPO:-https://github.com/google/pkcs11test.git}"
REV="${PKCS11TEST_REV:-2cbe462c62bacf537b9a9a427a1c053d8c2e4760}"
PIN="${AZIHSM_PKCS11_TEST_PIN:-1234}"
INCLUDE="$HERE/include-list.txt"
PATCH="$HERE/hsm-profile-login.patch"
SRC="$WORK/src"

fail()
{
    echo "pkcs11test gate: $*" >&2
    exit 1
}

[ -f "$MOD" ] || fail "module not found: $MOD"
MOD="$(cd "$(dirname "$MOD")" && pwd)/$(basename "$MOD")"

# --- 1. The include-list, before anything expensive --------------------------
# Tolerate trailing whitespace, CRLF and repeated names so a list-hygiene slip
# cannot masquerade as a renamed test in the count check below.
[ -f "$INCLUDE" ] || fail "include-list not found: $INCLUDE"
mapfile -t NAMES < <(
    sed -e 's/\r$//' -e 's/[[:space:]]*$//' "$INCLUDE" |
        grep -v -E '^[[:space:]]*(#|$)' | sort -u
)
[ "${#NAMES[@]}" -gt 0 ] || fail "include-list names no tests: $INCLUDE"

# --- 2. Source at the pinned revision, fixture patch applied ----------------
mkdir -p "$WORK"
if [ ! -d "$SRC/.git" ]; then
    # A half-made clone would poison every later run; take it with us.
    git clone -q "$REPO" "$SRC" || { rm -rf "$SRC"; fail "cannot clone $REPO"; }
fi
if ! git -C "$SRC" cat-file -e "$REV^{commit}" 2>/dev/null; then
    git -C "$SRC" fetch -q origin || fail "cannot fetch $REV from $REPO"
fi
# Clean before checking out: the previous run left the fixture patch applied,
# and git refuses to move HEAD across those files once the pin changes.
git -C "$SRC" reset -q --hard
git -C "$SRC" clean -qfdx
git -C "$SRC" checkout -q --detach "$REV" || fail "cannot check out $REV"
git -C "$SRC" apply "$PATCH" ||
    fail "the fixture patch does not apply at $REV (regenerate it — see README.md)"

# --- 3. Build from clean (the makefile tracks no header dependencies) ------
make -C "$SRC" -s -j"$(nproc 2>/dev/null || echo 2)" > "$WORK/build.log" 2>&1 ||
    { tail -n 30 "$WORK/build.log"; fail "build failed (see $WORK/build.log)"; }

# --- 4. Run exactly the include-list ---------------------------------------
FILTER="$(IFS=:; echo "${NAMES[*]}")"
echo "pkcs11test gate: ${#NAMES[@]} listed tests against $MOD"
set +e
(
    cd "$SRC" &&
        ./pkcs11test -m "$(basename "$MOD")" -l "$(dirname "$MOD")" -s 0 -u "$PIN" -X \
            --gtest_filter="$FILTER"
) > "$WORK/run.log" 2>&1
status=$?
set -e

grep -E '^\[  FAILED  \] |^\[  PASSED  \] ' "$WORK/run.log" || true
if [ "$status" -ne 0 ]; then
    # The job log is all a CI run leaves behind, so put the assertions in it.
    echo "--- pkcs11test output ---" >&2
    cat "$WORK/run.log" >&2
    fail "listed tests failed (pkcs11test exited $status)"
fi

# A filter that matches nothing is a pass as far as GoogleTest is concerned, so
# every listed test must be accounted for by name.
comm -13 \
    <(grep -E '^\[ RUN      \] ' "$WORK/run.log" | sed -E 's/^\[ RUN      \] //' | sort -u) \
    <(printf '%s\n' "${NAMES[@]}") > "$WORK/missing.txt"
if [ -s "$WORK/missing.txt" ]; then
    echo "--- listed but never run (renamed or removed upstream?) ---" >&2
    cat "$WORK/missing.txt" >&2
    fail "$(wc -l < "$WORK/missing.txt") listed test(s) did not run"
fi

# pkcs11test's own skip mechanism does NOT mark a case skipped for GoogleTest:
# the body returns early and the case still reports OK. Such a test asserts
# nothing, so it must not sit on the list pretending to be a check.
comm -12 \
    <(awk '/^Following tests were skipped/ { f = 1; next }
           /^\[/ { f = 0 }
           f && NF { sub(/^ +/, ""); print }' "$WORK/run.log" | sort -u) \
    <(printf '%s\n' "${NAMES[@]}") > "$WORK/skipped.txt"
if [ -s "$WORK/skipped.txt" ]; then
    echo "--- listed but skipped inside pkcs11test (asserted nothing) ---" >&2
    cat "$WORK/skipped.txt" >&2
    fail "$(wc -l < "$WORK/skipped.txt") listed test(s) were skipped, not executed"
fi

echo "pkcs11test gate: all ${#NAMES[@]} listed tests passed"
