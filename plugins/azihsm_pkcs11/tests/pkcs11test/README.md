# Conformance gate: Google pkcs11test

[pkcs11test](https://github.com/google/pkcs11test) (Apache-2.0) is Google's
PKCS#11 conformance program: 330 GoogleTest cases that `dlopen` any Cryptoki
module and check its behaviour against the spec — return-value precedence,
operation lifetimes, two-call sizing, template rules, token and session
semantics. It is the external oracle for this module, independent of our own
unit and functional tests, and it runs as a CI gate on pushes to and pull
requests into the staging branch.

## How the gate works

`run.sh <module.so> [work-dir]`

1. clones pkcs11test at the pinned revision (`PKCS11TEST_REV` in the script)
   into the work directory, or reuses a previous clone there,
2. resets that checkout, applies `hsm-profile-login.patch` (below) and builds
   the tool from clean — its makefile has no header dependencies, so an
   incremental build after a header change is silently stale,
3. runs it against the module with `-s 0 -u <pin> -X` and
   `--gtest_filter=<every name in include-list.txt>`,
4. fails unless **every listed test passed, ran, and actually asserted
   something**.

That third condition is not pedantry. GoogleTest exits 0 when a filter matches
nothing, so a test renamed upstream would silently stop being checked; and
pkcs11test's own skip mechanism does not mark a case skipped for GoogleTest —
the test body returns early and the case still prints `[ OK ]` and counts as
passed. A module that lost a whole mechanism would then keep a green gate,
because every test of that mechanism would "pass" by skipping. So the script
also compares the tests that ran against the list, and fails if a listed test
appears in pkcs11test's skip report.

The gate is an **include-list, not an exclude-list**: only the tests named in
`include-list.txt` must pass. Gating on the whole run would be red until the
module is complete — pkcs11test's `SKIP_IF_UNIMPLEMENTED` guard sits at
`C_*Init`, and our unimplemented mechanisms fail earlier, in fixture set-up
(key generation for DES/RSA/EC, the streaming stubs), so they show up as
failures. Gating on the listed names keeps every behaviour that once passed
from regressing while the list grows piece by piece.

**Policy:** when a piece lands, run the tool without a filter, add every newly
green name to `include-list.txt`, and mention the additions in the commit
message. Never remove a name without saying why. A test pkcs11test skips
belongs off the list until the feature lands, because it would assert nothing.

Flags: `-X` disables the Security Officer tests (this token has no SO
credential — the AZIHSM DDI has none); `-I` (token initialisation) is not
needed because `C_Login` provisions the partition lazily.

The gate drives the **mock-backed** module (`cargo build --features mock`), not
the standalone no-device build: every interesting conformance behaviour is
key-backed and needs a device behind the login.

## The fixture patch (`hsm-profile-login.patch`)

Four one-line changes to pkcs11test's fixture base classes:

| file | class | from | to |
|---|---|---|---|
| `pkcs11test.h` | `SecretKeyTest` | `ReadOnlySessionTest` | `ROUserSessionTest` |
| `sign.cc` | `SignTest` | `ReadOnlySessionTest` | `ROUserSessionTest` |
| `hmac.cc` | `HmacTest` | `ReadOnlySessionTest` | `ROUserSessionTest` |
| `keypair.cc` | `KeyPairTest` | `ReadWriteSessionTest` | `RWUserSessionTest` |

i.e. the cipher, signature, MAC and key-pair fixtures log in as the user before
generating their keys. To regenerate the patch against a newer revision, make
those same four base-class substitutions in a clean checkout and `git diff`.

Why: pkcs11test's fixtures encode the soft-token model, where key generation
and use work in a public session. On this token every key operation runs in an
authenticated device session (`CKF_LOGIN_REQUIRED`), which the spec permits:
`CKR_USER_NOT_LOGGED_IN` is a listed return of `C_GenerateKey`,
`C_EncryptInit` and friends. Without the patch every key-backed fixture fails
in set-up before reaching the behaviour under test; with it the same tests run
unchanged against the logged-in profile. Public-object and digest tests need no
login and are untouched. Auto-opening a device session for public sessions was
considered and rejected — it would defeat the login.

## What the gate covers today (130 of 330)

Digests (SHA-1/256/384/512, one-shot and multi-part, sizing, the operation
state machine), the library/slot/session/login surface, public data objects,
BER decoding, the AES-CBC one-shot cipher tests (round trip, sizing, wrong key,
IV validation, argument errors) and the operation-lifetime rules on the cipher
and digest entry points.

A full run reports 155 passing, but 25 of those assert nothing and are
deliberately **not** on the list: 23 that pkcs11test skips (the MD5 digest
parameter, token initialisation, the SO logins suppressed by `-X`,
`C_GetOperationState`, the dual-function digest+encrypt) and the two AES-ECB
IV cases, whose bodies return immediately for a mechanism that has no IV. They
come onto the list when the feature behind them lands.

Not yet covered, by bucket: the streaming cipher calls (`C_EncryptUpdate` and
friends — the AES streaming piece), mechanisms this module does not implement
(DES/3DES/AES-ECB, RSA, EC, sign/verify, HMAC, key pairs, wrap/unwrap, random
number generation beyond the pre-`C_Initialize` checks), entry points that are
stubs (`C_CopyObject`, `C_SetAttributeValue`, `C_GetObjectSize`,
`C_DigestKey`), key import through `C_CreateObject` with `CKA_VALUE` (the SDK
has none), and a few tests whose expectations assume a soft token — for
example `EncryptDecryptInitInvalid` wants `CKR_KEY_TYPE_INCONSISTENT` for an
advertised-but-unimplemented RSA mechanism, which resolves when the mechanism
table stops advertising it.

Two behaviours cannot be checked on the mock device at all, and are hardware
run items: a wrong PIN (the mock accepts any credential) and unmasking a
persisted key in a second process (the mock's masking key is process-local).
The gate also runs against the in-memory object store only; the persistent
backend (`AZIHSM_PKCS11_PERSIST=1`) has unit tests but no conformance run.

## Running it locally

```sh
cargo build -p azihsm_pkcs11 --features mock
plugins/azihsm_pkcs11/tests/pkcs11test/run.sh target/debug/azihsm_pkcs11.so
```

`tests/run_validation.sh` runs it too, when the mock module is present. For the
full picture rather than the gate, run the built tool from the work directory
without a filter:

```sh
cd "${TMPDIR:-/tmp}/azihsm-pkcs11test/src"
./pkcs11test -m azihsm_pkcs11.so -l <repo>/target/debug -s 0 -u 1234 -X
```
