<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# TBOR DDI Test Coverage Matrix

This file maps each TBOR wire-protocol requirement (spec arm, gate, or
invariant) to the integration test that proves it. It is maintained
alongside the test suite: when a test is added, renamed, deleted, or
collapsed into a `for` loop, update the row(s) that reference it in the
same PR.

Source of truth for each command's wire shape, status arms, and
preconditions: [`docs/tbor-ddi/`](../../../../docs/tbor-ddi/).
Source of truth for the `TborStatus` enum:
[`ddi/tbor/types/src/status.rs`](../src/status.rs).

Test counts (last updated 2026-06-08):
* emu: 50 tests
* mock: 6 tests

## Legend

| Symbol | Meaning |
|---|---|
| ✅ | Covered by at least one test that asserts the specific status / behavior |
| 🔁 | Covered by a `for`-loop sub-case inside the named test |
| 🟡 | Covered indirectly — test asserts `DdiError::DdiError(_)` rather than a specific `TborStatus` |
| ⚠️ | Gap — no current test covers this arm |
| n/a | Not applicable on this backend |

All test names below are relative to the
`commands::` module of the `azihsm_ddi_tbor_tests` test binary
(`ddi/tbor/types/tests/azihsm_ddi_tbor_tests.rs`).

---

## `ApiRev` (opcode out-of-session)

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Round-trip returns wire-correct `TborApiRevResp` | ✅ | `api_rev::round_trip_emu` |  |
| Repeated calls return stable values | ✅ | `api_rev::api_rev_repeated_stable_emu` | Smoke for transport idempotence |
| Independent of session state (no session open, then open, then close — all succeed) | ✅ | `api_rev::api_rev_independent_of_session_state_emu` | Proves the dispatcher does not gate `ApiRev` on session presence |
| Default-PSK gate bypass (E5) | ✅ | `default_psk_gate::default_psk_gate_api_rev_bypass_emu` | Out-of-session opcodes are never default-PSK-gated |
| Mock backend rejects the opcode at the transport layer | ✅ (mock) | `api_rev::unsupported_on_mock` | Mock has no TBOR-capable transport |

## `SessionOpenInit` (opcode out-of-session, phase 1 of handshake)

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Happy path (CO + Authenticated) | ✅ | `open_session::open_session_co_authenticated_happy_emu` |  |
| Happy path (CU + PlainText) | ✅ | `open_session::open_session_cu_plaintext_happy_emu` |  |
| Role gate: CO + PlainText → `InvalidSessionType` | ✅ | `open_session::open_session_co_plaintext_rejected_emu` |  |
| Role gate: CU + Authenticated → `InvalidSessionType` | ✅ | `open_session::open_session_cu_authenticated_rejected_emu` |  |
| `psk_id` not in `{0, 1}` → `InvalidPskId` | ✅ 🔁 | `open_session::open_session_invalid_psk_id_emu` | Loop over `[2, 0x7F, 0xFF]` |
| `session_type` byte not in `{0, 1}` → `InvalidSessionType` | ✅ | `open_session::open_session_invalid_session_type_byte_emu` | Bypasses typed enum; ships raw byte `42` |
| `suite_id` not in `{0x01}` → `UnsupportedSessionSuite` | ✅ 🔁 | `open_session::open_session_unsupported_suite_id_emu` | Loop over `[0x00, 0x02, 0xff]` |
| Default-PSK gate bypass (E3, both roles) | ✅ | `default_psk_gate::default_psk_gate_session_open_init_bypass_emu` |  |
| Multiple concurrent sessions return distinct session ids | ✅ | `open_session::open_session_multiple_concurrent_emu` |  |
| Malformed `pk_init` (length / curve) | ⚠️ | — | Spec arm exists in handler; no negative test |

## `SessionOpenFinish` (opcode out-of-session, phase 2 of handshake)

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Phase-2 MAC bit-flip → `SessionAuthFailure` | ✅ | `open_session::session_open_finish_mac_tampered_emu` | Also: FW destroys the pending slot on MAC mismatch |
| Phase-2 `seed_envelope` tamper → `SessionAuthFailure` | ✅ | `open_session::session_open_finish_seed_envelope_tampered_emu` | Syntactically valid header, bogus IV/CT/tag |
| Unknown `session_id` → FW rejection | 🟡 | `open_session::session_open_finish_unknown_session_id_emu` | Asserts `DdiError::DdiError(_)`; specific status not pinned |
| Second `Finish` against an already-completed slot → FW rejection | 🟡 | `open_session::open_session_double_finish_emu` | Asserts `DdiError::DdiError(_)` |
| Finish against a pending slot whose Init was for a different role | ⚠️ | — | Spec arm exists; not exercised |

## `SessionClose` (opcode in-session, allow-listed)

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Happy path on Active CU session | ✅ | `session_close::session_close_cu_plaintext_active_emu` |  |
| Happy path on Active CO session | ✅ | `session_close::session_close_co_authenticated_active_emu` |  |
| Close a Pending-only slot (between Init and Finish) | ✅ | `session_close::session_close_pending_slot_emu` |  |
| Unknown `session_id` → FW rejection | 🟡 | `session_close::session_close_unknown_id_emu` | Asserts `DdiError::DdiError(_)` |
| Double-close of the same id → FW rejection | 🟡 | `session_close::session_close_double_close_emu` | Asserts `DdiError::DdiError(_)` |
| Slot is freed for subsequent open after close | ✅ | `session_close::session_close_then_reopen_emu` |  |
| Default-PSK gate bypass (E2, both roles) | ✅ | `default_psk_gate::default_psk_gate_session_close_bypass_emu` |  |

## `PskChange` (opcode in-session, allow-listed)

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Happy path (CU); rotation took effect (reopen under rotated bytes succeeds) | ✅ | `psk_change::psk_change_happy_cu_emu` | Shared body via `run_psk_change_happy` |
| Happy path (CO); rotation took effect | ✅ | `psk_change::psk_change_happy_co_emu` |  |
| Reopen with old default PSK fails after rotation | ✅ | `psk_change::psk_change_reopen_with_old_psk_fails_emu` | Either host- or FW-side rejection accepted |
| One-shot per session: second `PskChange` on same session → `InvalidPermissions` | ✅ | `psk_change::psk_change_second_attempt_same_session_fails_emu` |  |
| Envelope ciphertext bit-flip → `AeadEnvelopeAuthFailed` | ✅ 🔁 | `psk_change::psk_change_envelope_tampered_emu` | Loop over `[ct_flip, aad_flip]` |
| Envelope AAD bit-flip → `AeadEnvelopeAuthFailed` | ✅ 🔁 | `psk_change::psk_change_envelope_tampered_emu` | Same test, second sub-case |
| Empty `psk_envelope` → `InvalidArg` | ✅ | `psk_change::psk_change_empty_envelope_emu` |  |
| AAD encodes wrong session id (rest of envelope is valid) → `AeadEnvelopeAuthFailed` | ✅ | `psk_change::psk_change_wrong_session_id_in_aad_emu` | FW recomputes AEAD-GCM tag over caller-supplied AAD, then constant-compares against `build_psk_change_aad(req.session_id)` |
| Envelope encrypted under a different session's `param_key` → `AeadEnvelopeAuthFailed` | ✅ | `psk_change::psk_change_envelope_from_other_session_emu` | Session A's `param_key` + session B's id |
| Plaintext length ≠ `PSK_LEN` → `InvalidArg` | ✅ 🔁 | `psk_change::psk_change_wrong_plaintext_length_emu` | Loop over `[PSK_LEN - 1, PSK_LEN + 1]` |
| AAD length ≠ `PSK_CHANGE_AAD_LEN` → `InvalidArg` | ✅ | `psk_change::psk_change_wrong_aad_length_emu` | 64-byte AAD: AEAD-open succeeds but FW length-checks before AAD compare |
| Default-PSK gate bypass (E1, CO) | ✅ | `default_psk_gate::default_psk_gate_psk_change_bypass_emu` | CU bypass implicitly exercised by `psk_change_happy_cu_emu` |

## `PartInit` (opcode in-session, gated)

### Dispatcher / handler gates (reject before partition state mutation)

| Requirement | Status | Test | Notes |
|---|---|---|---|
| CO session with default PSK → `DefaultPskMustRotate` (dispatcher gate) | ✅ | `part_init::fw_rejects::part_init_reject_default_psk_co_emu` |  |
| CU session (under rotated PSK) → `InvalidPermissions` (handler role gate) | ✅ | `part_init::fw_rejects::part_init_reject_cu_session_emu` | CU PSK rotated up-front so default-PSK gate doesn't fire first |
| Rotated CO session with malformed `PartPolicy` (all zeros) → `InvalidArg` (`policy::from_bytes` decode gate) | ✅ | `part_init::fw_rejects::part_init_reject_bad_policy_emu` |  |
| Second `PartInit` after a successful one → `PtaKeyAlreadySet` (one-shot `part_set_pta_key` guard) | ✅ | `part_init::happy_path::part_init_smoke_roundtrip_emu` | Verified as step 2 of the smoke roundtrip |

### Happy-path invariants

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Returns DER-tagged (`0x30`) PKCS#10 CSR ≤ `PTA_CSR_MAX_LEN` | ✅ | `part_init::happy_path::part_init_smoke_roundtrip_emu` |  |
| CSR parses with `x509::X509Csr`; ECDSA-P384 self-signature verifies | ✅ | `part_init::happy_path::part_init_smoke_roundtrip_emu` |  |
| Returns CBOR-tagged (`0xD2` = COSE_Sign1) PTAReport ≤ `PTA_REPORT_MAX_LEN` | ✅ | `part_init::happy_path::part_init_smoke_roundtrip_emu` |  |
| PTAReport COSE_Sign1 verifies under PID-leaf pubkey (slot-0 cert chain leaf) | ✅ | `part_init::happy_path::part_init_smoke_roundtrip_emu` | Via `verify_pta_report` helper using `KeyAttester::verify` |
| PTAReport's embedded COSE_Key `(pk_x, pk_y)` matches CSR SPKI | ✅ | `part_init::happy_path::part_init_smoke_roundtrip_emu` | Cross-binds report to CSR pubkey |
| Cold-start determinism: same `(UDS, MachineSeed, Policy, POTA thumb)` → byte-identical PTA pubkey | ✅ | `part_init::happy_path::part_init_determinism_emu` | Uses `ctx.erase()` between runs |

### `mach_seed_envelope` AEAD bindings

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Ciphertext bit-flip → `AeadEnvelopeAuthFailed` | ✅ | `part_init::crypto_rejects::part_init_envelope_tampered_emu` |  |
| AAD encodes wrong session id → `AeadEnvelopeAuthFailed` | ✅ | `part_init::crypto_rejects::part_init_wrong_session_id_in_aad_emu` | Constant-compare path in `build_part_init_mach_seed_aad` |
| Envelope from a different session's `param_key` | ✅ | `part_init::crypto_rejects::part_init_envelope_from_other_session_emu` | Two CO sessions sequentially (close A, open B); CO + Authenticated cannot run concurrent because of `VaultSessionLimitReached` |
| AAD length ≠ `PART_INIT_MACH_SEED_AAD_LEN` | ✅ | `part_init::crypto_rejects::part_init_wrong_aad_length_emu` | 64-byte AAD; FW length-checks before AAD compare |
| `mach_seed` plaintext length ≠ `MACH_SEED_LEN` | ✅ 🔁 | `part_init::crypto_rejects::part_init_wrong_mach_seed_length_emu` | Loop over `[MACH_SEED_LEN - 1, MACH_SEED_LEN + 1]`; one rotated-CO session reused across iterations (length check fires before any partition mutation) |
| Malformed `pota_thumbprint` length | ⚠️ | — | Wire field is fixed-size; FW reaction not exercised |

## Default-PSK dispatcher gate (cross-cutting)

The gate (see `fw/core/lib/src/ddi/tbor/mod.rs::dispatch`) rejects
in-session commands not on the bootstrap allow-list when the calling
role's partition PSK still matches the compiled-in default.

| Spec arm | Status | Test | Notes |
|---|---|---|---|
| E1: `PskChange` is allow-listed (CO) | ✅ | `default_psk_gate::default_psk_gate_psk_change_bypass_emu` | CU implicitly via `psk_change_happy_cu_emu` |
| E2: `SessionClose` is allow-listed (both roles) | ✅ | `default_psk_gate::default_psk_gate_session_close_bypass_emu` |  |
| E3: `SessionOpenInit` is out-of-session (both roles) | ✅ | `default_psk_gate::default_psk_gate_session_open_init_bypass_emu` |  |
| E4: A non-allow-listed in-session command under default PSK is rejected with `DefaultPskMustRotate` | ✅ | `part_init::fw_rejects::part_init_reject_default_psk_co_emu` | `PartInit` is currently the only such opcode; this row collapses what `default_psk_gate.rs` calls E4 |
| E5: `ApiRev` is out-of-session | ✅ | `default_psk_gate::default_psk_gate_api_rev_bypass_emu` |  |

## Host-side TBOR codec (no FW round-trip required)

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Empty response surfaces FW status without attempting body decode | ✅ | `fw_error_decode::empty_response_surfaces_fw_status` | Mock + emu |
| Non-empty error response surfaces FW status before schema decode | ✅ | `fw_error_decode::fields_response_surfaces_fw_status_before_schema_decode` | Mock + emu |
| `status == 0` with a valid body still decodes the body | ✅ | `fw_error_decode::zero_status_with_valid_body_still_decodes` | Mock + emu |
| TOC entry of wrong type yields `TborDecodeError::UnexpectedTocType` | ✅ | `unexpected_toc_type::wrong_toc_entry_type_yields_unexpected_toc_type` | Mock + emu |
| `mach_seed` AAD wire-layout encoder stability | ✅ | `harness::session::part_init::tests::mach_seed_aad_layout` | Unit test; pure host-side |

---

## Known gaps (summary)

The rows marked ⚠️ above, consolidated:

1. **`SessionOpenInit`**: malformed `pk_init` (length / curve) — no negative test.
2. **`SessionOpenFinish`**: Finish against a pending slot opened for a different role — no test.
3. **`PartInit` wire fields**: `pota_thumbprint` is fixed-size on the wire so the FW reaction to a malformed value is not exercised; would require host-side encoding bypass.

Indirect coverage (🟡) — these rows assert only `DdiError::DdiError(_)`
and could be tightened to assert a specific `TborStatus`:

1. `session_close::session_close_unknown_id_emu` — likely `SessionNotFound`.
2. `session_close::session_close_double_close_emu` — likely `SessionNotFound`.
3. `open_session::session_open_finish_unknown_session_id_emu` — likely `SessionNotFound` or `SessionNotPending`.
4. `open_session::open_session_double_finish_emu` — likely `SessionNotPending`.

---

## Maintenance rules

* Adding a test → add the row (or extend the existing row's "Notes" with the new sub-case label) in the same PR.
* Renaming a test → rename in this file in the same PR.
* Deleting / collapsing tests → either re-point the row at the new test or, if a requirement is genuinely no longer covered, downgrade ✅ to ⚠️ and add it to the "Known gaps" list.
* Adding a new TBOR opcode → add a new section with the same row template (happy path, gates, AEAD bindings if applicable, default-PSK arm).
* Status arms enumerated in [`status.rs`](../src/status.rs) that are not surfaced by any landed TBOR command's handler do **not** belong in this matrix — they belong to MBOR / other DDI coverage.
