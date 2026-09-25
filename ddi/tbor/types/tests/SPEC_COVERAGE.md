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

Test counts (last updated 2026-09-25):
* emu: 119 tests
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
| Happy path on Active CU session | ✅ | `session_close::session_close_cu_plaintext_active` |  |
| Happy path on Active CO session | ✅ | `session_close::session_close_co_authenticated_active` |  |
| Close a Pending-only slot (between Init and Finish) | ✅ | `session_close::session_close_pending_slot` |  |
| Unknown `session_id` → FW rejection | 🟡 | `session_close::session_close_unknown_id` | Asserts `DdiError::DdiError(_)` |
| Double-close of the same id → FW rejection | 🟡 | `session_close::session_close_double_close` | Asserts `DdiError::DdiError(_)` |
| Slot is freed for subsequent open after close | ✅ | `session_close::session_close_then_reopen` |  |
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
| CO session with default PSK → `DefaultPskMustRotate` (dispatcher gate) | ✅ | `part_init::fw_rejects::part_init_reject_default_psk_co` |  |
| CU session (under rotated PSK) → `InvalidPermissions` (handler role gate) | ✅ | `part_init::fw_rejects::part_init_reject_cu_session` | CU PSK rotated up-front so default-PSK gate doesn't fire first |
| Rotated CO session with malformed `PartPolicy` (all zeros) → `InvalidArg` (`policy::from_bytes` decode gate) | ✅ | `part_init::fw_rejects::part_init_reject_bad_policy` |  |
| Second `PartInit` after a successful one → `PtaKeyAlreadySet` (one-shot `part_set_pta_key` guard) | ✅ | `part_init::success_path::part_init_smoke_roundtrip` | Verified as step 2 of the smoke roundtrip |
| Concurrent valid `PartInit` requests → exactly one success; every loser gets `PtaKeyAlreadySet`; final state is `Initializing` | ✅ | `part_init::success_path::part_init_multi_threaded_single_winner` | Runs on emulator and hardware using the same active CO session; verifies the winning atomic commit through `PartInfo` |

### Happy-path invariants

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Returns DER-tagged (`0x30`) PKCS#10 CSR ≤ `PTA_CSR_MAX_LEN` | ✅ | `part_init::success_path::part_init_smoke_roundtrip` |  |
| CSR parses with `x509::X509Csr`; ECDSA-P384 self-signature verifies | ✅ | `part_init::success_path::part_init_smoke_roundtrip` |  |
| Returns CBOR-tagged (`0xD2` = COSE_Sign1) PTAReport ≤ `PTA_REPORT_MAX_LEN` | ✅ | `part_init::success_path::part_init_smoke_roundtrip` |  |
| PTAReport COSE_Sign1 verifies under PID-leaf pubkey (slot-0 cert chain leaf) | ✅ | `part_init::success_path::part_init_smoke_roundtrip` | Via `verify_pta_report` helper using `KeyAttester::verify` |
| PTAReport's embedded COSE_Key `(pk_x, pk_y)` matches CSR SPKI | ✅ | `part_init::success_path::part_init_smoke_roundtrip` | Cross-binds report to CSR pubkey |
| Cold-start determinism: same `(UDS, MachineSeed, Policy, POTA thumb)` → byte-identical PTA pubkey | ✅ | `part_init::success_path::part_init_determinism` | Uses `ctx.erase()` between runs |

### `mach_seed_envelope` AEAD bindings

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Ciphertext bit-flip → `AeadEnvelopeAuthFailed` | ✅ | `part_init::crypto_rejects::part_init_envelope_tampered` |  |
| AAD encodes wrong session id → `AeadEnvelopeAuthFailed` | ✅ | `part_init::crypto_rejects::part_init_wrong_session_id_in_aad` | Constant-compare path in `build_part_init_mach_seed_aad` |
| Envelope from a different session's `param_key` | ✅ | `part_init::crypto_rejects::part_init_envelope_from_other_session` | Two CO sessions sequentially (close A, open B); CO + Authenticated cannot run concurrent because of `VaultSessionLimitReached` |
| AAD length ≠ `PART_INIT_MACH_SEED_AAD_LEN` | ✅ | `part_init::crypto_rejects::part_init_wrong_aad_length` | 64-byte AAD; FW length-checks before AAD compare |
| `mach_seed` plaintext length ≠ `MACH_SEED_LEN` | ✅ 🔁 | `part_init::crypto_rejects::part_init_wrong_mach_seed_length` | Loop over `[MACH_SEED_LEN - 1, MACH_SEED_LEN + 1]`; one rotated-CO session reused across iterations (length check fires before any partition mutation) |
| Malformed `pota_thumbprint` length | ⚠️ | — | Wire field is fixed-size; FW reaction not exercised |

## `PartFinal` (opcode in-session, gated)

Backend note: emulator tests transport and validate the real PTA
certificate chain through OOB descriptors. Native M1.0 tests send one
schema-required placeholder descriptor with no OOB payload because the
current hardware firmware intentionally ignores certificate descriptors;
full native certificate-chain validation remains M1.5 work.

| Requirement | Status | Test | Notes |
|---|---|---|---|
| First instantiation returns a 260-byte `local_mk_backup` | ✅ | `part_final::part_final_smoke_roundtrip` | Original test body |
| Restore a prior backup with the same provisioning identity | ✅ | `part_final::part_final_restore_prev_backup` | Original test body |
| Tampered prior backup is rejected | 🟡 | `part_final::part_final_reject_tampered_backup` | Original test body; exact status is not pinned |
| Command before `PartInit` is rejected | 🟡 | `part_final::part_final_reject_wrong_state` | Original test body; exact status is not pinned |
| Re-supplied policy must match the `PartInit` policy hash | 🟡 | `part_final::part_final_reject_policy_mismatch` | Original test body; exact status is not pinned |
| PTA chain must anchor to policy POTA | 🟡 (emu) | `part_final::part_final_reject_unanchored_chain_emu` | Original test body; exact status is not pinned and full native chain validation is planned for M1.5 |
| PTA certificate key must match the partition PTA key | 🟡 (emu) | `part_final::part_final_reject_pta_mismatch_emu` | Original test body; exact status is not pinned and M1.0 hardware uses the documented surrogate |
| `Initialized` partition continues serving host IO | ✅ | `part_final::part_final_partition_serves_io_when_initialized` | Original dedicated regression |
| CU session is rejected with `InvalidPermissions` and CO can retry | ✅ | `part_final::part_final_rejects_cu_and_allows_co_retry` | Rotates the CU PSK first so the role gate is reached |
| Backup from a different machine-seed identity is rejected | ✅ | `part_final::part_final_rejects_backup_from_different_mach_seed` | Verifies identity/state remain stable and fresh finalization still succeeds |
| Second `PartFinal` is rejected without leaving `Initialized` | ✅ | `part_final::part_final_rejects_second_finalize` | Also verifies a reopened CO session still works |
| Concurrent valid `PartFinal` requests → exactly one success; every loser gets `InvalidArg` | ✅ | `part_final::part_final_multi_threaded_single_winner` | Runs on emulator and hardware using the same active CO session; the lifecycle transition to `Initialized` is what serialises the race, not any in-FSM flag |

## Default-PSK dispatcher gate (cross-cutting)

The gate (see `fw/core/lib/src/ddi/tbor/mod.rs::dispatch`) rejects
in-session commands not on the bootstrap allow-list when the calling
role's partition PSK still matches the compiled-in default.

| Spec arm | Status | Test | Notes |
|---|---|---|---|
| E1: `PskChange` is allow-listed (CO) | ✅ | `default_psk_gate::default_psk_gate_psk_change_bypass_emu` | CU implicitly via `psk_change_happy_cu_emu` |
| E2: `SessionClose` is allow-listed (both roles) | ✅ | `default_psk_gate::default_psk_gate_session_close_bypass_emu` |  |
| E3: `SessionOpenInit` is out-of-session (both roles) | ✅ | `default_psk_gate::default_psk_gate_session_open_init_bypass_emu` |  |
| E4: A non-allow-listed in-session command under default PSK is rejected with `DefaultPskMustRotate` | ✅ | `part_init::fw_rejects::part_init_reject_default_psk_co` | `PartInit` is currently the only such opcode; this row collapses what `default_psk_gate.rs` calls E4 |
| E5: `ApiRev` is out-of-session | ✅ | `default_psk_gate::default_psk_gate_api_rev_bypass_emu` |  |

## Host-side TBOR codec (no FW round-trip required)

| Requirement | Status | Test | Notes |
|---|---|---|---|


## `GetCertChainInfo` (opcode out-of-session)

Integration and host-side response-codec coverage for the TBOR
`GetCertChainInfo` command. The command reports the certificate count
and leaf-certificate SHA-256 thumbprint for a certificate-chain slot
without requiring an active session.

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Valid slot returns a non-empty certificate chain and a populated SHA-256 thumbprint | ✅ | `get_cert_chain_info::round_trip` | Exercises provisioned slot 0 and verifies `num_certs > 0`, fixed thumbprint length, and non-zero thumbprint data |
| `TborGetCertChainInfoReq::new` preserves `slot_id` across representative boundary values | ✅ 🔁 | `get_cert_chain_info::request_constructor_preserves_slot_id` | Covers `0`, `1`, `2`, `127`, `254`, and `u8::MAX` |
| Default request targets slot 0 | ✅ | `get_cert_chain_info::default_request_targets_slot_zero` | Verifies the derived `Default` request value |
| Default request is equivalent to explicit slot 0 | ✅ | `get_cert_chain_info::default_request_matches_explicit_slot_zero` | Compares complete FW responses |
| Repeated calls return stable metadata | ✅ | `get_cert_chain_info::repeated_stable` | Two consecutive calls return identical responses |
| Multiple consecutive calls remain stable | ✅ 🔁 | `get_cert_chain_info::repeated_calls_remain_stable` | Repeats the command several times to detect accidental mutable state |
| TBOR result matches MBOR `GetCertChainInfo` | ✅ | `get_cert_chain_info::matches_mbor_path` | Cross-checks both `num_certs` and leaf thumbprint against the shared certificate store |
| Reported `num_certs` defines the valid `GetCert` index range | ✅ 🔁 | `get_cert_chain_info::reported_count_defines_certificate_bounds` | Every advertised certificate is readable; index `num_certs` is rejected with `InvalidArg` |
| Maximum certificate index is rejected | ✅ | `get_cert_chain_info::maximum_certificate_index_rejected` | `u8::MAX` is outside the valid `0..num_certs` certificate index range |
| Reading certificates does not mutate chain metadata | ✅ | `get_cert_chain_info::certificate_reads_do_not_change_chain_info` | Compares metadata before and after reading every advertised certificate |
| Certificate bytes are stable across repeated reads | ✅ 🔁 | `get_cert_chain_info::certificates_are_stable_across_reads` | Reads every advertised certificate twice |
| Distinct certificate indices do not alias identical certificate bytes | ✅ 🔁 | `get_cert_chain_info::certificate_indices_do_not_alias` | Pairwise comparison across the advertised chain |
| Unsupported slot IDs are rejected with `InvalidArg` | ✅ 🔁 | `get_cert_chain_info::unsupported_slot_boundaries_rejected` | Covers `1`, `2`, `127`, `254`, and `u8::MAX` |
| First unsupported slot is rejected | ✅ | `get_cert_chain_info::first_unsupported_slot_rejected` | Explicit boundary test for slot 1 |
| Maximum `slot_id` is rejected | ✅ | `get_cert_chain_info::maximum_slot_id_rejected` | Explicit request-field boundary test for `u8::MAX` |
| A rejected slot request does not affect valid slot 0 | ✅ | `get_cert_chain_info::invalid_slot_does_not_affect_valid_slot` | Metadata before and after the rejected request must match |
| Repeated rejected slot requests do not affect valid slot 0 | ✅ 🔁 | `get_cert_chain_info::repeated_invalid_slots_do_not_affect_valid_slot` | Exercises several unsupported IDs before re-reading slot 0 |
| Out-of-session command remains stable across CO session activity | ✅ | `get_cert_chain_info::stable_across_co_session_activity` | Opens and closes a CO Authenticated session between reads |
| Out-of-session command remains callable while a CO session is active | ✅ | `get_cert_chain_info::callable_while_co_session_active` | Validates session independence while the CO session remains open |
| Out-of-session command remains stable across CU session activity | ✅ | `get_cert_chain_info::stable_across_cu_session_activity` | Uses the supported CU PlainText bootstrap session |
| Out-of-session command remains callable while a CU session is active | ✅ | `get_cert_chain_info::callable_while_cu_session_active` | Uses the supported CU PlainText bootstrap session |
| Response missing the thumbprint field is rejected as truncated | ✅ | `get_cert_chain_info::truncated_response_rejected` | Expects `DecodeError::MessageTruncated` |
| Response with maximum TOC entries decodes the known prefix | ✅ | `get_cert_chain_info::max_toc_response_decodes_known_fields` | Verifies forward compatibility with trailing unknown TOC fields |
| Single unknown trailing response field is ignored | ✅ | `get_cert_chain_info::trailing_unknown_field_is_ignored` | Known `num_certs` and thumbprint fields remain intact |
| Wrong TOC type for `num_certs` is rejected | ✅ | `get_cert_chain_info::wrong_num_certs_type_rejected` | Encodes `num_certs` as `Uint16`; expects `UnexpectedTocType` |
| Wrong TOC type for `thumbprint` is rejected | ✅ | `get_cert_chain_info::wrong_thumbprint_type_rejected` | Encodes the thumbprint as `Uint8`; expects `UnexpectedTocType` |

## `EccGenerateKey` (opcode in-session, gated)

Firmware integration coverage for the TBOR `EccGenerateKey` command. These tests exercise
the dispatcher and firmware through `TestCtx::tbor` / `expect_fw_reject`.

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Generates fresh ECC keypairs on all supported curves | ✅ | `ecc_generate_key::ecc_generate_key_all_curves` | Covers P-256, P-384, and P-521 and verifies distinct masked/private and public-key outputs. |
| Session-scoped generation is allowed before partition finalization | ✅ | `ecc_generate_key::ecc_generate_key_session_scope_before_finalize` | Session scope does not require Ephemeral or Local masking keys. |
| Crypto-User session may generate ECC keys | ✅ | `ecc_generate_key::ecc_generate_key_allowed_on_crypto_user_session` | Uses a rotated CU PSK and exercises all supported curves. |
| SecurityDomain scope is rejected before its masking key is provisioned | ✅ | `ecc_generate_key::ecc_generate_key_security_domain_scope_rejected` | Expects `UnsupportedKeyScope`. |
| Ephemeral scope is rejected before partition finalization | ✅ | `ecc_generate_key::ecc_generate_key_ephemeral_scope_before_finalize_rejected` | Expects `UnsupportedKeyScope`. |
| Local scope is rejected before partition finalization | ✅ | `ecc_generate_key::ecc_generate_key_local_scope_before_finalize_rejected` | Expects `UnsupportedKeyScope`. |
| Supported provisioned scopes generate valid keys | ✅ | `ecc_generate_key::ecc_generate_key_scopes` | Covers Session, Ephemeral, and Local scopes across all supported curves. |
| Unknown curve values are rejected | ✅ | `ecc_generate_key::ecc_generate_key_unknown_curve_rejected` | Covers values below/above the supported curve range and `u8::MAX`. |
| Unknown key scope is rejected | ✅ | `ecc_generate_key::ecc_generate_key_unknown_scope_rejected` | Expects `UnsupportedKeyScope`. |
| Mismatched session id is rejected | ✅ | `ecc_generate_key::ecc_generate_key_mismatched_session_id_rejected` | Exercises the invalid session id on all supported curves. |
| DERIVE key usage is accepted | ✅ | `ecc_generate_key::ecc_generate_key_derive_usage` | Generates a derive-capable P-256 ECC key. |
| DERIVE key usage is accepted on all supported curves | ✅ | `ecc_generate_key::ecc_generate_key_derive_usage_all_curves` | Covers P-256, P-384, and P-521. |
| Non-empty key label is accepted | ✅ | `ecc_generate_key::ecc_generate_key_non_empty_label_all_curves` | Exercises a non-empty label on all supported ECC curves. |
| One-byte key label is accepted | ✅ | `ecc_generate_key::ecc_generate_key_one_byte_label` | Covers the smallest non-empty key label. |
| Maximum key-label length is accepted | ✅ | `ecc_generate_key::ecc_generate_key_max_label_length_all_curves` | Exercises `TBOR_KEY_LABEL_MAX_LEN` on all supported ECC curves. |
| Key label longer than the maximum is rejected | ✅ | `ecc_generate_key::ecc_generate_key_label_too_long_rejected` | Expects `TborInvalidFixedLength`. |
| Binary key label is accepted | ✅ | `ecc_generate_key::ecc_generate_key_binary_label` | Covers arbitrary non-text label bytes including `0x00`, `0x80`, and `0xff`. |
| DERIVE usage accepts valid key labels | ✅ | `ecc_generate_key::ecc_generate_key_derive_usage_with_labels_all_curves` | Covers non-empty and maximum-length labels with DERIVE on all supported ECC curves. |
| Default CO PSK is rejected | ✅ | `ecc_generate_key::ecc_generate_key_rejects_default_co_psk` | Expects `DefaultPskMustRotate`. |
| SIGN and DERIVE combined usage is rejected | ✅ | `ecc_generate_key::ecc_generate_key_sign_and_derive_usage_rejected` | Expects `InvalidPermissions`. |
| Empty key-usage bitfield is rejected | ✅ | `ecc_generate_key::ecc_generate_key_zero_usage_rejected` | `key_usage = 0` expects `InvalidPermissions`. |
| Unknown key-usage bits are rejected | ✅ | `ecc_generate_key::ecc_generate_key_unknown_usage_rejected` | Uses an unsupported high usage bit and expects `InvalidPermissions`. |
| Defined but invalid ECC key usages are rejected | ✅ | `ecc_generate_key::ecc_generate_key_known_invalid_usages_rejected` | Covers ENCRYPT, DECRYPT, VERIFY, WRAP, UNWRAP, and invalid usage combinations. |
| Closed session is rejected | ✅ | `ecc_generate_key::ecc_generate_key_closed_session_rejected` | Attempts generation after session close on P-256, P-384, and P-521 and expects `SessionNotFound`. |
| Session-scoped generation succeeds after closing and reopening the CO session | ✅ | `ecc_generate_key::ecc_generate_key_session_scope_after_reopen` | Confirms a newly opened authenticated CO session can generate a Session-scoped key. |

## `EcdhDerive` (opcode in-session, gated)

| Requirement | Status | Test | Notes |
|---|---|---|---|
| Derive succeeds for P-256, P-384, and P-521 | ✅ 🔁 | `ecdh_derive::ecdh_derive_all_curves` | Loops over all three supported curves and validates the returned masked-secret envelope length |
| Derived result can be returned under Session, Ephemeral, and Local scopes | ✅ 🔁 | `ecdh_derive::ecdh_derive_scopes` | Loops over all provisioned output scopes |
| CO session using the default PSK → `DefaultPskMustRotate` | ✅ | `ecdh_derive::ecdh_derive_rejects_default_co_psk` | Verifies the dispatcher gate for CO before ECDH field validation |
| CU session using the default PSK → `DefaultPskMustRotate` | ✅ | `ecdh_derive::ecdh_derive_rejects_default_cu_psk` | Verifies the dispatcher gate for CU before ECDH field validation |
| Peer public key shorter than the required wire length → `InvalidArg` | ✅ 🔁 | `ecdh_derive::ecdh_derive_bad_peer_pub_len_rejected` | Loops over P-256, P-384, and P-521; each peer key is truncated by one byte |
| P-256 peer public key with one trailing byte → `InvalidArg` | ✅ | `ecdh_derive::ecdh_derive_p256_peer_pub_trailing_byte_rejected` | 64-byte valid peer key becomes 65 bytes and reaches ECDH length validation |
| P-384 peer public key with one trailing byte → `InvalidArg` | ✅ | `ecdh_derive::ecdh_derive_p384_peer_pub_trailing_byte_rejected` | 96-byte valid peer key becomes 97 bytes and reaches ECDH length validation |
| P-521 peer public key with one trailing byte → `TborInvalidFixedLength` | ✅ | `ecdh_derive::ecdh_derive_p521_peer_pub_trailing_byte_rejected` | Valid P-521 peer key already occupies the 136-byte TBOR maximum; 137 bytes is rejected during TBOR decoding |
| Peer public key wire size belongs to a different curve → `InvalidArg` | ✅ 🔁 | `ecdh_derive::ecdh_derive_peer_curve_mismatch_rejected` | Covers all six local/peer mismatched-curve combinations |
| Peer coordinates fail coordinate/public-key validation → `EccPublicKeyValidationFailed` | ✅ 🔁 | `ecdh_derive::ecdh_derive_invalid_peer_coordinates_rejected` | Loops over P-256, P-384, and P-521 using all-zero peer coordinates |
| P-256 peer coordinates exceed the field upper bound → `EccPublicKeyValidationFailed` | ✅ | `ecdh_derive::ecdh_derive_peer_coordinates_above_upper_bound_rejected` | Uses all-ones coordinates to exercise the coordinate upper-bound validation branch |
| In-range P-256 peer coordinates that are not on the curve → `EccPointValidationFailed` | ✅ | `ecdh_derive::ecdh_derive_off_curve_peer_point_rejected` | Uses `(1, 1)` to reach the separate curve-equation validation branch |
| Tampered masked private-key envelope → `AesGcmDecryptTagDoesNotMatch` | ✅ | `ecdh_derive::ecdh_derive_tampered_masked_key_rejected` | Flips one byte in the authenticated masked-key envelope |
| Masked key is not an ECC private key → `InvalidKeyType` | ✅ | `ecdh_derive::ecdh_derive_wrong_key_class_rejected` | Supplies a valid masked AES key |
| SecurityDomain output scope is not provisioned → `UnsupportedKeyScope` | ✅ | `ecdh_derive::ecdh_derive_unsupported_target_scope_rejected` | Requests SecurityDomain result scope |
| Request session id does not match active handle session → `FileHandleSessionIdDoesNotMatch` | ✅ | `ecdh_derive::ecdh_derive_unknown_session_rejected` | Uses `u16::MAX` as an unused session id |
| Session-scoped ECC keys and derived results work before partition finalization | ✅ | `ecdh_derive::ecdh_derive_session_scope_before_finalize` | Uses a rotated CO session before `PartFinal` |
| Crypto-User session is authorized to derive | ✅ | `ecdh_derive::ecdh_derive_allowed_on_crypto_user_session` | Rotates the CU PSK first so the command reaches its handler |
| Imported ECC private key with `KEY_USAGE_DERIVE` can derive | ✅ | `ecdh_derive::ecdh_derive_with_unwrapped_key` | Imports host-generated P-256 PKCS#8 material through `UnwrapKey` |
| Imported ECC private key without Derive permission → `InvalidPermissions` | ✅ | `ecdh_derive::ecdh_derive_key_without_derive_usage_rejected` | Key has Sign/Verify usage only |
| Empty peer public key → `InvalidArg` | ✅ | `ecdh_derive::ecdh_derive_empty_peer_pub_rejected` |  |
| Empty masked private-key envelope → `TborInvalidFixedLength` | ✅ | `ecdh_derive::ecdh_derive_empty_masked_key_rejected` |  |
| Truncated masked private-key envelope → `TborInvalidFixedLength` | ✅ | `ecdh_derive::ecdh_derive_truncated_masked_key_rejected` | Removes one byte from an otherwise valid envelope |
| Unknown output-scope discriminant → `UnsupportedKeyScope` | ✅ | `ecdh_derive::ecdh_derive_invalid_scope_rejected` | Uses scope `0xff` |
| Local result scope before partition finalization → `UnsupportedKeyScope` | ✅ | `ecdh_derive::ecdh_derive_local_target_before_finalize_rejected` | Input key remains Session scoped so the output-scope gate is isolated |
| Ephemeral result scope before partition finalization → `UnsupportedKeyScope` | ✅ | `ecdh_derive::ecdh_derive_ephemeral_target_before_finalize_rejected` | Input key remains Session scoped so the output-scope gate is isolated |
| Session-scoped private key cannot be reused after its originating session closes | ✅ | `ecdh_derive::ecdh_derive_session_key_from_other_session_rejected` | Reopened session cannot authenticate the old session-scoped masked key |
| Local-scoped private key remains usable after session close and reopen | ✅ | `ecdh_derive::ecdh_derive_local_key_across_sessions` | Confirms Local masking scope survives the session lifecycle |
 | Non-empty key labels are accepted | ✅ | `ecdh_derive::ecdh_derive_non_empty_key_label` |  |
 | Key label at `TBOR_KEY_LABEL_MAX_LEN` is accepted | ✅ | `ecdh_derive::ecdh_derive_max_key_label_length` |  |
 | Key label over `TBOR_KEY_LABEL_MAX_LEN` → `TborInvalidFixedLength` | ✅ | `ecdh_derive::ecdh_derive_key_label_too_long_rejected` |  |
 | Distinct non-empty key labels are accepted for identical ECDH inputs | ✅ | `ecdh_derive::ecdh_derive_different_labels_succeed` |  |
 | Binary key labels are accepted | ✅ | `ecdh_derive::ecdh_derive_binary_key_label` |  |
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

1. `session_close::session_close_unknown_id` — likely `SessionNotFound`.
2. `session_close::session_close_double_close` — likely `SessionNotFound`.
3. `open_session::session_open_finish_unknown_session_id_emu` — likely `SessionNotFound` or `SessionNotPending`.
4. `open_session::open_session_double_finish_emu` — likely `SessionNotPending`.
5. `part_final::part_final_reject_tampered_backup` — expected `AesGcmDecryptTagDoesNotMatch`.
6. `part_final::part_final_reject_wrong_state` — expected `InvalidArg`.
7. `part_final::part_final_reject_policy_mismatch` — expected `InvalidArg`.
8. `part_final::part_final_reject_unanchored_chain_emu` — expected `InvalidArg`.
9. `part_final::part_final_reject_pta_mismatch_emu` — expected `PartFinalPtaMismatch`.

---

## Maintenance rules

* Adding a test → add the row (or extend the existing row's "Notes" with the new sub-case label) in the same PR.
* Renaming a test → rename in this file in the same PR.
* Deleting / collapsing tests → either re-point the row at the new test or, if a requirement is genuinely no longer covered, downgrade ✅ to ⚠️ and add it to the "Known gaps" list.
* Adding a new TBOR opcode → add a new section with the same row template (happy path, gates, AEAD bindings if applicable, default-PSK arm).
* Status arms enumerated in [`status.rs`](../src/status.rs) that are not surfaced by any landed TBOR command's handler do **not** belong in this matrix — they belong to MBOR / other DDI coverage.
