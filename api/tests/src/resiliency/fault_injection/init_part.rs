// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests for `init` (partition initialization).
//!
//! These tests exercise the retry-with-backoff machinery on
//! [`HsmPartition::init`] by injecting transient DDI faults through
//! the resiliency test device.
//!
//! Unlike `open_partition` (which retries unconditionally),
//! `init_part` only retries when a resiliency config is provided.
//!
//! The DDI operations exercised during init depend on the source:
//!
//! **Caller-source path** (default, `AZIHSM_USE_TPM` not set):
//!
//! | Step | DDI op                          |
//! |------|---------------------------------|
//! | 1    | `InitBk3`                       |
//! | 2    | `GetCertChainInfo` (POTA)       |
//! | 3    | `GetCertificate` (POTA)         |
//! | 4    | `GetEstablishCredEncryptionKey` |
//! | 5    | `EstablishCredential`           |
//!
//! **TPM-source path** (`AZIHSM_USE_TPM` set):
//!
//! | Step | DDI op                          |
//! |------|---------------------------------|
//! | 1    | `GetSealedBk3` + TPM unseal     |
//! | 2    | `GetCertChainInfo` + TPM sign    |
//! | 3    | `GetCertificate` + TPM sign     |
//! | 4    | `GetEstablishCredEncryptionKey` |
//! | 5    | `EstablishCredential`           |
//!
//! On retries with caller-source POTA, the `PotaEndorsementCallback`
//! is invoked to re-endorse over the current device's PID public key.
//!
//! Tests targeting `InitBk3` and POTA callback are caller-only and
//! are skipped when `AZIHSM_USE_TPM` is set. Tests targeting
//! `GetSealedBk3` are TPM-only and are skipped when it is not set.
//! Tests targeting `GetEstablishCredEncryptionKey` and
//! `EstablishCredential` run on both paths.
//!
//! # Adding a new retryable error
//!
//! Append the new [`FaultError`] variant to [`INIT_RETRYABLE_ERRORS`]
//! (and to [`super::ALL_RETRYABLE_ERRORS`] if it's new globally).
//! All loop-based tests will automatically cover it. To add a
//! non-retryable error, append to [`super::NON_RETRYABLE_ERRORS`].

use azihsm_res_test_dev::*;

use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

/// All error codes that trigger `init_part` retry when resiliency is
/// enabled. Includes transient IO-abort conditions (retried by all
/// resiliency-enabled paths) and credential/provisioning failures
/// specific to `init_part`.
const INIT_RETRYABLE_ERRORS: &[FaultError] = &[
    // IO-abort errors (shared with open_partition, open_session, etc.)
    FaultError::Driver(DriverError::IoAborted),
    FaultError::Driver(DriverError::IoAbortInProgress),
    FaultError::Status(DdiStatus::CredentialsNotEstablished),
    FaultError::Status(DdiStatus::NonceMismatch),
    FaultError::Status(DdiStatus::PartitionNotProvisioned),
    FaultError::Status(DdiStatus::EccVerifyFailed),
];

/// Returns `true` when `error` is one of the init-retryable error codes.
fn is_init_retryable(error: &FaultError) -> bool {
    INIT_RETRYABLE_ERRORS.iter().any(|e| e == error)
}

/// Error codes that `init()` treats as "credentials already established"
/// and converts into `Ok(())` at the `HsmPartition::init` level, even
/// though they are not retried by the `#[resiliency_init_part]` macro.
const CREDENTIALS_ALREADY_ESTABLISHED_ERRORS: &[FaultError] = &[
    FaultError::Status(DdiStatus::KeyNotFound),
    FaultError::Status(DdiStatus::PartitionAlreadyProvisioned),
    FaultError::Status(DdiStatus::VaultAppLimitReached),
];

/// Returns `true` when `error` produces `Ok` from `HsmPartition::init()`,
/// either because the macro retries and succeeds, or because `init()`
/// itself handles it as "credentials already established".
fn is_init_ok_outcome(error: &FaultError) -> bool {
    is_init_retryable(error)
        || CREDENTIALS_ALREADY_ESTABLISHED_ERRORS
            .iter()
            .any(|e| e == error)
}

/// Returns `true` when a single fault of `error` on `EstablishCredential`
/// is recoverable.
///
/// This is broader than [`is_init_retryable`] because
/// `try_establish_credential` has an internal one-shot retry for
/// `MaskedKeyDecodeFailed` (clears the stale BMK and re-attempts with
/// empty BMK/MUK). A single `MaskedKeyDecodeFailed` fault is therefore
/// consumed by that internal recovery before the outer retry loop ever
/// sees it.
fn is_establish_credential_single_fault_recoverable(error: &FaultError) -> bool {
    is_init_ok_outcome(error) || *error == FaultError::Status(DdiStatus::MaskedKeyDecodeFailed)
}

/// Expected number of times `target_op` is invoked in a fault-injection
/// test.
///
/// * Retryable errors (macro-level retry): `min(injected_faults + 1, MAX_RETRIES + 1)`.
///   The `+1` accounts for the successful call after all faults are
///   consumed, capped by the maximum number of attempts.
/// * "Credentials already established" errors: 1. These are not retried
///   by the macro but are caught by `init()` at the outer level, so the
///   DDI op is only called once.
/// * `MaskedKeyDecodeFailed` on `EstablishCredential`: at most 2,
///   from `try_establish_credential`'s internal one-shot retry.
/// * All other non-retryable errors: 1 (single failed call).
fn expected_op_calls(error: &FaultError, target_op: DdiOp, injected_faults: u32) -> u32 {
    if is_init_retryable(error) {
        // Retried by the `#[resiliency_init_part]` macro.
        (injected_faults + 1).min(MAX_RETRIES + 1)
    } else if CREDENTIALS_ALREADY_ESTABLISHED_ERRORS
        .iter()
        .any(|e| e == error)
    {
        // Caught by `init()` at the outer level — no retry, just 1 call.
        1
    } else if target_op == DdiOp::EstablishCredential
        && *error == FaultError::Status(DdiStatus::MaskedKeyDecodeFailed)
    {
        // try_establish_credential retries once internally on
        // MaskedKeyDecodeFailed, consuming at most 2 calls.
        2.min(injected_faults + 1)
    } else {
        1
    }
}

/// Helper: open the first partition and reset it for a fresh init.
fn open_and_reset() -> HsmPartition {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    let part =
        HsmPartitionManager::open_partition(&list[0].path).expect("Failed to open partition");
    part.reset().expect("Partition reset failed");
    part
}

/// Helper: call `part.init(...)` with resiliency enabled.
fn init_with_resiliency(part: &HsmPartition) -> HsmResult<()> {
    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(part);
    let (resiliency_config, _ctx) = make_resiliency_config(part);
    part.init(
        creds,
        None,
        None,
        obk_info,
        pota_endorsement,
        Some(resiliency_config),
    )
}

/// `init` recovers from a single transient fault on `InitBk3` for
/// retryable error codes, and fails immediately for non-retryable ones.
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set.
#[api_test]
fn test_init_recovers_from_init_bk3_single_fault() {
    if use_tpm() {
        return;
    }
    for error in &super::all_test_errors() {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::InitBk3);

        inject_fault(FaultRule::fail_nth(DdiOp::InitBk3, 1, *error));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::InitBk3);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_init_ok_outcome,
            "single fault on InitBk3",
        );

        let expected = expected_op_calls(error, DdiOp::InitBk3, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on InitBk3: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `init` recovers from a single transient fault on
/// `GetEstablishCredEncryptionKey` for retryable error codes, and fails
/// immediately for non-retryable ones.
#[api_test]
fn test_init_recovers_from_get_establish_cred_key_single_fault() {
    for error in &super::all_test_errors() {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::GetEstablishCredEncryptionKey);

        inject_fault(FaultRule::fail_nth(
            DdiOp::GetEstablishCredEncryptionKey,
            1,
            *error,
        ));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::GetEstablishCredEncryptionKey);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_init_ok_outcome,
            "single fault on GetEstablishCredEncryptionKey",
        );

        let expected = expected_op_calls(error, DdiOp::GetEstablishCredEncryptionKey, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on GetEstablishCredEncryptionKey: expected {expected} calls for \
             {error:?}, got {}",
            after - before,
        );
    }
}

/// `init` recovers from a single transient fault on
/// `EstablishCredential` for retryable error codes, and fails
/// immediately for non-retryable ones.
///
/// Note: `MaskedKeyDecodeFailed` is also recoverable here because
/// `try_establish_credential` handles it internally (clears stale BMK
/// and retries once), so a single fault is consumed before the outer
/// retry loop.
#[api_test]
fn test_init_recovers_from_establish_credential_single_fault() {
    for error in &super::all_test_errors() {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::EstablishCredential);

        inject_fault(FaultRule::fail_nth(DdiOp::EstablishCredential, 1, *error));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::EstablishCredential);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_establish_credential_single_fault_recoverable,
            "single fault on EstablishCredential",
        );

        let expected = expected_op_calls(error, DdiOp::EstablishCredential, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on EstablishCredential: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `init` recovers on the last retry when `InitBk3` fails for the
/// first `MAX_RETRIES` attempts (retryable errors), or fails immediately
/// on the first attempt (non-retryable errors).
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set.
#[api_test]
fn test_init_recovers_from_init_bk3_last_retry() {
    if use_tpm() {
        return;
    }
    for error in &super::all_test_errors() {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::InitBk3);

        inject_fault(FaultRule::fail_next(DdiOp::InitBk3, MAX_RETRIES, *error));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::InitBk3);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_init_ok_outcome,
            "last retry on InitBk3",
        );

        let expected = expected_op_calls(error, DdiOp::InitBk3, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on InitBk3: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `init` recovers on the last retry when
/// `GetEstablishCredEncryptionKey` fails for the first `MAX_RETRIES`
/// attempts (retryable errors), or fails immediately on the first
/// attempt (non-retryable errors).
#[api_test]
fn test_init_recovers_from_get_establish_cred_key_last_retry() {
    for error in &super::all_test_errors() {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::GetEstablishCredEncryptionKey);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetEstablishCredEncryptionKey,
            MAX_RETRIES,
            *error,
        ));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::GetEstablishCredEncryptionKey);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_init_ok_outcome,
            "last retry on GetEstablishCredEncryptionKey",
        );

        let expected = expected_op_calls(error, DdiOp::GetEstablishCredEncryptionKey, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on GetEstablishCredEncryptionKey: expected {expected} calls for \
             {error:?}, got {}",
            after - before,
        );
    }
}

/// `init` recovers on the last retry when `EstablishCredential` fails
/// for the first `MAX_RETRIES` attempts (retryable errors), or fails
/// immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_init_recovers_from_establish_credential_last_retry() {
    for error in &super::all_test_errors() {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::EstablishCredential);

        inject_fault(FaultRule::fail_next(
            DdiOp::EstablishCredential,
            MAX_RETRIES,
            *error,
        ));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::EstablishCredential);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_init_ok_outcome,
            "last retry on EstablishCredential",
        );

        let expected = expected_op_calls(error, DdiOp::EstablishCredential, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on EstablishCredential: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

// Retry Exhaustion tests
//
// These tests inject MAX_RETRIES + 1 consecutive faults so that
// every retry is consumed and the operation ultimately fails.

/// `init` fails when `InitBk3` returns a retryable error for
/// `MAX_RETRIES + 1` consecutive calls (initial attempt + all retries),
/// for every retryable error code.
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set.
#[api_test]
fn test_init_fails_from_init_bk3_exhausted() {
    if use_tpm() {
        return;
    }
    for error in INIT_RETRYABLE_ERRORS {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::InitBk3);

        inject_fault(FaultRule::fail_next(
            DdiOp::InitBk3,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::InitBk3);
        clear_faults();

        assert!(
            result.is_err(),
            "init should fail after exhausting all {MAX_RETRIES} retries with {error:?} on InitBk3, got: {result:?}"
        );

        let expected = expected_op_calls(error, DdiOp::InitBk3, MAX_RETRIES + 1);
        assert_eq!(
            after - before,
            expected,
            "exhaustion on InitBk3: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `init` fails when `GetEstablishCredEncryptionKey` returns a retryable
/// error for `MAX_RETRIES + 1` consecutive calls, for every retryable
/// error code.
#[api_test]
fn test_init_fails_from_get_establish_cred_key_exhausted() {
    for error in INIT_RETRYABLE_ERRORS {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::GetEstablishCredEncryptionKey);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetEstablishCredEncryptionKey,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::GetEstablishCredEncryptionKey);
        clear_faults();

        assert!(
            result.is_err(),
            "init should fail after exhausting all {MAX_RETRIES} retries with {error:?} on GetEstablishCredEncryptionKey, got: {result:?}"
        );

        let expected =
            expected_op_calls(error, DdiOp::GetEstablishCredEncryptionKey, MAX_RETRIES + 1);
        assert_eq!(
            after - before,
            expected,
            "exhaustion on GetEstablishCredEncryptionKey: expected {expected} calls for \
             {error:?}, got {}",
            after - before,
        );
    }
}

/// `init` fails when `EstablishCredential` returns a retryable error for
/// `MAX_RETRIES + 1` consecutive calls, for every retryable error code.
#[api_test]
fn test_init_fails_from_establish_credential_exhausted() {
    for error in INIT_RETRYABLE_ERRORS {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::EstablishCredential);

        inject_fault(FaultRule::fail_next(
            DdiOp::EstablishCredential,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::EstablishCredential);
        clear_faults();

        assert!(
            result.is_err(),
            "init should fail after exhausting all {MAX_RETRIES} retries with {error:?} on EstablishCredential, got: {result:?}"
        );

        let expected = expected_op_calls(error, DdiOp::EstablishCredential, MAX_RETRIES + 1);
        assert_eq!(
            after - before,
            expected,
            "exhaustion on EstablishCredential: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

// POTA callback on retry

/// When init retries after a transient fault, the `PotaEndorsementCallback`
/// is invoked to re-endorse the POTA over the (potentially new) device's
/// PID public key. Verify that the callback's cert-chain DDI calls occur
/// on the retry attempt.
///
/// Strategy: inject a single `IoAborted` on the 1st `EstablishCredential`
/// call. The first attempt performs the POTA endorsement inline (caller-
/// supplied data). The second attempt invokes the callback, which calls
/// `part.pub_key()` → `GetCertChainInfo` + `GetCertificate`.
///
/// After recovery, `GetCertChainInfo` should have been called more times
/// than in a single-attempt init (the callback invoked it on the retry).
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set
/// (TPM source has no `PotaEndorsementCallback`).
#[api_test]
fn test_init_pota_callback_invoked_on_retry() {
    if use_tpm() {
        return;
    }
    let part = open_and_reset();

    // Force a retry: fail the 1st EstablishCredential.
    inject_fault(FaultRule::fail_nth(
        DdiOp::EstablishCredential,
        1,
        DriverError::IoAborted,
    ));

    let result = init_with_resiliency(&part);

    // Capture call counts before clearing faults (clear_faults resets counters).
    let cert_chain_info_calls = op_call_count(DdiOp::GetCertChainInfo);
    let cert_calls = op_call_count(DdiOp::GetCertificate);

    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover and invoke the POTA callback on retry, got: {result:?}"
    );

    // The POTA callback calls part.pub_key() which does:
    // GetCertChainInfo (to get cert count) + GetCertificate (to get the last cert).
    // On attempt 0, caller-provided POTA is used (no cert-chain calls for POTA).
    // On attempt 1 (retry), the callback fetches the PID cert.
    //
    // So we expect at least 1 GetCertChainInfo call from the callback.
    // (There may be additional calls from the establish_credential flow itself.)
    assert!(
        cert_chain_info_calls >= 1,
        "Expected at least 1 GetCertChainInfo call from the POTA callback on retry, got: {cert_chain_info_calls}"
    );
    assert!(
        cert_calls >= 1,
        "Expected at least 1 GetCertificate call from the POTA callback on retry, got: {cert_calls}"
    );
}

// No retry without resiliency config

/// When resiliency is not enabled, `init` does not retry on
/// `IoAborted` — the error propagates immediately.
#[api_test]
fn test_init_no_retry_without_resiliency() {
    let part = open_and_reset();
    let before = op_call_count(DdiOp::EstablishCredential);

    inject_fault(FaultRule::fail_nth(
        DdiOp::EstablishCredential,
        1,
        DriverError::IoAborted,
    ));

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);

    // No resiliency config → no retry.
    let result = part.init(creds, None, None, obk_info, pota_endorsement, None);
    let after = op_call_count(DdiOp::EstablishCredential);
    clear_faults();

    assert_eq!(
        result.unwrap_err(),
        HsmError::IoAborted,
        "init without resiliency should propagate IoAborted immediately"
    );

    // Without resiliency, only 1 call to EstablishCredential (the failed one).
    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 EstablishCredential call, got {}",
        after - before,
    );
}

// Device-reset-triggered tests
//
// These tests trigger a device reset at the moment a DDI
// operation is entered, using `FaultRule::reset_on_next`. The reset
// wipes all established credentials in the simulator, so the DDI
// operation naturally fails with `CredentialsNotEstablished`.
// This closely mirrors real hardware behavior where a reset can
// occur at any point during a DDI operation.
//
// Unlike the fault-injection tests above (which inject synthetic
// error codes), these tests exercise the full reset → natural failure
// → retry path.

/// A device reset during `InitBk3` triggers a retry that recovers
/// successfully.
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set.
#[api_test]
fn test_init_recovers_after_reset_on_init_bk3() {
    if use_tpm() {
        return;
    }
    let part = open_and_reset();
    let before = op_call_count(DdiOp::InitBk3);

    inject_fault(FaultRule::reset_on_next(DdiOp::InitBk3, 1));

    let result = init_with_resiliency(&part);
    let after = op_call_count(DdiOp::InitBk3);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after a device reset on InitBk3, got: {result:?}"
    );

    // 1 failed call (reset) + 1 successful retry = 2 calls.
    assert_eq!(
        after - before,
        2,
        "reset on InitBk3: expected 2 calls, got {}",
        after - before,
    );
}

/// A device reset during `GetEstablishCredEncryptionKey` triggers a retry
/// that recovers successfully.
#[api_test]
fn test_init_recovers_after_reset_on_get_establish_cred_key() {
    let part = open_and_reset();
    let before = op_call_count(DdiOp::GetEstablishCredEncryptionKey);

    inject_fault(FaultRule::reset_on_next(
        DdiOp::GetEstablishCredEncryptionKey,
        1,
    ));

    let result = init_with_resiliency(&part);
    let after = op_call_count(DdiOp::GetEstablishCredEncryptionKey);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after a device reset on GetEstablishCredEncryptionKey, got: {result:?}"
    );

    // Simulator (mock): Above reset wipes certificate chain so POTA endorsement fails causing a retry → 1 established creds failed + 1 retry = 2 calls.
    // Hardware: Certificate chain is unaffected by above reset call, so POTA endorsement succeeds on the first established creds = 1 calls.
    #[cfg(feature = "mock")]
    let expected = 2;
    #[cfg(not(feature = "mock"))]
    let expected = 1;
    assert_eq!(
        after - before,
        expected,
        "reset on GetEstablishCredEncryptionKey: expected {expected} calls, got {}",
        after - before,
    );
}

/// A device reset during `EstablishCredential` triggers a retry that
/// recovers successfully.
#[api_test]
fn test_init_recovers_after_reset_on_establish_credential() {
    let part = open_and_reset();
    let before = op_call_count(DdiOp::EstablishCredential);

    inject_fault(FaultRule::reset_on_next(DdiOp::EstablishCredential, 1));

    let result = init_with_resiliency(&part);
    let after = op_call_count(DdiOp::EstablishCredential);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after a device reset on EstablishCredential, got: {result:?}"
    );

    // 1 failed call (reset) + 1 successful retry = 2 calls.
    assert_eq!(
        after - before,
        2,
        "reset on EstablishCredential: expected 2 calls, got {}",
        after - before,
    );
}

/// Without resiliency, a device reset during `EstablishCredential` is not
/// retried — the error propagates immediately.
#[api_test]
fn test_init_fails_after_reset_without_resiliency() {
    let part = open_and_reset();
    let before = op_call_count(DdiOp::EstablishCredential);

    inject_fault(FaultRule::reset_on_next(DdiOp::EstablishCredential, 1));

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);

    // No resiliency config → no retry.
    let result = part.init(creds, None, None, obk_info, pota_endorsement, None);
    let after = op_call_count(DdiOp::EstablishCredential);
    clear_faults();

    assert!(
        result.is_err(),
        "init without resiliency should fail after device reset, got: {result:?}"
    );

    // Without resiliency, only 1 call to EstablishCredential (the failed one).
    assert_eq!(
        after - before,
        1,
        "no-retry reset: expected 1 EstablishCredential call, got {}",
        after - before,
    );
}

/// Two consecutive device resets on `EstablishCredential` are each handled
/// by the retry machinery, and `init` ultimately succeeds.
#[api_test]
fn test_init_recovers_after_consecutive_reset() {
    let part = open_and_reset();
    let before = op_call_count(DdiOp::EstablishCredential);

    // Trigger device reset on the next 2 EstablishCredential calls.
    inject_fault(FaultRule::reset_on_next(DdiOp::EstablishCredential, 2));

    let result = init_with_resiliency(&part);
    let after = op_call_count(DdiOp::EstablishCredential);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after 2 consecutive device resets on EstablishCredential, got: {result:?}"
    );

    // 2 failed calls (resets) + 1 successful retry = 3 calls.
    assert_eq!(
        after - before,
        3,
        "consecutive resets on EstablishCredential: expected 3 calls, got {}",
        after - before,
    );
}

/// After a reset-triggered retry on `EstablishCredential`, the POTA
/// endorsement callback is invoked to re-sign over the (potentially
/// new) device's PID public key. Verify by checking that
/// `GetCertChainInfo` was called by the callback on the retry.
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set.
#[api_test]
fn test_init_pota_reendorsement_after_reset() {
    if use_tpm() {
        return;
    }
    let part = open_and_reset();

    // Trigger device reset on the 1st EstablishCredential — forces a retry.
    inject_fault(FaultRule::reset_on_next(DdiOp::EstablishCredential, 1));

    let cert_chain_before = op_call_count(DdiOp::GetCertChainInfo);

    let result = init_with_resiliency(&part);

    let cert_chain_after = op_call_count(DdiOp::GetCertChainInfo);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after device reset + POTA re-endorsement, got: {result:?}"
    );

    // The POTA callback calls part.pub_key() → GetCertChainInfo + GetCertificate.
    // On attempt 0, caller-provided POTA is used (no callback).
    // On attempt 1 (retry), the callback fetches the PID cert.
    assert!(
        cert_chain_after > cert_chain_before,
        "GetCertChainInfo should have been called by the POTA callback after device reset \
         (before: {cert_chain_before}, after: {cert_chain_after})"
    );
}

// TPM code path tests
//
// These tests exercise the TPM-source init path where the BK3 key
// is retrieved via `GetSealedBk3` + TPM unseal (instead of `InitBk3`)
// and the POTA endorsement is signed by the TPM (instead of caller-
// provided data).
//
// All tests in this section are gated behind `AZIHSM_USE_TPM` and
// are skipped when that environment variable is not set.

/// `init` (TPM path) recovers from a single transient fault on
/// `GetSealedBk3` for retryable error codes, and fails immediately for
/// non-retryable ones.
/// TPM-source only — skipped when `AZIHSM_USE_TPM` is not set.
#[api_test]
fn test_init_tpm_recovers_from_get_sealed_bk3_single_fault() {
    if !use_tpm() {
        return;
    }
    for error in &super::all_test_errors() {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::GetSealedBk3);

        inject_fault(FaultRule::fail_nth(DdiOp::GetSealedBk3, 1, *error));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::GetSealedBk3);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_init_retryable,
            "single fault on GetSealedBk3 (TPM path)",
        );

        let expected = expected_op_calls(error, DdiOp::GetSealedBk3, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on GetSealedBk3 (TPM): expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `init` (TPM path) recovers on the last retry when `GetSealedBk3`
/// fails for the first `MAX_RETRIES` attempts (retryable errors), or
/// fails immediately on the first attempt (non-retryable errors).
/// TPM-source only — skipped when `AZIHSM_USE_TPM` is not set.
#[api_test]
fn test_init_tpm_recovers_from_get_sealed_bk3_last_retry() {
    if !use_tpm() {
        return;
    }
    for error in &super::all_test_errors() {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::GetSealedBk3);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetSealedBk3,
            MAX_RETRIES,
            *error,
        ));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::GetSealedBk3);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_init_retryable,
            "last retry on GetSealedBk3 (TPM path)",
        );

        let expected = expected_op_calls(error, DdiOp::GetSealedBk3, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on GetSealedBk3 (TPM): expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `init` (TPM path) fails when `GetSealedBk3` returns a retryable error
/// for `MAX_RETRIES + 1` consecutive calls, for every retryable error
/// code.
/// TPM-source only — skipped when `AZIHSM_USE_TPM` is not set.
#[api_test]
fn test_init_tpm_fails_from_get_sealed_bk3_exhausted() {
    if !use_tpm() {
        return;
    }
    for error in INIT_RETRYABLE_ERRORS {
        let part = open_and_reset();
        let before = op_call_count(DdiOp::GetSealedBk3);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetSealedBk3,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = init_with_resiliency(&part);
        let after = op_call_count(DdiOp::GetSealedBk3);
        clear_faults();

        assert!(
            result.is_err(),
            "init should fail after exhausting all {MAX_RETRIES} retries with {error:?} on GetSealedBk3, got: {result:?}"
        );

        let expected = expected_op_calls(error, DdiOp::GetSealedBk3, MAX_RETRIES + 1);
        assert_eq!(
            after - before,
            expected,
            "exhaustion on GetSealedBk3 (TPM): expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// A device reset during `GetSealedBk3` (TPM path) triggers a retry
/// that recovers successfully.
/// TPM-source only — skipped when `AZIHSM_USE_TPM` is not set.
#[api_test]
fn test_init_tpm_recovers_after_reset_on_get_sealed_bk3() {
    if !use_tpm() {
        return;
    }
    let part = open_and_reset();
    let before = op_call_count(DdiOp::GetSealedBk3);

    inject_fault(FaultRule::reset_on_next(DdiOp::GetSealedBk3, 1));

    let result = init_with_resiliency(&part);
    let after = op_call_count(DdiOp::GetSealedBk3);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after a device reset on GetSealedBk3 (TPM path), got: {result:?}"
    );

    // Simulator (mock): Above reset wipes certificate chain so POTA endorsement fails causing a retry → 1 established creds failed + 1 retry = 2 calls.
    // Hardware: Certificate chain is unaffected by above reset call, so POTA endorsement succeeds on the first established creds = 1 calls.
    // the reset → 1 call.
    #[cfg(feature = "mock")]
    let expected = 2;
    #[cfg(not(feature = "mock"))]
    let expected = 1;
    assert_eq!(
        after - before,
        expected,
        "reset on GetSealedBk3 (TPM): expected {expected} calls, got {}",
        after - before,
    );
}
