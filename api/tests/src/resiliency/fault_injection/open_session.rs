// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests for `open_session`.
//!
//! These tests exercise the retry-with-restore machinery on
//! [`HsmPartition::open_session`] using two complementary strategies:
//!
//! 1. Fault-injection tests — inject transient DDI faults through
//!    the resiliency test device and verify the retry path recovers.
//! 2. reset-triggered tests — trigger an NVMe Subsystem Reset during
//!    a DDI operation via `FaultRule::reset_on_next` (simulating a live
//!    migration event occurring mid-operation) so the DDI returns
//!    `CredentialsNotEstablished` naturally, then verify that
//!    `restore_partition` re-establishes credentials and the retry
//!    succeeds.
//!
//! `open_session` only retries when resiliency is enabled (a
//! [`HsmResiliencyConfig`] was passed to [`HsmPartition::init`]).
//!
//! On a retryable failure the open-session path:
//! 1. Applies exponential backoff for IO-abort errors.
//! 2. Calls `restore_partition` to re-establish credentials.
//! 3. Retries the `ddi::open_session` call.
//!
//! The DDI operations exercised during `open_session` are:
//!
//! | Step | DDI op                       |
//! |------|------------------------------|
//! | 1    | `GetSessionEncryptionKey`    |
//! | 2    | `OpenSession`                |
//!
//! `restore_partition` internally calls `init_part`, whose BK3
//! step differs by source:
//!
//! | Source  | BK3 DDI op      |
//! |---------|-----------------|
//! | Caller  | `InitBk3`       |
//! | TPM     | `GetSealedBk3`  |
//!
//! Tests that verify `restore_partition` ran check the appropriate
//! BK3 op based on `AZIHSM_USE_TPM`.
//!
//! Tests that inject faults on `InitBk3` during `restore_partition`
//! or verify the POTA endorsement callback are caller-only and are
//! skipped when `AZIHSM_USE_TPM` is set.
//!
//! # Adding a new retryable error
//!
//! Append the new [`FaultError`] variant to [`OPEN_SESSION_RETRYABLE_ERRORS`]
//! (and to [`super::ALL_RETRYABLE_ERRORS`] if it's new globally).
//! All loop-based tests will automatically cover it. To add a
//! non-retryable error, append to [`super::NON_RETRYABLE_ERRORS`].

use azihsm_res_test_dev::*;

use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

/// All error codes that trigger `open_session` retry when resiliency is enabled.
const OPEN_SESSION_RETRYABLE_ERRORS: &[FaultError] = &[
    FaultError::Driver(DriverError::IoAborted),
    FaultError::Driver(DriverError::IoAbortInProgress),
    FaultError::Status(DdiStatus::CredentialsNotEstablished),
    FaultError::Status(DdiStatus::NonceMismatch),
    FaultError::Status(DdiStatus::PartitionNotProvisioned),
];

/// Returns `true` when `error` is one of the open-session-retryable
/// error codes.
fn is_open_session_retryable(error: &FaultError) -> bool {
    super::is_retryable(error, &OPEN_SESSION_RETRYABLE_ERRORS)
}

/// Expected number of times the faulted `target_op` is invoked in a
/// fault-injection test.
///
/// * Retryable errors: `min(injected_faults + 1, MAX_RETRIES + 1)`.
///   The `+1` accounts for the successful call after all faults are
///   consumed, capped by the maximum number of attempts.
/// * Non-retryable errors: 1 (single failed call, no retry).
fn expected_op_calls(error: &FaultError, injected_faults: u32) -> u32 {
    super::expected_op_calls_for(error, injected_faults, &OPEN_SESSION_RETRYABLE_ERRORS)
}

/// Helper: open and init a partition with resiliency enabled, returning
/// the partition, credentials, and the RAII context that cleans up.
fn init_with_resiliency() -> (HsmPartition, HsmCredentials, ResiliencyTestCtx) {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    let part =
        HsmPartitionManager::open_partition(&list[0].path).expect("Failed to open partition");
    part.reset().expect("Partition reset failed");

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);
    let (resiliency_config, ctx) = make_resiliency_config(&part);
    part.init(
        creds,
        None,
        None,
        obk_info,
        pota_endorsement,
        Some(resiliency_config),
    )
    .expect("Partition init failed");

    (part, creds, ctx)
}

/// Helper: open and init a partition without resiliency.
fn init_without_resiliency() -> (HsmPartition, HsmCredentials) {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    let part =
        HsmPartitionManager::open_partition(&list[0].path).expect("Failed to open partition");
    part.reset().expect("Partition reset failed");

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);
    part.init(creds, None, None, obk_info, pota_endorsement, None)
        .expect("Partition init failed");

    (part, creds)
}

// Single-fault recovery on GetSessionEncryptionKey

/// `open_session` recovers from a single transient fault on
/// `GetSessionEncryptionKey` for retryable error codes, and fails
/// immediately for non-retryable ones.
#[api_test]
fn test_open_session_recovers_from_get_session_key_single_fault() {
    for error in &super::all_test_errors() {
        let (part, creds, _ctx) = init_with_resiliency();
        let rev = part.api_rev_range().max();
        let before = op_call_count(DdiOp::GetSessionEncryptionKey);

        inject_fault(FaultRule::fail_nth(
            DdiOp::GetSessionEncryptionKey,
            1,
            *error,
        ));

        let result = part.open_session(rev, &creds, None);
        let after = op_call_count(DdiOp::GetSessionEncryptionKey);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_open_session_retryable,
            "single fault on GetSessionEncryptionKey",
        );

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on GetSessionEncryptionKey: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

// Single-fault recovery on OpenSession

/// `open_session` recovers from a single transient fault on
/// `OpenSession` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_open_session_recovers_from_open_session_single_fault() {
    for error in &super::all_test_errors() {
        let (part, creds, _ctx) = init_with_resiliency();
        let rev = part.api_rev_range().max();
        let before = op_call_count(DdiOp::OpenSession);

        inject_fault(FaultRule::fail_nth(DdiOp::OpenSession, 1, *error));

        let result = part.open_session(rev, &creds, None);
        let after = op_call_count(DdiOp::OpenSession);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_open_session_retryable,
            "single fault on OpenSession",
        );

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on OpenSession: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

// Last-retry recovery

/// `open_session` recovers on the last retry when `GetSessionEncryptionKey`
/// fails for the first `MAX_RETRIES` attempts (retryable errors), or fails
/// immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_open_session_recovers_from_get_session_key_last_retry() {
    for error in &super::all_test_errors() {
        let (part, creds, _ctx) = init_with_resiliency();
        let rev = part.api_rev_range().max();
        let before = op_call_count(DdiOp::GetSessionEncryptionKey);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetSessionEncryptionKey,
            MAX_RETRIES,
            *error,
        ));

        let result = part.open_session(rev, &creds, None);
        let after = op_call_count(DdiOp::GetSessionEncryptionKey);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_open_session_retryable,
            "last retry on GetSessionEncryptionKey",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on GetSessionEncryptionKey: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `open_session` recovers on the last retry when `OpenSession` fails
/// for the first `MAX_RETRIES` attempts (retryable errors), or fails
/// immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_open_session_recovers_from_open_session_last_retry() {
    for error in &super::all_test_errors() {
        let (part, creds, _ctx) = init_with_resiliency();
        let rev = part.api_rev_range().max();
        let before = op_call_count(DdiOp::OpenSession);

        inject_fault(FaultRule::fail_next(
            DdiOp::OpenSession,
            MAX_RETRIES,
            *error,
        ));

        let result = part.open_session(rev, &creds, None);
        let after = op_call_count(DdiOp::OpenSession);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_open_session_retryable,
            "last retry on OpenSession",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on OpenSession: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

// No retry without resiliency config

/// When resiliency is not enabled, `open_session` does not retry on
/// `IoAborted` — the error propagates immediately.
#[api_test]
fn test_open_session_no_retry_without_resiliency() {
    let (part, creds) = init_without_resiliency();
    let rev = part.api_rev_range().max();

    inject_fault(FaultRule::fail_nth(
        DdiOp::OpenSession,
        1,
        DriverError::IoAborted,
    ));

    let result = part.open_session(rev, &creds, None);
    clear_faults();

    assert_eq!(
        result.unwrap_err(),
        HsmError::IoAborted,
        "open_session without resiliency should propagate IoAborted immediately"
    );
}

// Exhaustion: all retries fail

/// `open_session` fails when every attempt to call
/// `GetSessionEncryptionKey` triggers a device reset.  After
/// `MAX_RETRIES` iterations, all retries are exhausted.
#[api_test]
fn test_open_session_fails_from_get_session_key_exhausted() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();
    let before = op_call_count(DdiOp::GetSessionEncryptionKey);

    // Every call to GetSessionEncryptionKey triggers an NSSR, so the
    // DDI op naturally fails with CredentialsNotEstablished each time.
    inject_fault(FaultRule::reset_on_next(
        DdiOp::GetSessionEncryptionKey,
        MAX_RETRIES + 1,
    ));

    let result = part.open_session(rev, &creds, None);
    let after = op_call_count(DdiOp::GetSessionEncryptionKey);
    clear_faults();

    assert!(
        result.is_err(),
        "open_session should fail after exhausting all {MAX_RETRIES} retries on GetSessionEncryptionKey, got: {result:?}"
    );

    // initial attempt + MAX_RETRIES retries = MAX_RETRIES + 1 calls
    assert_eq!(
        after - before,
        MAX_RETRIES + 1,
        "exhaustion on GetSessionEncryptionKey: expected {} calls, got {}",
        MAX_RETRIES + 1,
        after - before,
    );
}

/// `open_session` fails when every attempt to call `OpenSession`
/// triggers a device reset.  After `MAX_RETRIES` iterations, all
/// retries are exhausted.
#[api_test]
fn test_open_session_fails_from_open_session_exhausted() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();
    let before = op_call_count(DdiOp::OpenSession);

    // Every call to OpenSession triggers an NSSR, so the DDI op
    // naturally fails with CredentialsNotEstablished each time.
    inject_fault(FaultRule::reset_on_next(
        DdiOp::OpenSession,
        MAX_RETRIES + 1,
    ));

    let result = part.open_session(rev, &creds, None);
    let after = op_call_count(DdiOp::OpenSession);
    clear_faults();

    assert!(
        result.is_err(),
        "open_session should fail after exhausting all {MAX_RETRIES} retries on OpenSession, got: {result:?}"
    );

    // initial attempt + MAX_RETRIES retries = MAX_RETRIES + 1 calls
    assert_eq!(
        after - before,
        MAX_RETRIES + 1,
        "exhaustion on OpenSession: expected {} calls, got {}",
        MAX_RETRIES + 1,
        after - before,
    );
}

// restore_partition tests

/// When `open_session` retries, `restore_partition` re-establishes
/// credentials via `init_part` (which calls `InitBk3` or
/// `GetSealedBk3` depending on the source, followed by
/// `GetEstablishCredEncryptionKey` and `EstablishCredential`) before
/// re-attempting the session open.
#[api_test]
fn test_restore_partition_reestablishes_credentials_on_retry() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    let op = bk3_op();
    // Record BK3 op count from the init phase.
    let bk3_before = op_call_count(op);

    // Inject a single fault on OpenSession so the retry path triggers.
    inject_fault(FaultRule::fail_nth(
        DdiOp::OpenSession,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = part.open_session(rev, &creds, None);

    // Check counters before clearing (clear_faults resets counters).
    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "open_session should recover after restore_partition re-establishes credentials"
    );

    // restore_partition calls init_part which calls the BK3 op.
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition (before: {bk3_before}, after: {bk3_after})"
    );
}

/// When `CredentialsNotEstablished` is returned on `OpenSession`, the
/// retry path triggers `restore_partition` which re-establishes
/// credentials and retries successfully.
#[api_test]
fn test_restore_partition_recovers_credentials_not_established() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    // Inject CredentialsNotEstablished on OpenSession
    inject_fault(FaultRule::fail_nth(
        DdiOp::OpenSession,
        1,
        FaultError::Status(DdiStatus::CredentialsNotEstablished),
    ));

    let op = bk3_op();
    let bk3_before = op_call_count(op);
    let result = part.open_session(rev, &creds, None);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "open_session should recover from CredentialsNotEstablished via restore_partition: {result:?}"
    );

    // restore_partition re-established credentials.
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition (before: {bk3_before}, after: {bk3_after})"
    );
}

// Fault during restore_partition's init_part

/// When `open_session` retries and `restore_partition`'s inner
/// `init_part` also hits a transient fault on `InitBk3`, the
/// proc-macro retry inside `init_part` recovers, and
/// `open_session` ultimately succeeds.
///
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set.
#[api_test]
fn test_open_session_recovers_when_restore_init_part_faults() {
    if use_tpm() {
        return;
    }
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    // 1st OpenSession → IoAborted → triggers retry path.
    inject_fault(FaultRule::fail_nth(
        DdiOp::OpenSession,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    // During restore, init_part calls InitBk3 — fail the next call.
    // The proc macro retries InitBk3 internally.
    // (fail_next is used because InitBk3's global counter is
    //  already > 0 from the init() call in init_with_resiliency.)
    inject_fault(FaultRule::fail_next(
        DdiOp::InitBk3,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = part.open_session(rev, &creds, None);
    clear_faults();

    assert!(
        result.is_ok(),
        "open_session should recover even when restore's init_part hits a transient fault on InitBk3, got: {result:?}"
    );
}

/// Compound fault: `OpenSession` fails (triggering retry) AND
/// `EstablishCredential` fails during `restore_partition`'s
/// `init_part` call. Both recover via their respective retry
/// mechanisms (outer retry + proc-macro retry).
#[api_test]
fn test_open_session_recovers_from_compound_fault() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    // OpenSession → IoAborted → triggers retry path.
    inject_fault(FaultRule::fail_nth(
        DdiOp::OpenSession,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    // EstablishCredential during restore's init_part → IoAborted.
    // Proc macro retries internally.
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = part.open_session(rev, &creds, None);
    clear_faults();

    assert!(
        result.is_ok(),
        "open_session should recover from compound faults on OpenSession + EstablishCredential, got: {result:?}"
    );
}

/// When `init_part` retries inside `restore_partition` due to a
/// transient fault on `EstablishCredential`, the POTA endorsement
/// callback is invoked on the retry attempt to re-endorse over the
/// (potentially new) device's PID public key.
///
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set
/// (TPM path does not use the POTA endorsement callback).
#[api_test]
fn test_restore_pota_callback_invoked_during_init_part_retry() {
    if use_tpm() {
        return;
    }
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    // OpenSession → IoAborted → triggers retry + restore_partition.
    inject_fault(FaultRule::fail_nth(
        DdiOp::OpenSession,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    // EstablishCredential during restore's init_part → IoAborted.
    // This forces the proc macro to retry, invoking the POTA callback
    // on attempt > 0.
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    // Capture cert-chain counters before the retried flow.
    let cert_chain_before = op_call_count(DdiOp::GetCertChainInfo);

    let result = part.open_session(rev, &creds, None);

    // Capture counters before clearing (clear_faults resets counters).
    let cert_chain_after = op_call_count(DdiOp::GetCertChainInfo);
    clear_faults();

    assert!(
        result.is_ok(),
        "open_session should recover after POTA re-endorsement during restore's init_part retry, got: {result:?}"
    );

    // The POTA callback calls part.pub_key() → GetCertChainInfo + GetCertificate.
    // On init_part attempt 0, caller-provided POTA is used (no callback).
    // On attempt 1 (retry), the callback fetches the PID cert.
    assert!(
        cert_chain_after > cert_chain_before,
        "GetCertChainInfo should have been called by the POTA callback during restore's init_part retry"
    );
}

/// A second `open_session` call retries independently from the first.
/// The first session opens cleanly; then after closing it, the second
/// encounters a fault, triggers restore, and recovers.
#[api_test]
fn test_open_session_second_session_retries_independently() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    // First session opens cleanly.
    let session1 = part
        .open_session(rev, &creds, None)
        .expect("First open_session should succeed");

    // Close the first session before opening the second — the simulator
    // only allows one session per file handle.
    drop(session1);

    // Inject a fault for the next OpenSession call.
    inject_fault(FaultRule::fail_next(
        DdiOp::OpenSession,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = part.open_session(rev, &creds, None);
    clear_faults();

    assert!(
        result.is_ok(),
        "Second open_session should recover independently after fault, got: {result:?}"
    );
}

// reset-triggered tests
//
// These tests trigger an NVMe Subsystem Reset at the moment a DDI
// operation is entered, using `FaultRule::reset_on_next`. The reset
// wipes all established credentials in the simulator, so the DDI
// operation naturally fails with `CredentialsNotEstablished`.
// This closely mirrors real hardware behavior where a reset can
// occur at any point during a DDI operation.

/// After a reset, `open_session` detects `CredentialsNotEstablished`
/// and triggers `restore_partition` which re-establishes credentials
/// via `init_part`, then retries the session open successfully.
#[api_test]
fn test_open_session_recovers_after_reset() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    // Trigger reset when the first DDI op of open_session is entered.
    inject_fault(FaultRule::reset_on_next(DdiOp::GetSessionEncryptionKey, 1));

    let result = part.open_session(rev, &creds, None);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "open_session should recover after reset via restore_partition, got: {result:?}"
    );

    // restore_partition called init_part which calls the BK3 op.
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// A first session opens and closes normally, then a reset during the
/// next `open_session` call invalidates device state. The retry path
/// restores the partition and opens successfully.
#[api_test]
fn test_open_session_recovers_after_reset_between_sessions() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    let session1 = part
        .open_session(rev, &creds, None)
        .expect("First open_session should succeed before reset");

    // Close session1 before triggering reset — the simulator only
    // allows one session per file handle.
    drop(session1);

    // Trigger reset when the second open_session enters its first DDI op.
    inject_fault(FaultRule::reset_on_next(DdiOp::GetSessionEncryptionKey, 1));

    let result = part.open_session(rev, &creds, None);
    clear_faults();

    assert!(
        result.is_ok(),
        "Second open_session should recover after reset via restore_partition, got: {result:?}"
    );
}

/// Without resiliency enabled, `open_session` does not retry after an
/// reset — the `CredentialsNotEstablished` error propagates immediately.
#[api_test]
fn test_open_session_fails_after_reset_without_resiliency() {
    let (part, creds) = init_without_resiliency();
    let rev = part.api_rev_range().max();

    // Trigger reset when the first DDI op of open_session is entered.
    inject_fault(FaultRule::reset_on_next(DdiOp::GetSessionEncryptionKey, 1));

    let result = part.open_session(rev, &creds, None);
    clear_faults();

    assert!(
        result.is_err(),
        "open_session without resiliency should fail after reset, got: {result:?}"
    );
}

/// Two consecutive resets are each followed by a successful
/// `open_session`. The retry-with-restore machinery handles both
/// events independently.
#[api_test]
fn test_open_session_recovers_after_consecutive_reset() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    // First reset → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::GetSessionEncryptionKey, 1));
    let session1 = part
        .open_session(rev, &creds, None)
        .expect("open_session should recover after first reset");
    drop(session1);

    // Second reset → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::GetSessionEncryptionKey, 1));
    let session2 = part
        .open_session(rev, &creds, None)
        .expect("open_session should recover after second reset");
    drop(session2);
}

/// After a reset, `restore_partition` calls `init_part` with the
/// resiliency config. If an additional fault causes `init_part` to
/// retry, the POTA endorsement callback is invoked to re-endorse
/// over the current device's PID public key.
///
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set
/// (TPM path does not use the POTA endorsement callback).
#[api_test]
fn test_open_session_pota_reendorsement_after_reset() {
    if use_tpm() {
        return;
    }
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    // Trigger reset when the first DDI op of open_session is entered.
    inject_fault(FaultRule::reset_on_next(DdiOp::GetSessionEncryptionKey, 1));

    // Fail the next EstablishCredential inside restore's init_part
    // so the proc macro retries and invokes the POTA callback.
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let cert_chain_before = op_call_count(DdiOp::GetCertChainInfo);

    let result = part.open_session(rev, &creds, None);

    let cert_chain_after = op_call_count(DdiOp::GetCertChainInfo);
    clear_faults();

    assert!(
        result.is_ok(),
        "open_session should recover after reset + POTA re-endorsement, got: {result:?}"
    );

    assert!(
        cert_chain_after > cert_chain_before,
        "GetCertChainInfo should have been called by the POTA callback after reset"
    );
}

// reset-triggered tests on OpenSession DDI op
//
// These mirror the GetSessionEncryptionKey reset tests above but
// trigger the reset at the OpenSession DDI command instead. This
// exercises a different failure point: GetSessionEncryptionKey
// succeeds, then reset fires when OpenSession is entered.

/// After a reset on the `OpenSession` DDI op, `open_session` detects
/// `CredentialsNotEstablished` and triggers `restore_partition` which
/// re-establishes credentials, then retries successfully.
#[api_test]
fn test_open_session_recovers_after_reset_on_open_session() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    // Trigger reset when the OpenSession DDI op is entered.
    inject_fault(FaultRule::reset_on_next(DdiOp::OpenSession, 1));

    let result = part.open_session(rev, &creds, None);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "open_session should recover after reset on OpenSession, got: {result:?}"
    );

    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset on OpenSession \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// A first session opens and closes normally, then a reset on the
/// `OpenSession` DDI op during the next `open_session` call
/// invalidates device state. The retry path restores and succeeds.
#[api_test]
fn test_open_session_recovers_after_reset_on_open_session_between_sessions() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    let session1 = part
        .open_session(rev, &creds, None)
        .expect("First open_session should succeed before reset");
    drop(session1);

    // Trigger reset when the second open_session's OpenSession DDI op is entered.
    inject_fault(FaultRule::reset_on_next(DdiOp::OpenSession, 1));

    let result = part.open_session(rev, &creds, None);
    clear_faults();

    assert!(
        result.is_ok(),
        "Second open_session should recover after reset on OpenSession, got: {result:?}"
    );
}

/// Without resiliency enabled, `open_session` does not retry after an
/// reset on the `OpenSession` DDI op — the error propagates immediately.
#[api_test]
fn test_open_session_fails_after_reset_on_open_session_without_resiliency() {
    let (part, creds) = init_without_resiliency();
    let rev = part.api_rev_range().max();

    inject_fault(FaultRule::reset_on_next(DdiOp::OpenSession, 1));

    let result = part.open_session(rev, &creds, None);
    clear_faults();

    assert!(
        result.is_err(),
        "open_session without resiliency should fail after reset on OpenSession, got: {result:?}"
    );
}

/// Two consecutive resets on `OpenSession` are each followed by a
/// successful recovery.
#[api_test]
fn test_open_session_recovers_after_consecutive_reset_on_open_session() {
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    // First reset on OpenSession → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::OpenSession, 1));
    let session1 = part
        .open_session(rev, &creds, None)
        .expect("open_session should recover after first reset on OpenSession");
    drop(session1);

    // Second reset on OpenSession → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::OpenSession, 1));
    let session2 = part
        .open_session(rev, &creds, None)
        .expect("open_session should recover after second reset on OpenSession");
    drop(session2);
}

/// After a reset on `OpenSession`, `restore_partition` calls
/// `init_part`. If an additional fault causes `init_part` to retry,
/// the POTA endorsement callback is invoked to re-endorse over the
/// current device's PID public key.
///
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set
/// (TPM path does not use the POTA endorsement callback).
#[api_test]
fn test_open_session_pota_reendorsement_after_reset_on_open_session() {
    if use_tpm() {
        return;
    }
    let (part, creds, _ctx) = init_with_resiliency();
    let rev = part.api_rev_range().max();

    // Trigger reset when the OpenSession DDI op is entered.
    inject_fault(FaultRule::reset_on_next(DdiOp::OpenSession, 1));

    // Fail the next EstablishCredential inside restore's init_part
    // so the proc macro retries and invokes the POTA callback.
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let cert_chain_before = op_call_count(DdiOp::GetCertChainInfo);

    let result = part.open_session(rev, &creds, None);

    let cert_chain_after = op_call_count(DdiOp::GetCertChainInfo);
    clear_faults();

    assert!(
        result.is_ok(),
        "open_session should recover after reset on OpenSession + POTA re-endorsement, got: {result:?}"
    );

    assert!(
        cert_chain_after > cert_chain_before,
        "GetCertChainInfo should have been called by the POTA callback after reset on OpenSession"
    );
}
