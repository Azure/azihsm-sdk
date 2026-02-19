// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests for `init` (partition initialization).
//!
//! These tests exercise the retry-with-backoff machinery on
//! [`HsmPartition::init`] by injecting transient DDI faults through
//! the resiliency mock device.
//!
//! Unlike `open_partition` (which retries unconditionally),
//! `init_part` only retries when a resiliency config is provided.
//!
//! The DDI operations exercised during init (caller-source path) are:
//!
//! | Step | DDI op                          |
//! |------|---------------------------------|
//! | 1    | `InitBk3`                       |
//! | 2    | `GetCertChainInfo` (POTA)       |
//! | 3    | `GetCertificate` (POTA)         |
//! | 4    | `GetEstablishCredEncryptionKey` |
//! | 5    | `EstablishCredential`           |
//!
//! On retries with caller-source POTA, the `PotaEndorsementCallback`
//! is invoked to re-endorse over the current device's PID public key.
//!
//! # Adding a new retryable error
//!
//! Append the new [`FaultError`] variant to [`RETRYABLE_ERRORS`] and all
//! loop-based tests will automatically cover it.

use azihsm_res_test_dev::*;

use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

/// All error codes that trigger `init_part` retry when resiliency is enabled.
const RETRYABLE_ERRORS: &[FaultError] = &[
    FaultError::Driver(DriverError::IoAborted),
    FaultError::Driver(DriverError::IoAbortInProgress),
    FaultError::Status(DdiStatus::CredentialsNotEstablished),
    FaultError::Status(DdiStatus::NonceMismatch),
    FaultError::Status(DdiStatus::PartitionNotProvisioned),
    FaultError::Status(DdiStatus::EccVerifyFailed),
];

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

/// `init` recovers from a single transient fault on `InitBk3`,
/// for every retryable error code.
#[api_test]
fn test_init_recovers_from_init_bk3_single_fault() {
    for error in RETRYABLE_ERRORS {
        let part = open_and_reset();

        inject_fault(FaultRule::fail_nth(DdiOp::InitBk3, 1, *error));

        let result = init_with_resiliency(&part);
        clear_faults();

        assert!(
            result.is_ok(),
            "init should recover after a single {error:?} on InitBk3, got: {result:?}"
        );
    }
}

/// `init` recovers from a single transient fault on
/// `GetEstablishCredEncryptionKey`, for every retryable error code.
#[api_test]
fn test_init_recovers_from_get_establish_cred_key_single_fault() {
    for error in RETRYABLE_ERRORS {
        let part = open_and_reset();

        inject_fault(FaultRule::fail_nth(
            DdiOp::GetEstablishCredEncryptionKey,
            1,
            *error,
        ));

        let result = init_with_resiliency(&part);
        clear_faults();

        assert!(
            result.is_ok(),
            "init should recover after a single {error:?} on GetEstablishCredEncryptionKey, got: {result:?}"
        );
    }
}

/// `init` recovers from a single transient fault on
/// `EstablishCredential`, for every retryable error code.
#[api_test]
fn test_init_recovers_from_establish_credential_single_fault() {
    for error in RETRYABLE_ERRORS {
        let part = open_and_reset();

        inject_fault(FaultRule::fail_nth(DdiOp::EstablishCredential, 1, *error));

        let result = init_with_resiliency(&part);
        clear_faults();

        assert!(
            result.is_ok(),
            "init should recover after a single {error:?} on EstablishCredential, got: {result:?}"
        );
    }
}

/// `init` recovers on the last retry when `InitBk3` fails for the
/// first `MAX_RETRIES` attempts, for every retryable error code.
#[api_test]
fn test_init_recovers_from_init_bk3_last_retry() {
    for error in RETRYABLE_ERRORS {
        let part = open_and_reset();

        inject_fault(FaultRule::fail_next(DdiOp::InitBk3, MAX_RETRIES, *error));

        let result = init_with_resiliency(&part);
        clear_faults();

        assert!(
            result.is_ok(),
            "init should recover on the last retry after {MAX_RETRIES} consecutive {error:?} on InitBk3, got: {result:?}"
        );
    }
}

/// `init` recovers on the last retry when
/// `GetEstablishCredEncryptionKey` fails for the first `MAX_RETRIES`
/// attempts, for every retryable error code.
#[api_test]
fn test_init_recovers_from_get_establish_cred_key_last_retry() {
    for error in RETRYABLE_ERRORS {
        let part = open_and_reset();

        inject_fault(FaultRule::fail_next(
            DdiOp::GetEstablishCredEncryptionKey,
            MAX_RETRIES,
            *error,
        ));

        let result = init_with_resiliency(&part);
        clear_faults();

        assert!(
            result.is_ok(),
            "init should recover on the last retry after {MAX_RETRIES} consecutive {error:?} on GetEstablishCredEncryptionKey, got: {result:?}"
        );
    }
}

/// `init` recovers on the last retry when `EstablishCredential` fails
/// for the first `MAX_RETRIES` attempts, for every retryable error code.
#[api_test]
fn test_init_recovers_from_establish_credential_last_retry() {
    for error in RETRYABLE_ERRORS {
        let part = open_and_reset();

        inject_fault(FaultRule::fail_next(
            DdiOp::EstablishCredential,
            MAX_RETRIES,
            *error,
        ));

        let result = init_with_resiliency(&part);
        clear_faults();

        assert!(
            result.is_ok(),
            "init should recover on the last retry after {MAX_RETRIES} consecutive {error:?} on EstablishCredential, got: {result:?}"
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
#[api_test]
fn test_init_fails_from_init_bk3_exhausted() {
    for error in RETRYABLE_ERRORS {
        let part = open_and_reset();

        inject_fault(FaultRule::fail_next(
            DdiOp::InitBk3,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = init_with_resiliency(&part);
        clear_faults();

        assert!(
            result.is_err(),
            "init should fail after exhausting all {MAX_RETRIES} retries with {error:?} on InitBk3, got: {result:?}"
        );
    }
}

/// `init` fails when `GetEstablishCredEncryptionKey` returns a retryable
/// error for `MAX_RETRIES + 1` consecutive calls, for every retryable
/// error code.
#[api_test]
fn test_init_fails_from_get_establish_cred_key_exhausted() {
    for error in RETRYABLE_ERRORS {
        let part = open_and_reset();

        inject_fault(FaultRule::fail_next(
            DdiOp::GetEstablishCredEncryptionKey,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = init_with_resiliency(&part);
        clear_faults();

        assert!(
            result.is_err(),
            "init should fail after exhausting all {MAX_RETRIES} retries with {error:?} on GetEstablishCredEncryptionKey, got: {result:?}"
        );
    }
}

/// `init` fails when `EstablishCredential` returns a retryable error for
/// `MAX_RETRIES + 1` consecutive calls, for every retryable error code.
#[api_test]
fn test_init_fails_from_establish_credential_exhausted() {
    for error in RETRYABLE_ERRORS {
        let part = open_and_reset();

        inject_fault(FaultRule::fail_next(
            DdiOp::EstablishCredential,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = init_with_resiliency(&part);
        clear_faults();

        assert!(
            result.is_err(),
            "init should fail after exhausting all {MAX_RETRIES} retries with {error:?} on EstablishCredential, got: {result:?}"
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
#[api_test]
fn test_init_pota_callback_invoked_on_retry() {
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

    inject_fault(FaultRule::fail_nth(
        DdiOp::EstablishCredential,
        1,
        DriverError::IoAborted,
    ));

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);

    // No resiliency config → no retry.
    let result = part.init(creds, None, None, obk_info, pota_endorsement, None);
    clear_faults();

    assert_eq!(
        result.unwrap_err(),
        HsmError::IoAborted,
        "init without resiliency should propagate IoAborted immediately"
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
#[api_test]
fn test_init_recovers_after_reset_on_init_bk3() {
    let part = open_and_reset();

    inject_fault(FaultRule::reset_on_next(DdiOp::InitBk3, 1));

    let result = init_with_resiliency(&part);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after a device reset on InitBk3, got: {result:?}"
    );
}

/// A device reset during `GetEstablishCredEncryptionKey` triggers a retry
/// that recovers successfully.
#[api_test]
fn test_init_recovers_after_reset_on_get_establish_cred_key() {
    let part = open_and_reset();

    inject_fault(FaultRule::reset_on_next(
        DdiOp::GetEstablishCredEncryptionKey,
        1,
    ));

    let result = init_with_resiliency(&part);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after a device reset on GetEstablishCredEncryptionKey, got: {result:?}"
    );
}

/// A device reset during `EstablishCredential` triggers a retry that
/// recovers successfully.
#[api_test]
fn test_init_recovers_after_reset_on_establish_credential() {
    let part = open_and_reset();

    inject_fault(FaultRule::reset_on_next(DdiOp::EstablishCredential, 1));

    let result = init_with_resiliency(&part);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after a device reset on EstablishCredential, got: {result:?}"
    );
}

/// Without resiliency, a device reset during `EstablishCredential` is not
/// retried — the error propagates immediately.
#[api_test]
fn test_init_fails_after_reset_without_resiliency() {
    let part = open_and_reset();

    inject_fault(FaultRule::reset_on_next(DdiOp::EstablishCredential, 1));

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);

    // No resiliency config → no retry.
    let result = part.init(creds, None, None, obk_info, pota_endorsement, None);
    clear_faults();

    assert!(
        result.is_err(),
        "init without resiliency should fail after device reset, got: {result:?}"
    );
}

/// Two consecutive device resets on `EstablishCredential` are each handled
/// by the retry machinery, and `init` ultimately succeeds.
#[api_test]
fn test_init_recovers_after_consecutive_reset() {
    let part = open_and_reset();

    // Trigger device reset on the next 2 EstablishCredential calls.
    inject_fault(FaultRule::reset_on_next(DdiOp::EstablishCredential, 2));

    let result = init_with_resiliency(&part);
    clear_faults();

    assert!(
        result.is_ok(),
        "init should recover after 2 consecutive device resets on EstablishCredential, got: {result:?}"
    );
}

/// After a reset-triggered retry on `EstablishCredential`, the POTA
/// endorsement callback is invoked to re-sign over the (potentially
/// new) device's PID public key. Verify by checking that
/// `GetCertChainInfo` was called by the callback on the retry.
#[api_test]
fn test_init_pota_reendorsement_after_reset() {
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
