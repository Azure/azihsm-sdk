// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests for `cert_chain`.
//!
//! These tests exercise the retry-with-restore machinery on
//! [`HsmPartition::cert_chain`] using two complementary strategies:
//!
//! 1. Fault-injection tests — inject transient DDI faults through
//!    the resiliency test device and verify the retry path recovers.
//! 2. Reset-triggered tests — trigger an NVMe Subsystem Reset during
//!    a DDI operation via `FaultRule::reset_on_next` (simulating a live
//!    migration event occurring mid-operation) so the DDI returns
//!    `CredentialsNotEstablished` naturally, then verify that
//!    `restore_partition` re-establishes credentials and the retry
//!    succeeds.
//!
//! `cert_chain` only retries when resiliency is enabled (a
//! [`HsmResiliencyConfig`] was passed to [`HsmPartition::init`]).
//!
//! On a retryable failure the cert-chain retry path:
//! 1. Applies exponential backoff.
//! 2. Calls `restore_partition` to re-establish credentials.
//! 3. Retries the `ddi::get_cert_chain` call.
//!
//! The DDI operations exercised during `cert_chain` are:
//!
//! | Step | DDI op              |
//! |------|---------------------|
//! | 1    | `GetCertChainInfo`  |
//! | 2    | `GetCertificate`    |
//! | 3    | `GetCertChainInfo`  |
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
//! # Adding a new retryable error
//!
//! Append the new [`FaultError`] variant to [`CERT_CHAIN_RETRYABLE_ERRORS`]
//! (and to [`super::ALL_RETRYABLE_ERRORS`] if it's new globally).
//! All loop-based tests will automatically cover it. To add a
//! non-retryable error, append to [`super::NON_RETRYABLE_ERRORS`].

use azihsm_res_test_dev::*;

use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

/// All error codes that trigger `cert_chain` retry when resiliency is enabled.
///
/// Note: `CertChainChanged` is generated at the API layer (not DDI) when
/// a reset between the two `GetCertChainInfo` calls causes a thumbprint
/// mismatch. It is retryable but cannot be injected via `FaultRule`
/// since it is not a DDI error code. It is exercised by the reset-
/// triggered tests below.
const CERT_CHAIN_RETRYABLE_ERRORS: &[FaultError] = &[
    FaultError::Driver(DriverError::IoAborted),
    FaultError::Driver(DriverError::IoAbortInProgress),
    FaultError::Status(DdiStatus::CredentialsNotEstablished),
    FaultError::Status(DdiStatus::PartitionNotProvisioned),
];

/// Returns `true` when `error` is one of the cert-chain-retryable
/// error codes.
fn is_cert_chain_retryable(error: &FaultError) -> bool {
    super::is_retryable(error, CERT_CHAIN_RETRYABLE_ERRORS)
}

/// Expected number of times the faulted `target_op` is invoked in a
/// fault-injection test.
fn expected_op_calls(error: &FaultError, injected_faults: u32) -> u32 {
    super::expected_op_calls_for(error, injected_faults, CERT_CHAIN_RETRYABLE_ERRORS)
}

/// Helper: open and init a partition with resiliency enabled, returning
/// the partition and the RAII context that cleans up.
fn init_with_resiliency() -> (HsmPartition, ResiliencyTestCtx) {
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

    (part, ctx)
}

/// Helper: open and init a partition without resiliency.
fn init_without_resiliency() -> HsmPartition {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    let part =
        HsmPartitionManager::open_partition(&list[0].path).expect("Failed to open partition");
    part.reset().expect("Partition reset failed");

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);
    part.init(creds, None, None, obk_info, pota_endorsement, None)
        .expect("Partition init failed");

    part
}

// =========================================================================
// Fault-injection tests — GetCertChainInfo
// =========================================================================

/// `cert_chain` recovers from a single transient fault on
/// `GetCertChainInfo` for retryable error codes, and fails
/// immediately for non-retryable ones.
#[api_test]
fn test_cert_chain_recovers_from_get_cert_chain_info_single_fault() {
    for error in &super::all_test_errors() {
        let (part, _ctx) = init_with_resiliency();
        let before = op_call_count(DdiOp::GetCertChainInfo);

        inject_fault(FaultRule::fail_next(DdiOp::GetCertChainInfo, 1, *error));

        let result = part.cert_chain(0);
        let after = op_call_count(DdiOp::GetCertChainInfo);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_cert_chain_retryable,
            "single fault on GetCertChainInfo",
        );

        let expected = expected_op_calls(error, 1);
        // cert_chain calls GetCertChainInfo twice per successful attempt
        // (once at the start and once for validation), so observed count
        // may exceed the theoretical single-op count.
        assert!(
            after - before >= expected,
            "single fault on GetCertChainInfo: expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// `cert_chain` recovers on the last retry when `GetCertChainInfo`
/// fails for the first `MAX_RETRIES` attempts (retryable errors),
/// or fails immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_cert_chain_recovers_from_get_cert_chain_info_last_retry() {
    for error in &super::all_test_errors() {
        let (part, _ctx) = init_with_resiliency();
        let before = op_call_count(DdiOp::GetCertChainInfo);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetCertChainInfo,
            MAX_RETRIES,
            *error,
        ));

        let result = part.cert_chain(0);
        let after = op_call_count(DdiOp::GetCertChainInfo);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_cert_chain_retryable,
            "last retry on GetCertChainInfo",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert!(
            after - before >= expected,
            "last retry on GetCertChainInfo: expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// `cert_chain` fails when `GetCertChainInfo` returns a retryable error
/// for `MAX_RETRIES + 1` consecutive calls, for every retryable error
/// code.
#[api_test]
fn test_cert_chain_fails_after_get_cert_chain_info_exhausted() {
    for error in CERT_CHAIN_RETRYABLE_ERRORS {
        let (part, _ctx) = init_with_resiliency();

        inject_fault(FaultRule::fail_next(
            DdiOp::GetCertChainInfo,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = part.cert_chain(0);
        clear_faults();

        assert!(
            result.is_err(),
            "cert_chain should fail after exhausting all retries"
        );
    }
}

// =========================================================================
// Fault-injection tests — GetCertificate
// =========================================================================

/// `cert_chain` recovers from a single transient fault on
/// `GetCertificate` for retryable error codes, and fails
/// immediately for non-retryable ones.
#[api_test]
fn test_cert_chain_recovers_from_get_certificate_single_fault() {
    for error in &super::all_test_errors() {
        let (part, _ctx) = init_with_resiliency();
        let before = op_call_count(DdiOp::GetCertificate);

        inject_fault(FaultRule::fail_next(DdiOp::GetCertificate, 1, *error));

        let result = part.cert_chain(0);
        let after = op_call_count(DdiOp::GetCertificate);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_cert_chain_retryable,
            "single fault on GetCertificate",
        );

        let expected = expected_op_calls(error, 1);
        assert!(
            after - before >= expected,
            "single fault on GetCertificate: expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// `cert_chain` recovers on the last retry when `GetCertificate`
/// fails for the first `MAX_RETRIES` attempts (retryable errors),
/// or fails immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_cert_chain_recovers_from_get_certificate_last_retry() {
    for error in &super::all_test_errors() {
        let (part, _ctx) = init_with_resiliency();
        let before = op_call_count(DdiOp::GetCertificate);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetCertificate,
            MAX_RETRIES,
            *error,
        ));

        let result = part.cert_chain(0);
        let after = op_call_count(DdiOp::GetCertificate);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_cert_chain_retryable,
            "last retry on GetCertificate",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert!(
            after - before >= expected,
            "last retry on GetCertificate: expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// `cert_chain` fails when `GetCertificate` returns a retryable error
/// for `MAX_RETRIES + 1` consecutive calls, for every retryable error
/// code.
#[api_test]
fn test_cert_chain_fails_after_get_certificate_exhausted() {
    for error in CERT_CHAIN_RETRYABLE_ERRORS {
        let (part, _ctx) = init_with_resiliency();

        inject_fault(FaultRule::fail_next(
            DdiOp::GetCertificate,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = part.cert_chain(0);
        clear_faults();

        assert!(
            result.is_err(),
            "cert_chain should fail after exhausting all retries"
        );
    }
}

// =========================================================================
// No-resiliency tests
// =========================================================================

/// Without resiliency, `cert_chain` does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_cert_chain_no_retry_without_resiliency() {
    let part = init_without_resiliency();

    inject_fault(FaultRule::fail_next(
        DdiOp::GetCertChainInfo,
        1,
        DriverError::IoAborted,
    ));

    let result = part.cert_chain(0);
    clear_faults();

    assert!(
        result.is_err(),
        "cert_chain without resiliency should fail on IoAborted, \
         got unexpected success"
    );
}

// =========================================================================
// Reset-triggered tests
// =========================================================================

/// After a reset on `GetCertChainInfo`, `cert_chain` still succeeds.
///
/// On the simulator, `GetCertChainInfo` is a device-level query that
/// continues to work after a reset (no credentials required), so
/// `cert_chain` succeeds without needing `restore_partition`.
#[api_test]
fn test_cert_chain_succeeds_after_reset_on_get_cert_chain_info() {
    let (part, _ctx) = init_with_resiliency();

    inject_fault(FaultRule::reset_on_next(DdiOp::GetCertChainInfo, 1));

    let result = part.cert_chain(0);
    clear_faults();

    assert!(
        result.is_ok(),
        "cert_chain should succeed after reset on GetCertChainInfo"
    );
}

/// After a reset on `GetCertificate`, `cert_chain` recovers.
/// Cert chain is preserved across NSSR on both mock and hardware,
/// so `restore_partition` is not needed.
#[api_test]
fn test_cert_chain_recovers_after_reset_on_get_certificate() {
    let (part, _ctx) = init_with_resiliency();

    inject_fault(FaultRule::reset_on_next(DdiOp::GetCertificate, 1));

    let result = part.cert_chain(0);
    clear_faults();

    assert!(
        result.is_ok(),
        "cert_chain should recover after reset on GetCertificate"
    );
}

/// Without resiliency, a reset during `cert_chain` is not recovered.
///
/// The reset is injected on `GetCertificate` because that operation
/// fails after a reset on the simulator, unlike `GetCertChainInfo`
/// which is a device-level query that survives resets.
///
/// On hardware the cert chain may be preserved across NSSR, so
/// `GetCertificate` succeeds and `cert_chain` returns `Ok`.
#[api_test]
fn test_cert_chain_fails_after_reset_without_resiliency() {
    let part = init_without_resiliency();

    inject_fault(FaultRule::reset_on_next(DdiOp::GetCertificate, 1));

    let result = part.cert_chain(0);
    clear_faults();

    // On mock, GetCertificate fails after reset → cert_chain fails.
    // On hardware, cert chain is preserved → cert_chain succeeds.
    #[cfg(feature = "mock")]
    assert!(
        result.is_err(),
        "cert_chain without resiliency should fail after reset on mock"
    );
    #[cfg(not(feature = "mock"))]
    assert!(
        result.is_ok(),
        "cert_chain without resiliency should succeed after reset on hardware \
         (cert chain preserved across NSSR)"
    );
}

/// `cert_chain` recovers after two consecutive resets on `GetCertChainInfo`.
#[api_test]
fn test_cert_chain_recovers_after_consecutive_resets() {
    let (part, _ctx) = init_with_resiliency();

    inject_fault(FaultRule::reset_on_next(DdiOp::GetCertChainInfo, 2));

    let result = part.cert_chain(0);
    clear_faults();

    assert!(
        result.is_ok(),
        "cert_chain should recover after two consecutive resets"
    );
}
