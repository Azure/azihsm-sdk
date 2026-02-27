// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests for `open_partition`.
//!
//! These tests exercise the retry-with-backoff machinery on
//! [`HsmPartitionManager::open_partition`] by injecting transient DDI
//! faults through the resiliency test device.
//!
//! Unlike `init_part` (which only retries with a resiliency config),
//! `open_partition` retries unconditionally on IO-abort errors.
//!
//! The DDI operations exercised during open_partition are:
//!
//! | Step | DDI op          |
//! |------|-----------------|
//! | 1    | `GetApiRev`     |
//! | 2    | `GetDeviceInfo` |
//!
//! # Adding a new retryable error
//!
//! Append the new [`FaultError`] variant to [`OPEN_PART_RETRYABLE_ERRORS`]
//! (and to [`super::ALL_RETRYABLE_ERRORS`] if it's new globally).
//! All loop-based tests will automatically cover it.

use azihsm_res_test_dev::*;

use crate::*;

/// Error codes that trigger `open_partition` retry. Currently only
/// IO-abort conditions are retried.
const OPEN_PART_RETRYABLE_ERRORS: &[FaultError] = &[
    FaultError::Driver(DriverError::IoAborted),
    FaultError::Driver(DriverError::IoAbortInProgress),
];

/// Returns `true` when `error` is one of the open_partition-retryable
/// error codes.
fn is_open_part_retryable(error: &FaultError) -> bool {
    OPEN_PART_RETRYABLE_ERRORS.iter().any(|e| e == error)
}

/// Expected number of times `target_op` is invoked in a fault-injection
/// test.
///
/// `open_partition` calls `GetApiRev` **twice** per successful attempt:
/// once inside `open_dev → get_device_kind` and once explicitly. A
/// failed attempt only reaches one call before bailing out.
/// `GetDeviceInfo` is called once per attempt (inside `get_device_kind`).
///
/// * Retryable, faults consumed: `failed_attempts + calls_per_success`.
/// * Retryable, exhausted: `MAX_RETRIES + 1` (all failed, 1 call each).
/// * Non-retryable: 1 (single failed call).
fn expected_op_calls(error: &FaultError, target_op: DdiOp, injected_faults: u32) -> u32 {
    if !is_open_part_retryable(error) {
        return 1;
    }

    let failed_attempts = injected_faults.min(MAX_RETRIES + 1);
    let succeeded = injected_faults <= MAX_RETRIES;

    // GetApiRev: 1 call per failed attempt, 2 calls on the successful one.
    // GetDeviceInfo: 1 call per attempt (failed or successful).
    let calls_on_success = if target_op == DdiOp::GetApiRev { 2 } else { 1 };
    failed_attempts + if succeeded { calls_on_success } else { 0 }
}

/// Helper: get the path of the first available partition.
fn first_partition_path() -> String {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    list[0].path.clone()
}

/// `open_partition` recovers from a single transient fault on `GetApiRev`
/// for retryable error codes, and fails immediately for non-retryable ones.
#[api_test]
fn test_open_partition_recovers_from_get_api_rev_single_fault() {
    for error in &super::all_test_errors() {
        let path = first_partition_path();
        let before = op_call_count(DdiOp::GetApiRev);

        inject_fault(FaultRule::fail_nth(DdiOp::GetApiRev, 1, *error));

        let result = HsmPartitionManager::open_partition(&path);
        let after = op_call_count(DdiOp::GetApiRev);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_open_part_retryable,
            "single fault on GetApiRev",
        );

        let expected = expected_op_calls(error, DdiOp::GetApiRev, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on GetApiRev: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `open_partition` recovers from a single transient fault on
/// `GetDeviceInfo` for retryable error codes, and fails immediately for
/// non-retryable ones.
#[api_test]
fn test_open_partition_recovers_from_get_device_info_single_fault() {
    for error in &super::all_test_errors() {
        let path = first_partition_path();
        let before = op_call_count(DdiOp::GetDeviceInfo);

        inject_fault(FaultRule::fail_nth(DdiOp::GetDeviceInfo, 1, *error));

        let result = HsmPartitionManager::open_partition(&path);
        let after = op_call_count(DdiOp::GetDeviceInfo);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_open_part_retryable,
            "single fault on GetDeviceInfo",
        );

        let expected = expected_op_calls(error, DdiOp::GetDeviceInfo, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on GetDeviceInfo: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `open_partition` recovers on the last retry when `GetApiRev` fails
/// for the first `MAX_RETRIES` attempts (retryable errors), or fails
/// immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_open_partition_recovers_from_get_api_rev_last_retry() {
    for error in &super::all_test_errors() {
        let path = first_partition_path();
        let before = op_call_count(DdiOp::GetApiRev);

        inject_fault(FaultRule::fail_next(DdiOp::GetApiRev, MAX_RETRIES, *error));

        let result = HsmPartitionManager::open_partition(&path);
        let after = op_call_count(DdiOp::GetApiRev);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_open_part_retryable,
            "last retry on GetApiRev",
        );

        let expected = expected_op_calls(error, DdiOp::GetApiRev, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on GetApiRev: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `open_partition` recovers on the last retry when `GetDeviceInfo`
/// fails for the first `MAX_RETRIES` attempts (retryable errors), or
/// fails immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_open_partition_recovers_from_get_device_info_last_retry() {
    for error in &super::all_test_errors() {
        let path = first_partition_path();
        let before = op_call_count(DdiOp::GetDeviceInfo);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetDeviceInfo,
            MAX_RETRIES,
            *error,
        ));

        let result = HsmPartitionManager::open_partition(&path);
        let after = op_call_count(DdiOp::GetDeviceInfo);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_open_part_retryable,
            "last retry on GetDeviceInfo",
        );

        let expected = expected_op_calls(error, DdiOp::GetDeviceInfo, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on GetDeviceInfo: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

// Retry Exhaustion tests
//
// These tests inject MAX_RETRIES + 1 consecutive faults so that
// every retry is consumed and the operation ultimately fails.

/// `open_partition` fails when `GetApiRev` returns a retryable error for
/// `MAX_RETRIES + 1` consecutive calls, for every retryable error code.
#[api_test]
fn test_open_partition_fails_from_get_api_rev_exhausted() {
    for error in OPEN_PART_RETRYABLE_ERRORS {
        let path = first_partition_path();
        let before = op_call_count(DdiOp::GetApiRev);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetApiRev,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = HsmPartitionManager::open_partition(&path);
        let after = op_call_count(DdiOp::GetApiRev);
        clear_faults();

        assert!(
            result.is_err(),
            "open_partition should fail after exhausting all {MAX_RETRIES} retries with {error:?} on GetApiRev, got: {result:?}"
        );

        let expected = expected_op_calls(error, DdiOp::GetApiRev, MAX_RETRIES + 1);
        assert_eq!(
            after - before,
            expected,
            "exhaustion on GetApiRev: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}

/// `open_partition` fails when `GetDeviceInfo` returns a retryable error
/// for `MAX_RETRIES + 1` consecutive calls, for every retryable error
/// code.
#[api_test]
fn test_open_partition_fails_from_get_device_info_exhausted() {
    for error in OPEN_PART_RETRYABLE_ERRORS {
        let path = first_partition_path();
        let before = op_call_count(DdiOp::GetDeviceInfo);

        inject_fault(FaultRule::fail_next(
            DdiOp::GetDeviceInfo,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = HsmPartitionManager::open_partition(&path);
        let after = op_call_count(DdiOp::GetDeviceInfo);
        clear_faults();

        assert!(
            result.is_err(),
            "open_partition should fail after exhausting all {MAX_RETRIES} retries with {error:?} on GetDeviceInfo, got: {result:?}"
        );

        let expected = expected_op_calls(error, DdiOp::GetDeviceInfo, MAX_RETRIES + 1);
        assert_eq!(
            after - before,
            expected,
            "exhaustion on GetDeviceInfo: expected {expected} calls for {error:?}, got {}",
            after - before,
        );
    }
}
