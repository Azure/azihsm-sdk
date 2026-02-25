// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests for `open_partition`.
//!
//! These tests exercise the retry-with-backoff machinery on
//! [`HsmPartitionManager::open_partition`] by injecting transient DDI
//! faults through the resiliency mock device.
//!

use azihsm_ddi_resiliency::*;

use crate::*;

/// Helper: get the path of the first available partition.
fn first_partition_path() -> String {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    list[0].path.clone()
}

/// `open_partition` recovers when the 1st `GetApiRev` fails with `IoAborted`.
#[api_test]
fn test_open_partition_recovers_from_get_api_rev_io_aborted() {
    let path = first_partition_path();

    inject_fault(FaultRule::fail_nth(
        DdiOp::GetApiRev,
        1,
        DriverError::IoAborted,
    ));

    let result = HsmPartitionManager::open_partition(&path);

    clear_faults();

    assert!(
        result.is_ok(),
        "open_partition should recover after a single transient IoAborted on GetApiRev, got: {result:?}"
    );
}

/// `open_partition` recovers when the 1st `GetApiRev` fails with `IoAbortInProgress`.
#[api_test]
fn test_open_partition_recovers_from_get_api_rev_io_abort_in_progress() {
    let path = first_partition_path();

    inject_fault(FaultRule::fail_nth(
        DdiOp::GetApiRev,
        1,
        DriverError::IoAbortInProgress,
    ));

    let result = HsmPartitionManager::open_partition(&path);

    clear_faults();

    assert!(
        result.is_ok(),
        "open_partition should recover after a single transient IoAbortInProgress on GetApiRev, got: {result:?}"
    );
}

/// `open_partition` recovers when the 1st `GetDeviceInfo` fails with `IoAborted`.
#[api_test]
fn test_open_partition_recovers_from_get_device_info_io_aborted() {
    let path = first_partition_path();

    inject_fault(FaultRule::fail_nth(
        DdiOp::GetDeviceInfo,
        1,
        DriverError::IoAborted,
    ));

    let result = HsmPartitionManager::open_partition(&path);

    clear_faults();

    assert!(
        result.is_ok(),
        "open_partition should recover after a single transient IoAborted on GetDeviceInfo, got: {result:?}"
    );
}

/// `open_partition` recovers when the 1st `GetDeviceInfo` fails with `IoAbortInProgress`.
#[api_test]
fn test_open_partition_recovers_from_get_device_info_io_abort_in_progress() {
    let path = first_partition_path();

    inject_fault(FaultRule::fail_nth(
        DdiOp::GetDeviceInfo,
        1,
        DriverError::IoAbortInProgress,
    ));

    let result = HsmPartitionManager::open_partition(&path);

    clear_faults();

    assert!(
        result.is_ok(),
        "open_partition should recover after a single transient IoAbortInProgress on GetDeviceInfo, got: {result:?}"
    );
}

/// `open_partition` recovers on the last retry when `GetApiRev` fails
/// with `IoAborted` for the first 5 attempts.
///
/// `GetApiRev` is the first `exec_op` call in each attempt, so each
/// failing call consumes exactly one fault from the `fail_next` counter.
#[api_test]
fn test_open_partition_recovers_from_get_api_rev_io_aborted_last_retry() {
    let path = first_partition_path();

    // Fail the first MAX_RETRIES GetApiRev calls; the next attempt succeeds.
    inject_fault(FaultRule::fail_next(
        DdiOp::GetApiRev,
        MAX_RETRIES,
        DriverError::IoAborted,
    ));

    let result = HsmPartitionManager::open_partition(&path);

    clear_faults();

    assert!(
        result.is_ok(),
        "open_partition should recover on the last retry after {MAX_RETRIES} consecutive IoAborted on GetApiRev, got: {result:?}"
    );
}

/// `open_partition` recovers on the last retry when `GetDeviceInfo` fails
/// with `IoAborted` for the first 5 attempts.
///
/// `GetDeviceInfo` is called once per attempt (after `GetApiRev` succeeds),
/// so each failing call consumes exactly one fault from the counter.
#[api_test]
fn test_open_partition_recovers_from_get_device_info_io_aborted_last_retry() {
    let path = first_partition_path();

    // Fail the first MAX_RETRIES GetDeviceInfo calls; the next attempt succeeds.
    inject_fault(FaultRule::fail_next(
        DdiOp::GetDeviceInfo,
        MAX_RETRIES,
        DriverError::IoAborted,
    ));

    let result = HsmPartitionManager::open_partition(&path);

    clear_faults();

    assert!(
        result.is_ok(),
        "open_partition should recover on the last retry after {MAX_RETRIES} consecutive IoAborted on GetDeviceInfo, got: {result:?}"
    );
}
