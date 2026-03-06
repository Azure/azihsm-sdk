// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests.
//!
//! This module contains two categories of resiliency tests:
//!
//! 1. Fault-injection tests (`res-test` feature) — each sub-module
//!    targets a specific API surface and uses the resiliency DDI device
//!    to inject transient faults, verifying that the retry-with-backoff
//!    machinery recovers correctly.
//!
//! 2. Stress tests (`res-test` feature) — multi-threaded tests that
//!    trigger real NSSRs via [`HsmPartition::reset`]
//!    while worker threads perform key operations concurrently.
//!
//! # Shared error arrays (fault-injection tests)
//!
//! [`ALL_RETRYABLE_ERRORS`] contains every error code that is retryable
//! by at least one resiliency-enabled operation. Individual sub-modules
//! define narrower arrays (e.g. `INIT_RETRYABLE_ERRORS`) for the errors
//! their specific operation retries.
//!
//! [`NON_RETRYABLE_ERRORS`] contains representative non-retryable errors.
//!
//! [`all_test_errors`] returns the union of both arrays, used by
//! parametric tests that iterate all error codes and branch on
//! retryability.

#[cfg(feature = "res-test")]
use azihsm_res_test_dev::*;

#[cfg(feature = "res-test")]
mod close_session;
#[cfg(feature = "res-test")]
mod helpers;
#[cfg(feature = "res-test")]
mod init_part;
#[cfg(feature = "res-test")]
mod key_gen;
#[cfg(feature = "res-test")]
mod key_ops;
#[cfg(feature = "res-test")]
mod open_part;
#[cfg(feature = "res-test")]
mod open_session;
#[cfg(feature = "res-test")]
mod stress;

/// Asserts that a retryable error produces `Ok` and a non-retryable
/// error produces `Err`.
///
/// `is_retryable` is the operation-specific predicate (e.g.
/// `is_init_retryable`, `is_open_part_retryable`).
/// `context` is a short phrase included in the assertion message,
/// e.g. `"single fault on InitBk3"`.
#[cfg(feature = "res-test")]
fn assert_retryable_outcome<T: std::fmt::Debug>(
    result: &Result<T, azihsm_api::HsmError>,
    error: &FaultError,
    is_retryable: impl Fn(&FaultError) -> bool,
    context: &str,
) {
    if is_retryable(error) {
        assert!(
            result.is_ok(),
            "{context}: expected Ok for retryable {error:?}, got {result:?}"
        );
    } else {
        assert!(
            result.is_err(),
            "{context}: expected Err for non-retryable {error:?}, got {result:?}"
        );
    }
}

/// Every error code that is retryable by at least one resiliency-enabled
/// operation (open_partition, init_part, open_session, …).
///
/// Individual sub-modules have narrower operation-specific arrays that
/// are subsets of this list. Future PRs will extend this array as more
/// operations gain resiliency support.
#[cfg(feature = "res-test")]
const ALL_RETRYABLE_ERRORS: &[FaultError] = &[
    FaultError::Driver(DriverError::IoAborted),
    FaultError::Driver(DriverError::IoAbortInProgress),
    FaultError::DeviceNotReady,
    FaultError::Status(DdiStatus::CredentialsNotEstablished),
    FaultError::Status(DdiStatus::NonceMismatch),
    FaultError::Status(DdiStatus::PartitionNotProvisioned),
    FaultError::Status(DdiStatus::EccVerifyFailed),
    FaultError::Status(DdiStatus::SessionNeedsRenegotiation),
    FaultError::Status(DdiStatus::PendingKeyGeneration),
    FaultError::Status(DdiStatus::KeyNotFound),
];

/// Error codes that trigger retry for key-generation (`resiliency_key_gen`)
/// and key-operation (`resiliency_key_op`) macros.
///
/// This is a subset of [`ALL_RETRYABLE_ERRORS`]; `close_session` and
/// `open_session` have their own narrower / broader lists.
#[cfg(feature = "res-test")]
const KEY_OP_RETRYABLE_ERRORS: &[FaultError] = &[
    FaultError::Driver(DriverError::IoAborted),
    FaultError::Driver(DriverError::IoAbortInProgress),
    FaultError::DeviceNotReady,
    FaultError::Status(DdiStatus::SessionNeedsRenegotiation),
    FaultError::Status(DdiStatus::PendingKeyGeneration),
    FaultError::Status(DdiStatus::KeyNotFound),
];

/// Representative non-retryable errors — no operation should retry these.
#[cfg(feature = "res-test")]
const NON_RETRYABLE_ERRORS: &[FaultError] = &[
    FaultError::Status(DdiStatus::InvalidArg),
    FaultError::Status(DdiStatus::InternalError),
    FaultError::Status(DdiStatus::MaskedKeyDecodeFailed),
];

/// Returns `true` when `error` is in the given retryable-errors slice.
#[cfg(feature = "res-test")]
fn is_retryable(error: &FaultError, retryable_errors: &[FaultError]) -> bool {
    retryable_errors.iter().any(|e| e == error)
}

/// Expected number of DDI op invocations for a fault-injection test.
///
/// * Retryable errors: `min(injected_faults + 1, MAX_RETRIES + 1)`.
/// * Non-retryable errors: 1 (single failed call, no retry).
#[cfg(feature = "res-test")]
fn expected_op_calls_for(
    error: &FaultError,
    injected_faults: u32,
    retryable_errors: &[FaultError],
) -> u32 {
    if is_retryable(error, retryable_errors) {
        (injected_faults + 1).min(azihsm_api::MAX_RETRIES + 1)
    } else {
        1
    }
}

/// Combined list of all errors to exercise in parametric tests.
#[cfg(feature = "res-test")]
fn all_test_errors() -> Vec<FaultError> {
    ALL_RETRYABLE_ERRORS
        .iter()
        .chain(NON_RETRYABLE_ERRORS)
        .copied()
        .collect()
}
