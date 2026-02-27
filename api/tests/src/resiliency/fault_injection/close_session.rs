// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests for `close_session`.
//!
//! The `close_session` DDI operation uses hand-written
//! retryable-error swallowing rather than the `#[resiliency_key_op]`
//! macro. When a retryable error occurs (indicating the device has
//! been through a resiliency event), the session that the call
//! intended to close is already destroyed, so `close_session` treats
//! the error as success instead of retrying.
//!
//! # DDI operations under test
//!
//! | Operation        | DDI op         |
//! |------------------|----------------|
//! | `close_session`  | `CloseSession` |
//!
//! # Test strategy
//!
//! `close_session` is only called from `HsmSession`'s `Drop` impl,
//! which discards the result. Therefore these tests verify:
//!
//! 1. Dropping a session with a retryable fault on `CloseSession`
//!    does not panic and issues exactly one DDI call (no retry).
//! 2. After a reset on `CloseSession`, the partition remains usable
//!    and a new session can be opened.
//! 3. Non-retryable errors on `CloseSession` also do not panic
//!    (Drop must never panic).

use azihsm_res_test_dev::DdiOp;
use azihsm_res_test_dev::DdiStatus;
use azihsm_res_test_dev::DriverError;
use azihsm_res_test_dev::FaultError;
use azihsm_res_test_dev::FaultRule;
use azihsm_res_test_dev::clear_faults;
use azihsm_res_test_dev::inject_fault;
use azihsm_res_test_dev::op_call_count;

use super::super::helpers::*;
use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

/// All error codes that `close_session` treats as success.
const RETRYABLE_ERRORS: &[FaultError] = &[
    FaultError::Driver(DriverError::IoAborted),
    FaultError::Driver(DriverError::IoAbortInProgress),
    FaultError::Status(DdiStatus::SessionNeedsRenegotiation),
    FaultError::Status(DdiStatus::PendingKeyGeneration),
];

// =========================================================================
// Fault-injection tests
// =========================================================================

/// Dropping a session with a retryable fault on `CloseSession` does
/// not panic and issues exactly one DDI call (no wasteful retry).
#[api_test]
fn test_close_session_swallows_retryable_errors() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        let before = op_call_count(DdiOp::CloseSession);

        inject_fault(FaultRule::fail_next(DdiOp::CloseSession, 1, *error));

        // Drop the session — triggers close_session internally.
        drop(session);

        let after = op_call_count(DdiOp::CloseSession);
        clear_faults();

        // close_session should have been called exactly once (no retry).
        assert_eq!(
            after - before,
            1,
            "close_session should issue exactly 1 CloseSession DDI call \
             for retryable {error:?}, got {}",
            after - before,
        );
    }
}

/// A non-retryable error on `CloseSession` does not panic — Drop must
/// be infallible. The error is silently discarded.
#[api_test]
fn test_close_session_does_not_panic_on_non_retryable_error() {
    for error in super::NON_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        let before = op_call_count(DdiOp::CloseSession);

        inject_fault(FaultRule::fail_next(DdiOp::CloseSession, 1, *error));

        // Drop — must not panic.
        drop(session);

        let after = op_call_count(DdiOp::CloseSession);
        clear_faults();

        assert_eq!(
            after - before,
            1,
            "close_session should issue exactly 1 CloseSession DDI call \
             for non-retryable {error:?}, got {}",
            after - before,
        );
    }
}

/// After a retryable fault on `CloseSession`, the partition handle
/// remains valid — querying partition metadata does not panic or
/// return an error.
///
/// Full "reset → re-init → open_session" recovery is covered by
/// `test_close_session_does_not_panic_after_reset`.
#[api_test]
fn test_partition_handle_valid_after_close_session_fault() {
    for error in RETRYABLE_ERRORS {
        let (part, session, _ctx) = init_with_resiliency_and_session();

        inject_fault(FaultRule::fail_next(DdiOp::CloseSession, 1, *error));

        // Drop the session — close_session swallows the error.
        drop(session);
        clear_faults();

        // The partition handle should still be valid; calling
        // `api_rev_range` must not panic.
        let _ = part.api_rev_range();
    }
}

// =========================================================================
// Reset-triggered tests
// =========================================================================

/// Dropping a session while `CloseSession` triggers a reset does not
/// panic, and the partition remains functional afterward.
#[api_test]
fn test_close_session_does_not_panic_after_reset() {
    let (part, session, _ctx) = init_with_resiliency_and_session();

    inject_fault(FaultRule::reset_on_next(DdiOp::CloseSession, 1));

    // Drop — close_session sees SessionNeedsRenegotiation, swallows it.
    drop(session);
    clear_faults();

    // After the device is reset, re-init and verify usability.
    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);
    let (resiliency_config, _ctx2) = make_resiliency_config(&part);
    part.init(
        creds,
        None,
        None,
        obk_info,
        pota_endorsement,
        Some(resiliency_config),
    )
    .expect("Partition re-init after reset should succeed");

    let rev = part.api_rev_range().max();
    let result = part.open_session(rev, &creds, None);
    assert!(
        result.is_ok(),
        "Partition should be usable after close_session swallows a reset, \
         got err: {:?}",
        result.as_ref().err(),
    );
}
