// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware `GetUnwrappingKey` fuzzing with exact rejection oracles.
//!
//! Each iteration exercises both roles, default-PSK gating, closed sessions,
//! boundary IDs, and key stability within one partition incarnation. Structured
//! input additionally selects a request's session ID, role, and lifecycle state.
//! Typed requests do not cover malformed wire frames or injected PAL faults;
//! mismatched and closed-session requests are rejected before the handler.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::time::Duration;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use azihsm_ddi_tbor_test_harness::*;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;

/// Lifecycle state in which to send the input-selected request.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum RequestState {
    RotatedPsk,
    DefaultPsk,
    Closed,
}

/// Select a reachable session ID, a boundary value, or the full fuzzed u16.
#[derive(Arbitrary, Debug)]
enum SessionIdSource {
    Active,
    Arbitrary,
    Zero,
    Maximum,
}

/// Request field and state selectors, with bounded repeated successful reads.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    fuzzed_session_id: u16,
    session_id_source: SessionIdSource,
    role: common::FuzzRole,
    state: RequestState,
    repetitions: u8,
}

impl FuzzInput {
    /// Resolve the request's only field without assuming arbitrary IDs are invalid.
    fn session_id(&self, active_session_id: u16) -> u16 {
        match self.session_id_source {
            SessionIdSource::Active => active_session_id,
            SessionIdSource::Arbitrary => self.fuzzed_session_id,
            SessionIdSource::Zero => 0,
            SessionIdSource::Maximum => u16::MAX,
        }
    }
}

/// Independently predicted result, including transport and dispatcher rejections.
#[derive(Debug)]
enum Expected {
    Success,
    Reject(TborStatus),
}

/// Predict the result in transport-before-dispatch order from established state.
fn expected_outcome(
    request_session_id: u16,
    bound_session_id: Option<u16>,
    default_psk: bool,
) -> Expected {
    match bound_session_id {
        None => Expected::Reject(TborStatus::SessionNotFound),
        Some(bound) if request_session_id != bound => {
            Expected::Reject(TborStatus::FileHandleSessionIdDoesNotMatch)
        }
        Some(_) if default_psk => Expected::Reject(TborStatus::DefaultPskMustRotate),
        Some(_) => Expected::Success,
    }
}

/// Validate the little-endian RSA-2048 modulus and standard public exponent.
fn assert_valid_unwrapping_pub_key(pub_key: &[u8]) {
    assert_eq!(pub_key.len(), UNWRAPPING_PUB_KEY_LEN);
    let modulus_len = UNWRAPPING_PUB_KEY_LEN - core::mem::size_of::<u32>();
    let (modulus, exponent) = pub_key.split_at(modulus_len);
    assert!(
        modulus.iter().any(|&byte| byte != 0),
        "unwrapping modulus must not be all zero",
    );
    assert_ne!(modulus[0] & 1, 0, "unwrapping modulus must be odd");
    assert_ne!(
        modulus[modulus_len - 1] & 0x80,
        0,
        "unwrapping modulus must have exactly 2048 significant bits",
    );
    assert_eq!(
        u32::from_le_bytes(exponent.try_into().expect("four-byte RSA exponent")),
        65_537,
        "unwrapping key must use the standard RSA public exponent",
    );
}

/// Issue a request against a precomputed oracle and validate every successful key.
///
/// Valid requests poll for key readiness for at most 100 retries, 100 ms apart.
/// Only an exactly matched expected rejection returns `None`; all unexpected
/// errors, including driver errors and emulator key-generation failures, panic.
fn check_request(
    ctx: &TestCtx,
    request_session_id: u16,
    bound_session_id: Option<u16>,
    default_psk: bool,
) -> Option<[u8; UNWRAPPING_PUB_KEY_LEN]> {
    let expected = expected_outcome(request_session_id, bound_session_id, default_psk);
    let request = TborGetUnwrappingKeyReq {
        session_id: request_session_id,
    };
    let mut result = ctx.tbor(&request);
    if matches!(expected, Expected::Success) {
        for _ in 0..100 {
            if !matches!(
                result,
                Err(DdiError::TborStatus(TborStatus::PendingKeyGeneration))
            ) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
            result = ctx.tbor(&request);
        }
    }
    match (expected, result) {
        (Expected::Success, Ok(resp)) => {
            assert_valid_unwrapping_pub_key(&resp.pub_key);
            Some(resp.pub_key)
        }
        (Expected::Reject(status), Err(err)) => {
            assert_fw_rejects(&err, status);
            None
        }
        (Expected::Success, Err(err)) => {
            panic!("valid GetUnwrappingKey request failed: {err:?}");
        }
        (Expected::Reject(status), Ok(_)) => {
            panic!("GetUnwrappingKey unexpectedly succeeded; expected {status:?}");
        }
    }
}

/// Exercise a rotated role's live session, then close it and verify stale IDs.
///
/// Repeated and boundary-ID successes must agree with the first public key.
/// The caller compares keys across role transitions without resetting the device.
fn exercise_rotated_session(
    ctx: &TestCtx,
    session: &SessionHandshake,
    input: &FuzzInput,
    selected_role: bool,
) -> [u8; UNWRAPPING_PUB_KEY_LEN] {
    let bound = Some(session.session_id);
    let first = check_request(ctx, session.session_id, bound, false)
        .expect("matching rotated-PSK request must succeed");

    for _ in 0..=input.repetitions % 3 {
        let next = check_request(ctx, session.session_id, bound, false)
            .expect("repeated GetUnwrappingKey must succeed");
        assert_eq!(first, next, "partition unwrapping key must remain stable");
    }

    for session_id in [0, u16::MAX] {
        if let Some(key) = check_request(ctx, session_id, bound, false) {
            assert_eq!(first, key, "boundary-ID success must return the same key");
        }
    }
    if selected_role && input.state == RequestState::RotatedPsk {
        if let Some(key) = check_request(ctx, input.session_id(session.session_id), bound, false) {
            assert_eq!(first, key, "fuzzed-ID success must return the same key");
        }
    }

    ctx.session_close(session.session_id)
        .expect("close rotated-PSK session");
    check_request(ctx, session.session_id, None, false);
    first
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        // A deterministic sweep keeps all core scenarios reachable even with
        // an empty corpus, while generating only one RSA key per iteration.
        let bootstrap = ctx
            .open_session(input.role.psk_id(), input.role.session_type())
            .expect("open selected role under default PSK");
        let session_id = bootstrap.session_id();
        let bound = Some(session_id);
        for request_id in [session_id, 0, u16::MAX] {
            check_request(ctx, request_id, bound, true);
        }
        if input.state == RequestState::DefaultPsk {
            check_request(ctx, input.session_id(session_id), bound, true);
        }
        bootstrap.close().expect("close default-PSK session");
        for request_id in [session_id, 0, u16::MAX] {
            check_request(ctx, request_id, None, true);
        }
        if input.state == RequestState::Closed {
            check_request(ctx, input.session_id(session_id), None, true);
        }

        let co = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        common::finalize_partition(ctx, &co);
        let co_key =
            exercise_rotated_session(ctx, &co, &input, matches!(input.role, common::FuzzRole::Co));

        let cu = bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK);
        let cu_key =
            exercise_rotated_session(ctx, &cu, &input, matches!(input.role, common::FuzzRole::Cu));
        assert_eq!(
            co_key, cu_key,
            "CO and CU must observe the same partition key"
        );
    });
});
