// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_ddi_tbor_types::SD_SEALING_PUB_KEY_LEN;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Select the active CO session ID instead of the arbitrary ID.
    use_active_session_id: bool,
    fuzzed_session_id: u16,
    /// Close the CO session before issuing the command to exercise the
    /// handler's inactive-session rejection path.
    close_session_before_request: bool,
    /// Scope requested for `SdSealingKeyGen`.
    key_scope: common::KeyScope,
}

#[derive(Clone, Copy)]
enum Expected {
    Success,
    Reject(TborStatus),
}

fn expected_outcome(
    request_session_id: u16,
    active_session_id: u16,
    session_was_closed: bool,
    scope: common::KeyScope,
) -> Expected {
    // The emulator/driver rejects a request with no session bound to the
    // handle before firmware dispatch. A mismatched ID on an otherwise
    // active handle has a distinct file-handle status.
    if session_was_closed {
        return Expected::Reject(TborStatus::SessionNotFound);
    }
    if request_session_id != active_session_id {
        return Expected::Reject(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    match scope {
        common::KeyScope::Ephemeral
        | common::KeyScope::Local
        | common::KeyScope::SecurityDomain => Expected::Success,
        common::KeyScope::Unspecified | common::KeyScope::Session | common::KeyScope::Internal => {
            Expected::Reject(TborStatus::UnsupportedKeyScope)
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        if input.key_scope == common::KeyScope::SecurityDomain {
            common::create_test_security_domain(ctx, &session);
        } else {
            common::finalize_partition(ctx, &session);
        }

        let session_id = if input.use_active_session_id {
            session.session_id
        } else {
            input.fuzzed_session_id
        };
        let scope = input.key_scope.to_tbor();

        if input.close_session_before_request {
            ctx.session_close(session.session_id)
                .expect("session close before fuzzed request should succeed");
        }

        let expected = expected_outcome(
            session_id,
            session.session_id,
            input.close_session_before_request,
            input.key_scope,
        );
        let req = TborSdSealingKeyGenReq { session_id, scope };
        let result = ctx.tbor(&req);

        match result {
            Ok(resp) => {
                assert!(
                    matches!(expected, Expected::Success),
                    "invalid SdSealingKeyGen request unexpectedly succeeded"
                );
                assert_eq!(
                    resp.masked_key.len(),
                    MASKED_SEALING_KEY_LEN,
                    "masked sealing key has the wrong length"
                );
                assert!(
                    resp.masked_key.iter().any(|&byte| byte != 0),
                    "masked sealing key must not be all-zero"
                );
                assert_eq!(
                    resp.pub_key.len(),
                    SD_SEALING_PUB_KEY_LEN,
                    "sealing public key has the wrong length"
                );
                assert!(
                    resp.pub_key.iter().any(|&byte| byte != 0),
                    "sealing public key must not be all-zero"
                );
            }
            Err(err @ DdiError::DriverError(_)) => {
                panic!("Crash Detected: {err:?}");
            }
            Err(err) => match expected {
                Expected::Success => {
                    panic!("valid SdSealingKeyGen request failed: {err:?}");
                }
                Expected::Reject(expected_status) => assert!(
                    matches!(err, DdiError::TborStatus(status) if status == expected_status),
                    "expected {expected_status:?}, got {err:?}"
                ),
            },
        }

        if !input.close_session_before_request {
            ctx.session_close(session.session_id)
                .expect("session close should succeed");
        }
    });
});
