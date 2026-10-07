// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::SessionHandshake;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_ddi_tbor_types::SD_SEALING_PUB_KEY_LEN;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const SCOPE_EPHEMERAL: u8 = 0b010;
const SCOPE_LOCAL: u8 = 0b011;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Select the active CO session ID instead of the arbitrary ID.
    use_active_session_id: bool,
    fuzzed_session_id: u16,
    /// Close the CO session before issuing the command to exercise the
    /// handler's inactive-session rejection path.
    close_session_before_request: bool,
    /// Bias iterations toward the two scopes expected to succeed while
    /// retaining arbitrary scope bytes for unsupported-scope coverage.
    prefer_supported_scope: bool,
    fuzzed_scope: u8,
}

#[derive(Clone, Copy)]
enum Expected {
    Success,
    Reject(TborStatus),
}

fn finalize_partition(ctx: &TestCtx, session: &SessionHandshake) {
    let pota = CaKey::generate();
    let policy = common::known_good_part_policy(pota.raw_pub());
    let init = ctx
        .part_init(
            session,
            &common::mach_seed(),
            &policy,
            &common::pota_thumbprint(),
        )
        .expect("PartInit should succeed");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy, &[], &chain.der_items())
        .expect("PartFinal should succeed");
}

fn expected_outcome(
    request_session_id: u16,
    active_session_id: u16,
    session_was_closed: bool,
    scope: u8,
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
    if matches!(scope, SCOPE_EPHEMERAL | SCOPE_LOCAL) {
        Expected::Success
    } else {
        Expected::Reject(TborStatus::UnsupportedKeyScope)
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        finalize_partition(ctx, &session);

        let session_id = if input.use_active_session_id {
            session.session_id
        } else {
            input.fuzzed_session_id
        };
        let scope = if input.prefer_supported_scope {
            if input.fuzzed_scope & 1 == 0 {
                SCOPE_EPHEMERAL
            } else {
                SCOPE_LOCAL
            }
        } else {
            input.fuzzed_scope
        };

        if input.close_session_before_request {
            ctx.session_close(session.session_id)
                .expect("session close before fuzzed request should succeed");
        }

        let expected = expected_outcome(
            session_id,
            session.session_id,
            input.close_session_before_request,
            scope,
        );
        let req = TborSdSealingKeyGenReq { session_id, scope };
        let result = ctx.tbor(&req);

        match result {
            Ok(resp) => {
                assert!(
                    matches!(expected, Expected::Success),
                    "invalid SdSealingKeyGen request unexpectedly succeeded: \
                     session_id={session_id}, scope={scope:#04x}"
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
