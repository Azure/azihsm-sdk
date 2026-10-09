// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::CO_PSK_ID;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::SessionOpenInitOptions;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::build_mac_fin;
use azihsm_ddi_tbor_types::MAC_FIN_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborStatus;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum TestAppOps {
    OpenSession([u8; 16], [u8; 16]),
    CloseSession(u16),
}

fuzz_target!(|ops: Vec<TestAppOps>| {
    common::common_fuzz_test(&|ctx: &TestCtx, path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let mut file_handles = Vec::new();

        for op in &ops {
            match op {
                TestAppOps::OpenSession(user_id, pin) => {
                    // The existing TBOR session occupies this file handle, so
                    // another SessionOpenInit must hit the per-handle limit.
                    let result = ctx.session_open_init(CO_PSK_ID, SessionType::Authenticated);
                    assert!(
                        matches!(
                            result,
                            Err(DdiError::TborStatus(status))
                                if status == TborStatus::FileHandleSessionLimitReached
                        ),
                        "SessionOpenInit on an occupied file handle should hit the session limit: {result:?}"
                    );

                    // TBOR sessions are opened on their own file handle. Use
                    // the rotated CO PSK for Phase 1, then fuzz Phase 2 with
                    // the original user-id/PIN bytes as a MAC mutation.
                    let secondary = TestCtx::new_with_path(path);
                    let pending = match secondary.session_open_init_with_options(
                        SessionOpenInitOptions::new(CO_PSK_ID, SessionType::Authenticated)
                            .with_psk(&ROTATED_CO_PSK),
                    ) {
                        Ok(pending) => pending,
                        Err(DdiError::TborStatus(status))
                            if status == TborStatus::VaultSessionLimitReached =>
                        {
                            continue;
                        }
                        Err(error) => {
                            panic!("SessionOpenInit with the rotated CO PSK failed: {error:?}")
                        }
                    };
                    let pending_session_id = pending.session_id;
                    let expected_mac = build_mac_fin(&pending)
                        .expect("building a valid SessionOpenFinish MAC should succeed");

                    if user_id[0] & 1 == 0 {
                        let opened = secondary
                            .session_open_finish_with_mac(pending, expected_mac)
                            .expect("SessionOpenFinish with the valid MAC should succeed");
                        file_handles.push((secondary, opened.session_id));
                    } else {
                        let mut invalid_mac = expected_mac;
                        for (index, byte) in user_id.iter().chain(pin.iter()).enumerate() {
                            invalid_mac[index % MAC_FIN_LEN] ^= *byte;
                        }
                        invalid_mac[0] ^= 1;

                        let finish_result =
                            secondary.session_open_finish_with_mac(pending, invalid_mac);
                        assert!(
                            matches!(
                                finish_result,
                                Err(DdiError::TborStatus(status))
                                    if status == TborStatus::SessionAuthFailure
                            ),
                            "SessionOpenFinish with a mutated MAC should fail authentication: {finish_result:?}"
                        );

                        let close_result = secondary.session_close(pending_session_id);
                        assert!(
                            matches!(
                                close_result,
                                Err(DdiError::TborStatus(status))
                                    if status == TborStatus::SessionNotFound
                            ),
                            "SessionClose on a failed handshake should report SessionNotFound: {close_result:?}"
                        );
                    }
                }
                TestAppOps::CloseSession(session_id) => {
                    if let Some((file_handle, opened_session_id)) = file_handles.pop() {
                        let result = file_handle.session_close(*session_id);
                        if *session_id == opened_session_id {
                            result.expect("SessionClose for the matching session should succeed");
                        } else {
                            assert!(
                                matches!(
                                    result,
                                    Err(DdiError::TborStatus(status))
                                        if status == TborStatus::FileHandleSessionIdDoesNotMatch
                                ),
                                "SessionClose for a different session ID should be rejected: {result:?}"
                            );
                            file_handle
                                .session_close(opened_session_id)
                                .expect("closing the tracked session should succeed");
                        }
                    }
                }
            }
        }

        for (file_handle, session_id) in file_handles {
            file_handle
                .session_close(session_id)
                .expect("closing the tracked session should succeed");
        }

        ctx.session_close(session.session_id)
            .expect("closing the bootstrap session should succeed");
    });
});
