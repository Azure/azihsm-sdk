// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test for the `ClearUserCredentials` test-hook action.
//!
//! Drives `DdiTestAction::ClearUserCredentials` (DdiOp 2004) against an
//! open session and asserts the platform handler reports success. The
//! action needs no request-specific payload, so it is sent with
//! `DdiTestActionContext::None`.
//!
//! Requires the `helpers` feature (host send helpers) and a device
//! whose firmware is built with `mcr_test_hooks`.

#![cfg(feature = "helpers")]
#![allow(clippy::unwrap_used)]

mod common;

use azihsm_ddi_mbor_types::DdiStatus;
use azihsm_ddi_test_hooks::helper_test_action_cmd;
use azihsm_ddi_test_hooks::DdiTestAction;
use azihsm_ddi_test_hooks::DdiTestActionContext;
use common::common_cleanup;
use common::common_setup;
use common::ddi_dev_test;
use test_with_tracing::test;

#[test]
fn clear_user_credentials_succeeds() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::ClearUserCredentials,
                DdiTestActionContext::None,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            assert_eq!(resp.unwrap().hdr.status, DdiStatus::Success);
        },
    );
}
