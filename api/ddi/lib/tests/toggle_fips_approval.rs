// Copyright (C) Microsoft Corporation. All rights reserved.

// Import the macro from the self_test module
mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

fn is_unsupported_cmd(err: &DdiError) -> bool {
    if let DdiError::DdiStatus(DdiStatus::UnsupportedCmd) = err {
        println!("Firmware is not built with fips_validation_hooks.");
        true
    } else {
        false
    }
}

fn verify_physical_device(dev: &mut <DdiTest as Ddi>::Dev) -> bool {
    if get_device_kind(dev) != DdiDeviceKind::Physical {
        tracing::debug!(
            "Toggle FIPS approved status is only support in Physical platform. Skipping the test..."
        );
        return false;
    }

    true
}

#[test]
fn test_toggle_fips_approved_state() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device(dev) {
                return;
            }

            let original_fips_approval_state = is_fips_approved_module(dev);

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::ToggleFipsApprovedState,
                DdiTestActionContext::None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            let new_fips_approved_state = is_fips_approved_module(dev);

            assert_eq!(
                original_fips_approval_state, !new_fips_approved_state,
                "FIPS approved state should be toggled"
            );

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::ToggleFipsApprovedState,
                DdiTestActionContext::None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            let final_fips_approved_state = is_fips_approved_module(dev);

            assert_eq!(
                original_fips_approval_state, final_fips_approved_state,
                "FIPS approved state should be toggled back to the original state"
            );
        },
    );
}
