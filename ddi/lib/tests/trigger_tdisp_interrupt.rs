// Copyright (C) Microsoft Corporation. All rights reserved.

// Import the macro from the self_test module
mod common;

use std::env;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

static SKIP_COMMON_CLEANUP: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[test]
fn trigger_tdisp_interrupt() {
    ddi_dev_test(
        common_setup,
        |dev, ddi, path, session_id| {
            if SKIP_COMMON_CLEANUP.load(std::sync::atomic::Ordering::SeqCst) {
                tracing::warn!("VM is gone. No more common_cleanup");
                return;
            }

            common_cleanup(dev, ddi, path, session_id);
        },
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Read the parameters from an environment variable
            let int_type_str = env::var("INTERRUPT_TYPE").unwrap_or_else(|_| "TDISP".to_string());
            let interrupt_type = match int_type_str.as_str() {
                "TDISP" => DdiTestActionInterruptSimulationType::Tdisp,
                "IDE" => DdiTestActionInterruptSimulationType::Ide,
                "FLR" => DdiTestActionInterruptSimulationType::Flr,
                "PERST_UP" => DdiTestActionInterruptSimulationType::PerstUp,
                "PERST_DOWN" => DdiTestActionInterruptSimulationType::PerstDown,
                _ => {
                    tracing::warn!("Invalid interrupt type specified: {}", int_type_str);
                    return;
                }
            };

            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerTdispInterrupt,
                DdiTestActionContext::TdispInterruptType(interrupt_type),
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            SKIP_COMMON_CLEANUP.store(true, std::sync::atomic::Ordering::SeqCst);

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

fn is_unsupported_cmd(err: &DdiError) -> bool {
    if let DdiError::DdiStatus(DdiStatus::UnsupportedCmd) = err {
        println!("Firmware is not built with mcr_test_hooks.");
        true
    } else {
        false
    }
}
