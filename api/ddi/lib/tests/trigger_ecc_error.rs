// Copyright (C) Microsoft Corporation. All rights reserved.

// Import the macro from the self_test module
mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn trigger_dtcm_ecc_error_cp0() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let ecc_error_info = DdiTestActionEccErrorInfo {
                ecc_error_type: DdiTestActionEccErrorType::DtcmDoubleBit,
                cpu_id: DdiTestActionSocCpuId::Admin,
            };

            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerEccError,
                None,
                None,
                None,
                None,
                None,
                Some(ecc_error_info),
                None,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Expect Err(DriverError(IoAborted)) due to crash and recovery
            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted) => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn trigger_dtcm_ecc_error_cp1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let ecc_error_info = DdiTestActionEccErrorInfo {
                ecc_error_type: DdiTestActionEccErrorType::DtcmDoubleBit,
                cpu_id: DdiTestActionSocCpuId::Hsm,
            };

            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerEccError,
                None,
                None,
                None,
                None,
                None,
                Some(ecc_error_info),
                None,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Expect Err(DriverError(IoAborted)) due to crash and recovery
            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted) => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
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
