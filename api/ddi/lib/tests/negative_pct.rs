// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_ecc_generate_p256_trigger_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerNegativePctFailure,
                None,
                None,
                None,
                None,
                Some(0),
                None,
                None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted)
                    | DdiError::DriverError(DriverError::IoAbortInProgress)
                    | DdiError::DeviceNotReady => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn test_ecc_generate_p384_trigger_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerNegativePctFailure,
                None,
                None,
                None,
                None,
                Some(0),
                None,
                None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P384,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted)
                    | DdiError::DriverError(DriverError::IoAbortInProgress)
                    | DdiError::DeviceNotReady => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn test_ecc_generate_p521_trigger_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerNegativePctFailure,
                None,
                None,
                None,
                None,
                Some(0),
                None,
                None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P521,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted)
                    | DdiError::DriverError(DriverError::IoAbortInProgress)
                    | DdiError::DeviceNotReady => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn test_ecdh_256_key_exchange_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerNegativePctFailure,
                None,
                None,
                None,
                None,
                Some(0),
                None,
                None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted)
                    | DdiError::DriverError(DriverError::IoAbortInProgress)
                    | DdiError::DeviceNotReady => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn test_ecdh_384_key_exchange_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerNegativePctFailure,
                None,
                None,
                None,
                None,
                Some(0),
                None,
                None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P384,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted)
                    | DdiError::DriverError(DriverError::IoAbortInProgress)
                    | DdiError::DeviceNotReady => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerNegativePctFailure,
                None,
                None,
                None,
                None,
                Some(0),
                None,
                None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P521,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted)
                    | DdiError::DriverError(DriverError::IoAbortInProgress)
                    | DdiError::DeviceNotReady => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn test_get_unwrapping_key_trigger_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerNegativePctFailure,
                None,
                None,
                None,
                None,
                Some(0),
                None,
                None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            std::thread::sleep(std::time::Duration::from_secs(30));

            let req = DdiGetUnwrappingKeyCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetUnwrappingKey,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetUnwrappingKeyReq {},
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted)
                    | DdiError::DriverError(DriverError::IoAbortInProgress)
                    | DdiError::DeviceNotReady => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn test_get_establish_cred_encryption_key_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerNegativePctFailure,
                None,
                None,
                None,
                None,
                Some(0),
                None,
                None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            // This will call the reset function
            common_cleanup(dev, ddi, path, None);

            let req = DdiGetEstablishCredEncryptionKeyCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetEstablishCredEncryptionKey,
                    sess_id: None,
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetEstablishCredEncryptionKeyReq {},
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted)
                    | DdiError::DriverError(DriverError::IoAbortInProgress)
                    | DdiError::DeviceNotReady => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn test_get_session_encryption_key_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if let Err(err) = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerNegativePctFailure,
                None,
                None,
                None,
                None,
                Some(1),
                None,
                None,
            ) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected error: {:?}", err);
            };

            // This will call the reset function
            common_cleanup(dev, ddi, path, None);

            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let req = DdiGetSessionEncryptionKeyCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetSessionEncryptionKey,
                    sess_id: None,
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetSessionEncryptionKeyReq {},
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted)
                    | DdiError::DriverError(DriverError::IoAbortInProgress)
                    | DdiError::DeviceNotReady => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}
