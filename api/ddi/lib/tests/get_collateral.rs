// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::thread;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

// THIS TEST IS FOR PHYSICAL MANTICORE ONLY
// Fetch DdiGetCollateralType::CertChainLen from multiple threads simultaneously
#[test]
fn test_get_collateral_cert_chain_length_multithread() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            // Skip test for virtual device as it doesn't support cert chain length yet
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!(
                    "Skipped test_get_collateral_cert_chain_length_multithread for virtual device"
                );
                return;
            }

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            let mut threads = Vec::new();
            let thread_count = MAX_SESSIONS - 1;
            println!("Thread count: {}", thread_count);

            for i in 0..thread_count {
                let device_path = path.to_string();

                let thread = thread::spawn(move || test_thread_fn(i, device_path, thread_count));
                threads.push(thread);
            }

            // Collect and compare the results
            let mut prev_num_cert: Option<u8> = None;
            for thread in threads {
                let result = thread.join();
                assert!(result.is_ok(), "result {:?}", result);
                let num_cert = result.unwrap();

                match prev_num_cert {
                    Some(prev) => assert_eq!(prev, num_cert),
                    None => prev_num_cert = Some(num_cert),
                }
            }
        },
    );
}

// Get and return Cert Chain Len
fn test_thread_fn(thread_id: usize, device_path: String, max_attempts: usize) -> u8 {
    tracing::debug!(thread_id, "Getting CertChainLen");

    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    let mut app_sess_id = None;
    let mut short_app_id = None;

    for _ in 0..max_attempts {
        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN);

        let resp = helper_open_session(
            &dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        );

        if resp.as_ref().is_err() {
            if matches!(
                resp.as_ref().unwrap_err(),
                DdiError::DdiStatus(DdiStatus::NonceMismatch)
            ) {
                continue;
            }
        }

        assert!(resp.is_ok(), "resp {:?}", resp);

        let resp = resp.unwrap();

        assert!(resp.hdr.sess_id.is_some());
        assert_eq!(resp.hdr.op, DdiOp::OpenSession);
        assert_eq!(resp.hdr.status, DdiStatus::Success);

        app_sess_id = Some(resp.data.sess_id);
        short_app_id = Some(resp.data.short_app_id);

        break;
    }

    let app_sess_id = app_sess_id.unwrap();

    let _short_app_sess_id = short_app_id.unwrap();

    // Make GetCollateral call
    let req = DdiGetCollateralCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetCollateral,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetCollateralReq {
            collateral_type: DdiGetCollateralType::CertChainLen,
            cert_id: None,
        },
        ext: None,
    };
    let mut cookie = None;
    let result = dev.exec_op(&req, &mut cookie);
    assert!(result.is_ok(), "result {:?}", result);
    let resp = result.unwrap();
    let num_certs = resp.data.num_certs;
    assert!(num_certs.is_some());

    num_certs.unwrap()
}

// THIS TEST IS FOR PHYSICAL MANTICORE ONLY
// Fetch DdiGetCollateralType::CertChainLen back to back a few times
// It should stays the same
#[test]
fn test_get_collateral_cert_chain_length_multiple_times() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Skip test for virtual device as it doesn't support cert chain length yet
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_get_collateral_cert_chain_length_multiple_times for virtual device");
                return;
            }

            let loop_count = 3;
            let mut previous_num_certs: u8 = 0;

            for i in 0..loop_count {
                let req = DdiGetCollateralCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::GetCollateral,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiGetCollateralReq {
                        collateral_type: DdiGetCollateralType::CertChainLen,
                        cert_id: None,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let result = dev.exec_op(&req, &mut cookie);
                assert!(result.is_ok(), "result {:?}", result);
                let resp = result.unwrap();
                let num_certs = resp.data.num_certs;
                assert!(num_certs.is_some());
                let num_certs = num_certs.unwrap();

                // Record and compare num_cert with previous runs
                if i == 0 {
                    previous_num_certs = num_certs;
                } else {
                    assert_eq!(
                        num_certs, previous_num_certs,
                        "num_certs should be the same",
                    );
                }
            }
        },
    );
}

// THIS TEST IS FOR PHYSICAL MANTICORE ONLY
// IDFU: Impact-less Device Firmware Update
#[test]
fn test_get_collateral_interrupted_by_idfu() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!(
                    "Skipped test_get_collateral_interrupted_by_idfu for virtual device"
                );
                return;
            }
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let session_id = resp.data.sess_id;

            // Gets collateral lengths but invalidates the cache in the firmware while getting the cert chain.
            // this is to simulate a scenario where the firmware is interrupted by an IDFU while getting the cert chain.
            let req = DdiGetCollateralCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetCollateral,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetCollateralReq {
                    collateral_type: DdiGetCollateralType::CertChainLen,
                    cert_id: None,
                },
                ext: None,
            };
            let mut cookie = None;
            let result = dev.exec_op(&req, &mut cookie);
            assert!(result.is_ok(), "result {:?}", result);
            let resp = result.unwrap();
            let num_certs = resp.data.num_certs;
            assert!(num_certs.is_some());

            let req = DdiGetCollateralCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetCollateral,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetCollateralReq {
                    collateral_type: DdiGetCollateralType::CertId,
                    cert_id: Some(0),
                },
                ext: None,
            };
            let mut cookie = None;
            let result = dev.exec_op(&req, &mut cookie);
            assert!(result.is_ok(), "result {:?}", result);

            invalidate_certs_in_partition(path.to_string());

            let req = DdiGetCollateralCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetCollateral,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetCollateralReq {
                    collateral_type: DdiGetCollateralType::CertId,
                    cert_id: Some(1),
                },
                ext: None,
            };
            let mut cookie = None;
            let result = dev.exec_op(&req, &mut cookie);
            assert!(result.is_err(), "result {:?}", result);
            assert!(matches!(
                result.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidCertificate)
            ));
        },
    );
}

/// Retrieve cert by ID before getting certchain length
/// Should result in error
#[test]
fn test_get_collateral_with_invalid_cert_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            tracing::debug!("Getting collateral for session {}", session_id);
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!(
                    "Skipped test_get_collateral_with_invalid_cert_id for virtual device"
                );
                return;
            }

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let session_id = resp.data.sess_id;

            let req = DdiGetCollateralCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetCollateral,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetCollateralReq {
                    collateral_type: DdiGetCollateralType::CertId,
                    cert_id: Some(0),
                },
                ext: None,
            };
            let mut cookie = None;
            let result = dev.exec_op(&req, &mut cookie);
            assert!(result.is_err(), "result {:?}", result);
            assert!(matches!(
                result.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidCertificate)
            ));
        },
    );
}

/// HELPER FUNCTION IS FOR PHYSICAL MANTICORE ONLY
/// Helper function to invalidate the cert cache in the firmware.
fn invalidate_certs_in_partition(device_path: String) {
    let ddi = DdiTest::default();
    let mut mngr_dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut mngr_dev);

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&mngr_dev, TEST_CRED_ID, TEST_CRED_PIN);

    let resp = helper_open_session(
        &mngr_dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    );
    assert!(resp.is_ok(), "Resp {:?}", resp);

    let resp = resp.unwrap();
    let vault_manager_sess_id = resp.data.sess_id;

    let resp = helper_test_action_cmd(
        &mut mngr_dev,
        vault_manager_sess_id,
        DdiTestAction::InvalidateCertSizeCache,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(resp.is_ok(), "Resp {:?}", resp);

    let resp = helper_close_session(
        &mngr_dev,
        Some(vault_manager_sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
    );
    assert!(resp.is_ok(), "Resp {:?}", resp);
}
