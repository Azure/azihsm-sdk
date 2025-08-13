// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::thread;
use std::time::Instant;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

const DIGEST: [u8; 96] = [100u8; 96];
const DIGEST_LEN: usize = 20;
const NUM_SECS: u64 = 20;

#[test]
fn test_multi_threaded_skip_plus_api_rev() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            let mut threads = Vec::new();

            let thread_device_path = path.to_string();
            let thread = thread::spawn(move || {
                get_api_thread_fn(thread_device_path);
            });
            threads.push(thread);

            let thread_device_path = path.to_string();
            let thread = thread::spawn(move || {
                skip_thread_fn(thread_device_path, 1);
            });
            threads.push(thread);

            for thread in threads {
                thread.join().unwrap();
            }
        },
    );
}

#[test]
fn mt_skip_p_ecc_sign_lvl1_abrt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            let mut threads = Vec::new();

            let thread_device_path = path.to_string();
            let thread = thread::spawn(move || {
                ecc_sign_thread_fn(thread_device_path, 2);
            });
            threads.push(thread);

            let thread_device_path = path.to_string();
            let thread = thread::spawn(move || {
                skip_thread_fn(thread_device_path, 2);
            });
            threads.push(thread);

            for thread in threads {
                thread.join().unwrap();
            }
        },
    );
}

#[test]
fn test_multi_threaded_skip_plus_ecc_sign_after_level_2_abort() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            let mut threads = Vec::new();

            let thread_device_path = path.to_string();
            let thread = thread::spawn(move || {
                ecc_sign_thread_fn(thread_device_path, 2);
            });
            threads.push(thread);

            let thread_device_path = path.to_string();
            let thread = thread::spawn(move || {
                level2_skip_thread_fn(thread_device_path, 2);
            });
            threads.push(thread);

            for thread in threads {
                thread.join().unwrap();
            }
        },
    );
}

fn skip_thread_fn(device_path: String, max_attempts: usize) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);
    let mut app_sess_id = None;

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

        break;
    }

    let vault_manager_sess_id = app_sess_id.unwrap();

    let start_time = Instant::now();
    while Instant::now().duration_since(start_time).as_secs() < NUM_SECS {
        let resp = helper_test_action_cmd(
            &mut dev,
            vault_manager_sess_id,
            DdiTestAction::Level1SkipIo,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(resp.is_err(), "resp {:?}", resp);
        thread::yield_now();
    }
}

fn get_api_thread_fn(device_path: String) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    let start_time = Instant::now();
    let mut counter = 0;
    while Instant::now().duration_since(start_time).as_secs() < NUM_SECS {
        let _resp = helper_get_api_rev(&dev, None, None);

        match _resp {
            Ok(_) => {}
            Err(e) => match e {
                DdiError::DriverError(DriverError::IoAborted) => {}
                DdiError::DriverError(DriverError::IoAbortInProgress) => {}
                DdiError::DeviceNotReady => {}
                _ => panic!("Failed due to unexpected error: {:?}", e),
            },
        }

        thread::yield_now();
        counter += 1;
    }

    println!("API rev thread ran {} times", counter);
}

fn level2_skip_thread_fn(device_path: String, max_attempts: usize) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);
    let mut app_sess_id = None;

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

        break;
    }

    let vault_manager_sess_id = app_sess_id.unwrap();

    let start_time = Instant::now();
    while Instant::now().duration_since(start_time).as_secs() < NUM_SECS {
        let resp = helper_test_action_cmd(
            &mut dev,
            vault_manager_sess_id,
            DdiTestAction::SetLevel2SkipIo,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(resp.is_err(), "resp {:?}", resp);
        thread::yield_now();
    }
}

fn ecc_sign_thread_fn(device_path: String, max_attempts: usize) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);
    let mut app_sess_id = None;

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

        break;
    }

    let app_sess_id = app_sess_id.unwrap();

    let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
    let resp = helper_ecc_generate_key_pair(
        &dev,
        Some(app_sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiEccCurve::P256,
        None,
        key_props,
    );

    assert!(resp.is_ok(), "{:?}", resp);
    let resp = resp.unwrap();

    thread::sleep(std::time::Duration::from_secs(1));

    let req = DdiEccSignCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EccSign,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiEccSignReq {
            key_id: resp.data.private_key_id,
            digest: MborByteArray::new(DIGEST, DIGEST_LEN).expect("failed to create byte array"),
            digest_algo: DdiHashAlgorithm::Sha256,
        },
        ext: None,
    };

    let start_time = Instant::now();
    while Instant::now().duration_since(start_time).as_secs() < NUM_SECS {
        let mut cookie = None;

        let _resp = dev.exec_op(&req, &mut cookie);
        match _resp {
            Ok(_) => {}
            Err(e) => match e {
                DdiError::DriverError(DriverError::IoAborted) => {}
                DdiError::DriverError(DriverError::IoAbortInProgress) => {}
                DdiError::DeviceNotReady => {}
                // This error is expected because the user session is cleared during level-2 abort
                DdiError::DdiStatus(DdiStatus::SessionNotFound) => {}
                _ => panic!("Failed due to unexpected error: {:?}", e),
            },
        }

        thread::yield_now();
    }
}
