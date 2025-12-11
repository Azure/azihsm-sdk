// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::thread;

use mcr_ddi::*;
use mcr_ddi_types::*;

use crate::common::*;

#[test]
fn test_get_unwrapping_key_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let resp = helper_get_unwrapping_key(dev, None, None);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_get_unwrapping_key_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let session_id = 20;
            let resp = helper_get_unwrapping_key(dev, Some(session_id), None);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_get_unwrapping_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_, _, _) = get_unwrapping_key(dev, session_id);
        },
    );
}

#[test]
fn test_get_unwrapping_key_multi_threaded_stress() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            let thread_count = MAX_SESSIONS;
            println!("Thread count: {}", thread_count);

            let mut threads = Vec::new();
            for i in 0..thread_count {
                let thread_id = i as u8;
                let thread_device_path = path.to_string();

                let thread = thread::spawn(move || {
                    test_get_unwrapping_key_thread_fn(thread_id, thread_device_path, thread_count)
                });
                threads.push(thread);
            }

            let mut first_pub_key_der: Option<Vec<u8>> = None;
            for thread in threads {
                let pub_key_der = thread.join().unwrap();
                if let Some(der) = &first_pub_key_der {
                    assert_eq!(&pub_key_der, der);
                } else {
                    first_pub_key_der = Some(pub_key_der)
                }
            }
        },
    );
}

fn test_get_unwrapping_key_thread_fn(
    _thread_id: u8,
    device_path: String,
    max_attempts: usize,
) -> Vec<u8> {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    let mut app_sess_id = None;

    for _ in 0..max_attempts {
        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            &dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

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

    let (_, pub_key_der, _) = get_unwrapping_key(&mut dev, app_sess_id);
    pub_key_der
}
