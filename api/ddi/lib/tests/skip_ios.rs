// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use core::option::Option::None;
use std::time::Instant;

use chrono::Local;
use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_skip_ios() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            set_device_kind(dev);
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "{:?}", resp);

            let resp = resp.unwrap();
            let vault_manager_sess_id = resp.data.sess_id;

            let resp = helper_test_action_cmd(
                dev,
                vault_manager_sess_id,
                DdiTestAction::Level1SkipIo,
                DdiTestActionContext::None,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            let mut retry_cnt = 0;
            // TODO: move this retry loop to dev.rs on both win and nix
            loop {
                if retry_cnt >= 5 {
                    panic!("Failed due maximum retry count reached");
                }
                let resp = helper_close_session(
                    dev,
                    Some(vault_manager_sess_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                match resp {
                    Ok(_) => break,
                    Err(e) => match e {
                        DdiError::DriverError(DriverError::IoAborted)
                        | DdiError::DriverError(DriverError::IoAbortInProgress)
                        | DdiError::DeviceNotReady => {
                            std::thread::sleep(std::time::Duration::from_secs(1));
                            retry_cnt += 1;
                        }
                        _ => panic!("Failed due to unexpected error: {:?}", e),
                    },
                }
            }
        },
    );
}

#[test]
fn test_skip_ios_followed_by_get_api_rev() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            set_device_kind(dev);
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "{:?}", resp);

            let resp = resp.unwrap();
            let vault_manager_sess_id = resp.data.sess_id;

            let resp = helper_test_action_cmd(
                dev,
                vault_manager_sess_id,
                DdiTestAction::Level1SkipIo,
                DdiTestActionContext::None,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            let mut retry_cnt = 0;
            loop {
                if retry_cnt >= 5 {
                    panic!("Failed due maximum retry count reached");
                }

                let resp = helper_close_session(
                    dev,
                    Some(vault_manager_sess_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );

                match resp {
                    Ok(_) => break,
                    Err(e) => match e {
                        DdiError::DriverError(DriverError::IoAborted)
                        | DdiError::DriverError(DriverError::IoAbortInProgress)
                        | DdiError::DeviceNotReady => {
                            std::thread::sleep(std::time::Duration::from_secs(1));
                            retry_cnt += 1;
                        }
                        _ => panic!("Failed due to unexpected error: {:?}", e),
                    },
                }
            }

            let resp = helper_get_api_rev(dev, None, None).unwrap();
            assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
            assert!(resp.hdr.rev.is_none());
            assert!(resp.hdr.sess_id.is_none());
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            assert!(resp.data.min.major <= resp.data.max.major);

            if resp.data.min.major == resp.data.max.major {
                assert!(resp.data.min.minor <= resp.data.max.minor);
            }

            assert_eq!(resp.data.min.major, 1);
            assert_eq!(resp.data.min.minor, 0);
            assert_eq!(resp.data.max.major, 1);
            assert_eq!(resp.data.max.minor, 0);
        },
    );
}

#[test]
fn test_skip_ios_followed_by_get_api_rev_for_20_seconds() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            const NUM_SECS: u64 = 20;
            let now = Local::now();
            let start_time = Instant::now();
            let mut counter: usize = 0;

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            set_device_kind(dev);
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "{:?}", resp);

            let resp = resp.unwrap();

            let vault_manager_sess_id = resp.data.sess_id;

            println!("start {}", now.format("%Y-%m-%d %H:%M:%S%.3f"));
            while Instant::now().duration_since(start_time).as_secs() < NUM_SECS {
                let resp = helper_test_action_cmd(
                    dev,
                    vault_manager_sess_id,
                    DdiTestAction::Level1SkipIo,
                    DdiTestActionContext::None,
                );
                assert!(resp.is_err(), "resp {:?}", resp);

                let resp = helper_get_api_rev(dev, None, None);

                match resp {
                    Ok(resp) => {
                        assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
                        assert!(resp.hdr.rev.is_none());
                        assert!(resp.hdr.sess_id.is_none());
                        assert_eq!(resp.hdr.status, DdiStatus::Success);

                        assert!(resp.data.min.major <= resp.data.max.major);

                        if resp.data.min.major == resp.data.max.major {
                            assert!(resp.data.min.minor <= resp.data.max.minor);
                        }

                        assert_eq!(resp.data.min.major, 1);
                        assert_eq!(resp.data.min.minor, 0);
                        assert_eq!(resp.data.max.major, 1);
                        assert_eq!(resp.data.max.minor, 0);
                    }
                    Err(e) => match e {
                        DdiError::DriverError(DriverError::IoAborted) => {}
                        DdiError::DriverError(DriverError::IoAbortInProgress) => {}
                        DdiError::DeviceNotReady => {}
                        // This error is expected because the user session is cleared during level-2 abort
                        DdiError::DdiStatus(DdiStatus::SessionNotFound) => {}
                        _ => panic!("Failed due to unexpected error: {:?}", e),
                    },
                }

                counter += 1;
            }
            println!("End {}", now.format("%Y-%m-%d %H:%M:%S%.3f"));
            println!("Number of Iterations : {}", counter);

            let mut retry_cnt = 0;
            loop {
                if retry_cnt >= 5 {
                    panic!("Failed due maximum retry count reached");
                }
                let resp = helper_close_session(
                    dev,
                    Some(vault_manager_sess_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                match resp {
                    Ok(_) => break,
                    Err(e) => match e {
                        DdiError::DriverError(DriverError::IoAborted)
                        | DdiError::DriverError(DriverError::IoAbortInProgress)
                        | DdiError::DeviceNotReady => {
                            std::thread::sleep(std::time::Duration::from_secs(1));
                            retry_cnt += 1;
                        }
                        _ => panic!("Failed due to unexpected error: {:?}", e),
                    },
                }
            }
        },
    );
}
