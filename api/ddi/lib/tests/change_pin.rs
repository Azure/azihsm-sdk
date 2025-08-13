// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::thread;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_change_pin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq { new_pin, pub_key },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);

            // Try to login with original credential should fail
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }

            // Try to login with new ALT credential should succeed
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN_ALT);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Restore to original credential
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq { new_pin, pub_key },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_change_pin_tampered_pin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let (mut tampered_new_pin, pub_key) =
                encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);
            tampered_new_pin.encrypted_pin.data_mut()[10] =
                tampered_new_pin.encrypted_pin.data()[10].wrapping_add(1);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq {
                    new_pin: tampered_new_pin,
                    pub_key,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            // Try to login with original credential should succeed
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_change_pin_tampered_iv() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let (mut tampered_new_pin, pub_key) =
                encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);
            tampered_new_pin.iv.data_mut()[10] = tampered_new_pin.iv.data()[10].wrapping_add(1);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq {
                    new_pin: tampered_new_pin,
                    pub_key,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            // Try to login with original credential should succeed
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_change_pin_tampered_nonce() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let (mut tampered_new_pin, pub_key) =
                encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);
            tampered_new_pin.nonce[0] = tampered_new_pin.nonce[0].wrapping_add(1);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq {
                    new_pin: tampered_new_pin,
                    pub_key,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            // Try to login with original credential should succeed
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_change_pin_tampered_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let (mut tampered_new_pin, pub_key) =
                encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);
            tampered_new_pin.tag[10] = tampered_new_pin.tag[10].wrapping_add(1);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq {
                    new_pin: tampered_new_pin,
                    pub_key,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            // Try to login with original credential should succeed
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_change_pin_tampered_pub_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let (new_pin, mut tampered_pub_key) =
                encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);
            tampered_pub_key.der.data_mut()[30] = tampered_pub_key.der.data()[30].wrapping_add(1);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq {
                    new_pin,
                    pub_key: tampered_pub_key,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            // Try to login with original credential should succeed
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_change_pin_null_pin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, [0; 16]);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq { new_pin, pub_key },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            // Try to login with original credential should succeed
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_change_pin_verify_nonce_change() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq {
                    new_pin: new_pin.clone(),
                    pub_key,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);

            let (new_pin2, _) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);
            assert_ne!(new_pin.nonce, new_pin2.nonce, "Nonce must change after use");

            // Restore to original credential
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq { new_pin, pub_key },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_change_pin_verify_public_key_not_change() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq {
                    new_pin: new_pin.clone(),
                    pub_key: pub_key.clone(),
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);

            let (_, pub_key2) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);
            assert_eq!(
                pub_key, pub_key2,
                "pub key must not change after change pin"
            );

            // Restore to original credential
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq { new_pin, pub_key },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_change_pin_same_pin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq { new_pin, pub_key },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);

            // Try to login with original credential should succeed
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Try to login with new ALT credential should fail
            {
                let mut new_dev = ddi.open_dev(path).unwrap();

                // Set Device Kind
                set_device_kind(&mut new_dev);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&new_dev, TEST_CRED_ID, TEST_CRED_PIN_ALT);

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_change_pin_multiple() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);

            {
                let req = DdiChangePinCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::ChangePin,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiChangePinReq {
                        new_pin: new_pin.clone(),
                        pub_key: pub_key.clone(),
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);

                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            for _ in 0..10 {
                let req = DdiChangePinCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::ChangePin,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiChangePinReq {
                        new_pin: new_pin.clone(),
                        pub_key: pub_key.clone(),
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);

                assert!(resp.is_err(), "resp {:?}", resp);
            }

            // Restore to original credential
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq { new_pin, pub_key },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_change_pin_multi_threaded_single_winner_stress() {
    for _ in 0..10 {
        test_change_pin_multi_threaded_single_winner();
    }
}

#[test]
fn test_change_pin_multi_threaded_single_winner() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let thread_count = MAX_SESSIONS - 1;

            let mut dev_list = Vec::new();
            for _ in 0..thread_count {
                let ddi = DdiTest::default();
                let mut dev_item = ddi.open_dev(path).unwrap();
                set_device_kind(&mut dev_item);
                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&dev_item, TEST_CRED_ID, TEST_CRED_PIN);
                let resp = helper_open_session(
                    &dev_item,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                )
                .unwrap();
                dev_list.push((dev_item, resp.data.sess_id));
            }

            let (new_pin, change_pin_pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);

            let mut thread_list = Vec::new();
            for i in 0..thread_count {
                let thread_id = i as u8;

                let (dev_item, dev_session_id) = dev_list.pop().unwrap();
                let new_pin_value = new_pin.clone();
                let change_pin_pub_key_value = change_pin_pub_key.clone();

                let thread = thread::spawn(move || {
                    test_thread_fn(
                        thread_id,
                        &dev_item,
                        dev_session_id,
                        new_pin_value,
                        change_pin_pub_key_value,
                    )
                });
                thread_list.push(thread);
            }

            let mut threads_failed = 0;
            let mut threads_passed = 0;

            for thread in thread_list {
                let result = thread.join();

                if result.is_ok() {
                    threads_passed += 1;
                } else {
                    threads_failed += 1;
                }
            }

            // Restore to original credential
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN);

            let req = DdiChangePinCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ChangePin,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiChangePinReq { new_pin, pub_key },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);

            assert_eq!(
                threads_passed, 1,
                "Only 1 thread should succeed, others must fail"
            );
            assert_eq!(
                threads_failed,
                thread_count - 1,
                "Only 1 thread should succeed, others must fail"
            );
        },
    );
}

fn test_thread_fn(
    _thread_id: u8,
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    new_pin: DdiEncryptedPin,
    pub_key: DdiDerPublicKey,
) {
    let req = DdiChangePinCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::ChangePin,
            sess_id: Some(session_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiChangePinReq { new_pin, pub_key },
        ext: None,
    };
    let mut cookie = None;

    dev.exec_op(&req, &mut cookie).unwrap();
}
