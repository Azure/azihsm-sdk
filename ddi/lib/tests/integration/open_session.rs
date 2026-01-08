// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use std::sync::Arc;
use std::thread;

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use parking_lot::RwLock;
use test_with_tracing::test;

use super::common::*;
use super::invalid_ecc_pub_key_vectors::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // Return incorrect session id since this is a no session command
    25
}

#[test]
fn test_open_session_with_session() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                dev,
                Some(incorrect_session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));
        },
    );
}

#[test]
fn test_open_session_without_revision() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(dev, None, None, encrypted_credential, pub_key);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::UnsupportedRevision)
            ));
        },
    );
}

#[test]
fn test_open_session() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

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

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert!(resp.hdr.sess_id.is_some());
            assert_eq!(resp.hdr.op, DdiOp::OpenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            assert!(!resp.data.bmk_session.is_empty());
        },
    );
}

#[test]
fn test_open_session_invalid_public_key_p384_y_as_prime() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, _) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            // Invalid public key for P384 with y coordinate as prime
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_ECC_384_PUBLIC_KEY_Y_AS_PRIME)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::EccPublicKeyValidationFailed))
            ));
        },
    );
}

#[test]
fn test_open_session_invalid_public_key_p384_x_as_prime() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, _) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            // Invalid public key for P384 with x coordinate as prime
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_ECC_384_PUBLIC_KEY_X_AS_PRIME)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::EccPublicKeyValidationFailed))
            ));
        },
    );
}

#[test]
fn test_open_session_invalid_public_key_p384_not_on_curve() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, _) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            // Invalid public key for P384 with point not on the curve
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_ECC_384_PUBLIC_KEY_INVALID_POINT_IN_CURVE)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::EccPointValidationFailed))
            ));
        },
    );
}

#[test]
fn test_open_session_invalid_public_key_p384_point_at_infinity() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, _) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            // Invalid public key for P384 with point at infinity
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&ECC_384_PUBLIC_KEY_POINT_AT_INFINITY)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
            );

            assert!(matches!(
                resp,
                Err(DdiError::MborError(MborError::EncodeError))
            ));
        },
    );
}

#[test]
fn test_open_session_without_get_key() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let encrypted_credential = DdiEncryptedSessionCredential {
                encrypted_id: MborByteArray::from_slice(&[
                    69, 237, 223, 217, 67, 83, 78, 223, 104, 238, 179, 193, 249, 43, 57, 102,
                ])
                .expect("failed to create byte array"),
                encrypted_pin: MborByteArray::from_slice(&[
                    240, 244, 194, 248, 223, 76, 238, 234, 13, 32, 210, 231, 13, 237, 38, 215,
                ])
                .expect("failed to create byte array"),
                encrypted_seed: MborByteArray::from_slice(&[2; 48])
                    .expect("failed to create byte array"),
                iv: MborByteArray::from_slice(&[
                    211, 139, 212, 48, 114, 222, 183, 23, 106, 21, 2, 21, 251, 191, 145, 18,
                ])
                .expect("failed to create byte array"),
                nonce: {
                    let mut nonce_bytes = [0u8; 32];
                    nonce_bytes[..4].copy_from_slice(&2187282822u32.to_le_bytes());
                    nonce_bytes
                },
                tag: [29; 48],
            };
            let pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&[
                    48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3,
                    98, 0, 4, 228, 32, 154, 215, 7, 164, 136, 26, 255, 240, 18, 97, 146, 199, 157,
                    131, 119, 73, 33, 204, 93, 243, 185, 33, 196, 61, 174, 170, 88, 184, 52, 43,
                    56, 60, 218, 178, 136, 240, 228, 185, 86, 20, 17, 21, 117, 186, 187, 35, 124,
                    103, 247, 209, 151, 99, 199, 184, 86, 211, 34, 178, 186, 186, 26, 198, 180,
                    234, 13, 173, 162, 86, 41, 213, 202, 15, 74, 78, 238, 23, 176, 178, 244, 177,
                    88, 186, 174, 161, 88, 156, 16, 7, 247, 14, 199, 98, 66, 224,
                ])
                .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_open_session_multiple() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            {
                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert!(!resp.data.bmk_session.is_empty());
            }

            for _ in 0..10 {
                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_open_session_multiple_get_key() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            {
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
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert!(!resp.data.bmk_session.is_empty());
            }

            for _ in 0..10 {
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
                    pub_key.clone(),
                );

                assert!(resp.is_err(), "resp {:?}", resp);

                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionLimitReached)
                ));
            }
        },
    );
}

#[test]
fn test_open_session_tamper_id() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            let value = tampered_encrypted_credential.encrypted_id.data()[10];
            tampered_encrypted_credential.encrypted_id.data_mut()[10] = value.wrapping_add(1);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::PinDecryptionFailed)
            ));
        },
    );
}

#[test]
fn test_open_session_tamper_pin() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            let value = tampered_encrypted_credential.encrypted_pin.data()[10];
            tampered_encrypted_credential.encrypted_pin.data_mut()[10] = value.wrapping_add(1);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::PinDecryptionFailed)
            ));
        },
    );
}

#[test]
fn test_open_session_tamper_iv() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            let value = tampered_encrypted_credential.iv.data()[10];
            tampered_encrypted_credential.iv.data_mut()[10] = value.wrapping_add(1);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::PinDecryptionFailed)
            ));
        },
    );
}

#[test]
fn test_open_session_tamper_nonce() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            tampered_encrypted_credential.nonce[0] =
                tampered_encrypted_credential.nonce[0].wrapping_add(1);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::NonceMismatch)
            ));
        },
    );
}

#[test]
fn test_open_session_tamper_tag() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            tampered_encrypted_credential.tag[10] =
                tampered_encrypted_credential.tag[10].wrapping_add(1);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::PinDecryptionFailed)
            ));
        },
    );
}

#[test]
fn test_open_session_tamper_pub_key() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, mut tampered_pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            let value = tampered_pub_key.der.data()[30];
            tampered_pub_key.der.data_mut()[30] = value.wrapping_add(1);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                tampered_pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_open_session_null_id() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, [0; 16], TEST_CRED_PIN, TEST_SESSION_SEED);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
            ));
        },
    );
}

#[test]
fn test_open_session_null_pin() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, [0; 16], TEST_SESSION_SEED);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
            ));
        },
    );
}

#[test]
fn test_open_session_verify_nonce_change() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

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
                encrypted_credential.clone(),
                pub_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert!(resp.hdr.sess_id.is_some());
            assert_eq!(resp.hdr.op, DdiOp::OpenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            assert!(!resp.data.bmk_session.is_empty());

            let (encrypted_credential2, _pub_key2) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            assert_ne!(
                encrypted_credential.nonce, encrypted_credential2.nonce,
                "Nonce must change after use"
            );
        },
    );
}

#[test]
fn test_open_session_verify_public_key_not_change() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

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
                pub_key.clone(),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert!(resp.hdr.sess_id.is_some());
            assert_eq!(resp.hdr.op, DdiOp::OpenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            assert!(!resp.data.bmk_session.is_empty());

            let (_encrypted_credential2, pub_key2) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            assert_eq!(
                pub_key, pub_key2,
                "Session pub key must not change after open session"
            );
        },
    );
}

#[test]
fn test_open_session_multi_threaded_all_should_open() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, ddi, path, _incorrect_session_id| {
            let threads_to_fail = 4;
            let thread_count = MAX_SESSIONS + threads_to_fail;

            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let mut file_handles: Vec<Arc<RwLock<<DdiTest as Ddi>::Dev>>> = Vec::new();

            let mut thread_list = Vec::new();
            for i in 0..thread_count {
                let thread_id = i as u8;
                let thread_file_handle =
                    Arc::new(RwLock::new(open_dev_and_set_device_kind(ddi, path)));
                file_handles.push(thread_file_handle.clone());

                let thread = thread::spawn(move || {
                    test_thread_fn(thread_id, thread_file_handle, thread_count)
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

            assert_eq!(
                threads_passed,
                thread_count - threads_to_fail,
                "All threads should succeed, none should fail"
            );
            assert_eq!(
                threads_failed, threads_to_fail,
                "All threads should succeed, none should fail"
            );
        },
    );
}

fn test_thread_fn(_thread_id: u8, device: Arc<RwLock<<DdiTest as Ddi>::Dev>>, max_attempts: usize) {
    let dev = device.read();

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
            pub_key.clone(),
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

        break;
    }
}

#[test]
fn test_open_session_null_id_then_proper_id() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);
            let old_nonce;

            {
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    [0; 16],
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );
                old_nonce = Some(encrypted_credential.nonce);

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);

                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
                ));
            }

            {
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );

                assert_ne!(
                    old_nonce.unwrap(),
                    encrypted_credential.nonce,
                    "Nonce is expected to be different now since crypto portion was successful previously"
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                assert!(!resp.data.bmk_session.is_empty());
            }
        },
    );
}

#[test]
fn test_open_session_with_reset_in_middle() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, ddi, path, _incorrect_session_id| {
            let session_id;
            {
                helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

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

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                assert!(!resp.data.bmk_session.is_empty());
                session_id = resp.data.sess_id;
            }

            // This will do the reset function
            common_cleanup(dev, ddi, path, Some(session_id));

            {
                helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

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

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                assert!(!resp.data.bmk_session.is_empty());
            }
        },
    );
}

#[test]
fn test_open_session_incorrect_id() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, [1; 16], TEST_CRED_PIN, TEST_SESSION_SEED);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
            ));
        },
    );
}

#[test]
fn test_open_session_incorrect_pin() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, [1; 16], TEST_SESSION_SEED);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
            ));
        },
    );
}

#[test]
fn test_open_session_max_sessions() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, ddi, path, _incorrect_session_id| {
            // This is the minimum number of sessions we should be able to create on both
            // virtual and physical device.
            let max_sessions = MAX_SESSIONS;

            let mut file_handles: Vec<Option<<DdiTest as Ddi>::Dev>> = Vec::new();
            for _ in 0..max_sessions {
                file_handles.push(None);
            }

            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            for element in file_handles.iter_mut() {
                *element = Some(open_dev_and_set_device_kind(ddi, path));

                if let Some(file_handle) = element {
                    let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                        file_handle,
                        TEST_CRED_ID,
                        TEST_CRED_PIN,
                        TEST_SESSION_SEED,
                    );

                    let resp = helper_open_session(
                        file_handle,
                        None,
                        Some(DdiApiRev { major: 1, minor: 0 }),
                        encrypted_credential,
                        pub_key,
                    );

                    assert!(resp.is_ok(), "resp {:?}", resp);

                    let resp = resp.unwrap();

                    assert!(resp.hdr.sess_id.is_some());
                    assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                    assert_eq!(resp.hdr.status, DdiStatus::Success);

                    assert!(!resp.data.bmk_session.is_empty());
                }
            }

            // Now we should not be able to open any more sessions
            let file_handle = open_dev_and_set_device_kind(ddi, path);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &file_handle,
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
            assert!(resp.is_err());
        },
    );
}

#[test]
fn test_open_session_multi_threaded_single_winner() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, path, _incorrect_session_id| {
            let thread_count = 16;

            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let mut thread_list = Vec::new();
            for i in 0..thread_count {
                let thread_id = i as u8;
                let thread_device_path = path.to_string();
                let thread_encrypted_credential = encrypted_credential.clone();
                let thread_pub_key = pub_key.clone();

                let thread = thread::spawn(move || {
                    test_thread_fn_open_session_single_winner(
                        thread_id,
                        thread_device_path,
                        thread_encrypted_credential,
                        thread_pub_key,
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

fn test_thread_fn_open_session_single_winner(
    _thread_id: u8,
    device_path: String,
    encrypted_credential: DdiEncryptedSessionCredential,
    pub_key: DdiDerPublicKey,
) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    let _resp = helper_open_session(
        &dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential.clone(),
        pub_key.clone(),
    )
    .unwrap();
}
