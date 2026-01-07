// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

mod common;
mod invalid_ecc_pub_key_vectors;

use std::thread;

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_mbor::MborDecode;
use azihsm_ddi_mbor::MborDecoder;
use azihsm_ddi_mbor::MborEncode;
use azihsm_ddi_mbor::MborEncoder;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;
use crate::invalid_ecc_pub_key_vectors::*;

#[test]
fn test_reopen_session_with_session() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let incorrect_session_id = setup_res.session_id + 3;
            let resp = helper_reopen_session(
                dev,
                incorrect_session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_without_revision() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                None,
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::UnsupportedRevision)
            ));
        },
    );
}

#[test]
fn test_reopen_session() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert_eq!(resp.hdr.sess_id, Some(setup_res.session_id));
            assert_eq!(resp.hdr.op, DdiOp::ReopenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert!(!resp.data.bmk_session.is_empty());
        },
    );
}

#[test]
fn test_reopen_session_mismatch_sessions() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let file_handle = open_dev_and_set_device_kind(ddi, path);
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &file_handle,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_open_session(
                &file_handle,
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

            let resp = helper_reopen_session(
                &file_handle,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    )
}

#[test]
fn test_reopen_session_invalid_public_key_p384_y_as_prime() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, _) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            // Invalid public key for P384 with y coordinate as prime
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_ECC_384_PUBLIC_KEY_Y_AS_PRIME)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_invalid_public_key_p384_x_as_prime() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, _) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            // Invalid public key for P384 with x coordinate as prime
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_ECC_384_PUBLIC_KEY_X_AS_PRIME)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_invalid_public_key_p384_not_on_curve() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, _) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            // Invalid public key for P384 with point not on the curve
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_ECC_384_PUBLIC_KEY_INVALID_POINT_IN_CURVE)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_invalid_public_key_p384_point_at_infinity() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, _) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            // Invalid public key for P384 with point at infinity
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&ECC_384_PUBLIC_KEY_POINT_AT_INFINITY)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_without_get_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let encrypted_credential = DdiEncryptedSessionCredential {
                encrypted_id: MborByteArray::from_slice(&[
                    69, 237, 223, 217, 67, 83, 78, 223, 104, 238, 179, 193, 249, 43, 57, 102,
                ])
                .expect("failed to create byte array"),
                encrypted_pin: MborByteArray::from_slice(&[
                    240, 244, 194, 248, 223, 76, 238, 234, 13, 32, 210, 231, 13, 237, 38, 215,
                ])
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
                encrypted_seed: MborByteArray::from_slice(&TEST_SESSION_SEED)
                    .expect("failed to create byte array"),
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

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_multiple() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            {
                let resp = helper_reopen_session(
                    dev,
                    setup_res.session_id,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                    setup_res.session_bmk,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert_eq!(resp.hdr.sess_id, Some(setup_res.session_id));
                assert_eq!(resp.hdr.op, DdiOp::ReopenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert!(!resp.data.bmk_session.is_empty());
            }

            for _ in 0..10 {
                let resp = helper_reopen_session(
                    dev,
                    setup_res.session_id,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                    setup_res.session_bmk,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_reopen_session_tamper_id() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );
            let value = tampered_encrypted_credential.encrypted_id.data()[10];
            tampered_encrypted_credential.encrypted_id.data_mut()[10] = value.wrapping_add(1);

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
                setup_res.session_bmk,
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
fn test_reopen_session_tamper_pin() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );
            let value = tampered_encrypted_credential.encrypted_pin.data()[10];
            tampered_encrypted_credential.encrypted_pin.data_mut()[10] = value.wrapping_add(1);

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
                setup_res.session_bmk,
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
fn test_reopen_session_tamper_iv() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );
            let value = tampered_encrypted_credential.iv.data()[10];
            tampered_encrypted_credential.iv.data_mut()[10] = value.wrapping_add(1);

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_tamper_nonce() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );
            tampered_encrypted_credential.nonce[0] =
                tampered_encrypted_credential.nonce[0].wrapping_add(1);

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_tamper_tag() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (mut tampered_encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );
            tampered_encrypted_credential.tag[10] =
                tampered_encrypted_credential.tag[10].wrapping_add(1);

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_tamper_pub_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, mut tampered_pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );
            let value = tampered_pub_key.der.data()[30];
            tampered_pub_key.der.data_mut()[30] = value.wrapping_add(1);

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                tampered_pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_null_id() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                [0; 16],
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_null_pin() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                [0; 16],
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_verify_nonce_change() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential.clone(),
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert_eq!(resp.hdr.sess_id, Some(setup_res.session_id));
            assert_eq!(resp.hdr.op, DdiOp::ReopenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert!(!resp.data.bmk_session.is_empty());

            let (encrypted_credential2, _pub_key2) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            assert_ne!(
                encrypted_credential.nonce, encrypted_credential2.nonce,
                "Nonce must change after use"
            );
        },
    );
}

#[test]
fn test_reopen_session_verify_public_key_not_change() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key.clone(),
                setup_res.session_bmk,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert_eq!(resp.hdr.sess_id, Some(setup_res.session_id));
            assert_eq!(resp.hdr.op, DdiOp::ReopenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert!(!resp.data.bmk_session.is_empty());

            let (_encrypted_credential2, pub_key2) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            assert_eq!(
                pub_key, pub_key2,
                "Session pub key must not change after open session"
            );
        },
    );
}

#[test]
fn test_reopen_session_null_id_then_proper_id() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );
            let old_nonce;

            {
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    [0; 16],
                    TEST_CRED_PIN,
                    setup_res.random_seed,
                );
                old_nonce = Some(encrypted_credential.nonce);

                let resp = helper_reopen_session(
                    dev,
                    setup_res.session_id,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                    setup_res.session_bmk,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }

            {
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    setup_res.random_seed,
                );

                assert_ne!(
                    old_nonce.unwrap(),
                    encrypted_credential.nonce,
                    "Nonce is expected to be different now since crypto portion was successful previously"
                );

                let resp = helper_reopen_session(
                    dev,
                    setup_res.session_id,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                    setup_res.session_bmk,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert_eq!(resp.hdr.sess_id, Some(setup_res.session_id));
                assert_eq!(resp.hdr.op, DdiOp::ReopenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert!(!resp.data.bmk_session.is_empty());
            }
        },
    );
}

#[test]
fn test_reopen_session_incorrect_id() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                [1; 16],
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_incorrect_pin() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                [1; 16],
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_dest_smaller_svn() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let setup_res = common_setup_for_lm(dev, ddi, path);
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let current_svn = extract_svn_from_bmk(setup_res.partition_bmk.as_slice());
            assert!(current_svn.is_some(), "Failed to extract SVN from BMK");
            let current_svn = current_svn.unwrap();
            let updated_svn = current_svn + 1;
            let mut partition_bmk_copy = setup_res.partition_bmk;
            update_svn_in_bmk(partition_bmk_copy.as_mut_slice(), updated_svn);

            // Get establish credential encryption key
            let resp = helper_get_establish_cred_encryption_key(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
            )
            .unwrap();
            // Establish credential
            let nonce = resp.data.nonce;
            let param_encryption_key = DeviceCredKey::new(&resp.data.pub_key, nonce).unwrap();
            let (establish_cred_encryption_key, ddi_public_key) = param_encryption_key
                .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
                .unwrap();
            let ddi_encrypted_credential = establish_cred_encryption_key
                .encrypt_establish_credential(TEST_CRED_ID, TEST_CRED_PIN, nonce)
                .unwrap();
            let resp = helper_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                ddi_encrypted_credential,
                ddi_public_key,
                setup_res.masked_bk3,
                partition_bmk_copy,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );
            // Cannot establish credential when destination SVN is smaller than source SVN
            assert!(resp.is_err(), "resp {:?}", resp);

            // now we try establishing credential with the right SVN to ensure everything still works
            let bmk = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );
            assert!(!bmk.is_empty(), "BMK session should not be empty");

            let mut session_bmk_copy = setup_res.session_bmk;
            update_svn_in_bmk(session_bmk_copy.as_mut_slice(), updated_svn);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential.clone(),
                pub_key.clone(),
                session_bmk_copy,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            // lets use the right SVN to ensure everything still works
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );
            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_reopen_session_multi_threaded_single_winner() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );
            let thread_count = 16;

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let mut thread_list = Vec::new();
            for _ in 0..thread_count {
                let dev_clone = dev.clone();
                let thread_encrypted_credential = encrypted_credential.clone();
                let thread_pub_key = pub_key.clone();

                let thread = thread::spawn(move || {
                    test_thread_fn_open_session_single_winner(
                        &dev_clone,
                        setup_res.session_id,
                        thread_encrypted_credential,
                        thread_pub_key,
                        setup_res.session_bmk,
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
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    encrypted_credential: DdiEncryptedSessionCredential,
    pub_key: DdiDerPublicKey,
    bmk: MborByteArray<1024>,
) {
    let _resp = helper_reopen_session(
        dev,
        session_id,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
        bmk,
    )
    .unwrap();
}

// Extract the SVN from the BMK metadata section
fn extract_svn_from_bmk(bmk: &[u8]) -> Option<u64> {
    const FORMAT_OFFSET: usize = 2;
    const ALGORITHM_OFFSET: usize = FORMAT_OFFSET + 2;
    const IV_LEN_OFFSET: usize = ALGORITHM_OFFSET + 2;
    const IV_PADDING_OFFSET: usize = IV_LEN_OFFSET + 2;
    const METADATA_LEN_OFFSET: usize = IV_PADDING_OFFSET + 2;
    const METADATA_PADDING_OFFSET: usize = METADATA_LEN_OFFSET + 2;
    const ENCRYPTED_KEY_LEN_OFFSET: usize = METADATA_PADDING_OFFSET + 2;
    const ENCRYPTED_KEY_PADDING_OFFSET: usize = ENCRYPTED_KEY_LEN_OFFSET + 2;
    const TAG_LEN_OFFSET: usize = ENCRYPTED_KEY_PADDING_OFFSET + 2;
    const RESERVED_OFFSET: usize = TAG_LEN_OFFSET + 34;

    if bmk.len() < RESERVED_OFFSET {
        return None;
    }

    let iv_len: usize =
        u16::from_le_bytes(bmk[ALGORITHM_OFFSET..IV_LEN_OFFSET].try_into().unwrap()).into();
    let iv_padding_len: usize =
        u16::from_le_bytes(bmk[IV_LEN_OFFSET..IV_PADDING_OFFSET].try_into().unwrap()).into();
    let metadata_len: usize = u16::from_le_bytes(
        bmk[IV_PADDING_OFFSET..METADATA_LEN_OFFSET]
            .try_into()
            .unwrap(),
    )
    .into();

    let metadata_offset = RESERVED_OFFSET + iv_len + iv_padding_len;

    if bmk.len() < metadata_offset + metadata_len {
        return None;
    }

    let metadata = &bmk[metadata_offset..metadata_offset + metadata_len];
    let mut decoder = MborDecoder::new(metadata, false);

    let metadata = DdiMaskedKeyMetadata::mbor_decode(&mut decoder);
    if metadata.is_err() {
        tracing::error!("mbor_decode error {:?}", metadata.unwrap_err());

        return None;
    }

    metadata.unwrap().svn
}

// Update the SVN in the BMK metadata section
fn update_svn_in_bmk(bmk: &mut [u8], svn: u64) {
    const FORMAT_OFFSET: usize = 2;
    const ALGORITHM_OFFSET: usize = FORMAT_OFFSET + 2;
    const IV_LEN_OFFSET: usize = ALGORITHM_OFFSET + 2;
    const IV_PADDING_OFFSET: usize = IV_LEN_OFFSET + 2;
    const METADATA_LEN_OFFSET: usize = IV_PADDING_OFFSET + 2;
    const METADATA_PADDING_OFFSET: usize = METADATA_LEN_OFFSET + 2;
    const ENCRYPTED_KEY_LEN_OFFSET: usize = METADATA_PADDING_OFFSET + 2;
    const ENCRYPTED_KEY_PADDING_OFFSET: usize = ENCRYPTED_KEY_LEN_OFFSET + 2;
    const TAG_LEN_OFFSET: usize = ENCRYPTED_KEY_PADDING_OFFSET + 2;
    const RESERVED_OFFSET: usize = TAG_LEN_OFFSET + 34;

    if bmk.len() < RESERVED_OFFSET {
        tracing::error!("BMK length is less than RESERVED_OFFSET");
        return;
    }

    let iv_len: usize =
        u16::from_le_bytes(bmk[ALGORITHM_OFFSET..IV_LEN_OFFSET].try_into().unwrap()).into();
    let iv_padding_len: usize =
        u16::from_le_bytes(bmk[IV_LEN_OFFSET..IV_PADDING_OFFSET].try_into().unwrap()).into();
    let metadata_len: usize = u16::from_le_bytes(
        bmk[IV_PADDING_OFFSET..METADATA_LEN_OFFSET]
            .try_into()
            .unwrap(),
    )
    .into();

    let metadata_offset = RESERVED_OFFSET + iv_len + iv_padding_len;

    if bmk.len() < metadata_offset + metadata_len {
        tracing::error!("BMK length is less than metadata section");
        return;
    }

    let metadata = &bmk[metadata_offset..metadata_offset + metadata_len];
    let mut decoder = MborDecoder::new(metadata, false);

    let metadata = DdiMaskedKeyMetadata::mbor_decode(&mut decoder);
    if metadata.is_err() {
        tracing::error!("mbor_decode error {:?}", metadata.unwrap_err());
        return;
    }
    let mut metadata = metadata.unwrap();
    metadata.svn = Some(svn);

    let metadata_slot = &mut bmk[metadata_offset..metadata_offset + metadata_len];
    let mut encoder = MborEncoder::new(metadata_slot, false);
    let metadata = metadata.mbor_encode(&mut encoder);
    if metadata.is_err() {
        tracing::error!("mbor_encode error {:?}", metadata.unwrap_err());
    }
}
