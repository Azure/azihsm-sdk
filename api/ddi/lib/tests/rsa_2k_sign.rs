// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use crypto::rand::rand_bytes;
use crypto::CryptoRsaSignaturePadding;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use rsa_padding::RsaDigestKind;
use rsa_padding::RsaEncoding;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_rsa_2k_sign_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let resp = helper_rsa_mod_exp(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));

            let resp = helper_rsa_mod_exp(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv_crt,
                MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_sign_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let session_id = 20;
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv_crt,
                MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_sign_incorrect_key_num_table() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0300,
                MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_2k_sign_incorrect_key_num_entry() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0020,
                MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::KeyNotFound)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_sign_incorrect_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Import a key with a wrong type
            let (private_key_id_wrong_type, _pub_key, _) = ecc_gen_key_mcr(
                dev,
                DdiEccCurve::P256,
                None,
                Some(session_id),
                DdiKeyUsage::SignVerify,
            );

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id_wrong_type,
                MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidKeyType)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_sign_incorrect_permission() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = rsa_secure_import_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                &TEST_RSA_2K_PRIVATE_KEY,
                DdiKeyClass::Rsa,
                DdiKeyUsage::EncryptDecrypt,
                None,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                resp.data.key_id,
                MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidPermissions)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_sign_message_data_below_lower_limit() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Skip test for virtual device as it doesn't check for RSA mod exp data
            // This is a FIPS only requirement
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::info!(
                    "Skipped test_rsa_2k_sign_message_data_below_lower_limit for virtual device"
                );
                return;
            }

            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let mut msg = MborByteArray::new([0x0; 512], 256).expect("failed to create byte array");
            let last_idx = msg.len() - 1;
            msg.data_mut()[last_idx] = 0x1;

            // Non crt
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                msg,
                DdiRsaOpType::Sign,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));

            // Crt
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv_crt,
                msg,
                DdiRsaOpType::Sign,
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
fn test_rsa_2k_sign_message_data_above_upper_limit() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Skip test for virtual device as it doesn't check for RSA mod exp data
            // This is a FIPS only requirement
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::info!(
                    "Skipped test_rsa_2k_sign_message_data_above_upper_limit for virtual device"
                );
                return;
            }

            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            // Non crt
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::new([0xff; 512], 256).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));

            // Crt
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv_crt,
                MborByteArray::new([0xff; 512], 256).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
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
fn test_rsa_2k_sign_and_verify_pkcs15_sha1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let hash = [0x1; 20];
            let padded_hash =
                RsaEncoding::encode_pkcs_v15(&hash, 2048 / 8, RsaDigestKind::Sha1).unwrap();

            let mut y = [0u8; 512];
            y[..padded_hash.len()].copy_from_slice(&padded_hash);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(
                sig_no_crt_key,
                [
                    0x80, 0x8A, 0xB6, 0xC3, 0xD8, 0x32, 0x76, 0x76, 0xF4, 0x6D, 0xAD, 0x0D, 0x95,
                    0xE7, 0xD6, 0xBE, 0x95, 0x65, 0x7B, 0xBC, 0xA8, 0xDC, 0xEA, 0x47, 0x69, 0xDA,
                    0xC2, 0x3E, 0x38, 0xDA, 0xA8, 0x69, 0x23, 0xD5, 0xAC, 0x1E, 0x21, 0x38, 0x73,
                    0x6E, 0xCE, 0xB1, 0x94, 0x38, 0x75, 0x76, 0x60, 0x98, 0x3F, 0x4F, 0xC1, 0x35,
                    0x50, 0x77, 0x3E, 0x43, 0xFC, 0xC0, 0x28, 0xD1, 0xA9, 0x01, 0xC3, 0xE2, 0x76,
                    0x33, 0xE7, 0x79, 0xCB, 0x0E, 0xAF, 0x20, 0xD8, 0xA6, 0x90, 0xAD, 0xC9, 0xF1,
                    0xBB, 0x3B, 0x53, 0x1E, 0x35, 0x6A, 0xA7, 0xB5, 0xE6, 0x36, 0xF1, 0x95, 0x4F,
                    0x55, 0x53, 0x00, 0x8E, 0x90, 0x25, 0xC4, 0xDC, 0x51, 0x74, 0xA0, 0x04, 0x65,
                    0x04, 0x2A, 0xFB, 0x73, 0xE4, 0x32, 0x62, 0x19, 0x63, 0x75, 0xBD, 0x8C, 0x33,
                    0xB9, 0xD4, 0xAE, 0x20, 0x50, 0x7F, 0xD7, 0x1D, 0x5A, 0xE1, 0xC1, 0x13, 0x52,
                    0xED, 0xF9, 0x10, 0x6D, 0xBB, 0x45, 0x4A, 0x32, 0x2F, 0x2E, 0x74, 0xF8, 0xA7,
                    0x6B, 0xA0, 0x20, 0x18, 0xA2, 0xEE, 0x76, 0x68, 0xC9, 0xF2, 0x15, 0xE4, 0xF6,
                    0xD5, 0x1F, 0x1D, 0x5D, 0x47, 0xE0, 0x8E, 0x13, 0x6A, 0x07, 0x08, 0xFC, 0x0D,
                    0xF7, 0xC9, 0xDD, 0xAC, 0x13, 0x39, 0x51, 0x42, 0x52, 0x29, 0xE1, 0x3E, 0x65,
                    0xF4, 0xB5, 0xE1, 0x9D, 0x4E, 0x44, 0x62, 0xBC, 0x1E, 0xC7, 0x55, 0xF9, 0xE5,
                    0xF9, 0x22, 0x1C, 0x3A, 0x54, 0x68, 0x23, 0x96, 0x0B, 0x0F, 0x85, 0xE1, 0xC5,
                    0x3C, 0x92, 0xD1, 0xDB, 0x8E, 0x2F, 0x3F, 0xFE, 0x4A, 0x30, 0xFA, 0xE7, 0x55,
                    0xAA, 0x81, 0x2C, 0x6C, 0xCD, 0x33, 0x73, 0xB0, 0xDB, 0xBA, 0x76, 0x44, 0x4C,
                    0xB1, 0x0B, 0xD1, 0xDE, 0x9F, 0x15, 0xB6, 0x6E, 0x60, 0xC7, 0x6D, 0x24, 0x82,
                    0x13, 0xF3, 0xB3, 0x1A, 0x27, 0x44, 0x6B, 0x4F, 0xFE
                ]
            );

            let result = rsa_verify_local_openssl(
                &TEST_RSA_2K_PUBLIC_KEY,
                &resp.data.x.data()[..resp.data.x.len()],
                &[0x1; 20],
                CryptoRsaSignaturePadding::Pkcs1_5,
                Some(DdiHashAlgorithm::Sha1),
                None,
            );
            assert!(result);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv_crt,
                MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(sig_no_crt_key, sig_crt_key);
        },
    );
}

#[test]
fn test_rsa_2k_sign_and_verify_pkcs15_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let hash = [0x1; 32];
            let padded_hash =
                RsaEncoding::encode_pkcs_v15(&hash, 2048 / 8, RsaDigestKind::Sha256).unwrap();

            let mut y = [0u8; 512];
            y[..padded_hash.len()].copy_from_slice(&padded_hash);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(
                sig_no_crt_key,
                [
                    0x55, 0x29, 0x5D, 0x05, 0xDD, 0xC9, 0x59, 0x18, 0x4A, 0x85, 0x7C, 0xE5, 0x43,
                    0x8C, 0x26, 0xD5, 0x23, 0x98, 0x43, 0xC0, 0x3D, 0x76, 0xA5, 0x41, 0x0C, 0x3A,
                    0x7D, 0x5E, 0x02, 0xED, 0x82, 0x18, 0xF9, 0x99, 0x95, 0xD2, 0x9F, 0x2E, 0xDB,
                    0xA7, 0xC0, 0x4D, 0x64, 0xEA, 0xA4, 0xB2, 0x58, 0xA4, 0x89, 0x5B, 0xA2, 0x50,
                    0x24, 0x37, 0xEF, 0x7E, 0x35, 0xD5, 0x49, 0xC8, 0xE2, 0x2B, 0x5A, 0x96, 0x79,
                    0xBD, 0xA3, 0x9A, 0xEB, 0x28, 0x85, 0xE7, 0x1A, 0x04, 0x54, 0xFB, 0x52, 0xAB,
                    0xF2, 0x2F, 0xF2, 0xCD, 0xD9, 0xFC, 0x82, 0x09, 0x42, 0x73, 0x16, 0x5D, 0xF9,
                    0xF4, 0x54, 0x40, 0xF8, 0x27, 0xFE, 0xFE, 0x24, 0x2E, 0xE6, 0x3F, 0xD2, 0x45,
                    0x04, 0x68, 0x47, 0x99, 0xD3, 0xA3, 0x71, 0x3A, 0x79, 0x98, 0x4A, 0x67, 0x7D,
                    0x53, 0xB5, 0x2A, 0xA6, 0x5E, 0x0A, 0x81, 0x66, 0x38, 0xAE, 0xEA, 0xD0, 0xE2,
                    0x76, 0x99, 0xBB, 0x2E, 0xBD, 0x1C, 0x22, 0x85, 0xCF, 0x1A, 0x6B, 0xE8, 0x1C,
                    0x3C, 0x55, 0x42, 0xDE, 0xED, 0x20, 0x27, 0x06, 0x15, 0x94, 0x9F, 0x25, 0x31,
                    0x52, 0x1D, 0x9E, 0xD6, 0x05, 0x99, 0x5E, 0xE3, 0x6E, 0x90, 0xB2, 0xA7, 0xDB,
                    0xF9, 0x3D, 0xD4, 0x55, 0xE9, 0x14, 0xA9, 0xFF, 0xC7, 0x96, 0xD5, 0x5A, 0x66,
                    0x21, 0x2F, 0xF7, 0x98, 0xCF, 0x28, 0x53, 0xED, 0xA6, 0xCB, 0x42, 0xD7, 0xDE,
                    0x56, 0xE4, 0xDF, 0x59, 0xF6, 0x32, 0x47, 0xC9, 0x50, 0xEC, 0xCC, 0x78, 0x3E,
                    0x88, 0x45, 0x8F, 0xCB, 0x58, 0xFB, 0xDA, 0x9A, 0xB5, 0x35, 0x57, 0x2F, 0xE9,
                    0xD3, 0x1D, 0x0D, 0xF4, 0x95, 0x0E, 0x77, 0x93, 0x3B, 0xAB, 0x33, 0x58, 0x1B,
                    0x1E, 0x9D, 0xA1, 0xC0, 0xA3, 0xC1, 0x55, 0xE4, 0x72, 0x00, 0x18, 0x06, 0x60,
                    0xC2, 0xB2, 0x66, 0x64, 0x46, 0xF5, 0x3A, 0x6F, 0x6F
                ]
            );

            let result = rsa_verify_local_openssl(
                &TEST_RSA_2K_PUBLIC_KEY,
                &resp.data.x.data()[..resp.data.x.len()],
                &[0x1; 32],
                CryptoRsaSignaturePadding::Pkcs1_5,
                Some(DdiHashAlgorithm::Sha256),
                None,
            );
            assert!(result);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv_crt,
                MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(sig_no_crt_key, sig_crt_key);
        },
    );
}

#[test]
fn test_rsa_2k_sign_and_verify_pkcs15_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let hash = [0x1; 48];
            let padded_hash =
                RsaEncoding::encode_pkcs_v15(&hash, 2048 / 8, RsaDigestKind::Sha384).unwrap();

            let mut y = [0u8; 512];
            y[..padded_hash.len()].copy_from_slice(&padded_hash);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(
                sig_no_crt_key,
                [
                    0x39, 0xF4, 0x58, 0x70, 0x2C, 0xD3, 0xC8, 0xFA, 0xDB, 0xF4, 0xFF, 0x97, 0x6D,
                    0xB2, 0xD5, 0x46, 0xAF, 0xEE, 0x56, 0xFF, 0x06, 0x02, 0xFD, 0x88, 0x0C, 0xA6,
                    0x9A, 0xD3, 0x9C, 0xDE, 0x82, 0x79, 0xB8, 0xAD, 0x33, 0x40, 0x25, 0x58, 0x99,
                    0xCB, 0x1B, 0x3D, 0xF3, 0x11, 0x5E, 0x54, 0xD4, 0x50, 0x71, 0xE4, 0xAA, 0x6A,
                    0x63, 0xA2, 0x1E, 0x62, 0xF7, 0xEB, 0xE9, 0xAB, 0x7B, 0xFF, 0xC0, 0x16, 0xB2,
                    0x1E, 0x9A, 0xE4, 0x65, 0x26, 0xCB, 0x0C, 0xE3, 0x57, 0x58, 0xC2, 0x39, 0x8A,
                    0xA6, 0x16, 0x6F, 0x40, 0x6E, 0xFE, 0xAD, 0x8F, 0xC3, 0x1D, 0xFC, 0xD0, 0xA6,
                    0x58, 0xAD, 0xA0, 0x31, 0x17, 0x2B, 0xFF, 0x27, 0x7B, 0x33, 0x69, 0x5B, 0x54,
                    0xA0, 0x88, 0xAA, 0xEB, 0xB4, 0x86, 0x99, 0x94, 0x3C, 0xA0, 0x97, 0x92, 0x30,
                    0xFF, 0xCC, 0x6A, 0x16, 0x56, 0xD1, 0xD0, 0xC0, 0x06, 0x46, 0x6A, 0xDE, 0x0E,
                    0x6C, 0xAE, 0x3B, 0xBA, 0xB0, 0x1C, 0xD3, 0x2E, 0x3B, 0x1F, 0x42, 0x5B, 0xAE,
                    0xBF, 0xD6, 0x53, 0x0D, 0xE7, 0x66, 0xDF, 0xF7, 0xFD, 0x3D, 0xD4, 0x04, 0x34,
                    0x36, 0x61, 0x2B, 0x29, 0x76, 0x6C, 0x75, 0xAA, 0x86, 0xE5, 0x9E, 0x31, 0x51,
                    0x60, 0x00, 0x68, 0xCB, 0xFE, 0xCD, 0x09, 0x52, 0x6F, 0x4B, 0x4F, 0xE8, 0x47,
                    0xA9, 0x1E, 0x31, 0xE1, 0x54, 0x29, 0x3E, 0x0D, 0x92, 0xAF, 0x16, 0x1E, 0x52,
                    0x78, 0xA8, 0xCD, 0x29, 0x88, 0xD1, 0xA0, 0x0F, 0x0F, 0x3D, 0x2E, 0x57, 0xC9,
                    0x57, 0xE0, 0xDA, 0x15, 0x66, 0x2B, 0xFF, 0x37, 0xAE, 0x3A, 0x87, 0xEC, 0x65,
                    0x6B, 0x51, 0xCC, 0xE3, 0x09, 0x2F, 0x1C, 0x18, 0x0F, 0x6D, 0x2C, 0xF6, 0x2A,
                    0x13, 0xE7, 0x66, 0xAD, 0x10, 0x63, 0x29, 0xAA, 0x36, 0x8A, 0x75, 0x38, 0x98,
                    0x91, 0xD8, 0x1D, 0xCC, 0x03, 0x38, 0x42, 0x3D, 0xB6
                ]
            );

            let result = rsa_verify_local_openssl(
                &TEST_RSA_2K_PUBLIC_KEY,
                &resp.data.x.data()[..resp.data.x.len()],
                &[0x1; 48],
                CryptoRsaSignaturePadding::Pkcs1_5,
                Some(DdiHashAlgorithm::Sha384),
                None,
            );
            assert!(result);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv_crt,
                MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(sig_no_crt_key, sig_crt_key);
        },
    );
}

#[test]
fn test_rsa_2k_sign_and_verify_pkcs15_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let hash = [0x1; 64];
            let padded_hash =
                RsaEncoding::encode_pkcs_v15(&hash, 2048 / 8, RsaDigestKind::Sha512).unwrap();

            let mut y = [0u8; 512];
            y[..padded_hash.len()].copy_from_slice(&padded_hash);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(
                sig_no_crt_key,
                [
                    0x35, 0xD9, 0x19, 0x8F, 0x62, 0x2E, 0x64, 0xE4, 0x23, 0x45, 0x25, 0xCB, 0x9F,
                    0x9F, 0x64, 0x7D, 0x90, 0xE2, 0xB2, 0x9A, 0x66, 0x8C, 0xA9, 0x9C, 0x6D, 0x06,
                    0x31, 0x8C, 0xE6, 0x1B, 0xA9, 0xF7, 0xEF, 0xA5, 0xD4, 0x8A, 0x81, 0xAA, 0xB7,
                    0xF4, 0x56, 0x41, 0xB0, 0xA7, 0x32, 0x37, 0x2F, 0xB7, 0x25, 0x82, 0x2E, 0x1B,
                    0x1B, 0x74, 0x87, 0xBD, 0xD7, 0x0B, 0x4E, 0x9E, 0xD7, 0x84, 0xF7, 0xBC, 0xCC,
                    0xF5, 0xFC, 0x9F, 0x04, 0xDD, 0x62, 0x79, 0x3C, 0xBD, 0xAA, 0xD9, 0x12, 0xC8,
                    0xA5, 0x3C, 0xE5, 0xB1, 0x85, 0x9F, 0x77, 0xEA, 0xB1, 0x77, 0xC4, 0xE9, 0xCA,
                    0x16, 0x23, 0xD4, 0x6D, 0xAD, 0xCB, 0xCE, 0x83, 0x06, 0xD0, 0x20, 0x83, 0xB0,
                    0xB5, 0x92, 0xF2, 0x24, 0xC8, 0x4F, 0xCC, 0xAF, 0x5C, 0xF3, 0xEC, 0x64, 0x04,
                    0xE5, 0xB7, 0x9B, 0x5B, 0xAE, 0xCE, 0x33, 0xFE, 0x19, 0x58, 0x42, 0x3F, 0xB6,
                    0xFF, 0xA6, 0xFF, 0x91, 0xFB, 0x7C, 0x2B, 0x66, 0x48, 0x8E, 0x9D, 0xF1, 0x9D,
                    0x3F, 0x1F, 0x71, 0xC4, 0xB7, 0x54, 0xE0, 0xDE, 0xB5, 0x63, 0x66, 0x48, 0xAE,
                    0x01, 0x64, 0x8F, 0x11, 0x3B, 0xC8, 0xFA, 0x28, 0x09, 0xB5, 0x6B, 0xBF, 0x05,
                    0x3E, 0x1E, 0x45, 0x85, 0x7E, 0xD9, 0x82, 0x52, 0xCB, 0x42, 0xF3, 0x6C, 0x77,
                    0x10, 0x92, 0x09, 0x62, 0xA5, 0xC3, 0xE0, 0xD9, 0x7B, 0x5E, 0x59, 0x4F, 0xDC,
                    0xF9, 0x7A, 0xE7, 0x77, 0x22, 0xF0, 0x2E, 0x88, 0xF6, 0xEE, 0xC8, 0xEB, 0xF3,
                    0x26, 0x0E, 0xB9, 0x5D, 0x03, 0x5F, 0x0B, 0xF5, 0x1C, 0x54, 0x5B, 0xC8, 0x8F,
                    0x7B, 0xC1, 0xC0, 0x88, 0xAB, 0x50, 0x95, 0xF1, 0x68, 0xD5, 0xD4, 0xE2, 0xA9,
                    0x09, 0x58, 0x1E, 0xCC, 0x02, 0xC7, 0xDF, 0x2D, 0x1A, 0xDC, 0xDA, 0x5C, 0x9D,
                    0x0C, 0x82, 0x11, 0x7B, 0x49, 0xDB, 0x56, 0x44, 0xF0
                ]
            );

            let result = rsa_verify_local_openssl(
                &TEST_RSA_2K_PUBLIC_KEY,
                &resp.data.x.data()[..resp.data.x.len()],
                &[0x1; 64],
                CryptoRsaSignaturePadding::Pkcs1_5,
                Some(DdiHashAlgorithm::Sha512),
                None,
            );
            assert!(result);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv_crt,
                MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                DdiRsaOpType::Sign,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(sig_no_crt_key, sig_crt_key);
        },
    );
}

#[test]
fn test_rsa_2k_sign_and_verify_pss_sha1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let hash = [0x1; 20];

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    2048 - 1,
                    RsaDigestKind::Sha1,
                    crypto_sha1,
                    0,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(
                    sig_no_crt_key,
                    [
                        0x90, 0x1C, 0x30, 0xA9, 0x70, 0x32, 0xA0, 0xA4, 0x56, 0x43, 0xBE, 0xE6,
                        0x8F, 0x05, 0x81, 0x2E, 0xFC, 0x61, 0x60, 0xE0, 0x49, 0x59, 0x0C, 0xEB,
                        0xC4, 0xE3, 0x18, 0x8B, 0x2B, 0x9E, 0x43, 0x48, 0x71, 0x4C, 0x71, 0x6A,
                        0xAC, 0x62, 0x3D, 0x6D, 0xA1, 0x33, 0x85, 0xD7, 0x4E, 0x42, 0x2B, 0xDF,
                        0x46, 0xCD, 0xCC, 0xD4, 0x65, 0x2B, 0x23, 0x68, 0x81, 0x13, 0xCF, 0xE5,
                        0x5C, 0x65, 0xB1, 0x41, 0x10, 0x7C, 0x03, 0x60, 0x36, 0x53, 0x41, 0xD7,
                        0x71, 0x47, 0x90, 0x39, 0xB9, 0x19, 0xA2, 0x49, 0x07, 0x18, 0x87, 0xD2,
                        0xA8, 0xF8, 0x55, 0x51, 0xC1, 0xEF, 0x75, 0xDD, 0x3C, 0x32, 0x3F, 0x5F,
                        0x3F, 0x66, 0x88, 0xF6, 0x70, 0x48, 0x9A, 0xDD, 0x64, 0x78, 0xB9, 0xE1,
                        0x76, 0xDA, 0xA0, 0x87, 0x97, 0x50, 0x09, 0x63, 0x97, 0x0F, 0xA8, 0x9C,
                        0x82, 0x3C, 0x3A, 0x46, 0xF1, 0xB0, 0x2E, 0x44, 0x2E, 0x2A, 0xFE, 0x71,
                        0x51, 0x7F, 0x28, 0x0C, 0xBD, 0x4C, 0xD2, 0xD0, 0xD6, 0xFF, 0x50, 0xA1,
                        0xDF, 0xDC, 0xC1, 0xE7, 0xFA, 0x9D, 0x18, 0x27, 0x2B, 0x4A, 0x68, 0xDF,
                        0xC2, 0x67, 0x7B, 0xA8, 0x5A, 0x7D, 0x38, 0xB3, 0x20, 0x64, 0x1B, 0xC1,
                        0xC2, 0xE1, 0x91, 0x8D, 0xC2, 0xE7, 0xEB, 0xD5, 0xE0, 0x13, 0xD0, 0xF6,
                        0xB5, 0x84, 0x84, 0x8E, 0x19, 0x21, 0x8E, 0x34, 0xAB, 0x1F, 0x12, 0xA5,
                        0xFF, 0x53, 0xE0, 0x1D, 0xE3, 0x52, 0x51, 0x62, 0x7B, 0xAC, 0xEF, 0xDC,
                        0x07, 0x0E, 0x2C, 0xA5, 0x83, 0xC7, 0xA7, 0xA1, 0x26, 0x80, 0x28, 0xE1,
                        0x8B, 0x20, 0x66, 0xF3, 0xE3, 0x13, 0x70, 0xDD, 0x58, 0xCA, 0x94, 0x6F,
                        0xF3, 0x90, 0xF6, 0x37, 0xD3, 0xA2, 0x6C, 0x8E, 0x88, 0xE1, 0x4E, 0x28,
                        0x5B, 0x22, 0x56, 0x6D, 0xE0, 0xFB, 0x6F, 0x21, 0xAC, 0xF2, 0xF7, 0x64,
                        0x37, 0xD3, 0x1A, 0xD4
                    ]
                );

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_2K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 20],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha1),
                    Some(0),
                );
                assert!(result);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv_crt,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(sig_no_crt_key, sig_crt_key);
            }

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    2048 - 1,
                    RsaDigestKind::Sha1,
                    crypto_sha1,
                    20,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_2K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 20],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha1),
                    Some(20),
                );
                assert!(result);
            }
        },
    );
}

#[test]
fn test_rsa_2k_sign_and_verify_pss_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let hash = [0x1; 32];

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    2048 - 1,
                    RsaDigestKind::Sha256,
                    crypto_sha256,
                    0,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(
                    sig_no_crt_key,
                    [
                        0xE0, 0xE5, 0x3A, 0x1F, 0x53, 0x3C, 0x6C, 0x9D, 0xAF, 0x6A, 0x6C, 0x41,
                        0x2E, 0x96, 0xFE, 0xA5, 0x14, 0x85, 0xDB, 0x12, 0x36, 0x3A, 0x6F, 0x3E,
                        0x35, 0x78, 0x46, 0x71, 0x5B, 0x36, 0x42, 0xE3, 0x80, 0x2F, 0x76, 0x83,
                        0xF1, 0x9E, 0x9C, 0xEF, 0x13, 0x6D, 0x74, 0x2E, 0x23, 0xF1, 0x3B, 0x19,
                        0xE9, 0x45, 0xD0, 0x7B, 0x96, 0x0D, 0xB0, 0x45, 0x57, 0x19, 0x90, 0x64,
                        0xB9, 0x99, 0x99, 0xEA, 0x0F, 0xE2, 0x13, 0x19, 0x3C, 0x01, 0x34, 0xAC,
                        0x95, 0x98, 0x16, 0x1D, 0x0A, 0xDF, 0x3A, 0xE6, 0xD4, 0x7F, 0x7F, 0x69,
                        0x30, 0x3A, 0x2E, 0x07, 0xAD, 0x36, 0xCC, 0x42, 0x1F, 0xCB, 0xFC, 0xA8,
                        0x47, 0x8A, 0xAD, 0x72, 0x9D, 0x0D, 0xC7, 0xE4, 0x35, 0xC6, 0xCD, 0xB6,
                        0x0B, 0x19, 0xDC, 0x52, 0x64, 0xF4, 0x4D, 0xED, 0xD4, 0x52, 0xB0, 0x8C,
                        0xD7, 0xA9, 0x54, 0xE0, 0xA2, 0xCF, 0x96, 0xCC, 0x3B, 0x24, 0x2A, 0xCF,
                        0xA4, 0x81, 0x68, 0x03, 0x43, 0x32, 0x5F, 0xA3, 0x96, 0x96, 0x67, 0xAD,
                        0x01, 0xB5, 0x20, 0x8A, 0x3F, 0x73, 0x04, 0xD3, 0x3D, 0x1F, 0x07, 0xA0,
                        0x92, 0x9C, 0x9C, 0x7D, 0xF9, 0x60, 0xF8, 0x55, 0xFA, 0x71, 0x6A, 0x10,
                        0x6C, 0x61, 0x37, 0x44, 0xDD, 0xB7, 0xCF, 0x45, 0x7F, 0x11, 0x86, 0xE6,
                        0x97, 0x9A, 0xB8, 0x1C, 0x32, 0x02, 0x5E, 0xBC, 0x1C, 0x88, 0x5D, 0x64,
                        0x1C, 0xA7, 0x1A, 0x5A, 0xA4, 0x6A, 0x4F, 0x6C, 0x73, 0xFB, 0x32, 0xA0,
                        0x94, 0x6D, 0xDD, 0xA2, 0x49, 0x4C, 0xCC, 0xD2, 0x81, 0x55, 0x70, 0x6B,
                        0xBE, 0xD4, 0x73, 0x85, 0x46, 0x9C, 0x67, 0x44, 0x94, 0x54, 0xF9, 0xB4,
                        0x00, 0xB4, 0xAC, 0x14, 0xB2, 0x59, 0xD5, 0xA9, 0xB4, 0x14, 0x33, 0xC0,
                        0xD5, 0x3B, 0x07, 0xB4, 0x81, 0x3A, 0xE2, 0xBB, 0xFB, 0x09, 0x31, 0x1E,
                        0xCA, 0xAD, 0xD2, 0xF6
                    ]
                );

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_2K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 32],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha256),
                    Some(0),
                );
                assert!(result);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv_crt,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(sig_no_crt_key, sig_crt_key);
            }

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    2048 - 1,
                    RsaDigestKind::Sha256,
                    crypto_sha256,
                    32,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_2K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 32],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha256),
                    Some(32),
                );
                assert!(result);
            }
        },
    );
}

#[test]
fn test_rsa_2k_sign_and_verify_pss_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let hash = [0x1; 48];

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    2048 - 1,
                    RsaDigestKind::Sha384,
                    crypto_sha384,
                    0,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(
                    sig_no_crt_key,
                    [
                        0x26, 0x2A, 0xCC, 0xB8, 0x6F, 0x55, 0x50, 0xBB, 0xD4, 0xAE, 0x92, 0xDF,
                        0xBA, 0xFC, 0xAA, 0xFF, 0x65, 0x5F, 0x8A, 0xB3, 0x28, 0x04, 0x39, 0xDF,
                        0x1D, 0x79, 0x6D, 0x15, 0x64, 0x99, 0x24, 0x7D, 0x6C, 0xA2, 0xE9, 0x47,
                        0xED, 0x41, 0xCD, 0xA9, 0xD6, 0xC1, 0x4A, 0x70, 0x8E, 0x13, 0xC9, 0x6E,
                        0x06, 0x46, 0x14, 0xC8, 0xCB, 0x44, 0x1E, 0x1C, 0x5B, 0x70, 0x6E, 0xC4,
                        0x58, 0x36, 0xD1, 0x82, 0xB9, 0x8D, 0x4E, 0x76, 0x34, 0xDD, 0x49, 0x9F,
                        0xA6, 0x12, 0xAA, 0xA0, 0x2A, 0xC2, 0x8A, 0xDB, 0xF1, 0x40, 0x43, 0x16,
                        0xC6, 0x0B, 0x6C, 0x7C, 0x1E, 0xF4, 0x7D, 0x70, 0x60, 0xAA, 0x43, 0x6F,
                        0xDA, 0x1F, 0xDB, 0xF6, 0xB4, 0x5E, 0x7B, 0x87, 0x41, 0x04, 0xD0, 0x39,
                        0xDE, 0x6F, 0x34, 0x31, 0x48, 0x58, 0x2B, 0x67, 0x17, 0xA0, 0x08, 0x25,
                        0x08, 0x3B, 0x0F, 0x7E, 0xBE, 0xD8, 0x2E, 0xFE, 0xA2, 0xE4, 0x16, 0xE6,
                        0xE3, 0x0C, 0xFB, 0xDF, 0x7A, 0x5B, 0x70, 0xDB, 0x25, 0x05, 0xD3, 0xF1,
                        0x38, 0xDE, 0x11, 0x70, 0xC0, 0xE1, 0x47, 0xC5, 0x74, 0xE9, 0x14, 0x79,
                        0x38, 0xBE, 0x2B, 0xDD, 0xF4, 0x31, 0x14, 0xAD, 0xB3, 0x8E, 0xBD, 0xB5,
                        0x73, 0x6A, 0x95, 0x16, 0x57, 0xBE, 0x40, 0xF0, 0x93, 0x7F, 0x88, 0x56,
                        0xAD, 0xE3, 0x28, 0xBF, 0x8A, 0xC5, 0x83, 0xDC, 0xC4, 0xAD, 0x70, 0xBD,
                        0xDE, 0xB4, 0x74, 0x0E, 0x69, 0xBA, 0x5B, 0xE9, 0xA2, 0x91, 0x5A, 0xB9,
                        0x6A, 0x04, 0xB4, 0x3C, 0xDF, 0x8A, 0x35, 0xD7, 0xB2, 0x23, 0x61, 0x53,
                        0x7F, 0x8D, 0x6B, 0x44, 0x57, 0x38, 0xFF, 0x58, 0x0D, 0x0D, 0x84, 0x56,
                        0x65, 0xAB, 0x6F, 0xA0, 0xC4, 0x1A, 0xBC, 0xC1, 0x24, 0xF9, 0x68, 0x8D,
                        0x47, 0x64, 0x31, 0x1B, 0xB5, 0x94, 0x64, 0x7A, 0x72, 0xE6, 0x2E, 0x14,
                        0x43, 0xBA, 0x7F, 0x3C
                    ]
                );

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_2K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 48],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha384),
                    Some(0),
                );
                assert!(result);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv_crt,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(sig_no_crt_key, sig_crt_key);
            }

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    2048 - 1,
                    RsaDigestKind::Sha384,
                    crypto_sha384,
                    48,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_2K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 48],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha384),
                    Some(48),
                );
                assert!(result);
            }
        },
    );
}

#[test]
fn test_rsa_2k_sign_and_verify_pss_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);
            let (_, key_id_rsa2k_priv_crt, _) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let hash = [0x1; 64];

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    2048 - 1,
                    RsaDigestKind::Sha512,
                    crypto_sha512,
                    0,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(
                    sig_no_crt_key,
                    [
                        0x3B, 0x22, 0x09, 0xB9, 0xB9, 0x55, 0xE2, 0x1B, 0xA0, 0x4F, 0xB0, 0xA8,
                        0x08, 0x5C, 0x9B, 0x57, 0xF5, 0xC4, 0xBE, 0xBE, 0x72, 0x6A, 0xF4, 0x4E,
                        0xF4, 0x66, 0x99, 0x93, 0x16, 0x03, 0xD6, 0x7F, 0x00, 0xB3, 0xE5, 0xD2,
                        0xB6, 0x8B, 0xD6, 0x03, 0xB8, 0xBF, 0x49, 0x68, 0x6F, 0xBC, 0x36, 0xD9,
                        0xEC, 0xE6, 0x91, 0xE0, 0x27, 0xA9, 0xB9, 0xA2, 0xCD, 0x0D, 0x76, 0xE8,
                        0xA9, 0x1E, 0x90, 0x4D, 0x33, 0x95, 0x72, 0x9B, 0x12, 0xB8, 0x66, 0x87,
                        0x5D, 0xE7, 0x9C, 0x53, 0x2E, 0x0C, 0x29, 0x26, 0xD0, 0xC9, 0x50, 0xBD,
                        0x1B, 0xC8, 0x60, 0x5F, 0x31, 0x14, 0xEB, 0xE0, 0x87, 0x15, 0x98, 0x07,
                        0x42, 0x90, 0x27, 0x55, 0xFB, 0x52, 0xFA, 0x23, 0xF2, 0x54, 0x68, 0x9C,
                        0x6C, 0xE9, 0xE9, 0x76, 0x9D, 0x61, 0x6B, 0x95, 0x62, 0x8A, 0xAE, 0x97,
                        0x09, 0xF4, 0xB3, 0x73, 0xA5, 0x36, 0x3D, 0xD9, 0xBC, 0x5C, 0xFE, 0xD6,
                        0x54, 0x8E, 0x52, 0xF3, 0x3D, 0x4D, 0xBB, 0x83, 0x85, 0x90, 0xF9, 0xF6,
                        0x7F, 0x42, 0x15, 0x55, 0x42, 0x2D, 0x3D, 0x7F, 0x99, 0x1F, 0x1A, 0x1B,
                        0xF9, 0xCA, 0x70, 0xD6, 0xFB, 0xC5, 0x60, 0x6B, 0xFF, 0x56, 0xD3, 0xBF,
                        0x32, 0xAC, 0x64, 0x7C, 0xF6, 0x1D, 0x4E, 0xC4, 0x82, 0x3F, 0x25, 0xE4,
                        0xE5, 0x9B, 0x5A, 0x53, 0xBE, 0x6F, 0xEB, 0x36, 0xFB, 0x31, 0xDD, 0xF0,
                        0x41, 0x30, 0x2B, 0xB9, 0x08, 0x97, 0x1E, 0x6C, 0xB7, 0x46, 0x42, 0x8B,
                        0xE4, 0xE3, 0xB0, 0x08, 0x90, 0xF7, 0xD3, 0x29, 0xF7, 0xA2, 0x82, 0x5E,
                        0xDC, 0x65, 0xF1, 0x9C, 0x6F, 0x01, 0x0C, 0x3A, 0x87, 0x33, 0x76, 0x8B,
                        0x4F, 0x55, 0xCF, 0x45, 0x01, 0xE2, 0xFD, 0x0F, 0x7B, 0xCC, 0xB9, 0x06,
                        0xDE, 0x2F, 0xCB, 0xF1, 0x0E, 0xDA, 0x87, 0x6E, 0x79, 0xE6, 0xD7, 0x34,
                        0x80, 0x8E, 0x29, 0x3D
                    ]
                );

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_2K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 64],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha512),
                    Some(0),
                );
                assert!(result);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv_crt,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(sig_no_crt_key, sig_crt_key);
            }

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    2048 - 1,
                    RsaDigestKind::Sha512,
                    crypto_sha512,
                    64,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let resp = helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_rsa2k_priv,
                    MborByteArray::new(y, padded_hash.len()).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_2K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 64],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha512),
                    Some(64),
                );
                assert!(result);
            }
        },
    );
}
