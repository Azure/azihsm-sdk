// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_sim::crypto::rsa::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_rsa_mod_exp_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2, None);

            let resp = helper_rsa_mod_exp(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
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
fn test_rsa_mod_exp_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2, None);

            let session_id = 20;
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
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
fn test_rsa_mod_exp_incorrect_key_num_table() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0300,
                MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_mod_exp_incorrect_key_num_entry() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0020,
                MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
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
fn test_rsa_mod_exp_incorrect_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Import a key with a wrong type
            let key_id_wrong_type = store_aes_keys(dev, session_id);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_wrong_type,
                MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
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
fn test_rsa_mod_exp_incorrect_permissions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
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
fn test_rsa_mod_exp() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2, None);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_mod_exp_encrypt_and_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2, None);

            let orig_x = [0x1u8; 512];
            let data_len_to_test = 256;

            let data = &orig_x[..data_len_to_test];

            let rsa_pub_key = RsaPublicKey::from_der(&TEST_RSA_2K_PUBLIC_KEY, None)
                .expect("failed to create RSA public key from DER");
            let encrypted_data = rsa_pub_key
                .encrypt(data, RsaCryptoPadding::None, None)
                .expect("failed to encrypt data with RSA public key");

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa2k_priv,
                MborByteArray::from_slice(&encrypted_data).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert_eq!(
                orig_x[..data_len_to_test],
                resp.data.x.data()[..resp.data.x.len()]
            );
        },
    );
}
