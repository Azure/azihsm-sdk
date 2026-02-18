// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_rsa_3k_decrypt_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 3, None);

            let resp = helper_rsa_mod_exp(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa3k_priv,
                MborByteArray::from_slice(&[0x1; 384]).expect("failed to create byte array"),
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
fn test_rsa_3k_decrypt_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 3, None);

            let session_id = 20;
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa3k_priv,
                MborByteArray::from_slice(&[0x1; 384]).expect("failed to create byte array"),
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
fn test_rsa_3k_decrypt_incorrect_key_num_table() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0300,
                MborByteArray::from_slice(&[0x1; 384]).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_3k_decrypt_incorrect_key_num_entry() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0020,
                MborByteArray::from_slice(&[0x1; 384]).expect("failed to create byte array"),
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
fn test_rsa_3k_decrypt_incorrect_key_type() {
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
                MborByteArray::from_slice(&[0x1; 384]).expect("failed to create byte array"),
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
fn test_rsa_3k_decrypt_message_data_below_lower_limit() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Skip test for virtual device as it doesn't check for RSA mod exp data
            // This is a FIPS only requirement
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::info!(
                    "Skipped test_rsa_3k_decrypt_message_data_below_lower_limit for virtual device"
                );
                return;
            }

            let (_key_id_rsa3k_pub, key_id_rsa3k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 3, None);

            let mut msg = MborByteArray::new([0x0; 512], 384).expect("failed to create byte array");
            let last_idx = msg.len() - 1;
            msg.data_mut()[last_idx] = 0x1;

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa3k_priv,
                msg,
                DdiRsaOpType::Decrypt,
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
fn test_rsa_3k_decrypt_message_data_above_upper_limit() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Skip test for virtual device as it doesn't check for RSA mod exp data
            // This is a FIPS only requirement
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!(
                    "Skipped test_rsa_3k_decrypt_message_data_above_upper_limit for virtual device"
                );
                return;
            }

            let (_key_id_rsa3k_pub, key_id_rsa3k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 3, None);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa3k_priv,
                MborByteArray::new([0xff; 512], 384).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
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
fn test_rsa_3k_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 3, None);

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa3k_priv,
                MborByteArray::from_slice(&[0x1; 384]).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_3k_encrypt_and_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 3, None);

            let orig_x = [0x1u8; 512];
            let data_len_to_test = 318;
            let resp = rsa_encrypt_local_openssl(
                &TEST_RSA_3K_PUBLIC_KEY,
                &orig_x,
                data_len_to_test,
                DdiRsaCryptoPadding::Oaep,
                Some(DdiHashAlgorithm::Sha256),
            );

            let mut encrypted_data = [0u8; 512];
            encrypted_data[..resp.len()].copy_from_slice(resp.as_slice());
            let encrypted_data_len = resp.len();

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_rsa3k_priv,
                MborByteArray::new(encrypted_data, encrypted_data_len)
                    .expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let mut padded_data = [0u8; 512];
            padded_data[..resp.data.x.len()]
                .copy_from_slice(&resp.data.x.data()[..resp.data.x.len()]);

            let unpadded_data_result = RsaEncoding::decode_oaep(
                &mut padded_data[..resp.data.x.len()],
                None,
                3072 / 8,
                RsaDigestKind::Sha256,
                crypto_sha256,
            );
            assert!(unpadded_data_result.is_ok());
            let unpadded_data = unpadded_data_result.unwrap();

            assert_eq!(orig_x[..data_len_to_test], unpadded_data);
        },
    );
}
