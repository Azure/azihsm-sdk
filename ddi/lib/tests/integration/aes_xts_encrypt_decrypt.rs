// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use azihsm_crypto::*;
use azihsm_ddi::*;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_aes_xts_encrypt_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

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
            assert!(resp.is_ok(), "resp: {:?}", resp);
            let resp = resp.unwrap();
            let app_sess_id = resp.data.sess_id;
            let short_app_sess_id = resp.data.short_app_id;

            // generate AES 256 bulk key 1
            let resp =
                generate_aes_bulk_256_key(dev, &app_sess_id, None, DdiAesKeySize::AesXtsBulk256);
            assert!(resp.is_ok(), "resp: {:?}", resp);
            let resp = resp.unwrap();

            assert!(resp.data.bulk_key_id.is_some());
            let key_id1_aes_bulk_256 = resp.data.bulk_key_id.unwrap() as u32;

            // generate AES 256 bulk key 2
            let resp =
                generate_aes_bulk_256_key(dev, &app_sess_id, None, DdiAesKeySize::AesXtsBulk256);
            assert!(resp.is_ok(), "resp: {:?}", resp);
            let resp = resp.unwrap();

            assert!(resp.data.bulk_key_id.is_some());
            let key_id2_aes_bulk_256 = resp.data.bulk_key_id.unwrap() as u32;

            // set up requests for the xts encrypt operations
            let data = vec![1; 1024 * 1024];
            let tweak = [0x4; 16usize];
            let data_len = data.len();

            // setup params for encrypt operation
            let mcr_fp_xts_params = DdiAesXtsParams {
                key_id1: key_id1_aes_bulk_256,
                key_id2: key_id2_aes_bulk_256,
                data_unit_len: data_len,
                session_id: app_sess_id,
                short_app_id: short_app_sess_id,
                tweak,
            };

            // execute encrypt operation
            let resp =
                dev.exec_op_fp_xts(DdiAesOp::Encrypt, mcr_fp_xts_params.clone(), data.clone());

            assert!(resp.is_ok(), "resp: {:?}", resp);
            let encrypted_resp = resp.unwrap();

            // ensure encrypted data length is the same as the original data
            // ensure encrypted data is different from original data
            assert_eq!(encrypted_resp.data.len(), data.len());
            assert_ne!(data, encrypted_resp.data);

            // execute decrypt operation
            let resp = dev.exec_op_fp_xts(
                DdiAesOp::Decrypt,
                mcr_fp_xts_params.clone(),
                encrypted_resp.data.clone(),
            );

            assert!(resp.is_ok(), "resp: {:?}", resp);
            let decrypted_resp = resp.unwrap();

            assert_eq!(decrypted_resp.data.len(), data.len());
            assert_eq!(decrypted_resp.data, data);

            // Close App Session
            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);
        },
    );
}

#[test]
fn test_aes_xts_encrypt_with_identical_key_content() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

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
            assert!(resp.is_ok(), "resp: {:?}", resp);
            let resp = resp.unwrap();

            let app_sess_id = resp.data.sess_id;
            let short_app_sess_id = resp.data.short_app_id;

            // generate AES 256 bulk key; 32 bytes of random data
            let mut buf = [0u8; 32];
            let buf = &mut buf;
            let _ = Rng::rand_bytes(buf);

            // set AES 256 bulk key 2 == key 1
            // import key 1
            let resp = rsa_secure_import_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                buf.as_slice(),
                DdiKeyClass::AesXtsBulk,
                DdiKeyUsage::EncryptDecrypt,
                None,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert!(resp.data.bulk_key_id.is_some());
            let key_id1_aes_bulk_256 = resp.data.bulk_key_id.unwrap() as u32;

            // import key 2
            let resp = rsa_secure_import_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                buf.as_slice(),
                DdiKeyClass::AesXtsBulk,
                DdiKeyUsage::EncryptDecrypt,
                None,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert!(resp.data.bulk_key_id.is_some());
            let key_id2_aes_bulk_256 = resp.data.bulk_key_id.unwrap() as u32;

            assert_ne!(key_id1_aes_bulk_256, key_id2_aes_bulk_256);

            // set up requests for the xts encrypt operations
            let data = vec![1; 1024 * 1024];
            let tweak = [0x4; 16usize];
            let data_len = data.len();

            // setup params for encrypt operation
            let mcr_fp_xts_params: DdiAesXtsParams = DdiAesXtsParams {
                key_id1: key_id1_aes_bulk_256,
                key_id2: key_id2_aes_bulk_256,
                data_unit_len: data_len,
                session_id: app_sess_id,
                short_app_id: short_app_sess_id,
                tweak,
            };

            // execute encrypt operation
            let resp =
                dev.exec_op_fp_xts(DdiAesOp::Encrypt, mcr_fp_xts_params.clone(), data.clone());

            assert!(resp.is_err(), "resp: {:?}", resp);

            // Close App Session
            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);
        },
    );
}

#[test]
fn test_aes_xts_encrypt_with_gcm_key_in_the_mix() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

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
            assert!(resp.is_ok(), "resp: {:?}", resp);
            let resp = resp.unwrap();

            let app_sess_id = resp.data.sess_id;
            let short_app_sess_id = resp.data.short_app_id;

            // generate AES 256 bulk key; 32 bytes of random data
            let mut buf = [0u8; 32];
            let buf = &mut buf;
            let _ = Rng::rand_bytes(buf);

            let mut gcm_key_buf = [0u8; 32];
            let gcm_key_buf = &mut gcm_key_buf;
            let _ = Rng::rand_bytes(gcm_key_buf);

            // set AES 256 bulk key 2 == key 1
            // import key 1
            let resp = rsa_secure_import_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                buf.as_slice(),
                DdiKeyClass::AesXtsBulk,
                DdiKeyUsage::EncryptDecrypt,
                None,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert!(resp.data.bulk_key_id.is_some());
            let key_id1_aes_bulk_256 = resp.data.bulk_key_id.unwrap() as u32;

            // import key 2
            let resp = rsa_secure_import_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                gcm_key_buf.as_slice(),
                DdiKeyClass::AesGcmBulkUnapproved,
                DdiKeyUsage::EncryptDecrypt,
                None,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert!(resp.data.bulk_key_id.is_some());
            let key_id2_aes_bulk_256 = resp.data.bulk_key_id.unwrap() as u32;

            assert_ne!(key_id1_aes_bulk_256, key_id2_aes_bulk_256);

            // set up requests for the xts encrypt operations
            let data = vec![1; 1024 * 1024];
            let tweak = [0x4; 16usize];
            let data_len = data.len();

            // setup params for encrypt operation
            let mcr_fp_xts_params: DdiAesXtsParams = DdiAesXtsParams {
                key_id1: key_id1_aes_bulk_256,
                key_id2: key_id2_aes_bulk_256,
                data_unit_len: data_len,
                session_id: app_sess_id,
                short_app_id: short_app_sess_id,
                tweak,
            };

            // execute encrypt operation
            let resp =
                dev.exec_op_fp_xts(DdiAesOp::Encrypt, mcr_fp_xts_params.clone(), data.clone());

            assert!(resp.is_err(), "resp: {:?}", resp);

            // Close App Session
            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);
        },
    );
}
