// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::cmp::min;
use std::thread;

use crypto::rand::rand_bytes;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use rsa_padding::RsaDigestKind;
use rsa_padding::RsaEncoding;
use test_with_tracing::test;

use crate::common::*;

const RAW_MSG: [u8; 512] = [1u8; 512];

#[test]
fn test_masked_key_aes_bulk_256_der_import() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let max_keys = get_device_info(ddi, path).tables as usize * 7;
            // We open a session in each thread and we can only do MAX_SESSIONS sessions max.
            let max_threads = MAX_SESSIONS;
            let thread_count = min(max_keys, max_threads);
            let thread_device_path = path.to_string();
            let mut parent_dev = dev.clone();

            let thread = thread::spawn(move || {
                test_aes_gcm_encrypt_decrypt_thread_fn(
                    thread_device_path,
                    thread_count,
                    &mut parent_dev,
                    session_id,
                );
            });
            thread.join().unwrap();
        },
    );
}

#[test]
fn test_masked_key_rsa_2k_no_crt_der_import_encrypt_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_rsa_der_import_encrypt_decrypt(dev, session_id, 2, true);
        },
    );
}

#[test]
fn test_masked_key_rsa_3k_no_crt_der_import_encrypt_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_rsa_der_import_encrypt_decrypt(dev, session_id, 3, true);
        },
    );
}

#[test]
fn test_masked_key_rsa_4k_no_crt_der_import_encrypt_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_rsa_der_import_encrypt_decrypt(dev, session_id, 4, true);
        },
    );
}

#[test]
fn test_masked_key_rsa_2k_der_import_encrypt_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_rsa_der_import_encrypt_decrypt(dev, session_id, 2, false);
        },
    );
}

#[test]
fn test_masked_key_rsa_3k_der_import_encrypt_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_rsa_der_import_encrypt_decrypt(dev, session_id, 3, false);
        },
    );
}

#[test]
fn test_masked_key_rsa_4k_der_import_encrypt_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_rsa_der_import_encrypt_decrypt(dev, session_id, 4, false);
        },
    );
}

fn test_aes_gcm_encrypt_decrypt_thread_fn(
    device_path: String,
    max_attempts: usize,
    parent_dev: &mut <DdiTest as Ddi>::Dev,
    parent_session: u16,
) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);
    let mut app_sess_id = None;
    let mut short_app_id = None;

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
        short_app_id = Some(resp.data.short_app_id);

        break;
    }

    let app_sess_id = app_sess_id.unwrap();
    let short_app_sess_id = short_app_id.unwrap();

    thread::sleep(std::time::Duration::from_secs(1));

    // generate AES 256 bulk key; 32 bytes of random data
    let mut buf = [0u8; 32];
    let buf = &mut buf;
    let _ = rand_bytes(buf);

    let resp = helper_der_import_aes_bulk_key(
        parent_dev,
        Some(parent_session),
        Some(DdiApiRev { major: 1, minor: 0 }),
        1,
        DdiKeyClass::AesGcmBulkUnapproved,
        buf,
    );

    if let Err(err) = &resp {
        if firmware_not_built_with_test_hooks(err) {
            println!("Firmware is not built with mcr_test_hooks.");
            return;
        }
    }

    assert!(resp.is_ok(), "resp: {:?}", resp);

    let resp = resp.unwrap();
    let key_id = resp.data.key_id;
    let key_id_aes_bulk_256 = resp.data.bulk_key_id;
    let masked_key = resp.data.masked_key;
    assert!(key_id_aes_bulk_256.is_some());

    // Set up requests for the gcm encrypt operations
    let aad = [0x4; 32usize];
    let iv = [0x3u8; 12];

    // Setup params for encrypt operation
    let mut mcr_fp_gcm_params: DdiAesGcmParams = DdiAesGcmParams {
        key_id: key_id_aes_bulk_256.unwrap() as u32,
        iv,
        aad: Some(aad.to_vec()),
        tag: None, // tag is not needed for encryption
        session_id: app_sess_id,
        short_app_id: short_app_sess_id,
    };

    // Execute encrypt operation
    let resp = dev.exec_op_fp_gcm(
        DdiAesOp::Encrypt,
        mcr_fp_gcm_params.clone(),
        RAW_MSG.to_vec(),
    );

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let encrypted_resp = resp.unwrap();

    // Ensure encrypted data length is the same as the original data
    // Ensure encrypted data is different from original data
    assert_eq!(encrypted_resp.data.len(), RAW_MSG.len());
    assert_ne!(RAW_MSG.to_vec(), encrypted_resp.data);
    let tag = encrypted_resp.tag;

    let resp = helper_get_new_key_id_from_unmask(
        parent_dev,
        Some(parent_session),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (_, new_bulk_key_id, _) = resp.unwrap();

    assert!(new_bulk_key_id.is_some());
    let newbulk_key_id = new_bulk_key_id.unwrap();

    // Execute decrypt operation
    mcr_fp_gcm_params.tag = tag;
    mcr_fp_gcm_params.key_id = newbulk_key_id as u32;
    let resp = dev.exec_op_fp_gcm(
        DdiAesOp::Decrypt,
        mcr_fp_gcm_params.clone(),
        encrypted_resp.data.clone(),
    );

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let decrypted_resp = resp.unwrap();

    assert_eq!(decrypted_resp.data.len(), RAW_MSG.len());
    assert_eq!(decrypted_resp.data, RAW_MSG);
}

fn test_rsa_der_import_encrypt_decrypt(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_size: u8,
    no_crt: bool,
) {
    let (key_id_pub, key_id_priv, masked_key) = if no_crt {
        store_rsa_keys_no_crt(
            dev,
            session_id,
            DdiKeyUsage::EncryptDecrypt,
            key_size,
            Some(1),
        )
    } else {
        store_rsa_keys_crt(
            dev,
            session_id,
            DdiKeyUsage::EncryptDecrypt,
            key_size,
            Some(1),
        )
    };

    let orig_x = [0x1u8; 512];
    let data_len_to_test = 190;
    let pub_key: &[u8] = match key_size {
        2 => &TEST_RSA_2K_PUBLIC_KEY,
        3 => &TEST_RSA_3K_PUBLIC_KEY,
        4 => &TEST_RSA_4K_PUBLIC_KEY,
        _ => unreachable!(),
    };

    let resp = rsa_encrypt_local_openssl(
        pub_key,
        &orig_x,
        data_len_to_test,
        DdiRsaCryptoPadding::Oaep,
        Some(DdiHashAlgorithm::Sha256),
    );

    let mut encrypted_data = [0u8; 512];
    encrypted_data[..resp.len()].copy_from_slice(resp.as_slice());
    let encrypted_data_len = resp.len();

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id_priv,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_key_id, _, pub_key) = resp.unwrap();
    assert!(pub_key.is_some());
    let pub_key = pub_key.unwrap();
    assert_eq!(pub_key.key_kind, key_id_pub.key_kind);
    assert_eq!(pub_key.der.as_slice(), key_id_pub.der.as_slice());

    let resp = helper_rsa_mod_exp(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        new_key_id,
        MborByteArray::new(encrypted_data, encrypted_data_len)
            .expect("failed to create byte array"),
        DdiRsaOpType::Decrypt,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();

    let mut padded_data = [0u8; 512];
    padded_data[..resp.data.x.len()].copy_from_slice(&resp.data.x.data()[..resp.data.x.len()]);

    let key_size = match key_size {
        2 => 2048 / 8,
        3 => 3072 / 8,
        4 => 4096 / 8,
        _ => unreachable!(),
    };

    let unpadded_data_result = RsaEncoding::decode_oaep(
        &mut padded_data[..resp.data.x.len()],
        None,
        key_size,
        RsaDigestKind::Sha256,
        crypto_sha256,
    );
    assert!(unpadded_data_result.is_ok());
    let unpadded_data = unpadded_data_result.unwrap();

    assert_eq!(orig_x[..data_len_to_test], unpadded_data);
}
