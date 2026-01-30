// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_masked_key_secret_kbkdf() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_kbkdf_sha1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha1;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_kbkdf_no_label() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = None;
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_kbkdf_no_context() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_kbkdf_aes128() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes128;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_kbkdf_aes192() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes192;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_kbkdf_aes_gcm_secret256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (session_id, short_app_id) = reopen_session_with_short_app_id(dev, session_id);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = "label".as_bytes().to_vec();
            let context_vec = "context".as_bytes().to_vec();
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_aes_gcm_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                context_vec,
                label_vec,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret256,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_kbkdf_aes_gcm_secret384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (session_id, short_app_id) = reopen_session_with_short_app_id(dev, session_id);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = "label".as_bytes().to_vec();
            let context_vec = "context".as_bytes().to_vec();
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_aes_gcm_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                context_vec,
                label_vec,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret384,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_kbkdf_aes_gcm_secret521() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (session_id, short_app_id) = reopen_session_with_short_app_id(dev, session_id);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = "label".as_bytes().to_vec();
            let context_vec = "context".as_bytes().to_vec();
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_aes_gcm_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                context_vec,
                label_vec,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret521,
            );
        },
    );
}

// Uses KbkdfCounterHmac to derive derived_key_id1 and derived_key_id2
// from secret_key_id1 and secret_key_id2, respectively.
// Then verifies derived keys can do an encrypt/decrypt loop
// key_tag is only used for derived_key_id1.
// Returns (derived_key_id1, derived_key_id2)
#[allow(clippy::too_many_arguments)]
fn test_secret_kbkdf_helper(
    dev: &mut <DdiTest as Ddi>::Dev,
    hash_algorithm: DdiHashAlgorithm,
    label: Option<Vec<u8>>,
    context: Option<Vec<u8>>,
    key_type: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
    session_id: u16,
) {
    let (secret_key_id1, secret_key_id2) =
        create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

    let label = {
        if let Some(label_vec) = label {
            let mut label_array = [0u8; 256];
            label_array[..label_vec.len()].copy_from_slice(&label_vec);
            Some(
                MborByteArray::new(label_array, label_vec.len())
                    .expect("failed to create byte array"),
            )
        } else {
            None
        }
    };
    let context = {
        if let Some(context_vec) = context {
            let mut context_array = [0u8; 256];
            context_array[..context_vec.len()].copy_from_slice(&context_vec);
            Some(
                MborByteArray::new(context_array, context_vec.len())
                    .expect("failed to create byte array"),
            )
        } else {
            None
        }
    };

    // Derive from first secret key
    // Derive first key
    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        label,
        context,
        key_type,
        key_tag,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let derived_key_id1 = resp.data.key_id;
    let masked_key = resp.data.masked_key;

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        derived_key_id1,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_derived_key_id1, _, _) = resp.unwrap();

    // Derive from second secret key
    // Derive first key
    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        label,
        context,
        key_type,
        None,
        key_properties,
        None,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let derived_key_id2 = resp.data.key_id;

    // Encrypt message with secret key 1
    let raw_msg = [1u8; 512];
    let msg_len = raw_msg.len();
    let mut msg = [0u8; 1024];
    msg[..msg_len].clone_from_slice(&raw_msg);

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        new_derived_key_id1,
        DdiAesOp::Encrypt,
        MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
        MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    // Decrypt with key 2 and confirm message is same
    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        derived_key_id2,
        DdiAesOp::Decrypt,
        resp.data.msg,
        MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    assert_eq!(resp.data.msg.data_take(), msg);
    assert_eq!(resp.data.msg.len(), msg_len);
}

#[allow(clippy::too_many_arguments)]
fn test_secret_kbkdf_aes_gcm_helper(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    short_app_id: u8,
    hash_algorithm: DdiHashAlgorithm,
    context_vec: Vec<u8>,
    label_vec: Vec<u8>,
    key_type: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
    secret_key_type: DdiKeyType,
) {
    let (secret_key_id1, secret_key_id2) = create_ecdh_secrets(session_id, dev, secret_key_type);

    let label = {
        let mut label_array = [0u8; 256];
        label_array[..label_vec.len()].copy_from_slice(&label_vec);
        Some(MborByteArray::new(label_array, label_vec.len()).expect("failed to create byte array"))
    };
    let context = {
        let mut context_array = [0u8; 256];
        context_array[..context_vec.len()].copy_from_slice(&context_vec);
        Some(
            MborByteArray::new(context_array, context_vec.len())
                .expect("failed to create byte array"),
        )
    };

    // Derive from first secret key

    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        label,
        context,
        key_type,
        key_tag,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let derived_key_id1 = resp.data.key_id;
    let masked_key = resp.data.masked_key;

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        derived_key_id1,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (_, new_derived_key_id1, _) = resp.unwrap();
    assert!(new_derived_key_id1.is_some());
    let new_derived_key_id1 = new_derived_key_id1.unwrap();

    // Derive from second secret key
    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        label,
        context,
        key_type,
        None,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_key_id2 = resp.unwrap().data.bulk_key_id.unwrap();

    // set up requests for the gcm encrypt operations
    let data = vec![1; 16384];
    let aad = [0x4; 32usize];
    let iv = [0x3u8; 12];

    // setup params for encrypt operation
    let mut mcr_fp_gcm_params: DdiAesGcmParams = DdiAesGcmParams {
        key_id: new_derived_key_id1 as u32,
        iv,
        aad: Some(aad.to_vec()),
        tag: None, // tag is not needed for encryption
        session_id,
        short_app_id,
    };

    // execute encrypt operation
    let resp = dev.exec_op_fp_gcm(DdiAesOp::Encrypt, mcr_fp_gcm_params.clone(), data.clone());

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let encrypted_resp = resp.unwrap();

    // ensure encrypted data length is the same as the original data
    // ensure encrypted data is different from original data
    assert_eq!(encrypted_resp.data.len(), data.len());
    assert_ne!(data, encrypted_resp.data);
    let tag = encrypted_resp.tag;

    // execute decrypt operation
    mcr_fp_gcm_params.tag = tag;

    // use derived_key_id2 for decryption
    mcr_fp_gcm_params.key_id = derived_key_id2 as u32;

    let resp = dev.exec_op_fp_gcm(
        DdiAesOp::Decrypt,
        mcr_fp_gcm_params.clone(),
        encrypted_resp.data.clone(),
    );

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let decrypted_resp = resp.unwrap();

    assert_eq!(decrypted_resp.data.len(), data.len());
    assert_eq!(decrypted_resp.data, data);

    close_app_session(dev, session_id);
}
