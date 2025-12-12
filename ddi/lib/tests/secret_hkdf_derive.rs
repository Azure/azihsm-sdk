// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_secret_hkdf_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_hkdf_derive(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
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
fn test_secret_hkdf_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_hkdf_derive(
                dev,
                Some(20),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
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
fn test_secret_hkdf_invalid_input_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::Secret256;
            let key_tag = None;

            // Generate ECC Key

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_properties,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            let private_key_id1 = resp.data.private_key_id;

            // Try deriving using ECC key instead of secret key
            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
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
fn test_secret_hkdf_invalid_output_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::Ecc256Private;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            // Derive from first secret key

            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
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
fn test_secret_hkdf_invalid_secret521_output_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::Secret521;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            // Derive from first secret key
            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
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
fn test_secret_hkdf_invalid_output_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
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
fn test_secret_hkdf_different_info_len() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let info_vec = "label".as_bytes().to_vec();
            let info = {
                let mut info_array = [0u8; 256];
                info_array[..info_vec.len()].copy_from_slice(&info_vec);
                Some(
                    MborByteArray::new(info_array, info_vec.len())
                        .expect("failed to create byte array"),
                )
            };

            // Derive first key

            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let derived_key_id1 = resp.unwrap().data.key_id;

            // Derive second key with different info len
            let info2 = {
                let mut info_array = [0u8; 256];
                info_array[..info_vec.len()].copy_from_slice(&info_vec);
                Some(
                    MborByteArray::new(info_array, info_vec.len() + 1)
                        .expect("failed to create byte array"),
                )
            };

            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info2,
                key_type,
                key_tag,
                key_properties,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let derived_key_id2 = resp.unwrap().data.key_id;

            // Encrypt message with secret key 1
            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                derived_key_id1,
                DdiAesOp::Encrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                derived_key_id2,
                DdiAesOp::Encrypt,
                resp.data.msg,
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_ne!(resp.data.msg.data_take(), msg);
            assert_eq!(resp.data.msg.len(), msg_len);
        },
    );
}

// Uses HKDF to derive derived_key_id1 and derived_key_id2
// from secret_key_id1 and secret_key_id2, respectively.
// Then verifies derived keys can do an encrypt/decrypt loop
// key_tag is only used for DERIVED_KEY_ID1.
// Returns (derived_key_id1, derived_key_id2)
#[allow(clippy::too_many_arguments)]
fn test_secret_hkdf_helper(
    dev: &mut <DdiTest as Ddi>::Dev,
    hash_algorithm: DdiHashAlgorithm,
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
    key_type: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
    session_id: u16,
) -> (u16, u16) {
    let (secret_key_id1, secret_key_id2) =
        create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

    let salt = {
        if let Some(salt_vec) = salt {
            let mut salt_array = [0u8; 256];
            salt_array[..salt_vec.len()].copy_from_slice(&salt_vec);
            Some(
                MborByteArray::new(salt_array, salt_vec.len())
                    .expect("failed to create byte array"),
            )
        } else {
            None
        }
    };
    let info = {
        if let Some(info_vec) = info {
            let mut info_array = [0u8; 256];
            info_array[..info_vec.len()].copy_from_slice(&info_vec);
            Some(
                MborByteArray::new(info_array, info_vec.len())
                    .expect("failed to create byte array"),
            )
        } else {
            None
        }
    };

    // Derive from first secret key
    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        salt,
        info,
        key_type,
        key_tag,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_key_id1 = resp.unwrap().data.key_id;

    // Derive from second secret key

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        salt,
        info,
        key_type,
        None,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_key_id2 = resp.unwrap().data.key_id;

    // Encrypt message with secret key 1
    let raw_msg = [1u8; 512];
    let msg_len = raw_msg.len();
    let mut msg = [0u8; 1024];
    msg[..msg_len].clone_from_slice(&raw_msg);

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        derived_key_id1,
        DdiAesOp::Encrypt,
        MborByteArray::new(msg, msg_len).expect("failed to create byte array"),
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

    (derived_key_id1, derived_key_id2)
}

#[test]
fn test_secret_hkdf() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_sha1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha1;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_no_salt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = None;
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_no_info() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_aes128() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes128;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_aes192() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes192;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn test_secret_hkdf_aes_gcm_helper(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    short_app_id: u8,
    hash_algorithm: DdiHashAlgorithm,
    salt: Vec<u8>,
    info: Vec<u8>,
    key_type: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
    secret_key_type: DdiKeyType,
) {
    let (secret_key_id1, secret_key_id2) = create_ecdh_secrets(session_id, dev, secret_key_type);

    let salt = {
        let mut salt_array = [0u8; 256];
        salt_array[..salt.len()].copy_from_slice(&salt);
        Some(MborByteArray::new(salt_array, salt.len()).expect("failed to create byte array"))
    };
    let info = {
        let mut info_array = [0u8; 256];
        info_array[..info.len()].copy_from_slice(&info);
        Some(MborByteArray::new(info_array, info.len()).expect("failed to create byte array"))
    };

    // Derive from first secret key
    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        salt,
        info,
        key_type,
        key_tag,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_key_id1 = resp.unwrap().data.bulk_key_id.unwrap();

    // Derive from second secret key
    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        salt,
        info,
        key_type,
        None,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_key_id2 = resp.unwrap().data.bulk_key_id.unwrap();

    // set up requests for the gcm encrypt operations
    let data = vec![1; 16384];
    let aad = [0x4; 32usize];
    let iv = [0x3u8; 12];

    // setup params for encrypt operation
    let mut mcr_fp_gcm_params: DdiAesGcmParams = DdiAesGcmParams {
        key_id: derived_key_id1 as u32,
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

#[allow(clippy::too_many_arguments)]
fn test_secret_hkdf_aes_xts_helper(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    short_app_id: u8,
    hash_algorithm: DdiHashAlgorithm,
    salt: Vec<u8>,
    info: Vec<u8>,
    key_type: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
    secret_key_type: DdiKeyType,
) {
    let (secret_key_id1, secret_key_id2) = create_ecdh_secrets(session_id, dev, secret_key_type);

    let salt = {
        let mut salt_array = [0u8; 256];
        salt_array[..salt.len()].copy_from_slice(&salt);
        Some(MborByteArray::new(salt_array, salt.len()).expect("failed to create byte array"))
    };
    let info = {
        let mut info_array = [0u8; 256];
        info_array[..info.len()].copy_from_slice(&info);
        Some(MborByteArray::new(info_array, info.len()).expect("failed to create byte array"))
    };

    // Derive both aes xts keys from first secret key

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        None,
        None,
        key_type,
        key_tag,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_aes_xts_key_id1 = resp.unwrap().data.bulk_key_id.unwrap();

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        salt,
        info,
        key_type,
        key_tag,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_aes_xts_tweak_key_id1 = resp.unwrap().data.bulk_key_id.unwrap();

    // Derive both aes xts keys from second secret key

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        None,
        None,
        key_type,
        key_tag,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_aes_xts_key_id2 = resp.unwrap().data.bulk_key_id.unwrap();

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        salt,
        info,
        key_type,
        None,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_aes_xts_tweak_key_id2 = resp.unwrap().data.bulk_key_id.unwrap();

    // set up requests for the xts encrypt operations
    let data = vec![1; 1024 * 1024];
    let tweak = [0x4; 16usize];
    let data_len = data.len();

    // setup params for encrypt operation
    let mut mcr_fp_xts_params = DdiAesXtsParams {
        data_unit_len: data_len,
        key_id1: derived_aes_xts_key_id1 as u32,
        key_id2: derived_aes_xts_tweak_key_id1 as u32,
        session_id,
        short_app_id,
        tweak,
    };

    // execute encrypt operation
    let resp = dev.exec_op_fp_xts(DdiAesOp::Encrypt, mcr_fp_xts_params.clone(), data.clone());

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let encrypted_resp = resp.unwrap();

    // ensure encrypted data length is the same as the original data
    // ensure encrypted data is different from original data
    assert_eq!(encrypted_resp.data.len(), data.len());
    assert_ne!(data, encrypted_resp.data);

    // use derived key id2 for decryption
    mcr_fp_xts_params.key_id1 = derived_aes_xts_key_id2 as u32;
    mcr_fp_xts_params.key_id2 = derived_aes_xts_tweak_key_id2 as u32;

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

    close_app_session(dev, session_id);
}

#[test]
fn test_secret_hkdf_aes_gcm_secret256() {
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
            let salt = "salt".as_bytes().to_vec();
            let info = "label".as_bytes().to_vec();
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_aes_gcm_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret256,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_aes_gcm_secret384() {
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
            let salt = "salt".as_bytes().to_vec();
            let info = "label".as_bytes().to_vec();
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_aes_gcm_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret384,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_aes_gcm_secret521() {
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
            let salt = "salt".as_bytes().to_vec();
            let info = "label".as_bytes().to_vec();
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_aes_gcm_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret521,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_aes_xts_secret256() {
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
            let salt = "salt".as_bytes().to_vec();
            let info = "info".as_bytes().to_vec();
            let key_type = DdiKeyType::AesXtsBulk256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_aes_xts_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret256,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_aes_xts_secret384() {
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
            let salt = "salt".as_bytes().to_vec();
            let info = "info".as_bytes().to_vec();
            let key_type = DdiKeyType::AesXtsBulk256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_aes_xts_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret384,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_aes_xts_secret521() {
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
            let salt = "salt".as_bytes().to_vec();
            let info = "info".as_bytes().to_vec();
            let key_type = DdiKeyType::AesXtsBulk256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_aes_xts_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret521,
            );
        },
    );
}

#[test]
fn test_secret_hkdf_name() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("info".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = 0x6677;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let (derived_key_id1, _derived_key_id2) = test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                Some(key_tag),
                key_properties,
                session_id,
            );

            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_tag,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.key_id, derived_key_id1);
            assert_eq!(resp.data.key_kind, key_type);
            assert!(resp.data.pub_key.is_none());
        },
    );
}

// Uses HKDF to derive aes_key and hmac_key
// from secret_key_id1 and secret_key_id2, respectively.
// Then verifies derived keys can do encrypt/decrypt loop
// with hash verification.
// Returns HMAC result
#[allow(clippy::too_many_arguments)]
fn test_secret_hkdf_aes_hmac_helper(
    dev: &mut <DdiTest as Ddi>::Dev,
    hash_algorithm: DdiHashAlgorithm,
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
    aes_key_type: DdiKeyType,
    hmac_key_type: DdiKeyType,
    session_id: u16,
) -> Vec<u8> {
    let (secret_key_id1, secret_key_id2) =
        create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

    let salt = {
        if let Some(salt_vec) = salt {
            let mut salt_array = [0u8; 256];
            salt_array[..salt_vec.len()].copy_from_slice(&salt_vec);
            Some(
                MborByteArray::new(salt_array, salt_vec.len())
                    .expect("failed to create byte array"),
            )
        } else {
            None
        }
    };
    let info = {
        if let Some(info_vec) = info {
            let mut info_array = [0u8; 256];
            info_array[..info_vec.len()].copy_from_slice(&info_vec);
            Some(
                MborByteArray::new(info_array, info_vec.len())
                    .expect("failed to create byte array"),
            )
        } else {
            None
        }
    };

    // Derive AES from first secret key

    let key_properties =
        helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        salt,
        info,
        aes_key_type,
        None,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let aes_key_id1 = resp.unwrap().data.key_id;

    // Derive AES from second secret key

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        salt,
        info,
        aes_key_type,
        None,
        key_properties,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let aes_key_id2 = resp.unwrap().data.key_id;

    // Derive HMAC from first secret key
    let key_properties =
        helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session);

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        salt,
        info,
        hmac_key_type,
        None,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let hmac_key_id1 = resp.unwrap().data.key_id;

    // Derive HMAC from second secret key

    let key_properties =
        helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session);

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        salt,
        info,
        hmac_key_type,
        None,
        key_properties,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let hmac_key_id2 = resp.unwrap().data.key_id;

    // Encrypt message with aes key 1
    let raw_msg = [1u8; 512];
    let msg_len = raw_msg.len();
    let mut msg = [0u8; 1024];
    msg[..msg_len].clone_from_slice(&raw_msg);

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        aes_key_id1,
        DdiAesOp::Encrypt,
        MborByteArray::new(msg, msg_len).expect("failed to create byte array"),
        MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let encrypted_msg = resp.data.msg;

    // Generate HMAC tag with hmac key 1

    let resp = helper_hmac(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        hmac_key_id1,
        encrypted_msg,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let tag = resp.data.tag;

    // Generate HMAC tag with hmac key 2 and confirm is same
    let resp = helper_hmac(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        hmac_key_id2,
        encrypted_msg,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    assert_eq!(resp.data.tag, tag);

    // Decrypt with key 2 and confirm message is same

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        aes_key_id2,
        DdiAesOp::Decrypt,
        encrypted_msg,
        MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    assert_eq!(resp.data.msg.data_take(), msg);
    assert_eq!(resp.data.msg.len(), msg_len);

    tag.data()[..tag.len()].to_vec()
}

#[test]
fn test_secret_hkdf_aes256_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let aes_key_type = DdiKeyType::Aes256;
            let hmac_key_type = DdiKeyType::HmacSha256;

            let hmac_output = test_secret_hkdf_aes_hmac_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                aes_key_type,
                hmac_key_type,
                session_id,
            );
            assert_eq!(hmac_output.len(), 32);
        },
    );
}

#[test]
fn test_secret_hkdf_aes256_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let aes_key_type = DdiKeyType::Aes256;
            let hmac_key_type = DdiKeyType::HmacSha384;

            let hmac_output = test_secret_hkdf_aes_hmac_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                aes_key_type,
                hmac_key_type,
                session_id,
            );
            assert_eq!(hmac_output.len(), 48);
        },
    );
}

#[test]
fn test_secret_hkdf_aes192_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let aes_key_type = DdiKeyType::Aes192;
            let hmac_key_type = DdiKeyType::HmacSha512;

            let hmac_output = test_secret_hkdf_aes_hmac_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                aes_key_type,
                hmac_key_type,
                session_id,
            );
            assert_eq!(hmac_output.len(), 64);
        },
    );
}

#[test]
fn test_secret_hkdf_aes128_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let aes_key_type = DdiKeyType::Aes128;
            let hmac_key_type = DdiKeyType::HmacSha256;

            let hmac_output = test_secret_hkdf_aes_hmac_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                aes_key_type,
                hmac_key_type,
                session_id,
            );
            assert_eq!(hmac_output.len(), 32);
        },
    );
}

#[test]
fn test_hkdf_derive_aesbulk256_with_rollback_error() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = Some(3354);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            match helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            close_app_session(dev, session_id);
        },
    );
}

#[test]
fn test_hkdf_derive_aesbulk256_with_rollback_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let mut key_tag: u16 = 0x1;
            let mut key_id = 0;
            // Exhaust the key vault with App keys
            loop {
                match helper_hkdf_derive(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    secret_key_id1,
                    hash_algorithm,
                    salt,
                    info,
                    key_type,
                    Some(key_tag),
                    key_properties,
                ) {
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => key_id = val.data.key_id,
                }

                key_tag += 1;
            }

            // Delete Key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            match helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3354),
                key_properties,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3355),
                key_properties,
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            match helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3356),
                key_properties,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            close_app_session(dev, session_id);
        },
    );
}

#[test]
fn test_hkdf_derive_aesbulk256_with_rollback_error_after_dma_out() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaOutFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            match helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3354),
                key_properties,
            ) {
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            close_app_session(dev, session_id);
        },
    );
}

#[test]
fn test_hkdf_derive_aesbulk256_with_rollback_error_after_dma_out_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let mut key_tag: u16 = 0x1;
            let mut key_id = 0;
            // Exhaust the key vault with App keys
            loop {
                match helper_hkdf_derive(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    secret_key_id1,
                    hash_algorithm,
                    salt,
                    info,
                    key_type,
                    Some(key_tag),
                    key_properties,
                ) {
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => key_id = val.data.key_id,
                }

                key_tag += 1;
            }

            // Delete Key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaOutFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            match helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3354),
                key_properties,
            ) {
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3355),
                key_properties,
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            match helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3356),
                key_properties,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            close_app_session(dev, session_id);
        },
    );
}

#[test]
fn test_hkdf_derive_aesbulk256_with_rollback_error_after_dma_end() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaEndFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = Some(3354);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            match helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
            ) {
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            close_app_session(dev, session_id);
        },
    );
}

#[test]
fn test_hkdf_derive_aesbulk256_with_rollback_error_after_dma_end_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = None;
            let info = None;
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let mut key_tag: u16 = 0x1;
            let mut key_id = 0;
            // Exhaust the key vault with App keys
            loop {
                match helper_hkdf_derive(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    secret_key_id1,
                    hash_algorithm,
                    salt,
                    info,
                    key_type,
                    Some(key_tag),
                    key_properties,
                ) {
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => key_id = val.data.key_id,
                }

                key_tag += 1;
            }

            // Delete Key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaEndFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            match helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3354),
                key_properties,
            ) {
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3355),
                key_properties,
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            match helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                Some(3356),
                key_properties,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            close_app_session(dev, session_id);
        },
    );
}

// Unmask the masked key returned in a DdiHkdfDeriveResp
// And see if it can be used normally
#[test]
fn test_secret_hkdf_and_unmask() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Run this test only for Mock device
            if get_device_kind(dev) != DdiDeviceKind::Virtual {
                println!("Unmask key Not supported for Physical Device.");
                return;
            }

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = Some("salt".as_bytes().to_vec());
            let info = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let (secret_key_id1, secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let salt = {
                if let Some(salt_vec) = salt {
                    let mut salt_array = [0u8; 256];
                    salt_array[..salt_vec.len()].copy_from_slice(&salt_vec);
                    Some(
                        MborByteArray::new(salt_array, salt_vec.len())
                            .expect("failed to create byte array"),
                    )
                } else {
                    None
                }
            };
            let info = {
                if let Some(info_vec) = info {
                    let mut info_array = [0u8; 256];
                    info_array[..info_vec.len()].copy_from_slice(&info_vec);
                    Some(
                        MborByteArray::new(info_array, info_vec.len())
                            .expect("failed to create byte array"),
                    )
                } else {
                    None
                }
            };

            // Derive from first secret key
            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;
            let derived_key_id1 = data.key_id;

            // Unmask this key
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                data.masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let unmasked_derived_key_id1 = resp.unwrap().data.key_id;
            assert_ne!(unmasked_derived_key_id1, derived_key_id1);

            // Derive from second secret key
            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id2,
                hash_algorithm,
                salt,
                info,
                key_type,
                None,
                key_properties,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let derived_key_id2 = resp.unwrap().data.key_id;

            // Encrypt message with secret key 1
            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unmasked_derived_key_id1, // use unmasked key instead of original key
                DdiAesOp::Encrypt,
                MborByteArray::new(msg, msg_len).expect("failed to create byte array"),
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
        },
    );
}

// Unmask the key returned in DdiEcdhKeyExchangeResp
#[test]
fn test_secret_hkdf_and_unmask_ecdh_key() {
    ddi_dev_test(common_setup, common_cleanup, |dev, _ddi, _path, sess_id| {
        // Run this test only for Mock device
        if get_device_kind(dev) != DdiDeviceKind::Virtual {
            println!("Unmask key Not supported for Physical Device.");
            return;
        }

        let hash_algorithm = DdiHashAlgorithm::Sha256;
        let salt = Some("salt".as_bytes().to_vec());
        let info = Some("label".as_bytes().to_vec());
        let key_type = DdiKeyType::Aes256;
        let key_tag = None;
        let key_properties =
            helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

        // ECDH two secrets
        let (secret_key_id1, secret_key_id2) = {
            let secret_key_type = DdiKeyType::Secret256;

            // Check secret key type. If it's not a secret key, we will use DdiKeyType::Secret256.
            let (secret_key_type, curve) = match secret_key_type {
                DdiKeyType::Secret256 => (DdiKeyType::Secret256, DdiEccCurve::P256),
                DdiKeyType::Secret384 => (DdiKeyType::Secret384, DdiEccCurve::P384),
                DdiKeyType::Secret521 => (DdiKeyType::Secret521, DdiEccCurve::P521),
                _ => (DdiKeyType::Secret256, DdiEccCurve::P256),
            };

            // Generate ECC Key Pair 1

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                curve,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            let private_key_id1 = resp.data.private_key_id;

            let pub_key1 = resp.data.pub_key.unwrap();
            let mut der1 = [0u8; 192];
            der1[..pub_key1.der.len()].clone_from_slice(&pub_key1.der.data()[..pub_key1.der.len()]);

            // Generate ECC Key Pair 2

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                curve,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let private_key_id2 = resp.data.private_key_id;

            let pub_key2 = resp.data.pub_key.unwrap();
            let mut der2 = [0u8; 192];
            der2[..pub_key2.der.len()].clone_from_slice(&pub_key2.der.data()[..pub_key2.der.len()]);

            // Perform Ecdh exchange for each pair
            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id1,
                MborByteArray::new(der2, pub_key2.der.len()).expect("failed to create byte array"),
                None,
                secret_key_type,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;
            let secret_key_id1 = data.key_id;
            let masked_key = data.masked_key;

            // Unmask this secret key
            let resp = helper_unmask_key(
                dev,
                Some(sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let unmasked_secret_key_id1 = resp.unwrap().data.key_id;
            assert_ne!(unmasked_secret_key_id1, secret_key_id1);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id2,
                MborByteArray::new(der1, pub_key1.der.len()).expect("failed to create byte array"),
                None,
                secret_key_type,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let secret_key_id2 = resp.unwrap().data.key_id;

            (unmasked_secret_key_id1, secret_key_id2)
        };

        let salt = {
            if let Some(salt_vec) = salt {
                let mut salt_array = [0u8; 256];
                salt_array[..salt_vec.len()].copy_from_slice(&salt_vec);
                Some(
                    MborByteArray::new(salt_array, salt_vec.len())
                        .expect("failed to create byte array"),
                )
            } else {
                None
            }
        };
        let info = {
            if let Some(info_vec) = info {
                let mut info_array = [0u8; 256];
                info_array[..info_vec.len()].copy_from_slice(&info_vec);
                Some(
                    MborByteArray::new(info_array, info_vec.len())
                        .expect("failed to create byte array"),
                )
            } else {
                None
            }
        };

        // Derive from first secret key
        let resp = helper_hkdf_derive(
            dev,
            Some(sess_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            secret_key_id1,
            hash_algorithm,
            salt,
            info,
            key_type,
            key_tag,
            key_properties,
        );

        assert!(resp.is_ok(), "resp {:?}", resp);
        let derived_key_id1 = resp.unwrap().data.key_id;

        // Derive from second secret key

        let resp = helper_hkdf_derive(
            dev,
            Some(sess_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            secret_key_id2,
            hash_algorithm,
            salt,
            info,
            key_type,
            None,
            key_properties,
        );

        assert!(resp.is_ok(), "resp {:?}", resp);
        let derived_key_id2 = resp.unwrap().data.key_id;

        // Encrypt message with secret key 1
        let raw_msg = [1u8; 512];
        let msg_len = raw_msg.len();
        let mut msg = [0u8; 1024];
        msg[..msg_len].clone_from_slice(&raw_msg);

        let resp = helper_aes_encrypt_decrypt(
            dev,
            Some(sess_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            derived_key_id1,
            DdiAesOp::Encrypt,
            MborByteArray::new(msg, msg_len).expect("failed to create byte array"),
            MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
        );

        assert!(resp.is_ok(), "resp {:?}", resp);
        let resp = resp.unwrap();

        // Decrypt with key 2 and confirm message is same

        let resp = helper_aes_encrypt_decrypt(
            dev,
            Some(sess_id),
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
    });
}
