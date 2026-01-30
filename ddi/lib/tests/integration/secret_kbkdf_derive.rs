// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_secret_kbkdf_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label = None;
            let context = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_kbkdf_derive(
                dev,
                None,
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

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_secret_kbkdf_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label = None;
            let context = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_kbkdf_derive(
                dev,
                Some(20),
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

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_secret_kbkdf_invalid_input_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label = None;
            let context = None;
            let key_type = DdiKeyType::Secret256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            // Generate ECC Key

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            let private_key_id1 = resp.data.private_key_id;

            // Try deriving using ECC key instead of secret key

            let resp = helper_kbkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id1,
                hash_algorithm,
                label,
                context,
                key_type,
                key_tag,
                key_properties,
                Default::default(),
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
fn test_secret_kbkdf_invalid_output_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label = None;
            let context = None;
            let key_type = DdiKeyType::Ecc256Private;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

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

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidKeyType)
            ));
        },
    );
}

#[test]
fn test_secret_kbkdf_invalid_secret521_output_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label = None;
            let context = None;
            let key_type = DdiKeyType::Secret521;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

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

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidKeyType)
            ));
        },
    );
}

#[test]
fn test_secret_kbkdf_invalid_output_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label = None;
            let context = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

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

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidPermissions)
            ));
        },
    );
}

#[test]
fn test_secret_kbkdf_different_label_len() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let context = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let label_vec = "label".as_bytes().to_vec();
            let label = {
                let mut label_array = [0u8; 256];
                label_array[..label_vec.len()].copy_from_slice(&label_vec);
                Some(
                    MborByteArray::new(label_array, label_vec.len())
                        .expect("failed to create byte array"),
                )
            };

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

            // Derive second key with different label len
            let label2 = {
                let mut label_array = [0u8; 256];
                label_array[..label_vec.len()].copy_from_slice(&label_vec);
                Some(
                    MborByteArray::new(label_array, label_vec.len() + 1)
                        .expect("failed to create byte array"),
                )
            };

            // Derive first key
            let resp = helper_kbkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                label2,
                context,
                key_type,
                key_tag,
                key_properties,
                Default::default(),
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
                derived_key_id1,
                DdiAesOp::Encrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            // Decrypt with key 2 and confirm message is different
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

            assert_ne!(resp.data.msg.data_take(), msg);
            assert_eq!(resp.data.msg.len(), msg_len);
        },
    );
}

#[test]
fn test_secret_kbkdf_different_context_len() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret_key_id1, _secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let context_vec = "context".as_bytes().to_vec();
            let context = {
                let mut context_array = [0u8; 256];
                context_array[..context_vec.len()].copy_from_slice(&context_vec);
                Some(
                    MborByteArray::new(context_array, context_vec.len())
                        .expect("failed to create byte array"),
                )
            };

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

            // Derive second key with different context len
            let context2 = {
                let mut context_array = [0u8; 256];
                context_array[..context_vec.len()].copy_from_slice(&context_vec);
                Some(
                    MborByteArray::new(context_array, context_vec.len() + 1)
                        .expect("failed to create byte array"),
                )
            };

            // Derive first key
            let resp = helper_kbkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_key_id1,
                hash_algorithm,
                label,
                context2,
                key_type,
                key_tag,
                key_properties,
                Default::default(),
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
                derived_key_id1,
                DdiAesOp::Encrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            // Decrypt with key 2 and confirm message is different
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

            assert_ne!(resp.data.msg.data_take(), msg);
            assert_eq!(resp.data.msg.len(), msg_len);
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
) -> (u16, u16) {
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
        Default::default(),
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
        derived_key_id1,
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

    (derived_key_id1, derived_key_id2)
}

#[test]
fn test_secret_kbkdf() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
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
fn test_secret_kbkdf_sha1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha1;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
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
fn test_secret_kbkdf_no_label() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = None;
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
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
fn test_secret_kbkdf_no_context() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
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
fn test_secret_kbkdf_aes128() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes128;
            let key_tag = None;
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
fn test_secret_kbkdf_aes192() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes192;
            let key_tag = None;
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
fn test_secret_kbkdf_name() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = 0x6677;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let (derived_key_id1, _derived_key_id2) = test_secret_kbkdf_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
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
    let derived_key_id1 = resp.unwrap().data.bulk_key_id.unwrap();

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
fn test_secret_kbkdf_aes_xts_helper(
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

    // Derive both aes xts keys from first secret key
    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        None,
        None,
        key_type,
        key_tag,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_aes_xts_key_id1 = resp.unwrap().data.bulk_key_id.unwrap();

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
    let derived_aes_xts_tweak_key_id1 = resp.unwrap().data.bulk_key_id.unwrap();

    // Derive both aes xts keys from second secret key
    let resp = helper_kbkdf_derive(
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
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_aes_xts_key_id2 = resp.unwrap().data.bulk_key_id.unwrap();

    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        label,
        context,
        key_type,
        key_tag,
        key_properties,
        Default::default(),
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_aes_xts_tweak_key_id2 = resp.unwrap().data.bulk_key_id.unwrap();

    // set up requests for the xts encrypt operations
    let data = vec![1; 1024];
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
fn test_secret_kbkdf_aes_gcm_secret256() {
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
            let key_tag = None;
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
fn test_secret_kbkdf_aes_gcm_secret384() {
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
            let key_tag = None;
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
fn test_secret_kbkdf_aes_gcm_secret521() {
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
            let key_tag = None;
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

#[test]
fn test_secret_kbkdf_aes_xts_secret256() {
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
            let key_type = DdiKeyType::AesXtsBulk256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_aes_xts_helper(
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
fn test_secret_kbkdf_aes_xts_secret384() {
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
            let key_type = DdiKeyType::AesXtsBulk256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_aes_xts_helper(
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
fn test_secret_kbkdf_aes_xts_secret521() {
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
            let key_type = DdiKeyType::AesXtsBulk256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_kbkdf_aes_xts_helper(
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

// Uses KBKDF to derive aes_key and hmac_key
// from secret_key_id1 and secret_key_id2, respectively.
// Then verifies derived keys can do encrypt/decrypt loop
// with hash verification.
// Returns HMAC result.
#[allow(clippy::too_many_arguments)]
fn test_secret_kbkdf_aes_hmac_helper(
    dev: &mut <DdiTest as Ddi>::Dev,
    hash_algorithm: DdiHashAlgorithm,
    label: Option<Vec<u8>>,
    context: Option<Vec<u8>>,
    aes_key_type: DdiKeyType,
    hmac_key_type: DdiKeyType,
    session_id: u16,
) -> Vec<u8> {
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

    // Derive AES from first secret key

    let key_properties =
        helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        label,
        context,
        aes_key_type,
        None,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let aes_key_id1 = resp.unwrap().data.key_id;

    // Derive AES from second secret key
    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        label,
        context,
        aes_key_type,
        None,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let aes_key_id2 = resp.unwrap().data.key_id;

    // Derive HMAC from first secret key

    let key_properties =
        helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session);

    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        label,
        context,
        hmac_key_type,
        None,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let hmac_key_id1 = resp.unwrap().data.key_id;

    // Derive HMAC from second secret key

    let resp = helper_kbkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        label,
        context,
        hmac_key_type,
        None,
        key_properties,
        Default::default(),
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
fn test_secret_kbkdf_aes256_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let aes_key_type = DdiKeyType::Aes256;
            let hmac_key_type = DdiKeyType::HmacSha256;

            let hmac_output = test_secret_kbkdf_aes_hmac_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                aes_key_type,
                hmac_key_type,
                session_id,
            );
            assert_eq!(hmac_output.len(), 32);
        },
    );
}

#[test]
fn test_secret_kbkdf_aes256_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let aes_key_type = DdiKeyType::Aes256;
            let hmac_key_type = DdiKeyType::HmacSha384;

            let hmac_output = test_secret_kbkdf_aes_hmac_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                aes_key_type,
                hmac_key_type,
                session_id,
            );
            assert_eq!(hmac_output.len(), 48);
        },
    );
}

#[test]
fn test_secret_kbkdf_aes192_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let aes_key_type = DdiKeyType::Aes192;
            let hmac_key_type = DdiKeyType::HmacSha512;

            let hmac_output = test_secret_kbkdf_aes_hmac_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                aes_key_type,
                hmac_key_type,
                session_id,
            );
            assert_eq!(hmac_output.len(), 64);
        },
    );
}

#[test]
fn test_secret_kbkdf_aes128_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let label_vec = Some("label".as_bytes().to_vec());
            let context_vec = Some("context".as_bytes().to_vec());
            let aes_key_type = DdiKeyType::Aes128;
            let hmac_key_type = DdiKeyType::HmacSha256;

            let hmac_output = test_secret_kbkdf_aes_hmac_helper(
                dev,
                hash_algorithm,
                label_vec,
                context_vec,
                aes_key_type,
                hmac_key_type,
                session_id,
            );
            assert_eq!(hmac_output.len(), 32);
        },
    );
}

// Unmask the masked key returned in a DdiKbkdfCounterHmacDeriveResp
// And see if it can be used normally
#[test]
fn test_secret_kbkdf_and_unmask() {
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
            let label = Some("label".as_bytes().to_vec());
            let context = Some("context".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = None;
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

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

            // Unmask this key
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let unmasked_derived_key_id1 = resp.unwrap().data.key_id;
            assert_ne!(unmasked_derived_key_id1, derived_key_id1);

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
                unmasked_derived_key_id1,
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
        },
    );
}
