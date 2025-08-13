// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use rsa_padding::RsaDigestKind;
use rsa_padding::RsaEncoding;

use crate::common::*;

fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    let sess_id = common_setup(dev, ddi, path);

    if get_device_kind(dev) == DdiDeviceKind::Physical {
        println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
    }

    sess_id
}

fn import_unwrap_key(dev: &mut <DdiTest as Ddi>::Dev, sess_id: u16) -> u16 {
    let mut der = [0u8; 3072];
    der[..TEST_RSA_2K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_2K_PRIVATE_KEY);

    let req = DdiDerKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DerKeyImport,
            sess_id: Some(sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiDerKeyImportReq {
            der: MborByteArray::new(der, TEST_RSA_2K_PRIVATE_KEY.len())
                .expect("failed to create byte array"),
            key_class: DdiKeyClass::Rsa,
            key_tag: None,
            key_properties: helper_key_properties(DdiKeyUsage::WrapUnwrap, DdiKeyAvailability::App),
        },
        ext: None,
    };
    let mut cookie = None;
    let resp = dev.exec_op(&req, &mut cookie);

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();

    assert_eq!(resp.data.kind, DdiKeyType::Rsa2kPrivate);

    resp.data.key_id
}

#[test]
fn test_rsa_unwrap_no_session() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let unwrap_key_id = import_unwrap_key(dev, session_id);

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            unwrap_key_id,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            None,
            key_props,
        );

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
        ));
    });
}

#[test]
fn test_rsa_unwrap_incorrect_session_id() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let unwrap_key_id = import_unwrap_key(dev, session_id);

        let session_id = 20;
        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            unwrap_key_id,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            None,
            key_props,
        );

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
        ));
    });
}

#[test]
fn test_rsa_unwrap_incorrect_key_num_table() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            0x300,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            None,
            key_props,
        );

        assert!(resp.is_err(), "resp {:?}", resp);
    });
}

#[test]
fn test_rsa_unwrap_incorrect_key_num_entry() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            0x0020,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            None,
            key_props,
        );

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::KeyNotFound)
        ));
    });
}

#[test]
fn test_rsa_unwrap_incorrect_der_len() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let unwrap_key_id = import_unwrap_key(dev, session_id);

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            unwrap_key_id,
            MborByteArray::new(der, 2048).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            None,
            key_props,
        );

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::RsaUnwrapAesUnwrapFailed)
        ));
    });
}

#[test]
fn test_rsa_unwrap_incorrect_key_type() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let unwrap_key_id = import_unwrap_key(dev, session_id);

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            unwrap_key_id,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Ecc,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            None,
            key_props,
        );

        assert!(resp.is_err(), "resp {:?}", resp);
    });
}

#[test]
fn test_rsa_unwrap_incorrect_hash() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let unwrap_key_id = import_unwrap_key(dev, session_id);

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            unwrap_key_id,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha256,
            None,
            key_props,
        );

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::RsaUnwrapOaepDecodeFailed)
        ));
    });
}

#[test]
fn test_rsa_unwrap_tampered_data() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let unwrap_key_id = import_unwrap_key(dev, session_id);

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        // Tamper the data:
        der[1500] += 1;

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            unwrap_key_id,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            None,
            key_props,
        );

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::RsaUnwrapAesUnwrapFailed)
        ));
    });
}

#[test]
fn test_rsa_unwrap_incorrect_input_key_usage() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        // Import a private key with incorrect usage
        let mut der = [0u8; 3072];
        der[..TEST_RSA_2K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_2K_PRIVATE_KEY);

        let req = DdiDerKeyImportCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::DerKeyImport,
                sess_id: Some(session_id),
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiDerKeyImportReq {
                der: MborByteArray::new(der, TEST_RSA_2K_PRIVATE_KEY.len())
                    .expect("failed to create byte array"),
                key_class: DdiKeyClass::Rsa,
                key_tag: None,
                key_properties: helper_key_properties(
                    DdiKeyUsage::EncryptDecrypt,
                    DdiKeyAvailability::App,
                ),
            },
            ext: None,
        };
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);

        assert!(resp.is_ok(), "resp {:?}", resp);
        let resp = resp.unwrap();
        let bad_unwrap_key_id = resp.data.key_id;
        assert_eq!(resp.data.kind, DdiKeyType::Rsa2kPrivate);

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            bad_unwrap_key_id,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            None,
            key_props,
        );

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::InvalidPermissions)
        ));
    });
}

#[test]
fn test_rsa_unwrap() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let unwrap_key_id = import_unwrap_key(dev, session_id);

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            unwrap_key_id,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            None,
            key_props,
        );

        assert!(resp.is_ok(), "resp {:?}", resp);
        let resp = resp.unwrap();
        let unwrapped_key_id = resp.data.key_id;
        assert_eq!(resp.data.kind, DdiKeyType::Rsa3kPrivate);

        // Try encrypting and decrypting with UNWRAPPED_KEY_ID
        // to confirm unwrapped key is correct
        let orig_x = [0x1u8; 512];
        let data_len_to_test = 190;
        let resp = rsa_encrypt_local_openssl(
            &TEST_RSA_3K_PUBLIC_KEY,
            &orig_x,
            data_len_to_test,
            DdiRsaCryptoPadding::Oaep,
            Some(DdiHashAlgorithm::Sha256),
        );

        let mut y = [0u8; 512];
        y[..resp.len()].copy_from_slice(resp.as_slice());
        let y_len = resp.len();

        let req = DdiRsaModExpCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::RsaModExp,
                sess_id: Some(session_id),
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiRsaModExpReq {
                key_id: unwrapped_key_id,
                y: MborByteArray::new(y, y_len).expect("failed to create byte array"),
                op_type: DdiRsaOpType::Decrypt,
            },
            ext: None,
        };
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);

        assert!(resp.is_ok(), "resp {:?}", resp);

        let resp = resp.unwrap();

        let mut padded_data = [0u8; 512];
        padded_data[..resp.data.x.len()].copy_from_slice(&resp.data.x.data()[..resp.data.x.len()]);

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
    });
}

#[test]
fn test_rsa_unwrap_key_tag() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let unwrap_key_id = import_unwrap_key(dev, session_id);

        let mut der = [0u8; 3072];
        der[..TEST_RSA_3K_PRIVATE_CKM_WRAPPED.len()]
            .copy_from_slice(&TEST_RSA_3K_PRIVATE_CKM_WRAPPED);
        let key_tag = 0x6677;

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            unwrap_key_id,
            MborByteArray::new(der, 2064).expect("failed to create byte array"),
            DdiKeyClass::Rsa,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            Some(key_tag),
            key_props,
        );

        assert!(resp.is_ok(), "resp {:?}", resp);
        let resp = resp.unwrap();
        let unwrapped_key_id = resp.data.key_id;
        assert_eq!(resp.data.kind, DdiKeyType::Rsa3kPrivate);

        // Confirm we can find the unwrapped key by tag
        let resp = helper_open_key(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            key_tag,
        );
        assert!(resp.is_ok(), "resp {:?}", resp);
        let resp = resp.unwrap();

        assert_eq!(resp.data.key_id, unwrapped_key_id);
        assert_eq!(resp.data.key_kind, DdiKeyType::Rsa3kPrivate);
    });
}

#[test]
fn test_rsa_unwrap_aes_key() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, session_id| {
        if get_device_kind(dev) == DdiDeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device. Please run rsa_unwrap_generated_key instead.");
            return;
        }

        let unwrap_key_id = import_unwrap_key(dev, session_id);

        let mut blob = [0u8; 3072];
        blob[..TEST_AES_256_CKM_WRAPPED.len()].copy_from_slice(&TEST_AES_256_CKM_WRAPPED);
        let key_tag = 0x5566;

        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        let resp = helper_rsa_unwrap(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            unwrap_key_id,
            MborByteArray::new(blob, 296).expect("failed to create byte array"),
            DdiKeyClass::Aes,
            DdiRsaCryptoPadding::Oaep,
            DdiHashAlgorithm::Sha1,
            Some(key_tag),
            key_props,
        );

        assert!(resp.is_ok(), "resp {:?}", resp);
        let resp = resp.unwrap();

        let unwrapped_key_id = resp.data.key_id;
        assert!(resp.data.pub_key.is_none());
        assert_eq!(resp.data.kind, DdiKeyType::Aes256);

        // Confirm we can find the unwrapped key by tag
        let resp = helper_open_key(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            key_tag,
        );
        assert!(resp.is_ok(), "resp {:?}", resp);

        let resp = resp.unwrap();
        assert_eq!(resp.data.key_id, unwrapped_key_id);
        assert_eq!(resp.data.key_kind, DdiKeyType::Aes256);
    });
}
