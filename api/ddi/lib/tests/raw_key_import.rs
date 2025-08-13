// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use crypto::rand::rand_bytes;
use mcr_ddi::DdiError;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

// Shared constants
const SECRET_256_SIZE: usize = 32;
const SECRET_384_SIZE: usize = 48;
const SECRET_521_SIZE: usize = 68;
const RSA_2K_KEY_SIZE: usize = 516;
const RSA_3K_KEY_SIZE: usize = 772;
const RSA_4K_KEY_SIZE: usize = 1028;
const RAW_KEY_BUFFER_SIZE: usize = 3072;
const HMAC_SHA256_SIZE: usize = 32;
const HMAC_SHA384_SIZE: usize = 48;
const HMAC_SHA512_SIZE: usize = 64;

// Key tag
const KEY_TAG: u16 = 0x5453;
const KEY_TAG_1: u16 = 0x5454;

fn verify_physical_device_and_hooks(dev: &mut <DdiTest as Ddi>::Dev) -> bool {
    if get_device_kind(dev) != DdiDeviceKind::Physical {
        println!("Physical device NOT found. Test only supported on physical device.");
        return false;
    }

    true
}

fn create_get_priv_key_request(session_id: Option<u16>, key_id: u16) -> DdiGetPrivKeyCmdReq {
    DdiGetPrivKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetPrivKey,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetPrivKeyReq { key_id },
        ext: None,
    }
}

pub fn retrieve_shared_raw_key<const N: usize>(
    dev: &mut <DdiTest as Ddi>::Dev,
    sess_id: u16,
    secret_key_id: u16,
) -> Result<[u8; N], DdiError> {
    // Changed return type to use DdiError
    let req = create_get_priv_key_request(Some(sess_id), secret_key_id);
    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie)?;

    // Extract the response and raw secret
    let raw_secret_len = resp.data.key_data.len();

    if raw_secret_len != N {
        return Err(DdiError::InvalidParameter);
    }

    // Convert slice to fixed-size array
    let mut result = [0u8; N];
    result.copy_from_slice(&resp.data.key_data.data()[..raw_secret_len]);

    Ok(result)
}

fn create_raw_key_import_request(
    session_id: Option<u16>,
    raw: [u8; 3072],
    key_length: usize,
    key_kind: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> DdiRawKeyImportCmdReq {
    DdiRawKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RawKeyImport,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiRawKeyImportReq {
            raw: MborByteArray::new(raw, key_length).expect("failed to create byte array"),
            key_kind,
            key_tag,
            key_properties,
        },
        ext: None,
    }
}

#[test]
fn test_raw_key_import_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create Secret256 key
            let mut secret_buf = [0u8; SECRET_256_SIZE];
            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(5),
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret256,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            // Validate error for invalid session.
            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "Expected FileHandleSessionIdDoesNotMatch error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_raw_key_import_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create Secret256 key
            let mut secret_buf = [0u8; SECRET_256_SIZE];
            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                None,
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret256,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            // Validate error for no session.
            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "Expected FileHandleSessionIdDoesNotMatch error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_availability() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create Secret521 key
            let mut secret_buf = [0u8; SECRET_521_SIZE];
            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::Session);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret521,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Validate error for invalid key availability.
            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::InvalidArg)
                ),
                "Expected InvalidArg error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create RSA 2k private key
            let mut rsa_2k_key = [0u8; RSA_2K_KEY_SIZE];
            rand_bytes(&mut rsa_2k_key).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..rsa_2k_key.len()].copy_from_slice(&rsa_2k_key);

            let key_properties =
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                rsa_2k_key.len(),
                DdiKeyType::Rsa2kPrivate,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Validate error for invalid key usage.
            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::InvalidPermissions)
                ),
                "Expected InvalidPermissions error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_type_aes_bulk_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create AES 256 bulk key
            let mut aes_bulk_key = [0u8; 32];
            rand_bytes(&mut aes_bulk_key).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..aes_bulk_key.len()].copy_from_slice(&aes_bulk_key);

            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                aes_bulk_key.len(),
                DdiKeyType::AesBulk256,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Validate error for invalid key type.
            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::InvalidKeyType)
                ),
                "Expected InvalidKeyType error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_type_rsa3kprivate() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create RSA 3k private key
            let mut rsa_3k_priv_key = [0u8; RSA_3K_KEY_SIZE];
            rand_bytes(&mut rsa_3k_priv_key).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..rsa_3k_priv_key.len()].copy_from_slice(&rsa_3k_priv_key);

            let key_properties =
                helper_key_properties(DdiKeyUsage::WrapUnwrap, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                rsa_3k_priv_key.len(),
                DdiKeyType::Rsa3kPrivate,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Validate error for invalid key type.
            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::InvalidKeyType)
                ),
                "Expected InvalidKeyType error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_type_rsa4kprivate() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create RSA 4k private key
            let mut rsa_4k_priv_key = [0u8; RSA_4K_KEY_SIZE];
            rand_bytes(&mut rsa_4k_priv_key).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..rsa_4k_priv_key.len()].copy_from_slice(&rsa_4k_priv_key);

            let key_properties =
                helper_key_properties(DdiKeyUsage::WrapUnwrap, DdiKeyAvailability::Session);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                rsa_4k_priv_key.len(),
                DdiKeyType::Rsa4kPrivate,
                None,
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Validate error for invalid key type.
            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::InvalidKeyType)
                ),
                "Expected InvalidKeyType error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_raw_key_import_secret256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create Secret256 key
            let mut secret_buf = [0u8; SECRET_256_SIZE];
            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret256,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let resp = resp.data;
            assert_ne!(resp.key_id, 0);

            let stored_key =
                retrieve_shared_raw_key::<SECRET_256_SIZE>(dev, session_id, resp.key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&secret_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_raw_key_import_secret384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create Secret384 key
            let mut secret_buf = [0u8; SECRET_384_SIZE];
            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret384,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let resp = resp.data;
            assert_ne!(resp.key_id, 0);

            // Verify Secret384 key by read back from device
            let stored_key =
                retrieve_shared_raw_key::<SECRET_384_SIZE>(dev, session_id, resp.key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&secret_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_raw_key_import_secret521() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create Secret521 key
            let mut secret_buf = [0u8; SECRET_521_SIZE];
            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret521,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let resp = resp.data;
            assert_ne!(resp.key_id, 0);

            // Verify Secret521 key by read back from device
            let stored_key =
                retrieve_shared_raw_key::<SECRET_521_SIZE>(dev, session_id, resp.key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&secret_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

// Individual test functions
#[test]
fn test_raw_key_import_multiple_keys_and_validate() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Import the first Secret256 key
            let mut secret_buf_1 = [0u8; SECRET_256_SIZE];
            rand_bytes(&mut secret_buf_1).expect("Failed to generate random bytes");

            let mut raw_key_1 = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key_1[..secret_buf_1.len()].copy_from_slice(&secret_buf_1);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key_1,
                secret_buf_1.len(),
                DdiKeyType::Secret256,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp_1 = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp_1 {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp_1 = resp_1.unwrap();
            let resp_1 = resp_1.data;
            assert_ne!(resp_1.key_id, 0);

            // Import the second Secret256 key
            let mut secret_buf_2 = [0u8; SECRET_256_SIZE];
            rand_bytes(&mut secret_buf_2).expect("Failed to generate random bytes");

            let mut raw_key_2 = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key_2[..secret_buf_2.len()].copy_from_slice(&secret_buf_2);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key_2,
                secret_buf_2.len(),
                DdiKeyType::Secret256,
                Some(KEY_TAG_1),
                key_properties,
            );
            let mut cookie = None;

            let resp_2 = dev.exec_op(&req, &mut cookie);

            let resp_2 = resp_2.unwrap();
            let resp_2 = resp_2.data;
            assert_ne!(resp_2.key_id, 0);

            // Validate the first imported Secret256 key
            let stored_key_1 =
                retrieve_shared_raw_key::<SECRET_256_SIZE>(dev, session_id, resp_1.key_id);
            match stored_key_1 {
                Ok(key_data) => {
                    assert_eq!(&secret_buf_1[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }

            // Validate the second imported Secret256 key
            let stored_key_2 =
                retrieve_shared_raw_key::<SECRET_256_SIZE>(dev, session_id, resp_2.key_id);
            match stored_key_2 {
                Ok(key_data) => {
                    assert_eq!(&secret_buf_2[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_raw_key_import_unwrapping_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Actual RSA 2K private key in Raw format
            const TEST_RSA_2K_PRIVATE_KEY_RAW: [u8; RSA_2K_KEY_SIZE] = [
                0x1D, 0xD7, 0x59, 0xF9, 0x8D, 0x2B, 0xF0, 0x71, 0x6D, 0xAB, 0x91, 0xF4, 0xDB, 0xD9,
                0x70, 0x89, 0x5D, 0x73, 0x58, 0x16, 0x1F, 0xA4, 0x31, 0xAD, 0x3D, 0x0E, 0xBE, 0xE1,
                0x64, 0x9D, 0x68, 0xAE, 0x46, 0x32, 0xE9, 0xF2, 0xC1, 0x8D, 0x00, 0xFA, 0x29, 0x3F,
                0x4C, 0x8F, 0x79, 0x73, 0xC8, 0xFF, 0x4F, 0x16, 0xED, 0x4A, 0x6D, 0x1E, 0x15, 0x4F,
                0xF0, 0x63, 0x59, 0x2B, 0xDC, 0xF4, 0x37, 0x97, 0xFD, 0xA2, 0x8C, 0x6B, 0xD0, 0x13,
                0xCC, 0xFE, 0x68, 0x69, 0xED, 0x16, 0xCA, 0xD1, 0x50, 0xBE, 0xC7, 0x42, 0x2B, 0xB4,
                0xFA, 0xC1, 0x24, 0xE4, 0xCB, 0x99, 0x41, 0x06, 0x99, 0x44, 0x2B, 0x9F, 0x35, 0x00,
                0xB4, 0x8D, 0xF4, 0x8A, 0xB0, 0x8A, 0xA9, 0xAA, 0xF4, 0x59, 0x48, 0x11, 0xCB, 0xCD,
                0x2D, 0xDA, 0x8D, 0xA8, 0x1D, 0x70, 0x98, 0x6B, 0x13, 0x05, 0xD3, 0x93, 0xA5, 0x6E,
                0x11, 0xF5, 0xDF, 0xC0, 0x3A, 0x84, 0xA0, 0x9E, 0x1B, 0xFF, 0x8A, 0x28, 0xC2, 0x4B,
                0x2B, 0xEB, 0x6B, 0xE8, 0x5F, 0xB2, 0x39, 0x89, 0xE8, 0x90, 0xAD, 0xB5, 0x0E, 0x9E,
                0xF9, 0x4B, 0xC8, 0x03, 0xFE, 0x5F, 0xC8, 0xCC, 0x11, 0x1F, 0x69, 0xFE, 0x66, 0x55,
                0x14, 0x74, 0xBE, 0xDC, 0x28, 0xAD, 0x47, 0x4A, 0x1F, 0xAC, 0x76, 0x0C, 0xDD, 0xA7,
                0x30, 0x1F, 0x53, 0x17, 0x35, 0xC8, 0xC8, 0x3E, 0xA0, 0x5D, 0x3B, 0xC5, 0x7C, 0xF5,
                0x3A, 0x97, 0xF2, 0xDA, 0x99, 0xC8, 0xDB, 0x25, 0xA9, 0xC4, 0xBF, 0x1F, 0xB7, 0x37,
                0x41, 0xBD, 0x2D, 0x3B, 0x87, 0x28, 0x79, 0xD0, 0x5E, 0x1D, 0xD0, 0xCC, 0x2D, 0x42,
                0x49, 0x2A, 0x90, 0xC9, 0xE8, 0x5B, 0x1F, 0xA4, 0x8B, 0xEF, 0x13, 0x4F, 0x79, 0xA1,
                0xB0, 0xCF, 0x92, 0x09, 0xB2, 0x91, 0xA6, 0x14, 0x1F, 0x87, 0x1E, 0xAF, 0x5D, 0x2C,
                0x66, 0x8B, 0x7B, 0x00, 0xC9, 0xFC, 0xDB, 0x8B, 0x25, 0x61, 0x26, 0x8F, 0x96, 0x55,
                0xDA, 0x98, 0x11, 0xFB, 0x5A, 0x5F, 0x83, 0x3F, 0x01, 0xFD, 0x1D, 0x25, 0x1D, 0x8A,
                0x2A, 0x58, 0xF4, 0x6D, 0x7A, 0x15, 0x67, 0x42, 0x20, 0x02, 0x2F, 0xAD, 0x12, 0x23,
                0x60, 0x70, 0x80, 0x3D, 0x31, 0x71, 0xBF, 0x02, 0xA2, 0xF4, 0x02, 0xE4, 0xC5, 0x30,
                0x76, 0xC6, 0xCC, 0x99, 0x6B, 0x4B, 0xA1, 0xF6, 0x02, 0xCF, 0xDF, 0xB0, 0xFF, 0xF2,
                0x02, 0xBD, 0xDC, 0x47, 0xFE, 0x6B, 0x23, 0x07, 0xF8, 0x8B, 0x4A, 0x0C, 0x6F, 0x5C,
                0x35, 0xC8, 0x71, 0xCE, 0x4D, 0xE0, 0x7B, 0xD8, 0xF1, 0x6D, 0x1E, 0x0F, 0xEB, 0x36,
                0x86, 0xC5, 0x65, 0x01, 0x6D, 0x21, 0xD8, 0xE2, 0x2E, 0x42, 0x3C, 0x68, 0x29, 0x46,
                0x60, 0x70, 0x7E, 0x7E, 0xA6, 0x8D, 0x64, 0x52, 0xCC, 0x38, 0xCF, 0x62, 0xC6, 0x35,
                0x0E, 0x38, 0x36, 0x0A, 0x68, 0x67, 0x6D, 0xDD, 0x14, 0x69, 0x41, 0x79, 0x29, 0x31,
                0xA7, 0x94, 0xB7, 0x43, 0xA5, 0x31, 0x64, 0x9E, 0xB3, 0xB5, 0x7A, 0xF5, 0x17, 0xDB,
                0xD2, 0x45, 0x1A, 0x90, 0xBC, 0xE8, 0xFB, 0x3D, 0xA9, 0xB1, 0x43, 0x0B, 0xCC, 0x64,
                0xAF, 0xD8, 0x1C, 0xDC, 0x68, 0xF0, 0xA9, 0x7F, 0x14, 0xCC, 0x5A, 0x3D, 0x90, 0x3E,
                0xFF, 0x8E, 0xD0, 0xCE, 0x71, 0x12, 0x29, 0xE0, 0x08, 0x50, 0xBE, 0xAC, 0x73, 0x0B,
                0x80, 0x5E, 0xC9, 0x41, 0xDF, 0xAB, 0x56, 0x28, 0x67, 0x6D, 0x69, 0x46, 0xBF, 0x61,
                0x12, 0x23, 0x8F, 0xBF, 0x96, 0x9B, 0x89, 0x3B, 0x39, 0x09, 0x8A, 0x68, 0xAC, 0x96,
                0x31, 0x29, 0xFE, 0x6F, 0x69, 0xB8, 0x59, 0xA8, 0x1E, 0xE6, 0xC6, 0x85, 0x81, 0x6E,
                0x35, 0x94, 0xA4, 0x47, 0x68, 0x88, 0x22, 0x97, 0x9E, 0x09, 0xF2, 0xC1, 0x2A, 0xC9,
                0x56, 0x84, 0x3F, 0x62, 0xE2, 0x77, 0x60, 0xE1, 0x01, 0x00, 0x01, 0x00,
            ];

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..TEST_RSA_2K_PRIVATE_KEY_RAW.len()]
                .copy_from_slice(&TEST_RSA_2K_PRIVATE_KEY_RAW);

            let key_properties =
                helper_key_properties(DdiKeyUsage::WrapUnwrap, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                TEST_RSA_2K_PRIVATE_KEY_RAW.len(),
                DdiKeyType::Rsa2kPrivate,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let resp = resp.data;
            assert_ne!(resp.key_id, 0);
        },
    );
}

#[test]
fn test_raw_key_import_rsa2k_decrypt_unsupported_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Actual RSA 2K private key in Raw format
            const TEST_RSA_2K_PRIVATE_KEY_RAW: [u8; RSA_2K_KEY_SIZE] = [
                0x1D, 0xD7, 0x59, 0xF9, 0x8D, 0x2B, 0xF0, 0x71, 0x6D, 0xAB, 0x91, 0xF4, 0xDB, 0xD9,
                0x70, 0x89, 0x5D, 0x73, 0x58, 0x16, 0x1F, 0xA4, 0x31, 0xAD, 0x3D, 0x0E, 0xBE, 0xE1,
                0x64, 0x9D, 0x68, 0xAE, 0x46, 0x32, 0xE9, 0xF2, 0xC1, 0x8D, 0x00, 0xFA, 0x29, 0x3F,
                0x4C, 0x8F, 0x79, 0x73, 0xC8, 0xFF, 0x4F, 0x16, 0xED, 0x4A, 0x6D, 0x1E, 0x15, 0x4F,
                0xF0, 0x63, 0x59, 0x2B, 0xDC, 0xF4, 0x37, 0x97, 0xFD, 0xA2, 0x8C, 0x6B, 0xD0, 0x13,
                0xCC, 0xFE, 0x68, 0x69, 0xED, 0x16, 0xCA, 0xD1, 0x50, 0xBE, 0xC7, 0x42, 0x2B, 0xB4,
                0xFA, 0xC1, 0x24, 0xE4, 0xCB, 0x99, 0x41, 0x06, 0x99, 0x44, 0x2B, 0x9F, 0x35, 0x00,
                0xB4, 0x8D, 0xF4, 0x8A, 0xB0, 0x8A, 0xA9, 0xAA, 0xF4, 0x59, 0x48, 0x11, 0xCB, 0xCD,
                0x2D, 0xDA, 0x8D, 0xA8, 0x1D, 0x70, 0x98, 0x6B, 0x13, 0x05, 0xD3, 0x93, 0xA5, 0x6E,
                0x11, 0xF5, 0xDF, 0xC0, 0x3A, 0x84, 0xA0, 0x9E, 0x1B, 0xFF, 0x8A, 0x28, 0xC2, 0x4B,
                0x2B, 0xEB, 0x6B, 0xE8, 0x5F, 0xB2, 0x39, 0x89, 0xE8, 0x90, 0xAD, 0xB5, 0x0E, 0x9E,
                0xF9, 0x4B, 0xC8, 0x03, 0xFE, 0x5F, 0xC8, 0xCC, 0x11, 0x1F, 0x69, 0xFE, 0x66, 0x55,
                0x14, 0x74, 0xBE, 0xDC, 0x28, 0xAD, 0x47, 0x4A, 0x1F, 0xAC, 0x76, 0x0C, 0xDD, 0xA7,
                0x30, 0x1F, 0x53, 0x17, 0x35, 0xC8, 0xC8, 0x3E, 0xA0, 0x5D, 0x3B, 0xC5, 0x7C, 0xF5,
                0x3A, 0x97, 0xF2, 0xDA, 0x99, 0xC8, 0xDB, 0x25, 0xA9, 0xC4, 0xBF, 0x1F, 0xB7, 0x37,
                0x41, 0xBD, 0x2D, 0x3B, 0x87, 0x28, 0x79, 0xD0, 0x5E, 0x1D, 0xD0, 0xCC, 0x2D, 0x42,
                0x49, 0x2A, 0x90, 0xC9, 0xE8, 0x5B, 0x1F, 0xA4, 0x8B, 0xEF, 0x13, 0x4F, 0x79, 0xA1,
                0xB0, 0xCF, 0x92, 0x09, 0xB2, 0x91, 0xA6, 0x14, 0x1F, 0x87, 0x1E, 0xAF, 0x5D, 0x2C,
                0x66, 0x8B, 0x7B, 0x00, 0xC9, 0xFC, 0xDB, 0x8B, 0x25, 0x61, 0x26, 0x8F, 0x96, 0x55,
                0xDA, 0x98, 0x11, 0xFB, 0x5A, 0x5F, 0x83, 0x3F, 0x01, 0xFD, 0x1D, 0x25, 0x1D, 0x8A,
                0x2A, 0x58, 0xF4, 0x6D, 0x7A, 0x15, 0x67, 0x42, 0x20, 0x02, 0x2F, 0xAD, 0x12, 0x23,
                0x60, 0x70, 0x80, 0x3D, 0x31, 0x71, 0xBF, 0x02, 0xA2, 0xF4, 0x02, 0xE4, 0xC5, 0x30,
                0x76, 0xC6, 0xCC, 0x99, 0x6B, 0x4B, 0xA1, 0xF6, 0x02, 0xCF, 0xDF, 0xB0, 0xFF, 0xF2,
                0x02, 0xBD, 0xDC, 0x47, 0xFE, 0x6B, 0x23, 0x07, 0xF8, 0x8B, 0x4A, 0x0C, 0x6F, 0x5C,
                0x35, 0xC8, 0x71, 0xCE, 0x4D, 0xE0, 0x7B, 0xD8, 0xF1, 0x6D, 0x1E, 0x0F, 0xEB, 0x36,
                0x86, 0xC5, 0x65, 0x01, 0x6D, 0x21, 0xD8, 0xE2, 0x2E, 0x42, 0x3C, 0x68, 0x29, 0x46,
                0x60, 0x70, 0x7E, 0x7E, 0xA6, 0x8D, 0x64, 0x52, 0xCC, 0x38, 0xCF, 0x62, 0xC6, 0x35,
                0x0E, 0x38, 0x36, 0x0A, 0x68, 0x67, 0x6D, 0xDD, 0x14, 0x69, 0x41, 0x79, 0x29, 0x31,
                0xA7, 0x94, 0xB7, 0x43, 0xA5, 0x31, 0x64, 0x9E, 0xB3, 0xB5, 0x7A, 0xF5, 0x17, 0xDB,
                0xD2, 0x45, 0x1A, 0x90, 0xBC, 0xE8, 0xFB, 0x3D, 0xA9, 0xB1, 0x43, 0x0B, 0xCC, 0x64,
                0xAF, 0xD8, 0x1C, 0xDC, 0x68, 0xF0, 0xA9, 0x7F, 0x14, 0xCC, 0x5A, 0x3D, 0x90, 0x3E,
                0xFF, 0x8E, 0xD0, 0xCE, 0x71, 0x12, 0x29, 0xE0, 0x08, 0x50, 0xBE, 0xAC, 0x73, 0x0B,
                0x80, 0x5E, 0xC9, 0x41, 0xDF, 0xAB, 0x56, 0x28, 0x67, 0x6D, 0x69, 0x46, 0xBF, 0x61,
                0x12, 0x23, 0x8F, 0xBF, 0x96, 0x9B, 0x89, 0x3B, 0x39, 0x09, 0x8A, 0x68, 0xAC, 0x96,
                0x31, 0x29, 0xFE, 0x6F, 0x69, 0xB8, 0x59, 0xA8, 0x1E, 0xE6, 0xC6, 0x85, 0x81, 0x6E,
                0x35, 0x94, 0xA4, 0x47, 0x68, 0x88, 0x22, 0x97, 0x9E, 0x09, 0xF2, 0xC1, 0x2A, 0xC9,
                0x56, 0x84, 0x3F, 0x62, 0xE2, 0x77, 0x60, 0xE1, 0x01, 0x00, 0x01, 0x00,
            ];

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..TEST_RSA_2K_PRIVATE_KEY_RAW.len()]
                .copy_from_slice(&TEST_RSA_2K_PRIVATE_KEY_RAW);

            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                TEST_RSA_2K_PRIVATE_KEY_RAW.len(),
                DdiKeyType::Rsa2kPrivate,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            match dev.exec_op(&req, &mut cookie) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidPermissions)) => (),
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with fips_validation_hooks.");
                }
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_raw_key_import_aes256_unsupported_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Actual RSA 2K private key in Raw format
            const TEST_AES256_RAW_KEY: [u8; 32] = [
                0x1D, 0xD7, 0x59, 0xF9, 0x8D, 0x2B, 0xF0, 0x71, 0x6D, 0xAB, 0x91, 0xF4, 0xDB, 0xD9,
                0x70, 0x89, 0x5D, 0x73, 0x58, 0x16, 0x1F, 0xA4, 0x31, 0xAD, 0x3D, 0x0E, 0xBE, 0xE1,
                0x64, 0x9D, 0x68, 0xAE,
            ];

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..TEST_AES256_RAW_KEY.len()].copy_from_slice(&TEST_AES256_RAW_KEY);

            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                TEST_AES256_RAW_KEY.len(),
                DdiKeyType::Aes256,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            match dev.exec_op(&req, &mut cookie) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with fips_validation_hooks.");
                }
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_raw_key_import_hmacsha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create HmacSha256 key
            let mut key_buf = [0u8; HMAC_SHA256_SIZE];
            rand_bytes(&mut key_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..key_buf.len()].copy_from_slice(&key_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                key_buf.len(),
                DdiKeyType::HmacSha256,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let resp = resp.data;
            assert_ne!(resp.key_id, 0);

            // Verify HmacSha256 key by read back from device
            let stored_key =
                retrieve_shared_raw_key::<HMAC_SHA256_SIZE>(dev, session_id, resp.key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&key_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_raw_key_import_hmacsha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create HmacSha384 key
            let mut key_buf = [0u8; HMAC_SHA384_SIZE];
            rand_bytes(&mut key_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..key_buf.len()].copy_from_slice(&key_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                key_buf.len(),
                DdiKeyType::HmacSha384,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let resp = resp.data;
            assert_ne!(resp.key_id, 0);

            // Verify HmacSha384 key by read back from device
            let stored_key =
                retrieve_shared_raw_key::<HMAC_SHA384_SIZE>(dev, session_id, resp.key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&key_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_raw_key_import_hmacsha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            // Create HmacSha512 key
            let mut key_buf = [0u8; HMAC_SHA512_SIZE];
            rand_bytes(&mut key_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..key_buf.len()].copy_from_slice(&key_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let req = create_raw_key_import_request(
                Some(session_id),
                raw_key,
                key_buf.len(),
                DdiKeyType::HmacSha512,
                Some(KEY_TAG),
                key_properties,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let resp = resp.data;
            assert_ne!(resp.key_id, 0);

            // Verify HmacSha512 key by read back from device
            let stored_key =
                retrieve_shared_raw_key::<HMAC_SHA512_SIZE>(dev, session_id, resp.key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&key_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}
