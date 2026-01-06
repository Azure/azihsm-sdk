// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

mod common;

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

// Key tag
const KEY_TAG: u16 = 0x5453;

// Test Digest
const DIGEST: [u8; 96] = [100u8; 96];

// Test Digest length
const DIGEST_LEN: usize = 20;

#[test]
fn test_open_key_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let resp = helper_open_key(dev, None, Some(DdiApiRev { major: 1, minor: 0 }), KEY_TAG);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_open_key_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let session_id = 20;

            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
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
fn test_open_key_incorrect_key_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0300,
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
fn test_open_key_no_key_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                Some(KEY_TAG),
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0000,
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
fn test_open_key_aes128() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                Some(KEY_TAG),
                key_props,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert_eq!(resp.data.key_kind, DdiKeyType::Aes128);
            assert!(resp.data.pub_key.is_none());
        },
    );
}

#[test]
fn test_open_key_aes192() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes192,
                Some(KEY_TAG),
                key_props,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert_eq!(resp.data.key_kind, DdiKeyType::Aes192);
            assert!(resp.data.pub_key.is_none());
        },
    );
}

#[test]
fn test_open_key_aes256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes256,
                Some(KEY_TAG),
                key_props,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert_eq!(resp.data.key_kind, DdiKeyType::Aes256);
            assert!(resp.data.pub_key.is_none());
        },
    );
}

#[test]
fn test_open_key_ecc256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Generate ECC key pair and store private key in vault
            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                Some(KEY_TAG),
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert!(resp.data.pub_key.is_some());
            let gen_pub_key = resp.data.pub_key.unwrap();

            // Call open key on generated private key to generate associated public key
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert_eq!(resp.data.key_kind, DdiKeyType::Ecc256Private);
            assert!(resp.data.pub_key.is_some());

            let open_pub_key = resp.data.pub_key.unwrap();
            assert_eq!(open_pub_key.der.len(), gen_pub_key.der.len());
            assert_eq!(open_pub_key.der, gen_pub_key.der);

            // Sign digest with generated ECC private key

            let resp = helper_ecc_sign(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                resp.data.key_id,
                MborByteArray::new(DIGEST, DIGEST_LEN).expect("failed to create byte array"),
                DdiHashAlgorithm::Sha256,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let mut signature = [0u8; 64];
            signature[..resp.data.signature.len() as usize].clone_from_slice(
                &resp.data.signature.data()[..resp.data.signature.len() as usize],
            );

            // Perform signature verification using the public key generated by open key
            ecc_verify_local_openssl(&signature, &open_pub_key, DIGEST, DIGEST_LEN);
        },
    );
}

#[test]
fn test_open_key_ecc384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Generate ECC key pair and store private key in vault

            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P384,
                Some(KEY_TAG),
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert!(resp.data.pub_key.is_some());
            let gen_pub_key = resp.data.pub_key.unwrap();

            // Call open key on generated private key to generate associated public key
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert_eq!(resp.data.key_kind, DdiKeyType::Ecc384Private);

            assert!(resp.data.pub_key.is_some());
            let open_pub_key = resp.data.pub_key.unwrap();
            assert_eq!(open_pub_key.der.len(), gen_pub_key.der.len());
            assert_eq!(open_pub_key.der, gen_pub_key.der);

            // Sign digest with generated ECC private key

            let resp = helper_ecc_sign(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                resp.data.key_id,
                MborByteArray::new(DIGEST, DIGEST_LEN).expect("failed to create byte array"),
                DdiHashAlgorithm::Sha384,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let mut signature = [0u8; 96];
            signature[..resp.data.signature.len() as usize].clone_from_slice(
                &resp.data.signature.data()[..resp.data.signature.len() as usize],
            );

            // Perform signature verification using the public key generated by open key
            ecc_verify_local_openssl(&signature, &open_pub_key, DIGEST, DIGEST_LEN);
        },
    );
}

#[test]
fn test_open_key_ecc521() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Generate ECC key pair and store private key in vault

            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P521,
                Some(KEY_TAG),
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert!(resp.data.pub_key.is_some());
            let gen_pub_key = resp.data.pub_key.unwrap();

            // Call open key on generated private key to generate associated public key
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert_eq!(resp.data.key_kind, DdiKeyType::Ecc521Private);

            assert!(resp.data.pub_key.is_some());
            let open_pub_key = resp.data.pub_key.unwrap();
            assert_eq!(open_pub_key.der.len(), gen_pub_key.der.len());
            assert_eq!(open_pub_key.der, gen_pub_key.der);

            // Sign digest with generated ECC private key
            let resp = helper_ecc_sign(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                resp.data.key_id,
                MborByteArray::new(DIGEST, DIGEST_LEN).expect("failed to create byte array"),
                DdiHashAlgorithm::Sha512,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let mut signature = [0u8; 132];
            signature[..resp.data.signature.len() as usize].clone_from_slice(
                &resp.data.signature.data()[..resp.data.signature.len() as usize],
            );

            // Perform signature verification using the public key generated by open key
            ecc_verify_local_openssl(&signature, &open_pub_key, DIGEST, DIGEST_LEN);
        },
    );
}

#[test]
fn test_open_deleted_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                Some(KEY_TAG),
                key_props,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                resp.data.key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::KeyNotFound)
            ));
        },
    );
}
