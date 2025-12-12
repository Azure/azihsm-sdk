// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_hmac_invalid_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
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
            let ecc_key_id = resp.data.private_key_id;

            // Hmac operation
            let resp = helper_hmac(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                ecc_key_id,
                MborByteArray::from_slice(&[0u8; 64]).expect("failed to create byte array"),
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
fn test_hmac_invalid_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let invalid_key_id = 20;

            // Hmac operation
            let resp = helper_hmac(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                invalid_key_id,
                MborByteArray::from_slice(&[0u8; 64]).expect("failed to create byte array"),
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
fn test_hmac_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hmac_key_id = create_hmac_key(session_id, DdiKeyType::HmacSha256, dev);
            let invalid_session = None;

            // Hmac operation
            let resp = helper_hmac(
                dev,
                invalid_session,
                Some(DdiApiRev { major: 1, minor: 0 }),
                hmac_key_id,
                MborByteArray::from_slice(&[0u8; 64]).expect("failed to create byte array"),
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
fn test_hmac_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hmac_key_id = create_hmac_key(session_id, DdiKeyType::HmacSha256, dev);
            let invalid_session_id = 21;

            // Hmac operation
            let resp = helper_hmac(
                dev,
                Some(invalid_session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                hmac_key_id,
                MborByteArray::from_slice(&[0u8; 64]).expect("failed to create byte array"),
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
fn test_hmac_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hmac_key_id = create_hmac_key(session_id, DdiKeyType::HmacSha256, dev);

            // Hmac operation
            let resp = helper_hmac(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                hmac_key_id,
                MborByteArray::from_slice(&[0u8; 64]).expect("failed to create byte array"),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.tag.len(), 32)
        },
    );
}

#[test]
fn test_hmac_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hmac_key_id = create_hmac_key(session_id, DdiKeyType::HmacSha384, dev);

            // Hmac operation
            let resp = helper_hmac(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                hmac_key_id,
                MborByteArray::from_slice(&[0u8; 64]).expect("failed to create byte array"),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.tag.len(), 48)
        },
    );
}

#[test]
fn test_hmac_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hmac_key_id = create_hmac_key(session_id, DdiKeyType::HmacSha512, dev);

            // Hmac operation
            let resp = helper_hmac(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                hmac_key_id,
                MborByteArray::from_slice(&[0u8; 64]).expect("failed to create byte array"),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.tag.len(), 64)
        },
    );
}
