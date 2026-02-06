// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

#[cfg(not(feature = "mock"))]
use azihsm_crypto::Rng;
use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

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
            let hmac_key_id =
                create_hmac_key(session_id, DdiKeyType::HmacSha256, dev, Default::default());
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
            let hmac_key_id =
                create_hmac_key(session_id, DdiKeyType::HmacSha256, dev, Default::default());
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
            let hmac_key_id =
                create_hmac_key(session_id, DdiKeyType::HmacSha256, dev, Default::default());

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
            let hmac_key_id =
                create_hmac_key(session_id, DdiKeyType::HmacSha384, dev, Default::default());

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
            let hmac_key_id =
                create_hmac_key(session_id, DdiKeyType::HmacSha512, dev, Default::default());

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

#[test]
#[cfg(not(feature = "mock"))]
fn test_var_hmac_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut bytes = [0u8; 1];
            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");
            let key_len = (bytes[0] % 33) + 32; // 32-64
            let hmac_key_id =
                create_hmac_key(session_id, DdiKeyType::VarHmac256, dev, Some(key_len));

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
#[cfg(not(feature = "mock"))]
fn test_var_hmac_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut bytes = [0u8; 1];
            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");
            let key_len = (bytes[0] % 81) + 48; // 48-128
            let hmac_key_id =
                create_hmac_key(session_id, DdiKeyType::VarHmac384, dev, Some(key_len));

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
#[cfg(not(feature = "mock"))]
fn test_var_hmac_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut bytes = [0u8; 1];
            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");
            let key_len = (bytes[0] % 65) + 64; // 64-128
            let hmac_key_id =
                create_hmac_key(session_id, DdiKeyType::VarHmac512, dev, Some(key_len));

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

#[test]
#[cfg(not(feature = "mock"))]
fn test_invalid_var_hmac_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut bytes = [0u8; 1];
            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");

            let invalid_key_len = bytes[0] % 32; // 0-31
            let res = create_hmac_key_ex(
                session_id,
                DdiKeyType::VarHmac256,
                dev,
                Some(invalid_key_len),
            );
            assert!(res.is_err());

            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");
            let invalid_key_len = (bytes[0] % 191) + 65; // 65  - 255
            let res = create_hmac_key_ex(
                session_id,
                DdiKeyType::VarHmac256,
                dev,
                Some(invalid_key_len),
            );
            assert!(res.is_err());

            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");
            let invalid_key_len = bytes[0] % 48; // 0-47
            let res = create_hmac_key_ex(
                session_id,
                DdiKeyType::VarHmac384,
                dev,
                Some(invalid_key_len),
            );
            assert!(res.is_err());

            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");
            let invalid_key_len = (bytes[0] % 127) + 129; // 129-255
            let res = create_hmac_key_ex(
                session_id,
                DdiKeyType::VarHmac384,
                dev,
                Some(invalid_key_len),
            );
            assert!(res.is_err());

            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");
            let invalid_key_len = bytes[0] % 64; // 0-63
            let res = create_hmac_key_ex(
                session_id,
                DdiKeyType::VarHmac512,
                dev,
                Some(invalid_key_len),
            );
            assert!(res.is_err());

            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");
            let invalid_key_len = (bytes[0] % 127) + 129; // 129-255
            let res = create_hmac_key_ex(
                session_id,
                DdiKeyType::VarHmac512,
                dev,
                Some(invalid_key_len),
            );
            assert!(res.is_err());
        },
    );
}
