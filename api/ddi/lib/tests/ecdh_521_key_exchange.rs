// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
mod invalid_ecc_pub_key_vectors;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;
use crate::invalid_ecc_pub_key_vectors::*;

// Max size of a ECC Public Key
const DER_MAX_SIZE: usize = 192;

// Returns: (private key id 1, public key 1, public key len 1, private key id 2, public key 2, public key len 2)
fn create_ecc_key_pairs(
    sess_id: u16,
    dev: &mut <DdiTest as Ddi>::Dev,
) -> (
    u16,
    [u8; DER_MAX_SIZE],
    usize,
    u16,
    [u8; DER_MAX_SIZE],
    usize,
) {
    // Initalize first keypair

    let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

    let resp = helper_ecc_generate_key_pair(
        dev,
        Some(sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiEccCurve::P521,
        None,
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    let priv_key_id1 = resp.data.private_key_id;
    let pub_key1 = resp.data.pub_key.unwrap();
    let mut der1 = [0u8; DER_MAX_SIZE];
    let der1_len = pub_key1.der.len();
    der1[..der1_len].clone_from_slice(&pub_key1.der.data()[..der1_len]);

    // Initialize second key pair

    let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

    let resp = helper_ecc_generate_key_pair(
        dev,
        Some(sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiEccCurve::P521,
        None,
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    let priv_key_id2 = resp.data.private_key_id;
    let pub_key2: DdiDerPublicKey = resp.data.pub_key.unwrap();
    let mut der2 = [0u8; DER_MAX_SIZE];
    let der2_len = pub_key2.der.len();
    der2[..der2_len].clone_from_slice(&pub_key2.der.data()[..der2_len]);

    (priv_key_id1, der1, der1_len, priv_key_id2, der2, der2_len)
}

#[test]
fn test_ecdh_521_key_exchange_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
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
fn test_ecdh_521_key_exchange_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            // Use incorrect session id
            let session_id = 20;
            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
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
fn test_ecdh_521_key_exchange_incorrect_private_key_num() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0020,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
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
fn test_ecdh_521_key_exchange_incorrect_public_key_size() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, _pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, 1).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
            );

            // This err can be either MborEncodeError or DdiStatus based on environment
            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_incorrect_target_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Ecc384Private,
                key_props,
            );
            // This err can be either MborEncodeError or DdiStatus based on environment
            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_incorrect_target_key_size() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret256,
                key_props,
            );

            // This err can be either MborEncodeError or DdiStatus based on environment
            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_incorrect_target_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
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
fn test_ecdh_521_key_exchange_incorrect_input_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, pub_key1, pub_key1_len, _priv_key_id2, _pub_key2, _pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            // Generate third key pair without Derive usage

            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P521,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let private_key_id3 = resp.data.private_key_id;
            let pub_key3 = resp.data.pub_key.unwrap();
            let mut der3 = [0u8; DER_MAX_SIZE];
            let der3_len = pub_key3.der.len();
            der3[..der3_len].clone_from_slice(&pub_key3.der.data()[..der3_len]);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id3,
                MborByteArray::new(pub_key1, pub_key1_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidPermissions)
            ));

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(der3, der3_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_256_mismatch_input_size() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, pub_key1, pub_key1_len, _priv_key_id2, _pub_key2, _pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            // Generate third key pair with 256 bit size

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

            let private_key_id3 = resp.data.private_key_id;
            let pub_key3 = resp.data.pub_key.unwrap();
            let mut der3 = [0u8; DER_MAX_SIZE];
            let der3_len = pub_key3.der.len();
            der3[..der3_len].clone_from_slice(&pub_key3.der.data()[..der3_len]);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id3,
                MborByteArray::new(pub_key1, pub_key1_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
            );
            // This err can be either MborEncodeError or DdiStatus based on environment
            assert!(resp.is_err(), "resp {:?}", resp);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(der3, der3_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret256,
                key_props,
            );

            // This err can be either MborEncodeError or DdiStatus based on environment
            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_384_mismatch_input_size() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, pub_key1, pub_key1_len, _priv_key_id2, _pub_key2, _pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            // Generate third key pair with 384 bit size

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P384,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let private_key_id3 = resp.data.private_key_id;
            let pub_key3 = resp.data.pub_key.unwrap();
            let mut der3 = [0u8; DER_MAX_SIZE];
            let der3_len = pub_key3.der.len();
            der3[..der3_len].clone_from_slice(&pub_key3.der.data()[..der3_len]);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id3,
                MborByteArray::new(pub_key1, pub_key1_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret384,
                key_props,
            );
            // This err can be either MborEncodeError or DdiStatus based on environment
            assert!(resp.is_err(), "resp {:?}", resp);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(der3, der3_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
            );

            // This err can be either MborEncodeError or DdiStatus based on environment
            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_invalid_public_key_y_as_prime() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, _pub_key2, _pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            // Invalid public key for P384 with y coordinate as prime
            let invalid_pub_key_der =
                MborByteArray::from_slice(&TEST_ECC_521_PUBLIC_KEY_Y_AS_PRIME)
                    .expect("failed to create byte array");

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                invalid_pub_key_der,
                None,
                DdiKeyType::Secret521,
                key_props,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::EccPublicKeyValidationFailed))
            ));
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_invalid_public_key_x_as_prime() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, _pub_key2, _pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            // Invalid public key for P384 with x coordinate as prime
            let invalid_pub_key_der =
                MborByteArray::from_slice(&TEST_ECC_521_PUBLIC_KEY_X_AS_PRIME)
                    .expect("failed to create byte array");

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                invalid_pub_key_der,
                None,
                DdiKeyType::Secret521,
                key_props,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::EccPublicKeyValidationFailed))
            ));
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_invalid_public_key_not_on_curve() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, _pub_key2, _pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            // Invalid public key for P521 point not on curve
            let invalid_pub_key_der =
                MborByteArray::from_slice(&TEST_ECC_521_PUBLIC_KEY_INVALID_POINT_IN_CURVE)
                    .expect("failed to create byte array");

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                invalid_pub_key_der,
                None,
                DdiKeyType::Secret521,
                key_props,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::EccPointValidationFailed))
            ));
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_invalid_public_key_point_at_infinity() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, _pub_key2, _pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            // Invalid public key for P521 with point at infinity
            let invalid_pub_key_der =
                MborByteArray::from_slice(&TEST_ECC_521_PUBLIC_KEY_POINT_AT_INFINITY)
                    .expect("failed to create byte array");

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                invalid_pub_key_der,
                None,
                DdiKeyType::Secret521,
                key_props,
            );

            assert!(matches!(
                resp,
                Err(DdiError::MborError(MborError::EncodeError))
            ));
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, pub_key1, pub_key1_len, priv_key_id2, pub_key2, pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id2,
                MborByteArray::new(pub_key1, pub_key1_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret521,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_ecdh_521_key_exchange_key_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, pub_key2_len) =
                create_ecc_key_pairs(session_id, dev);

            let key_tag = 0x6677;
            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                Some(key_tag),
                DdiKeyType::Secret521,
                key_props,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_tag,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.key_kind, DdiKeyType::Secret521);
            assert!(resp.data.pub_key.is_none());
        },
    );
}
