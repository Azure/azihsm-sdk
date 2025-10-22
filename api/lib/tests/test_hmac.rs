// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

fn create_hmac_key(session: &HsmSession, key_type: KeyType) -> HsmKeyHandle {
    // Generate two ECC keys
    let result = session.ecc_generate(
        EccCurve::P256,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
    let priv_key_handle1 = result.unwrap();

    let result = session.ecc_generate(
        EccCurve::P256,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
    let priv_key_handle2 = result.unwrap();

    // Get DER from second key handle
    let result = session.export_public_key(&priv_key_handle2);
    assert!(result.is_ok(), "result {:?}", result);
    let pub_key_der2 = result.unwrap();

    // Create secret for key pair
    let result = session.ecdh_key_exchange(
        &priv_key_handle1,
        &pub_key_der2,
        None,
        KeyType::Secret256,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
    let secret1 = result.unwrap();

    // Use HKDF to derive an HMAC key from secret
    let salt_bytes = "salt".as_bytes();
    let info_bytes = "label".as_bytes();

    let params = HkdfDeriveParameters {
        hash_algorithm: DigestKind::Sha256,
        salt: Some(salt_bytes),
        info: Some(info_bytes),
    };

    let result = session.hkdf_derive(
        &secret1,
        params,
        None,
        key_type,
        KeyProperties {
            key_usage: KeyUsage::SignVerify,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
    result.unwrap()
}

#[test]
fn test_hmac256() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha256);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();

        assert_ne!(data, hmac_tag);
        assert_eq!(hmac_tag.len(), 32)
    })
}

#[test]
fn test_hmac256_tampered() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha256);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();

        let mut tampered_data = data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(0x1);

        let result = app_session.hmac(&hmac_key, tampered_data.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let tampered_tag = result.unwrap();
        assert_eq!(hmac_tag.len(), tampered_tag.len());
        assert_ne!(hmac_tag, tampered_tag);
    })
}

#[test]
fn test_hmac256_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha256);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();
        assert_ne!(hmac_tag, data);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_eq!(hmac_tag, result.unwrap());

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_eq!(hmac_tag, result.unwrap());
    })
}

#[test]
fn test_hmac256_keysize_mismatch() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha256);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();
        assert_ne!(hmac_tag, data);

        let hmac_384_key = create_hmac_key(&app_session, KeyType::HmacSha384);

        let result = app_session.hmac(&hmac_384_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_ne!(hmac_tag[..32], result.unwrap()[..32]);

        let hmac_512_key = create_hmac_key(&app_session, KeyType::HmacSha512);

        let result = app_session.hmac(&hmac_512_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_ne!(hmac_tag[..32], result.unwrap()[..32]);
    })
}

#[test]
fn test_hmac256_msgsize_mismatch() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha256);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();

        assert_ne!(data, hmac_tag);
        assert_eq!(hmac_tag.len(), 32);

        let result = app_session.hmac(&hmac_key, data[..16].to_vec());
        assert!(result.is_ok(), "result {:?}", result);
        let new_tag = result.unwrap();

        assert_eq!(hmac_tag.len(), new_tag.len());
        assert_ne!(hmac_tag, new_tag);
    })
}

#[test]
fn test_hmac384() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha384);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();

        assert_ne!(data, hmac_tag);
        assert_eq!(hmac_tag.len(), 48)
    })
}

#[test]
fn test_hmac384_tampered() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha384);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();

        let mut tampered_data = data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(0x1);

        let result = app_session.hmac(&hmac_key, tampered_data.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let tampered_tag = result.unwrap();
        assert_eq!(hmac_tag.len(), tampered_tag.len());
        assert_ne!(hmac_tag, tampered_tag);
    })
}

#[test]
fn test_hmac384_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha384);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();
        assert_ne!(hmac_tag, data);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_eq!(hmac_tag, result.unwrap());

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_eq!(hmac_tag, result.unwrap());
    })
}

#[test]
fn test_hmac384_size_mismatch() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha384);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();
        assert_ne!(hmac_tag, data);

        let hmac_256_key = create_hmac_key(&app_session, KeyType::HmacSha256);

        let result = app_session.hmac(&hmac_256_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_ne!(hmac_tag[..32], result.unwrap()[..32]);

        let hmac_512_key = create_hmac_key(&app_session, KeyType::HmacSha512);

        let result = app_session.hmac(&hmac_512_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_ne!(hmac_tag[..32], result.unwrap()[..32]);
    })
}

#[test]
fn test_hmac384_msgsize_mismatch() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha384);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();

        assert_ne!(data, hmac_tag);
        assert_eq!(hmac_tag.len(), 48);

        let result = app_session.hmac(&hmac_key, data[..16].to_vec());
        assert!(result.is_ok(), "result {:?}", result);
        let new_tag = result.unwrap();

        assert_eq!(hmac_tag.len(), new_tag.len());
        assert_ne!(hmac_tag, new_tag);
    })
}

#[test]
fn test_hmac512() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha512);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();

        assert_ne!(data, hmac_tag);
        assert_eq!(hmac_tag.len(), 64)
    })
}

#[test]
fn test_hmac512_tampered() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha512);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();

        let mut tampered_data = data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(0x1);

        let result = app_session.hmac(&hmac_key, tampered_data.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let tampered_tag = result.unwrap();
        assert_eq!(hmac_tag.len(), tampered_tag.len());
        assert_ne!(hmac_tag, tampered_tag);
    })
}

#[test]
fn test_hmac512_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha512);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();
        assert_ne!(hmac_tag, data);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_eq!(hmac_tag, result.unwrap());

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_eq!(hmac_tag, result.unwrap());
    })
}

#[test]
fn test_hmac512_size_mismatch() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha512);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();
        assert_ne!(hmac_tag, data);

        let hmac_256_key = create_hmac_key(&app_session, KeyType::HmacSha256);

        let result = app_session.hmac(&hmac_256_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_ne!(hmac_tag[..32], result.unwrap()[..32]);

        let hmac_384_key = create_hmac_key(&app_session, KeyType::HmacSha384);

        let result = app_session.hmac(&hmac_384_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        assert_ne!(hmac_tag[..32], result.unwrap()[..32]);
    })
}

#[test]
fn test_hmac512_msgsize_mismatch() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let hmac_key = create_hmac_key(&app_session, KeyType::HmacSha512);

        let data = generate_random_vector(128);

        let result = app_session.hmac(&hmac_key, data.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let hmac_tag = result.unwrap();

        assert_ne!(data, hmac_tag);
        assert_eq!(hmac_tag.len(), 64);

        let result = app_session.hmac(&hmac_key, data[..16].to_vec());
        assert!(result.is_ok(), "result {:?}", result);
        let new_tag = result.unwrap();

        assert_eq!(hmac_tag.len(), new_tag.len());
        assert_ne!(hmac_tag, new_tag);
    })
}
