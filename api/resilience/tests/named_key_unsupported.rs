// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_open_key_unsupported() {
    let device_path = get_device_path_helper();

    let (dev, api_rev) = setup_device(&device_path);

    let session = dev
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session on dev1");

    let key_name = "keyname".as_bytes();
    let result = session.open_key(key_name);
    assert_eq!(result.unwrap_err(), HsmError::NamedKeysNotSupported);
}

#[test]
fn test_ecc_generate_named_key_unsupported() {
    let device_path = get_device_path_helper();

    let (dev, api_rev) = setup_device(&device_path);

    let session = dev
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session on dev1");

    let curve = EccCurve::P256;
    let key_name = "keyname".as_bytes();
    let key_usage = KeyUsage::SignVerify;

    // Generating named key fails
    let result = session.ecc_generate(
        curve,
        Some(key_name),
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::App,
        },
    );
    assert_eq!(result.unwrap_err(), HsmError::NamedKeysNotSupported);

    // Generating session key succeeds
    let result = session.ecc_generate(
        curve,
        None,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
}

#[test]
fn test_aes_generate_named_key_unsupported() {
    let device_path = get_device_path_helper();

    let (dev, api_rev) = setup_device(&device_path);

    let session = dev
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session on dev1");

    let key_size = AesKeySize::Aes256;
    let key_name = "keyname".as_bytes();
    let key_usage = KeyUsage::EncryptDecrypt;

    // Generating named key fails
    let result = session.aes_generate(
        key_size,
        Some(key_name),
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::App,
        },
    );
    assert_eq!(result.unwrap_err(), HsmError::NamedKeysNotSupported);

    // Generating session key succeeds
    let result = session.aes_generate(
        key_size,
        None,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
}

#[test]
fn test_ecdh_key_exchange_named_key_unsupported() {
    let device_path = get_device_path_helper();

    let (dev, api_rev) = setup_device(&device_path);

    let session = dev
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session on dev1");

    // Generate one P256 ECC Keys
    let result = session.ecc_generate(
        EccCurve::P256,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
    let ecdh_key1 = result.unwrap();

    // Generate another P256 ECC Key, and get the public key
    let result = session.ecc_generate(
        EccCurve::P256,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
    let ecdh_key2 = result.unwrap();

    let result = session.export_public_key(&ecdh_key2);
    assert!(result.is_ok(), "result {:?}", result);
    let pub_key = result.unwrap();

    // Perform ECDH
    let key_type = KeyType::Secret256;
    let key_name = "keyname".as_bytes();
    let key_usage = KeyUsage::Derive;

    // Generating named key fails
    let result = session.ecdh_key_exchange(
        &ecdh_key1,
        &pub_key,
        Some(key_name),
        key_type,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::App,
        },
    );
    assert_eq!(result.unwrap_err(), HsmError::NamedKeysNotSupported);

    // Generating session key succeeds
    let result = session.ecdh_key_exchange(
        &ecdh_key1,
        &pub_key,
        None,
        key_type,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
}

fn generate_secret_key(session: &HsmSession, curve_type: EccCurve) -> HsmKeyHandle {
    // Generate one P256 ECC Keys
    let result = session.ecc_generate(
        curve_type,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
    let ecdh_key1 = result.unwrap();

    // Generate another P256 ECC Key, and get the public key
    let result = session.ecc_generate(
        curve_type,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
    let ecdh_key2 = result.unwrap();

    let result = session.export_public_key(&ecdh_key2);
    assert!(result.is_ok(), "result {:?}", result);
    let pub_key = result.unwrap();

    // Perform ECDH
    let key_type = match curve_type {
        EccCurve::P256 => KeyType::Secret256,
        EccCurve::P384 => KeyType::Secret384,
        EccCurve::P521 => KeyType::Secret521,
    };
    let key_usage = KeyUsage::Derive;

    // Generating session key succeeds
    let result = session.ecdh_key_exchange(
        &ecdh_key1,
        &pub_key,
        None,
        key_type,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
    result.unwrap()
}

#[test]
fn test_hkdf_named_key_unsupported() {
    let device_path = get_device_path_helper();

    let (dev, api_rev) = setup_device(&device_path);

    let session = dev
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session on dev1");

    let secret_key = generate_secret_key(&session, EccCurve::P256);

    let key_name = "keyname".as_bytes();
    let key_usage = KeyUsage::EncryptDecrypt;
    let key_type = KeyType::Aes256;

    let params = HkdfDeriveParameters {
        hash_algorithm: DigestKind::Sha384,
        salt: Some("salt".as_bytes()),
        info: Some("info".as_bytes()),
    };

    // Generating named key fails
    let result = session.hkdf_derive(
        &secret_key,
        params,
        Some(key_name),
        key_type,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::App,
        },
    );
    assert_eq!(result.unwrap_err(), HsmError::NamedKeysNotSupported);

    // Generating session key succeeds
    let result = session.hkdf_derive(
        &secret_key,
        params,
        None,
        key_type,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
}

#[test]
fn test_kbkdf_named_key_unsupported() {
    let device_path = get_device_path_helper();

    let (dev, api_rev) = setup_device(&device_path);

    let session = dev
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session on dev1");

    let secret_key = generate_secret_key(&session, EccCurve::P256);

    let key_name = "keyname".as_bytes();
    let key_usage = KeyUsage::EncryptDecrypt;
    let key_type = KeyType::Aes256;

    let params = KbkdfDeriveParameters {
        hash_algorithm: DigestKind::Sha384,
        label: Some("label".as_bytes()),
        context: Some("context".as_bytes()),
    };

    // Generating named key fails
    let result = session.kbkdf_counter_hmac_derive(
        &secret_key,
        params,
        Some(key_name),
        key_type,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::App,
        },
    );
    assert_eq!(result.unwrap_err(), HsmError::NamedKeysNotSupported);

    // Generating session key succeeds
    let result = session.kbkdf_counter_hmac_derive(
        &secret_key,
        params,
        None,
        key_type,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
}

#[test]
fn test_unwrap_named_key_unsupported() {
    let device_path = get_device_path_helper();

    let (dev, api_rev) = setup_device(&device_path);

    let session = dev
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session on dev1");

    // Get the unwrapping key and generate wrapped data
    let unwrapping_key = session
        .get_unwrapping_key()
        .expect("Failed to get unwrapping key");
    let public_key_der = session
        .export_public_key(&unwrapping_key)
        .expect("Failed to export public key from unwrapping key");

    // Generate wrapped data (wrapped private key and its public key)
    let (wrapped_blob, _public_key_der_for_target) = generate_wrapped_data(public_key_der);

    let params = RsaUnwrapParams {
        key_class: KeyClass::Rsa,
        padding: RsaCryptoPadding::Oaep,
        hash_algorithm: DigestKind::Sha256,
    };
    let key_name = "keyname".as_bytes();
    let key_usage = KeyUsage::SignVerify;

    // Generating named key fails
    let result = session.rsa_unwrap(
        &unwrapping_key,
        wrapped_blob.clone(),
        params,
        Some(key_name),
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::Session,
        },
    );
    assert_eq!(result.unwrap_err(), HsmError::NamedKeysNotSupported);

    // Generating session key succeeds
    let result = session.rsa_unwrap(
        &unwrapping_key,
        wrapped_blob,
        params,
        None,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::App,
        },
    );
    assert!(result.is_ok(), "result {:?}", result);
}
