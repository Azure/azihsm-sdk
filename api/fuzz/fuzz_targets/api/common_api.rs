// Copyright (C) Microsoft Corporation. All rights reserved.

#[cfg(target_os = "linux")]
#[path = "../common.rs"]
mod common;

use mcr_api::*;
use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use uuid::Uuid;

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RSAInputKeyType {
    /// RSA 2048 Private Key
    Rsa2kPrivate,

    /// RSA 3072 Private Key
    Rsa3kPrivate,

    /// RSA 4096 Private Key
    Rsa4kPrivate,

    /// RSA 2048 Private CRT Key
    Rsa2kPrivateCrt,

    /// RSA 3072 Private CRT Key
    Rsa3kPrivateCrt,

    /// RSA 4096 Private CRT Key
    Rsa4kPrivateCrt,
}

#[allow(dead_code)]
pub fn rsa_input_key_type_to_key_type(input_key_type: RSAInputKeyType) -> KeyType {
    match input_key_type {
        RSAInputKeyType::Rsa2kPrivate => KeyType::Rsa2kPrivate,
        RSAInputKeyType::Rsa3kPrivate => KeyType::Rsa3kPrivate,
        RSAInputKeyType::Rsa4kPrivate => KeyType::Rsa4kPrivate,
        RSAInputKeyType::Rsa2kPrivateCrt => KeyType::Rsa2kPrivateCrt,
        RSAInputKeyType::Rsa3kPrivateCrt => KeyType::Rsa3kPrivateCrt,
        RSAInputKeyType::Rsa4kPrivateCrt => KeyType::Rsa4kPrivateCrt,
    }
}

#[allow(dead_code)]
pub fn api_fuzz_test(
    setup: fn(&HsmDevice, &str),
    cleanup: fn(&HsmDevice, &str),
    test: &dyn Fn(&HsmDevice, &str),
) {
    let devices = HsmDevice::get_devices();

    if devices.is_empty() {
        panic!("No devices found");
    }

    for dev_info in devices.iter() {
        let result = HsmDevice::open(&dev_info.path);
        assert!(result.is_ok(), "result: {:?}", result);
        let device = result.unwrap();
        setup(&device, &dev_info.path);
        test(&device, &dev_info.path);
        cleanup(&device, &dev_info.path);
    }
}

#[allow(dead_code)]
// 70FCF730-B876-4238-B835-8010CE8A3F76
pub(crate) const TEST_CRED_ID: [u8; 16] = [
    0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F, 0x76,
];

#[allow(dead_code)]
// DB3DC77F-C22E-4300-80D4-1B31B6F04800
pub(crate) const TEST_CRED_PIN: [u8; 16] = [
    0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48, 0x00,
];

#[allow(dead_code)]
pub(crate) const TEST_APP_CREDENTIALS: HsmAppCredentials = HsmAppCredentials {
    id: Uuid::from_bytes(TEST_CRED_ID),
    pin: TEST_CRED_PIN,
};

#[allow(dead_code)]
pub(crate) const TEST_APP_CREDENTIALS_2: HsmAppCredentials = HsmAppCredentials {
    id: Uuid::from_bytes([0x2; 16]),
    pin: [0x5; 16],
};

#[allow(dead_code)]
pub fn api_fuzz_common_setup(_device: &HsmDevice, path: &str) {
    let result = HsmDevice::open(path);
    assert!(result.is_ok(), "result: {:?}", result);
    let device = result.unwrap();

    let api_rev = device.get_api_revision_range().max;

    // Establishing credentials can only happen once, which means that after the
    // first call to this function, it will fail. Because of this, we ignore any
    // errors returned in the response.
    let _ = device.establish_credential(api_rev, TEST_APP_CREDENTIALS);
}

#[allow(dead_code)]
pub fn api_fuzz_common_cleanup(_device: &HsmDevice, path: &str) {
    let result = HsmDevice::open(path);
    assert!(result.is_ok(), "result: {:?}", result);
    let device = result.unwrap();

    let _api_rev = device.get_api_revision_range().max;
}

#[allow(dead_code)]
pub fn common_open_app_session(device: &HsmDevice) -> HsmSession {
    let result = device.open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
    assert!(result.is_ok(), "result: {:?}", result);

    result.unwrap()
}

/// This  function generates wrapped data,
/// wraps it using input wrapping_key_der using OpenSSL,
/// then returns the wrapped data, and the counterpart public key
///
/// # Arguments
/// * `wrapping_key_der` - Public key to wrap with, in DER format
///
/// # Returns
/// * `(Vec<u8>)` - The wrapped data blob,
#[allow(dead_code)]
pub(crate) fn wrap_data(wrapping_pub_key_der: Vec<u8>, data: &[u8]) -> Vec<u8> {
    let ace_binding = generate_aes(KeyType::Aes256);
    let aes_key = ace_binding.as_slice();
    let mut encrypted_aes_key = vec![0u8; 512];

    // Do RSA Encrypt of the aes_key with the wrapping public key
    let wrapping_pub_key = openssl::rsa::Rsa::public_key_from_der(&wrapping_pub_key_der).unwrap();
    let encrypted_aes_key_len = wrapping_pub_key
        .public_encrypt(
            aes_key,
            &mut encrypted_aes_key,
            openssl::rsa::Padding::PKCS1_OAEP,
        )
        .unwrap();
    encrypted_aes_key.truncate(encrypted_aes_key_len);

    // Do AES Wrap of the data with the aes_key
    let aes_size = aes_key.len();
    let cipher = match aes_size {
        16 => openssl::cipher::Cipher::aes_128_wrap_pad(),
        24 => openssl::cipher::Cipher::aes_192_wrap_pad(),
        32 => openssl::cipher::Cipher::aes_256_wrap_pad(),
        _ => panic!("Invalid AES key size"),
    };

    let mut ctx = openssl::cipher_ctx::CipherCtx::new().unwrap();
    ctx.set_flags(openssl::cipher_ctx::CipherCtxFlags::FLAG_WRAP_ALLOW);

    let result = ctx.encrypt_init(Some(cipher), Some(aes_key), None);
    assert!(result.is_ok(), "result: {:?}", result);

    let padding = 8 - data.len() % 8;
    let mut encrypted_data = vec![0; data.len() + padding + cipher.block_size() * 2];
    let count = ctx.cipher_update(data, Some(&mut encrypted_data)).unwrap();
    let rest = ctx.cipher_final(&mut encrypted_data[count..]).unwrap();
    encrypted_data.truncate(count + rest);

    // Concatenate the encrypted_aes_key and encrypted_data to form the wrapped blob
    let mut wrapped_data = Vec::with_capacity(encrypted_aes_key.len() + encrypted_data.len());
    wrapped_data.append(&mut encrypted_aes_key);
    wrapped_data.append(&mut encrypted_data);

    wrapped_data
}

/// Perform RSA Unwrap on the wrapped blob using the import key.
///
/// # Arguments
/// * `app_session` - app session  Handle
/// * `key_type` - Wrapped Blob Key Type
/// * `hash_algorithm` - Wrapped Blob Hash Algorithm
///* `target_key_usage` - Target Key usage
/// # Returns
/// * `HsmKeyHandle` - Unwrapped Key Handle
#[allow(dead_code)]
pub(crate) fn rsa_unwrap_from_wrap_data(
    app_session: &HsmSession,
    key_type: KeyType,
    hash_algorithm: DigestKind,
    target_key_usage: KeyUsage,
) -> HsmResult<HsmKeyHandle> {
    // Get handle to private wrapping key
    let result = app_session.get_unwrapping_key();
    assert!(result.is_ok(), "result: {:?}", result);
    let wrapping_key = result.unwrap();

    let result = app_session.export_public_key(&wrapping_key);
    assert!(result.is_ok(), "result: {:?}", result);
    let wrapping_key_der = result.unwrap();
    let mut key_class: KeyClass = KeyClass::Rsa;
    let pri_key = match key_type {
        KeyType::Rsa2kPrivate | KeyType::Rsa3kPrivate | KeyType::Rsa4kPrivate => {
            key_class = KeyClass::Rsa;
            generate_rsa_der(key_type).0
        }

        KeyType::Rsa2kPrivateCrt | KeyType::Rsa3kPrivateCrt | KeyType::Rsa4kPrivateCrt => {
            key_class = KeyClass::RsaCrt;
            generate_rsa_der(key_type).0
        }

        KeyType::Aes128 | KeyType::Aes192 | KeyType::Aes256 => {
            key_class = KeyClass::Aes;
            generate_aes(key_type)
        }

        KeyType::AesBulk256 => {
            key_class = KeyClass::AesBulk;
            generate_aes(key_type)
        }

        KeyType::Ecc384Private
        | KeyType::Ecc256Private
        | KeyType::Ecc521Private
        | KeyType::Secret256
        | KeyType::Secret384
        | KeyType::Secret521 => {
            key_class = KeyClass::Ecc;
            generate_ecc_der(key_type).0
        }
        _ => vec![],
    };

    let wrapped_blob = wrap_data(wrapping_key_der, &pri_key);

    // Unwrap key in wrapped_blob
    let wrapped_blob_params = RsaUnwrapParams {
        key_class,
        padding: RsaCryptoPadding::Oaep,
        hash_algorithm,
    };

    app_session.rsa_unwrap(
        &wrapping_key,
        wrapped_blob,
        wrapped_blob_params,
        None,
        KeyProperties {
            key_usage: target_key_usage,
            key_availability: KeyAvailability::App,
        },
    )
}

#[allow(dead_code)]
pub(crate) fn generate_aes(key_type: KeyType) -> Vec<u8> {
    let buf_len = match key_type {
        KeyType::Aes128 => 16,
        KeyType::Aes192 => 24,
        KeyType::Aes256 => 32,
        KeyType::AesBulk256 => 32,
        _ => 32,
    };

    let mut buf = [0u8; 32];
    let buf_slice = &mut buf[..buf_len];
    let _ = rand_bytes(buf_slice);
    buf_slice.to_vec()
}

/// Generate a RSA key pair using openssl.
///
/// # Arguments
/// * `size` - Size of the RSA key pair to generate (2048/ 3072/ 4096 etc).
///
/// # Returns
/// * `(RsaPrivateKey, RsaPublicKey)` - Generated RSA key pair.
///
/// # Errors
/// * `ManticoreError::RsaGenerateError` - If the RSA key pair generation fails.
#[allow(dead_code)]
pub(crate) fn generate_rsa_der(key_type: KeyType) -> (Vec<u8>, Vec<u8>) {
    // Rsa::generate() uses 65537 as public exponent

    let size = match key_type {
        KeyType::Rsa2kPrivate => 2048,
        KeyType::Rsa3kPrivate => 3072,
        KeyType::Rsa4kPrivate => 4096,
        KeyType::Rsa2kPrivateCrt => 2048,
        KeyType::Rsa3kPrivateCrt => 3072,
        KeyType::Rsa4kPrivateCrt => 4096,
        _ => 0,
    };

    // Generate RSA 3k key to send as target key
    let result = openssl::rsa::Rsa::generate(size);
    assert!(result.is_ok(), "result: {:?}", result);
    let rsa_private = result.unwrap();

    let result = openssl::pkey::PKey::from_rsa(rsa_private);
    assert!(result.is_ok(), "result: {:?}", result);
    let target_pkey = result.unwrap();

    let result = target_pkey.private_key_to_pkcs8();
    assert!(result.is_ok(), "result: {:?}", result);
    let target_der = result.unwrap();

    let result = target_pkey.public_key_to_der();
    assert!(result.is_ok(), "result: {:?}", result);
    let public_key_der = result.unwrap();

    (target_der, public_key_der)
}

/// Generate an ECC key pair using openssl.
///
/// # Arguments
/// * `curve` - The ECC curve of the key pair to generate (p256/ p384/ p521).
///
/// # Returns
/// * `(EccPrivateKey, EccPublicKey)` - Generated ECC key pair.
///
#[allow(dead_code)]
pub(crate) fn generate_ecc_der(key_type: KeyType) -> (Vec<u8>, Vec<u8>) {
    let curve_name = match key_type {
        KeyType::Ecc256Private | KeyType::Secret256 => Nid::X9_62_PRIME256V1,
        KeyType::Ecc384Private | KeyType::Secret384 => Nid::SECP384R1,
        KeyType::Ecc521Private | KeyType::Secret521 => Nid::SECP521R1,
        _ => Nid::SECP384R1,
    };

    let result = openssl::ec::EcGroup::from_curve_name(curve_name);
    assert!(result.is_ok());
    let group = result.unwrap();

    let result = openssl::ec::EcKey::generate(&group);
    assert!(result.is_ok(), "result: {:?}", result);
    let ecc_private = result.clone().unwrap();

    let result = openssl::ec::EcKey::from_public_key(&group, ecc_private.public_key());
    assert!(result.is_ok(), "result: {:?}", result);
    let _ecc_public = result.unwrap();

    let result = openssl::pkey::PKey::from_ec_key(ecc_private);
    assert!(result.is_ok(), "result: {:?}", result);
    let pkey_private = result.unwrap();

    let result = pkey_private.private_key_to_pkcs8();
    assert!(result.is_ok(), "result: {:?}", result);
    let target_der = result.unwrap();

    let result = pkey_private.public_key_to_der();
    assert!(result.is_ok(), "result: {:?}", result);
    let public_key_der = result.unwrap();

    (target_der, public_key_der)
}

#[allow(clippy::enum_variant_names)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccInputKeyType {
    /// ECC 256 Private Key
    Ecc256Private,

    /// ECC 384 Private Key
    Ecc384Private,

    /// ECC 521 Private Key
    Ecc521Private,
}

#[allow(dead_code)]
pub fn ecc_input_key_type_to_key_type(input_key_type: EccInputKeyType) -> KeyType {
    match input_key_type {
        EccInputKeyType::Ecc256Private => KeyType::Ecc256Private,
        EccInputKeyType::Ecc384Private => KeyType::Ecc384Private,
        EccInputKeyType::Ecc521Private => KeyType::Ecc521Private,
    }
}

#[allow(dead_code)]
pub fn curve_to_key_type(input_curve: EccCurve) -> KeyType {
    match input_curve {
        EccCurve::P256 => KeyType::Secret256,
        EccCurve::P384 => KeyType::Secret384,
        EccCurve::P521 => KeyType::Secret521,
    }
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesInputKeyType {
    /// AES 128-bit Key
    Aes128,

    /// AES 192-bit Key
    Aes192,

    /// AES 256-bit Key
    Aes256,
}

#[allow(dead_code)]
pub fn aes_input_key_type_to_key_type(input_key_type: AesInputKeyType) -> KeyType {
    match input_key_type {
        AesInputKeyType::Aes128 => KeyType::Aes128,
        AesInputKeyType::Aes192 => KeyType::Aes192,
        AesInputKeyType::Aes256 => KeyType::Aes256,
    }
}

#[allow(dead_code)]
pub fn generate_valid_secret(
    app_session: &mut HsmSession,
    curve: EccCurve,
) -> HsmResult<HsmKeyHandle> {
    // Generate two ECC key pairs
    let priv_key_handle1 = app_session.ecc_generate(
        curve,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    )?;

    let priv_key_handle2 = app_session.ecc_generate(
        curve,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    )?;
    let pub_key_der2 = app_session.export_public_key(&priv_key_handle2)?;

    // Key exchange with each cross pair
    let secret = app_session.ecdh_key_exchange(
        &priv_key_handle1,
        &pub_key_der2,
        None,
        curve_to_key_type(curve),
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    )?;

    // Return the resulting secret
    Ok(secret)
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacInputKeyType {
    /// HmacSha 256-bit Key
    HmacSha256,

    /// HmacSha 384-bit Key
    HmacSha384,

    /// HmacSha 512-bit Key
    HmacSha512,
}

#[allow(dead_code)]
pub fn hmac_key_type_to_key_type(input_key_type: HmacInputKeyType) -> KeyType {
    match input_key_type {
        HmacInputKeyType::HmacSha256 => KeyType::HmacSha256,
        HmacInputKeyType::HmacSha384 => KeyType::HmacSha384,
        HmacInputKeyType::HmacSha512 => KeyType::HmacSha512,
    }
}

#[allow(dead_code)]
pub fn generate_valid_hmacsha_key(
    app_session: &mut HsmSession,
    curve: EccCurve,
    hkdf_params: HkdfDeriveParameters,
    key_type: HmacInputKeyType,
) -> HsmResult<HsmKeyHandle> {
    // Generate two ECC key pairs
    let priv_key_handle1 = app_session.ecc_generate(
        curve,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    )?;

    let priv_key_handle2 = app_session.ecc_generate(
        curve,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    )?;
    let pub_key_der2 = app_session.export_public_key(&priv_key_handle2)?;

    // Key exchange with one pair
    let secret = app_session.ecdh_key_exchange(
        &priv_key_handle1,
        &pub_key_der2,
        None,
        curve_to_key_type(curve),
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    )?;

    // Derive HmacSha key using HKDF
    let hmac_key = app_session.hkdf_derive(
        &secret,
        hkdf_params,
        None,
        hmac_key_type_to_key_type(key_type),
        KeyProperties {
            key_usage: KeyUsage::SignVerify,
            key_availability: KeyAvailability::Session,
        },
    )?;

    // Return the resulting hmac key
    Ok(hmac_key)
}
