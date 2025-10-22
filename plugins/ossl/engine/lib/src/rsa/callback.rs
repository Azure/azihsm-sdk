// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uint;

use api_interface::REPORT_DATA_SIZE;
use mcr_api_resilient::DigestKind;
use mcr_api_resilient::KeyAvailability;
use mcr_api_resilient::KeyClass;
use mcr_api_resilient::KeyType;
use mcr_api_resilient::KeyUsage;
use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::safeapi::rsa::key::RsaKey;
use openssl_rust::BIGNUM;
use openssl_rust::BN_GENCB;
use openssl_rust::RSA;

use crate::common::hash::azihsm_hash_type;
use crate::common::hsm_key::HsmKeyContainer;
use crate::common::rsa_key::RsaKeyData;
use crate::common::rsa_key::RsaKeyUsage;

/// Import the given HSM key
pub(crate) fn import_rsa_key(
    key: *mut RSA,
    wrapped_blob: &[u8],
    digest_kind: DigestKind,
    key_usage: KeyUsage,
    key_availability: KeyAvailability,
    key_name: Option<&[u8]>,
    is_crt: bool,
) -> OpenSSLResult<()> {
    let rsa_key_usage = RsaKeyUsage::try_from(key_usage)?;

    let key_class = if is_crt {
        KeyClass::RsaCrt
    } else {
        KeyClass::Rsa
    };

    let key_container = HsmKeyContainer::unwrap_key(
        wrapped_blob.to_vec(),
        key_class,
        digest_kind,
        key_usage,
        key_availability,
        key_name,
    )?;

    // Get the size of the key
    let n = match key_container.key_kind() {
        KeyType::Rsa2kPublic | KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt => 2048,
        KeyType::Rsa3kPublic | KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt => 3072,
        KeyType::Rsa4kPublic | KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt => 4096,
        _ => return Err(OpenSSLError::InvalidKey),
    };

    let mut rsa = RsaKey::<RsaKeyData>::new_from_ptr(key);
    let key_data = RsaKeyData::new();
    key_data.set_imported_key(key_container);
    key_data.set_key_usage(rsa_key_usage);
    rsa.set_data(key_data)?;

    // This is to make RSA_size work, which a lot of code relies on
    rsa.set_n(n);
    Ok(())
}

/// Attest an RSA key
///
/// # Arguments
/// * `rsa_ptr` - pointer to `RSA` structure
/// * `report_data` - Report to the HSM
///
/// # Return
/// Attestation data, or error.
pub(crate) fn rsa_attest_key(
    rsa_ptr: *mut RSA,
    report_data: &[u8; REPORT_DATA_SIZE as usize],
) -> OpenSSLResult<Vec<u8>> {
    let rsa: RsaKey<RsaKeyData> = RsaKey::new_from_ptr(rsa_ptr);
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;

    rsa_keydata.attest_key(report_data)
}

/// RSA public key encryption callback
/// This function is called whenever we encrypt with an RSA key using the public key.
///
/// # Arguments
/// * `input` - The data to encrypt
/// * `key` - The `RSA` key to use
/// * `_` - Unused parameter to specify padding (Only OAEP supported)
///
/// # Returns
/// * `OpenSSLResult<Vec<u8>>` - The result of the encryption operation.
pub(super) fn rsa_pub_enc(input: &[u8], key: *mut RSA, _: c_int) -> OpenSSLResult<Vec<u8>> {
    let rsa: RsaKey<RsaKeyData> = RsaKey::new_from_ptr(key);
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    rsa_keydata.encrypt(input)
}

/// RSA private key encryption callback
/// Not supported by the HSM.
pub(super) fn rsa_priv_enc(_: &[u8], _: *mut RSA, _: c_int) -> OpenSSLResult<Vec<u8>> {
    Err(OpenSSLError::NotImplemented)
}

/// RSA public key decryption callback
/// Not supported by the HSM.
pub(super) fn rsa_pub_dec(_: &[u8], _: *mut RSA, _: c_int) -> OpenSSLResult<Vec<u8>> {
    Err(OpenSSLError::NotImplemented)
}

/// RSA private key decryption callback
/// This function is called whenever we decrypt with an RSA key using the private key.
///
/// # Arguments
/// * `input` - The data to decrypt
/// * `key` - The `RSA` key to use
/// * `_` - Unused parameter to specify padding (Only OAEP supported)
///
/// # Returns
/// * `OpenSSLResult<Vec<u8>>` - The result of the decryption operation.
pub(super) fn rsa_priv_dec(input: &[u8], key: *mut RSA, _: c_int) -> OpenSSLResult<Vec<u8>> {
    let rsa: RsaKey<RsaKeyData> = RsaKey::new_from_ptr(key);
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    rsa_keydata.decrypt(input)
}

/// RSA signing callback
/// This function is called whenever we sign with an RSA key.
///
/// # Arguments
/// * `hash_type` - NID of expected digest
/// * `dgst` - Digest to sign
/// * `key` - The `RSA` key to use
///
/// # Returns
/// * `OpenSSLResult<Vec<u8>>` - The result of the signing operation.
pub(super) fn rsa_sign(hash_type: c_int, dgst: &[u8], key: *const RSA) -> OpenSSLResult<Vec<u8>> {
    let hash_type = azihsm_hash_type(hash_type as c_uint)?;
    let rsa: RsaKey<RsaKeyData> = RsaKey::new_from_ptr(key as *mut RSA);
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    rsa_keydata.set_hash_type(hash_type);
    rsa_keydata.sign(dgst)
}

/// RSA verification callback
/// This function is called whenever we verify a digest with an RSA key.
///
/// # Arguments
/// * `hash_type` - NID of expected digest
/// * `dgst` - Digest to check
/// * `sig` - Signature to check with
/// * `key` - The `RSA` key to use
///
/// # Returns
/// * `OpenSSLResult<()>` - The result of the verification operation.
pub(super) fn rsa_verify(
    hash_type: c_int,
    dgst: &[u8],
    sig: &[u8],
    key: *const RSA,
) -> OpenSSLResult<()> {
    let hash_type = azihsm_hash_type(hash_type as c_uint)?;
    let rsa: RsaKey<RsaKeyData> = RsaKey::new_from_ptr(key as *mut RSA);
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    rsa_keydata.set_hash_type(hash_type);
    rsa_keydata.verify(dgst, sig)
}

/// Callback for keygen
/// Keygen is not implemented by the HSM.
pub(super) fn rsa_keygen(
    _: *mut RSA,
    _: c_int,
    _: *mut BIGNUM,
    _: *mut BN_GENCB,
) -> OpenSSLResult<()> {
    Err(OpenSSLError::NotImplemented)
}

/// Callback to finish RSA
pub(super) fn rsa_finish(key: *mut RSA) -> OpenSSLResult<()> {
    let mut rsa: RsaKey<RsaKeyData> = RsaKey::new_from_ptr(key as *mut RSA);
    rsa.free_data();
    Ok(())
}
