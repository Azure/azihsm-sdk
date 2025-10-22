// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uchar;

use api_interface::REPORT_DATA_SIZE;
use engine_common::handle_table::Handle;
use mcr_api_resilient::DigestKind;
use mcr_api_resilient::KeyAvailability;
use mcr_api_resilient::KeyClass;
use mcr_api_resilient::KeyUsage;
use openssl_rust::safeapi::ec::ecdsa_sig::Ecdsa_Sig;
use openssl_rust::safeapi::ec::key::EcKey;
use openssl_rust::safeapi::error::*;
use openssl_rust::BIGNUM;
use openssl_rust::BN_CTX;
use openssl_rust::ECDSA_SIG;
use openssl_rust::EC_FLAG_COFACTOR_ECDH;
use openssl_rust::EC_KEY;
use openssl_rust::EC_POINT;

use crate::common::base_key::Key;
use crate::common::base_key::ENGINE_KEY_HANDLE_TABLE;
use crate::common::ec_key::EcCurveType;
use crate::common::ec_key::EcKeyData;
use crate::common::hsm_key::HsmKeyContainer;

/// Import the wrapped key into HSM and set the key data to the EC_KEY object
///
/// # Arguments
/// * `key` - EC_KEY object
/// * `wrapped_blob` - Wrapped key blob
/// * `digest_kind` - Digest kind
/// * `key_usage` - Key usage
/// * `key_availability` - Key availability
/// * `key_name` - Key name
///
/// # Return
/// Result of the wrapped key import operation
pub(crate) fn ec_import_key(
    key: *mut EC_KEY,
    wrapped_blob: &[u8],
    digest_kind: DigestKind,
    key_usage: KeyUsage,
    key_availability: KeyAvailability,
    key_name: Option<&[u8]>,
) -> OpenSSLResult<()> {
    let key_container = HsmKeyContainer::unwrap_key(
        wrapped_blob.to_vec(),
        KeyClass::Ecc,
        digest_kind,
        key_usage,
        key_availability,
        key_name,
    )?;

    let mut ec_key = EcKey::<EcKeyData>::new_from_ptr(key);
    let curve_name = ec_key.curve_name()?;
    ec_key.set_key_group_by_name(curve_name)?;

    let key_data = EcKeyData::new();
    key_data.set_curve(curve_name)?;
    let is_ecdh_key = key_usage == KeyUsage::Derive;
    key_data.set_key_type(is_ecdh_key);
    key_data.set_imported_key(key_container);

    let pub_key = key_data.export_public_key()?;
    ec_key.set_pubkey_der(pub_key)?;

    ec_key.set_data(key_data)
}

/// Attest the key data associated with the EC_KEY object
/// and return the claim data from the HSM
///
/// # Arguments
/// * `key` - EC_KEY object
/// * `report_data` - Report data to attest with
///
/// # Return
/// Claim from the key attestation operation or error
pub(crate) fn ec_attest_key(
    key: *mut EC_KEY,
    report_data: &[u8; REPORT_DATA_SIZE as usize],
) -> OpenSSLResult<Vec<u8>> {
    let ec_key = EcKey::<EcKeyData>::new_from_ptr(key);

    let key_data = ec_key.get_data()?.ok_or(OpenSSLError::InvalidKey)?;

    key_data.attest_key(report_data)
}

/// OpenSSL `keygen` callback for EC
/// Generate a new EC key pair and set the key data to the EC_KEY object
///
/// # Arguments
/// * `key_out` - EC_KEY object to generate the key pair for. Must be non-null
///
/// # Return
/// Result of the key generation operation
pub(super) fn keygen_cb(key_out: *mut EC_KEY) -> OpenSSLResult<()> {
    let mut key: EcKey<EcKeyData> = EcKey::new_from_ptr(key_out);
    let curve_name = key.curve_name()?;
    key.set_key_group_by_name(curve_name)?;

    let ecdh_key = key.contains_flag(EC_FLAG_COFACTOR_ECDH as i32);

    let key_data = EcKeyData::new();
    key_data.set_curve(curve_name)?;
    key_data.set_key_type(ecdh_key);
    key_data.generate_key()?;

    let pub_key = key_data.export_public_key()?;
    key.set_pubkey_der(pub_key)?;

    key.set_data(key_data)?;
    Ok(())
}

/// OpenSSL `compute_key` callback for EC
/// Computes the shared secret key using ECDH key exchange
///
/// # Arguments
/// * `psecret` - Pointer to the shared secret key (unused)
/// * `psecret_len` - Pointer to the shared secret key length (unused)
/// * `pub_key` - Peer's public key. Must be non-null
/// * `ecdh` - ECDH key. Must be non-null
///
/// # Return
/// Shared secret key handle (Handle) or error
pub(super) fn compute_key_cb(
    _psecret: *mut *mut c_uchar,
    _psecret_len: *mut usize,
    pub_key: *const EC_POINT,
    ecdh: *const EC_KEY,
) -> OpenSSLResult<Handle> {
    let pvt_key: EcKey<EcKeyData> = EcKey::new_from_ptr(ecdh as *mut EC_KEY);
    let curve_name = pvt_key.curve_name()?;
    let mut peer_key: EcKey<EcKeyData> = EcKey::new_from_pubkey(pub_key, curve_name)?;

    let key_data = pvt_key.get_data()?.ok_or(OpenSSLError::InvalidKey)?;

    let peer_pubkey_der = peer_key.get_pubkey_der()?;
    peer_key.free();

    key_data.set_peer_key(peer_pubkey_der.clone());
    let ecdh_secret = key_data.compute_shared_secret()?;
    let handle = ENGINE_KEY_HANDLE_TABLE.insert_key(Key::Secret(ecdh_secret));
    Ok(handle)
}

/// OpenSSL key finish function
/// Free the key data associated with the EC_KEY object
///
/// # Arguments
/// * `key_out` - EC_KEY object to free. Must be non-null
pub(super) fn finish_cb(key_out: *mut EC_KEY) {
    let mut key: EcKey<EcKeyData> = EcKey::new_from_ptr(key_out);
    key.free_data();
}

/// OpenSSL EC key copy function
/// Copy the key data associated with the EC_KEY object
///
/// # Arguments
/// * `dst` - Destination EC_KEY object
/// * `src` - Source EC_KEY object
///
/// # Return
/// Result of the key copy operation
pub(super) fn copy_cb(dst: *mut EC_KEY, src: *const EC_KEY) -> OpenSSLResult<()> {
    let src_key: EcKey<EcKeyData> = EcKey::new_from_ptr(src as *mut EC_KEY);
    let src_data = src_key.get_data()?.ok_or(OpenSSLError::InvalidKey)?;

    let mut dst_key: EcKey<EcKeyData> = EcKey::new_from_ptr(dst);
    // Copy the key data from the source to the destination
    let dst_data = src_data.clone();
    dst_key.reset_data()?;
    dst_key.set_data(dst_data)
}

/// This function is a stub, as we do not support kinv or r params.
/// Always returns success.
///
/// # Arguments
/// * `key` - EC_KEY object (unused)
/// * `ctx` - BN_CTX object (unused)
/// * `kinv` - kinv parameter (unused)
/// * `r` - r parameter (unused)
///
/// # Return
/// Result of the setup operation
pub fn sign_setup_cb(
    _: *mut EC_KEY,
    _: *mut BN_CTX,
    _: *mut *mut BIGNUM,
    _: *mut *mut BIGNUM,
) -> OpenSSLResult<()> {
    Ok(())
}

/// OpenSSL `sign` callback for EC
/// Computes the digital signature of the given digest using the private EC key
///
/// # Arguments
/// * `_type` - Signature type (unused)
/// * `dgst` - Digest to sign
/// * `kinv` - Inverse of the ephemeral key (not supported)
/// * `r` - r parameter (not supported)
/// * `key` - EC_KEY object to sign with. Must be non-null
///
/// # Return
/// Signature of the digest in a byte vector or error
pub fn sign_cb(
    _type: c_int,
    dgst: Vec<u8>,
    kinv: *const BIGNUM,
    r: *const BIGNUM,
    key: *mut EC_KEY,
) -> OpenSSLResult<Vec<u8>> {
    if !kinv.is_null() {
        Err(OpenSSLError::IncorrectParam(
            "kinv".to_string(),
            "null".to_string(),
            format!("{kinv:?}"),
        ))?;
    }

    if !r.is_null() {
        Err(OpenSSLError::IncorrectParam(
            "r".to_string(),
            "null".to_string(),
            format!("{r:?}"),
        ))?;
    }

    let key: EcKey<EcKeyData> = EcKey::new_from_ptr(key);
    let key_data = key.get_data()?.ok_or(OpenSSLError::InvalidKey)?;

    key_data.sign(dgst)
}

/// OpenSSL `sign_sig` callback for EC
/// Computes the digital signature of the given digest using the private EC key and returns the ECDSA_SIG object
///
/// # Arguments
/// * `dgst` - Digest to sign
/// * `kinv` - Inverse of the ephemeral key (not supported)
/// * `r` - r parameter (not supported)
/// * `key` - EC_KEY object to sign with. Must be non-null
///
/// # Return
/// Signature in ECDSA_SIG object format or error
pub fn sign_sig_cb(
    dgst: Vec<u8>,
    kinv: *const BIGNUM,
    r: *const BIGNUM,
    key: *mut EC_KEY,
) -> OpenSSLResult<*mut ECDSA_SIG> {
    if !kinv.is_null() {
        Err(OpenSSLError::IncorrectParam(
            "kinv".to_string(),
            "null".to_string(),
            format!("{kinv:?}"),
        ))?;
    }

    if !r.is_null() {
        Err(OpenSSLError::IncorrectParam(
            "r".to_string(),
            "null".to_string(),
            format!("{r:?}"),
        ))?;
    }

    let key: EcKey<EcKeyData> = EcKey::new_from_ptr(key);
    let key_data = key.get_data()?.ok_or(OpenSSLError::InvalidKey)?;

    let sig_vec = key_data.sign(dgst)?;

    let sig = Ecdsa_Sig::from_raw(sig_vec)?;
    Ok(sig.as_mut_ptr())
}

/// OpenSSL `verify` callback for EC
/// Verifies the signature of the given digest using the public EC key
///
/// # Arguments
/// * `_type` - Signature type (unused)
/// * `dgst` - Digest to compare against
/// * `sig` - Signature to verify
/// * `key` - EC_KEY object to verify with. Must be non-null
///
/// # Return
/// Result of the verification operation
pub fn verify_cb(_type: c_int, dgst: Vec<u8>, sig: Vec<u8>, key: *mut EC_KEY) -> OpenSSLResult<()> {
    let key: EcKey<EcKeyData> = EcKey::new_from_ptr(key);
    let key_data = key.get_data()?.ok_or(OpenSSLError::InvalidKey)?;

    key_data.verify(dgst, sig)
}

/// OpenSSL `verify_sig` callback for EC
/// Verifies the signature in ECDSA_SIG format of the given digest using the public EC key
///
/// # Arguments
/// * `dgst` - Digest to compare against
/// * `sig` - Signature to verify in ECDSA_SIG format. Must be non-null
/// * `key` - EC_KEY object to verify with. Must be non-null
///
/// # Return
/// Result of the verification operation
pub fn verify_sig_cb(dgst: Vec<u8>, sig: *const ECDSA_SIG, key: *mut EC_KEY) -> OpenSSLResult<()> {
    let key: EcKey<EcKeyData> = EcKey::new_from_ptr(key);
    let key_data = key.get_data()?.ok_or(OpenSSLError::InvalidKey)?;

    let curve_name = key.curve_name()?;
    let curve_type = EcCurveType::from_curve_name(curve_name)?;
    // Get r/s parameter length
    let len = curve_type.sig_param_len();

    let sig_data = Ecdsa_Sig::new_from_ptr(sig as *mut ECDSA_SIG);
    let sig_vec = sig_data.to_raw(len)?;

    key_data.verify(dgst, sig_vec)
}
