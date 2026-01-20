// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_api::*;

use super::*;
use crate::AzihsmBuffer;
use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::deref_ptr;
use crate::utils::validate_ptr;

/// ECDH parameter structure matching C API
#[repr(C)]
pub struct AzihsmAlgoEcdhParams {
    pub_key: *const AzihsmBuffer,
}

impl<'a> TryFrom<&'a AzihsmAlgo> for &'a AzihsmAlgoEcdhParams {
    type Error = AzihsmStatus;

    /// Extracts a reference to ECDH parameters from the algorithm specification.
    ///
    /// # Safety
    /// The caller must ensure that `algo.params` points to valid `AzihsmAlgoEcdhParams` data
    /// when the algorithm ID is ECDH.
    #[allow(unsafe_code)]
    fn try_from(algo: &'a AzihsmAlgo) -> Result<Self, Self::Error> {
        // Check for null pointer
        validate_ptr(algo.params)?;

        // Safety: algo.params is validated to be non-null
        let params = unsafe { &*(algo.params as *const AzihsmAlgoEcdhParams) };

        Ok(params)
    }
}

/// HKDF parameter structure matching C API
#[repr(C)]
pub struct AzihsmAlgoHkdfParams {
    hmac_algo_id: AzihsmAlgoId,
    salt: *const AzihsmBuffer,
    info: *const AzihsmBuffer,
}

impl<'a> TryFrom<&'a AzihsmAlgo> for &'a AzihsmAlgoHkdfParams {
    type Error = AzihsmStatus;

    /// Extracts a reference to HKDF parameters from the algorithm specification.
    ///
    /// # Safety
    /// The caller must ensure that `algo.params` points to valid `AzihsmAlgoHkdfParams` data
    /// when the algorithm ID is HKDF.
    #[allow(unsafe_code)]
    fn try_from(algo: &'a AzihsmAlgo) -> Result<Self, Self::Error> {
        // Check for null pointer
        validate_ptr(algo.params)?;

        // Safety: algo.params is validated to be non-null
        let params = unsafe { &*(algo.params as *const AzihsmAlgoHkdfParams) };

        Ok(params)
    }
}

/// Derives a shared secret using Elliptic Curve Diffie-Hellman (ECDH)
///
/// Performs key agreement between a private key and a peer's public key
/// to derive a shared secret.
///
/// # Arguments
/// * `session` - HSM session for the operation
/// * `algo` - Algorithm specification containing peer public key
/// * `private_key_handle` - Handle to the local ECC private key
/// * `derived_key_props` - Properties for the derived key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the derived shared secret key
/// * `Err(AzihsmStatus)` - On failure (e.g., incompatible keys, invalid parameters)
pub(crate) fn ecdh_derive_key(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    base_key_handle: AzihsmHandle,
    derived_key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let ecdh_params: &AzihsmAlgoEcdhParams = algo.try_into()?;
    let peer_pub_key_buf = deref_ptr(ecdh_params.pub_key)?;
    let peer_pub_key_der: &[u8] = peer_pub_key_buf.try_into()?;

    // Get the base ECC private key
    let ecc_priv_key: &HsmEccPrivateKey =
        HANDLE_TABLE.as_ref(base_key_handle, HandleType::EccPrivKey)?;

    // Create ECDH algorithm with peer public key
    let mut ecdh_algo = EcdhAlgo::new(peer_pub_key_der);

    // Derive the shared secret
    let derived_key =
        HsmKeyManager::derive_key(session, &mut ecdh_algo, ecc_priv_key, derived_key_props)?;

    // Allocate handle for the derived generic secret key
    let handle = HANDLE_TABLE.alloc_handle(HandleType::GenericSecretKey, Box::new(derived_key));

    Ok(handle)
}

/// Derives keying material using HMAC-based Key Derivation Function (HKDF)
///
/// Expands a master key into derived keying material using HKDF.
///
/// # Arguments
/// * `session` - HSM session for the operation
/// * `algo` - HKDF algorithm parameters (hash algorithm, salt, info)
/// * `master_key_handle` - Handle to the master key (IKM - Input Keying Material)
/// * `derived_key_props` - Properties for the derived key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the derived key
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid parameters, unsupported algorithm)
pub(crate) fn hkdf_derive_key(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    base_key_handle: AzihsmHandle,
    derived_key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmStatus> {
    // Extract HKDF parameters
    let hkdf_params: &AzihsmAlgoHkdfParams = algo.try_into()?;

    // Convert HMAC algo ID to hash algo
    let hash_algo = match hkdf_params.hmac_algo_id {
        AzihsmAlgoId::HmacSha1 => HsmHashAlgo::Sha1,
        AzihsmAlgoId::HmacSha256 => HsmHashAlgo::Sha256,
        AzihsmAlgoId::HmacSha384 => HsmHashAlgo::Sha384,
        AzihsmAlgoId::HmacSha512 => HsmHashAlgo::Sha512,
        _ => Err(AzihsmStatus::InvalidArgument)?,
    };

    // Extract optional salt and info
    let salt = if hkdf_params.salt.is_null() {
        None
    } else {
        let salt_buf = deref_ptr(hkdf_params.salt)?;
        let salt_slice: &[u8] = salt_buf.try_into()?;
        Some(salt_slice)
    };

    let info = if hkdf_params.info.is_null() {
        None
    } else {
        let info_buf = deref_ptr(hkdf_params.info)?;
        let info_slice: &[u8] = info_buf.try_into()?;
        Some(info_slice)
    };

    // Get the base secret key
    let base_secret: &HsmGenericSecretKey =
        HANDLE_TABLE.as_ref(base_key_handle, HandleType::GenericSecretKey)?;

    // Create HKDF algorithm
    let mut hkdf_algo = HsmHkdfAlgo::new(hash_algo, salt, info)?;

    // Derive the key
    let derived_key = HsmKeyManager::derive_key(
        session,
        &mut hkdf_algo,
        base_secret,
        derived_key_props.clone(),
    )?;

    // Determine the handle type based on the derived key kind
    let handle = match derived_key_props.kind() {
        HsmKeyKind::Aes => {
            let aes_key: HsmAesKey = derived_key.try_into()?;
            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(aes_key))
        }

        HsmKeyKind::HmacSha256 | HsmKeyKind::HmacSha384 | HsmKeyKind::HmacSha512 => {
            let hmac_key: HsmHmacKey = derived_key.try_into()?;
            HANDLE_TABLE.alloc_handle(HandleType::HmacKey, Box::new(hmac_key))
        }
        _ => Err(AzihsmStatus::UnsupportedKeyKind)?,
    };

    Ok(handle)
}
