// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use super::*;
use crate::AzihsmAlgoEcdhParams;
use crate::AzihsmAlgoHkdfParams;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::deref_ptr;

/// Helper function to perform ECDH key derivation
pub(crate) fn ecdh_derive_key(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    base_key_handle: AzihsmHandle,
    derived_key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmError> {
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

/// Helper function to perform HKDF key derivation
pub(crate) fn hkdf_derive_key(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    base_key_handle: AzihsmHandle,
    derived_key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmError> {
    // Extract HKDF parameters
    let hkdf_params: &AzihsmAlgoHkdfParams = algo.try_into()?;

    // Convert HMAC algo ID to hash algo
    let hash_algo = match hkdf_params.hmac_algo_id {
        AzihsmAlgoId::HmacSha1 => HsmHashAlgo::Sha1,
        AzihsmAlgoId::HmacSha256 => HsmHashAlgo::Sha256,
        AzihsmAlgoId::HmacSha384 => HsmHashAlgo::Sha384,
        AzihsmAlgoId::HmacSha512 => HsmHashAlgo::Sha512,
        _ => Err(AzihsmError::InvalidArgument)?,
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
        _ => Err(AzihsmError::UnsupportedKeyKind)?,
    };

    Ok(handle)
}
