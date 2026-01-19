// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_api::*;

use super::*;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::*;

/// RSA-AES key wrapping parameters matching C API.
///
/// Defines parameters for RSA-AES key wrap/unwrap operations, which combine
/// RSA encryption with AES key wrapping to securely transport symmetric keys.
/// The RSA key encrypts an AES key, which in turn wraps the target key material.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoRsaAesKeyWrapParams {
    /// AES key size in bits (typically 128, 192, or 256)
    pub aes_key_bits: u32,

    /// OAEP parameters for RSA encryption of the AES key
    pub oaep_params: *const AzihsmAlgoRsaPkcsOaepParams,
}

impl<'a> TryFrom<&'a AzihsmAlgo> for &'a AzihsmAlgoRsaAesKeyWrapParams {
    type Error = AzihsmError;

    #[allow(unsafe_code)]
    fn try_from(algo: &'a AzihsmAlgo) -> Result<Self, Self::Error> {
        if algo.len != std::mem::size_of::<AzihsmAlgoRsaAesKeyWrapParams>() as u32 {
            Err(AzihsmError::InvalidArgument)?;
        }

        let params = cast_ptr::<AzihsmAlgoRsaAesKeyWrapParams>(algo.params)?;

        // Validate OAEP parameters pointer
        validate_ptr(params.oaep_params)?;

        Ok(params)
    }
}

impl<'a> TryFrom<&'a AzihsmAlgo> for &'a AzihsmAlgoRsaPkcsOaepParams {
    type Error = AzihsmError;

    #[allow(unsafe_code)]
    fn try_from(algo: &'a AzihsmAlgo) -> Result<Self, Self::Error> {
        if algo.len != std::mem::size_of::<AzihsmAlgoRsaPkcsOaepParams>() as u32 {
            Err(AzihsmError::InvalidArgument)?;
        }

        let params = cast_ptr::<AzihsmAlgoRsaPkcsOaepParams>(algo.params)?;

        // Validate hash algorithm ID
        match params.hash_algo_id {
            AzihsmAlgoId::Sha256 | AzihsmAlgoId::Sha384 | AzihsmAlgoId::Sha512 => {}
            _ => Err(AzihsmError::InvalidArgument)?,
        }

        // Label is optional - if provided, validate the buffer
        if !params.label.is_null() {
            let label_buf = deref_ptr(params.label)?;

            // Validate the buffer has valid data pointer if length > 0
            if label_buf.len > 0 {
                validate_ptr(label_buf.ptr)?;
            }
        }

        Ok(params)
    }
}

/// Generate an RSA key pair and return handles
pub(crate) fn rsa_generate_key_pair(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmError> {
    let mut rsa_algo = HsmRsaKeyUnwrappingKeyGenAlgo::try_from(algo)?;
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut rsa_algo, priv_key_props, pub_key_props)?;

    let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPrivKey, Box::new(priv_key));
    let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPubKey, Box::new(pub_key));

    Ok((priv_handle, pub_handle))
}

/// Unwrap a wrapped symmetric key using RSA-AES key wrapping
pub(crate) fn rsa_unwrap_key(
    algo: &AzihsmAlgo,
    unwrapping_key_handle: AzihsmHandle,
    wrapped_key: &[u8],
    key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmError> {
    // Get the unwrapping algorithm parameters
    let params = <&AzihsmAlgoRsaAesKeyWrapParams>::try_from(algo)?;

    // Get hash algo from OAEP parameters
    let oaep_params = deref_ptr(params.oaep_params)?;
    let hash_algo = HsmHashAlgo::try_from(oaep_params.hash_algo_id)?;

    // Get the unwrapping key (RSA private key)
    let unwrapping_key: HsmRsaPrivateKey = HsmRsaPrivateKey::try_from(unwrapping_key_handle)?;

    // Determine the key kind from the key properties
    let key_kind = key_props.kind();

    let handle = match key_kind {
        HsmKeyKind::Aes => {
            let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(hash_algo);

            // Unwrap the AES key
            let unwrapped_key = HsmKeyManager::unwrap_key(
                &mut unwrap_algo,
                &unwrapping_key,
                wrapped_key,
                key_props,
            )?;

            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(unwrapped_key))
        }
        _ => return Err(AzihsmError::UnsupportedKeyKind),
    };

    Ok(handle)
}

/// Unwrap a wrapped key pair using RSA-AES key wrapping
pub(crate) fn rsa_unwrap_key_pair(
    algo: &AzihsmAlgo,
    unwrapping_key_handle: AzihsmHandle,
    wrapped_key: &[u8],
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmError> {
    // Get the unwrapping algorithm parameters
    let params = <&AzihsmAlgoRsaAesKeyWrapParams>::try_from(algo)?;

    // Get hash algo from OAEP parameters
    let oaep_params = deref_ptr(params.oaep_params)?;
    let hash_algo = HsmHashAlgo::try_from(oaep_params.hash_algo_id)?;

    // Get the unwrapping key (RSA private key)
    let unwrapping_key: HsmRsaPrivateKey = HsmRsaPrivateKey::try_from(unwrapping_key_handle)?;

    // Determine the key type from the private key properties
    let key_kind = priv_key_props.kind();

    let (priv_handle, pub_handle) = match key_kind {
        HsmKeyKind::Rsa => {
            let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(hash_algo);

            // Unwrap RSA key pair
            let (priv_key, pub_key): (HsmRsaPrivateKey, HsmRsaPublicKey) =
                HsmKeyManager::unwrap_key_pair(
                    &mut unwrap_algo,
                    &unwrapping_key,
                    wrapped_key,
                    priv_key_props,
                    pub_key_props,
                )?;

            let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPrivKey, Box::new(priv_key));
            let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPubKey, Box::new(pub_key));

            (priv_handle, pub_handle)
        }
        HsmKeyKind::Ecc => {
            let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(hash_algo);

            // Unwrap ECC key pair
            let (priv_key, pub_key): (HsmEccPrivateKey, HsmEccPublicKey) =
                HsmKeyManager::unwrap_key_pair(
                    &mut unwrap_algo,
                    &unwrapping_key,
                    wrapped_key,
                    priv_key_props,
                    pub_key_props,
                )?;

            let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPrivKey, Box::new(priv_key));
            let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPubKey, Box::new(pub_key));

            (priv_handle, pub_handle)
        }
        _ => return Err(AzihsmError::UnsupportedKeyKind),
    };

    Ok((priv_handle, pub_handle))
}

/// Unmask a masked RSA key pair
pub(crate) fn rsa_unmask_key_pair(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmError> {
    let mut unmask_algo = HsmRsaKeyUnmaskAlgo::default();

    // Unmask RSA key pair
    let (priv_key, pub_key): (HsmRsaPrivateKey, HsmRsaPublicKey) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, masked_key)?;

    let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPrivKey, Box::new(priv_key));
    let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPubKey, Box::new(pub_key));

    Ok((priv_handle, pub_handle))
}
