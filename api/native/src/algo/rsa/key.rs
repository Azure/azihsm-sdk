// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;

use super::*;
use crate::AzihsmBuffer;
use crate::AzihsmHandle;
use crate::AzihsmStatus;
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
    type Error = AzihsmStatus;

    #[allow(unsafe_code)]
    fn try_from(algo: &'a AzihsmAlgo) -> Result<Self, Self::Error> {
        if algo.len != std::mem::size_of::<AzihsmAlgoRsaAesKeyWrapParams>() as u32 {
            Err(AzihsmStatus::InvalidArgument)?;
        }

        let params = cast_ptr::<AzihsmAlgoRsaAesKeyWrapParams>(algo.params)?;

        // Validate OAEP parameters pointer
        validate_ptr(params.oaep_params)?;

        Ok(params)
    }
}

impl<'a> TryFrom<&'a AzihsmAlgo> for &'a AzihsmAlgoRsaPkcsOaepParams {
    type Error = AzihsmStatus;

    #[allow(unsafe_code)]
    fn try_from(algo: &'a AzihsmAlgo) -> Result<Self, Self::Error> {
        if algo.len != std::mem::size_of::<AzihsmAlgoRsaPkcsOaepParams>() as u32 {
            Err(AzihsmStatus::InvalidArgument)?;
        }

        let params = cast_ptr::<AzihsmAlgoRsaPkcsOaepParams>(algo.params)?;

        // Validate hash algorithm ID
        match params.hash_algo_id {
            AzihsmAlgoId::Sha256 | AzihsmAlgoId::Sha384 | AzihsmAlgoId::Sha512 => {}
            _ => Err(AzihsmStatus::InvalidArgument)?,
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

/// Generates a new RSA key pair
///
/// Creates a new RSA public/private key pair with the specified key size.
///
/// # Arguments
/// * `session` - HSM session for key generation
/// * `algo` - RSA key generation algorithm parameters (key size)
/// * `priv_key_props` - Properties for the private key (extractable, persistent, etc.)
/// * `pub_key_props` - Properties for the public key
///
/// # Returns
/// * `Ok((AzihsmHandle, AzihsmHandle))` - Handles to (private_key, public_key)
/// * `Err(AzihsmStatus)` - On failure (e.g., unsupported key size)
pub(crate) fn rsa_generate_key_pair(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmStatus> {
    let mut rsa_algo = HsmRsaKeyUnwrappingKeyGenAlgo::try_from(algo)?;
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut rsa_algo, priv_key_props, pub_key_props)?;

    let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPrivKey, Box::new(priv_key));
    let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPubKey, Box::new(pub_key));

    Ok((priv_handle, pub_handle))
}

/// Unwraps (decrypts) a wrapped symmetric key using an RSA private key
///
/// Decrypts a key that was wrapped (encrypted) for secure transport or storage.
///
/// # Arguments
/// * `algo` - RSA unwrap algorithm (typically OAEP or PKCS#1 v1.5)
/// * `wrapping_key_handle` - Handle to the RSA private key used for unwrapping
/// * `wrapped_key` - Encrypted key material to unwrap
/// * `unwrapped_key_props` - Properties for the unwrapped key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the unwrapped key
/// * `Err(AzihsmStatus)` - On failure (e.g., decryption failure, invalid wrapped key)
pub(crate) fn rsa_unwrap_key(
    algo: &AzihsmAlgo,
    unwrapping_key_handle: AzihsmHandle,
    wrapped_key: &[u8],
    key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmStatus> {
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
        HsmKeyKind::AesGcm => {
            let mut unwrap_algo = HsmAesGcmKeyRsaAesKeyUnwrapAlgo::new(hash_algo);

            // Unwrap the AES GCM key
            let unwrapped_key = HsmKeyManager::unwrap_key(
                &mut unwrap_algo,
                &unwrapping_key,
                wrapped_key,
                key_props,
            )?;

            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(unwrapped_key))
        }

        // AesXts unwrapping
        HsmKeyKind::AesXts => {
            let mut unwrap_algo = HsmAesXtsKeyRsaAesKeyUnwrapAlgo::new(hash_algo);
            // Unwrap the AES-XTS key
            let unwrapped_key = HsmKeyManager::unwrap_key(
                &mut unwrap_algo,
                &unwrapping_key,
                wrapped_key,
                key_props,
            )?;
            HANDLE_TABLE.alloc_handle(HandleType::AesXtsKey, Box::new(unwrapped_key))
        }
        _ => return Err(AzihsmStatus::UnsupportedKeyKind),
    };

    Ok(handle)
}

/// Unwraps (decrypts) a wrapped RSA key pair using an RSA private key
///
/// Decrypts an RSA key pair that was wrapped for secure transport or storage.
///
/// # Arguments
/// * `algo` - RSA unwrap algorithm (typically OAEP or PKCS#1 v1.5)
/// * `wrapping_key_handle` - Handle to the RSA private key used for unwrapping
/// * `wrapped_key_pair` - Encrypted key pair material to unwrap
/// * `priv_key_props` - Properties for the unwrapped private key
/// * `pub_key_props` - Properties for the unwrapped public key
///
/// # Returns
/// * `Ok((AzihsmHandle, AzihsmHandle))` - Handles to (private_key, public_key)
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn rsa_unwrap_key_pair(
    algo: &AzihsmAlgo,
    unwrapping_key_handle: AzihsmHandle,
    wrapped_key: &[u8],
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmStatus> {
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
        _ => return Err(AzihsmStatus::UnsupportedKeyKind),
    };

    Ok((priv_handle, pub_handle))
}

/// Unmasks a masked RSA key pair and returns handles to both keys
///
/// Takes a masked RSA key pair (typically received from external storage)
/// and unmasks it within the HSM session, creating usable key handles.
///
/// # Arguments
/// * `session` - HSM session where the keys will be unmasked
/// * `masked_key_pair` - Byte slice containing the masked key pair material
///
/// # Returns
/// * `Ok((AzihsmHandle, AzihsmHandle))` - Handles to (private_key, public_key)
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn rsa_unmask_key_pair(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmStatus> {
    let mut unmask_algo = HsmRsaKeyUnmaskAlgo::default();

    // Unmask RSA key pair
    let (priv_key, pub_key): (HsmRsaPrivateKey, HsmRsaPublicKey) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, masked_key)?;

    let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPrivKey, Box::new(priv_key));
    let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPubKey, Box::new(pub_key));

    Ok((priv_handle, pub_handle))
}

/// Generate a key report for an RSA private key
pub(crate) fn rsa_generate_key_report(
    key_handle: AzihsmHandle,
    report_data: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the key from handle
    let key = &HsmRsaPrivateKey::try_from(key_handle)?;

    // Determine required size
    let required_size = HsmKeyManager::generate_key_report(key, report_data, None)?;

    // Validate and get output buffer
    let output_data = validate_output_buffer(output, required_size)?;

    // Generate actual key report
    let report_len = HsmKeyManager::generate_key_report(key, report_data, Some(output_data))?;

    // Update output buffer length
    output.len = report_len as u32;

    Ok(())
}
