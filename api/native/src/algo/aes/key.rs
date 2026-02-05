// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;

use super::*;
use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;

impl TryFrom<&AzihsmAlgo> for azihsm_api::HsmAesKeyGenAlgo {
    type Error = AzihsmStatus;

    /// Converts a C FFI algorithm specification to HsmAesKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmAesKeyGenAlgo::default())
    }
}

impl TryFrom<&AzihsmAlgo> for azihsm_api::HsmAesXtsKeyGenAlgo {
    type Error = AzihsmStatus;

    /// Converts a C FFI algorithm specification to HsmAesXtsKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmAesXtsKeyGenAlgo::default())
    }
}

/// Generates a new AES key
///
/// Creates a new AES symmetric key with the specified properties.
///
/// # Arguments
/// * `session` - HSM session for key generation
/// * `algo` - AES key generation algorithm parameters (key size)
/// * `key_props` - Properties for the generated key (extractable, persistent, etc.)
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the generated AES key
/// * `Err(AzihsmStatus)` - On failure (e.g., unsupported key size)
pub(crate) fn aes_generate_key(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let mut aes_algo = HsmAesKeyGenAlgo::try_from(algo)?;
    let key = HsmKeyManager::generate_key(session, &mut aes_algo, key_props)?;
    let handle = HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(key));

    Ok(handle)
}

/// Unmasks a masked AES key and returns a handle to it
///
/// Takes a masked AES key (typically received from external storage or transmission)
/// and unmasks it within the HSM session, creating a usable key handle.
///
/// # Arguments
/// * `session` - Reference to the HSM session where the key will be unmasked
/// * `masked_key` - Byte slice containing the masked key material
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the unmasked AES key for subsequent cryptographic operations
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn aes_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<AzihsmHandle, AzihsmStatus> {
    let mut unmask_algo = HsmAesKeyUnmaskAlgo::default();

    // Unmask AES key
    let key: HsmAesKey = HsmKeyManager::unmask_key(session, &mut unmask_algo, masked_key)?;

    let handle = HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(key));

    Ok(handle)
}

/// Generates a new AES-XTS key
///
/// Creates a new AES-XTS symmetric key with the specified properties.
/// AES-XTS mode requires a 512-bit key (for AES-256 XTS) which consists of
/// two 256-bit keys used for tweak and data encryption.
///
/// # Arguments
/// * `session` - HSM session for key generation
/// * `algo` - AES-XTS key generation algorithm parameters
/// * `key_props` - Properties for the generated key (extractable, persistent, etc.)
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the generated AES-XTS key
/// * `Err(AzihsmStatus)` - On failure (e.g., unsupported key size, invalid properties)
pub(crate) fn aes_xts_generate_key(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let mut aes_algo = HsmAesXtsKeyGenAlgo::try_from(algo)?;
    let key = HsmKeyManager::generate_key(session, &mut aes_algo, key_props)?;
    let handle = HANDLE_TABLE.alloc_handle(HandleType::AesXtsKey, Box::new(key));

    Ok(handle)
}

/// Unmasks a masked AES-XTS key and returns a handle to it
///
/// Takes a masked AES-XTS key pair (typically received from external storage or transmission)
/// and unmasks it within the HSM session, creating a usable key handle. The masked key
/// contains both the tweak key and data encryption key in the XTS key pair format.
///
/// # Arguments
/// * `session` - Reference to the HSM session where the key will be unmasked
/// * `masked_key` - Byte slice containing the masked XTS key pair material
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the unmasked AES-XTS key for subsequent cryptographic operations
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn aes_xts_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<AzihsmHandle, AzihsmStatus> {
    let mut unmask_algo = HsmAesXtsKeyUnmaskAlgo::default();

    // Unmask AES-XTS key
    let key: HsmAesXtsKey = HsmKeyManager::unmask_key(session, &mut unmask_algo, masked_key)?;

    let handle = HANDLE_TABLE.alloc_handle(HandleType::AesXtsKey, Box::new(key));

    Ok(handle)
}
