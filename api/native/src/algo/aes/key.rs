// Copyright (C) Microsoft Corporation. All rights reserved.

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

impl TryFrom<&AzihsmAlgo> for azihsm_api::HsmAesGcmKeyGenAlgo {
    type Error = AzihsmStatus;

    /// Converts a C FFI algorithm specification to HsmAesGcmKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmAesGcmKeyGenAlgo::default())
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
    let handle = match key_props.kind() {
        HsmKeyKind::Aes => {
            let mut aes_algo = HsmAesKeyGenAlgo::try_from(algo)?;
            let key = HsmKeyManager::generate_key(session, &mut aes_algo, key_props)?;
            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(key))
        }
        HsmKeyKind::AesXts => {
            let mut aes_algo = HsmAesXtsKeyGenAlgo::try_from(algo)?;
            let key = HsmKeyManager::generate_key(session, &mut aes_algo, key_props)?;
            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(key))
        }
        HsmKeyKind::AesGcm => {
            let mut aes_algo = HsmAesGcmKeyGenAlgo::try_from(algo)?;
            let key = HsmKeyManager::generate_key(session, &mut aes_algo, key_props)?;
            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(key))
        }
        _ => Err(AzihsmStatus::UnsupportedKeyKind)?,
    };

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
    let key: HsmGenericSecretKey =
        HsmKeyManager::unmask_key(session, &mut HsmAesKeyUnmaskAlgo::default(), masked_key)?;
    let handle = match key.props().kind() {
        HsmKeyKind::Aes => {
            let aes_key: HsmAesKey = key.try_into()?;
            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(aes_key))
        }
        HsmKeyKind::AesXts => {
            let xts_key: HsmAesXtsKey = key.try_into()?;
            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(xts_key))
        }
        HsmKeyKind::AesGcm => {
            let gcm_key: HsmAesGcmKey = key.try_into()?;
            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(gcm_key))
        }
        _ => Err(AzihsmStatus::UnsupportedKeyKind)?,
    };

    Ok(handle)
}
