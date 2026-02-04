// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_api::*;

use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;

impl TryFrom<AzihsmHandle> for HsmGenericSecretKey {
    type Error = AzihsmStatus;

    fn try_from(handle: AzihsmHandle) -> Result<Self, Self::Error> {
        let key: &HsmGenericSecretKey =
            HANDLE_TABLE.as_ref(handle, HandleType::GenericSecretKey)?;
        Ok(key.clone())
    }
}

/// Unmasks a generic secret key
///
/// Imports a previously masked (encrypted/protected) generic secret key back into the HSM.
/// The masked key contains the key material and properties, so no external properties
/// are needed.
///
/// # Arguments
/// * `session` - HSM session for the unmask operation
/// * `masked_key` - Byte slice containing the masked key material
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the unmasked generic secret key for subsequent operations
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn secret_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<AzihsmHandle, AzihsmStatus> {
    let mut unmask_algo = HsmGenericSecretKeyUnmaskAlgo::default();

    // Unmask generic secret key
    let key: HsmGenericSecretKey =
        HsmKeyManager::unmask_key(session, &mut unmask_algo, masked_key)?;

    let handle = HANDLE_TABLE.alloc_handle(HandleType::GenericSecretKey, Box::new(key));

    Ok(handle)
}
