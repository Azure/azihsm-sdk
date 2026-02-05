// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_api::*;

use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;

/// Unmasks an HMAC key
///
/// Imports a previously masked (encrypted/protected) HMAC key back into the HSM.
/// The masked key contains the key material and properties, so no external properties
/// are needed.
///
/// # Arguments
/// * `session` - HSM session for the unmask operation
/// * `masked_key` - Byte slice containing the masked key material
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the unmasked HMAC key for subsequent operations
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn hmac_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<AzihsmHandle, AzihsmStatus> {
    let mut unmask_algo = HsmHmacKeyUnmaskAlgo::default();

    // Unmask HMAC key
    let key: HsmHmacKey = HsmKeyManager::unmask_key(session, &mut unmask_algo, masked_key)?;

    let handle = HANDLE_TABLE.alloc_handle(HandleType::HmacKey, Box::new(key));

    Ok(handle)
}
