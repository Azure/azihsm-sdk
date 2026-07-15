// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;

use super::*;
use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::validate_algo_params_absent;

impl TryFrom<&AzihsmAlgo> for HsmSealingKeyGenAlgo {
    type Error = AzihsmStatus;

    /// Converts a C FFI algorithm specification to HsmSealingKeyGenAlgo.
    fn try_from(algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        // Sealing key generation has no algorithm-specific parameter
        // struct in the C ABI. Enforce `params == NULL` and `len == 0`
        // to reject malformed caller input.
        validate_algo_params_absent(algo)?;
        Ok(HsmSealingKeyGenAlgo::default())
    }
}

/// Generates a new security-domain sealing key.
///
/// # Arguments
/// * `session` - HSM session for key generation
/// * `algo` - Sealing key generation algorithm parameters (none)
/// * `key_props` - Properties for the generated key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the generated sealing key
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid session or props)
pub(crate) fn sealing_generate_key(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let mut sealing_algo = HsmSealingKeyGenAlgo::try_from(algo)?;
    let key = HsmKeyManager::generate_key(session, &mut sealing_algo, key_props)?;
    Ok(HANDLE_TABLE.alloc_handle(HandleType::SealingKey, Box::new(key)))
}
