// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;

use super::*;
use crate::AzihsmBuffer;
use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::validate_output_buffer;

impl TryFrom<&AzihsmAlgo> for HsmEccKeyGenAlgo {
    type Error = AzihsmStatus;

    /// Converts a C FFI algorithm specification to HsmEccKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmEccKeyGenAlgo::default())
    }
}

/// Helper function to generate an ECC key pair
pub(crate) fn ecc_generate_key_pair(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmStatus> {
    let mut ecc_algo = HsmEccKeyGenAlgo::try_from(algo)?;
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut ecc_algo, priv_key_props, pub_key_props)?;

    let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPrivKey, Box::new(priv_key));
    let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPubKey, Box::new(pub_key));

    Ok((priv_handle, pub_handle))
}

/// Unmask a masked ECC key pair
pub(crate) fn ecc_unmask_key_pair(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmStatus> {
    let mut unmask_algo = HsmEccKeyUnmaskAlgo::default();

    // Unmask ECC key pair
    let (priv_key, pub_key): (HsmEccPrivateKey, HsmEccPublicKey) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, masked_key)?;

    let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPrivKey, Box::new(priv_key));
    let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPubKey, Box::new(pub_key));

    Ok((priv_handle, pub_handle))
}

/// Generate a key report for an ECC private key
pub(crate) fn ecc_generate_key_report(
    key_handle: AzihsmHandle,
    report_data: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the key from handle
    let key = &HsmEccPrivateKey::try_from(key_handle)?;

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
