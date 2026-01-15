// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use crate::AzihsmBuffer;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::utils::validate_output_buffer;

/// Helper function to perform HMAC signing operation
pub(crate) fn hmac_sign(
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    // Get the key from handle
    let key = &HsmHmacKey::try_from(key_handle)?;

    // Create HMAC algorithm
    let mut algo = HsmHmacAlgo::new();

    // Determine required size
    let required_size = HsmSigner::sign(&mut algo, key, input, None)?;

    // Validate and get output buffer
    let output_data = validate_output_buffer(output, required_size)?;

    // Perform actual signing
    let sig_len = HsmSigner::sign(&mut algo, key, input, Some(output_data))?;

    // Update output buffer length
    output.len = sig_len as u32;

    Ok(())
}

/// Helper function to perform HMAC verification operation
pub(crate) fn hmac_verify(
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmError> {
    // Get the key from handle
    let key = &HsmHmacKey::try_from(key_handle)?;

    // Create HMAC algorithm
    let mut algo = HsmHmacAlgo::new();

    // Verify the signature
    Ok(HsmVerifier::verify(&mut algo, key, data, sig)?)
}
