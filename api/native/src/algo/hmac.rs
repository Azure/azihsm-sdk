// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_api::*;

use crate::AzihsmBuffer;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
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

/// Initialize streaming HMAC sign operation
pub(crate) fn hmac_sign_init(key_handle: AzihsmHandle) -> Result<AzihsmHandle, AzihsmError> {
    // Get the key from handle
    let key = HsmHmacKey::try_from(key_handle)?;

    // Create the HMAC algorithm
    let algo = HsmHmacAlgo::new();

    // Initialize the streaming signing context
    let ctx = HsmSigner::sign_init(algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::HmacSignStreamingCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Update streaming HMAC sign operation with additional data
pub(crate) fn hmac_sign_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmError> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmHmacSignContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::HmacSignStreamingCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

/// Finalize streaming HMAC sign operation and retrieve signature
pub(crate) fn hmac_sign_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    // Get a reference to determine the required signature size
    let ctx_ref: &mut HsmHmacSignContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::HmacSignStreamingCtx)?;
    let required_size = ctx_ref.finish(None)?;

    // Check if output buffer is large enough
    let output_data = validate_output_buffer(output, required_size)?;

    // Take ownership of the context and finalize
    let mut ctx: Box<HsmHmacSignContext> =
        HANDLE_TABLE.free_handle(ctx_handle, HandleType::HmacSignStreamingCtx)?;

    // Perform the final signing operation
    let sig_len = ctx.finish(Some(output_data))?;

    // Update the output buffer length with actual signature length
    output.len = sig_len as u32;

    Ok(())
}

/// Initialize streaming HMAC verify operation
pub(crate) fn hmac_verify_init(key_handle: AzihsmHandle) -> Result<AzihsmHandle, AzihsmError> {
    // Get the key from handle
    let key = HsmHmacKey::try_from(key_handle)?;

    // Create the HMAC algorithm
    let algo = HsmHmacAlgo::new();

    // Initialize the streaming verification context
    let ctx = HsmVerifier::verify_init(algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::HmacVerifyStreamingCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Update streaming HMAC verify operation with additional data
pub(crate) fn hmac_verify_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmError> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmHmacVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::HmacVerifyStreamingCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;
    Ok(())
}

/// Finalize streaming HMAC verify operation and verify signature
pub(crate) fn hmac_verify_final(
    ctx_handle: AzihsmHandle,
    signature: &[u8],
) -> Result<bool, AzihsmError> {
    // Take ownership of the context and finalize
    let mut ctx: Box<HsmHmacVerifyContext> =
        HANDLE_TABLE.free_handle(ctx_handle, HandleType::HmacVerifyStreamingCtx)?;

    // Perform the final verification operation
    let is_valid = ctx.finish(signature)?;

    Ok(is_valid)
}
