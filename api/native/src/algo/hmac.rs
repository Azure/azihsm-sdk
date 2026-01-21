// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_api::*;

use crate::AzihsmBuffer;
use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::validate_output_buffer;

/// Computes an HMAC signature for the given data
///
/// Single-shot operation that signs data using HMAC with the specified key.
///
/// # Arguments
/// * `key_handle` - Handle to the HMAC key
/// * `data` - Input data to sign
/// * `output` - Output buffer for the HMAC signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid key, buffer too small)
pub(crate) fn hmac_sign(
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
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

/// Verifies an HMAC signature for the given data
///
/// Single-shot operation that verifies an HMAC signature matches the provided data.
///
/// # Arguments
/// * `key_handle` - Handle to the HMAC key
/// * `data` - Input data to verify
/// * `signature` - Expected HMAC signature to verify against
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid key, invalid signature format)
pub(crate) fn hmac_verify(
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmStatus> {
    // Get the key from handle
    let key = &HsmHmacKey::try_from(key_handle)?;

    // Create HMAC algorithm
    let mut algo = HsmHmacAlgo::new();

    // Verify the signature
    Ok(HsmVerifier::verify(&mut algo, key, data, sig)?)
}

/// Initializes a streaming HMAC signing operation
///
/// Creates a context for incrementally computing an HMAC signature.
/// Use with `hmac_sign_update` and `hmac_sign_final`.
///
/// # Arguments
/// * `key_handle` - Handle to the HMAC key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the signing context
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid key)
pub(crate) fn hmac_sign_init(key_handle: AzihsmHandle) -> Result<AzihsmHandle, AzihsmStatus> {
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

/// Updates a streaming HMAC signing operation with additional data
///
/// Processes a chunk of data in an incremental HMAC signature computation.
///
/// # Arguments
/// * `ctx_handle` - Handle to the signing context
/// * `data` - Data chunk to include in the signature
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid context)
pub(crate) fn hmac_sign_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmHmacSignContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::HmacSignStreamingCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

/// Finalizes a streaming HMAC signing operation
///
/// Completes the HMAC signature computation and returns the final signature.
///
/// # Arguments
/// * `ctx_handle` - Handle to the signing context
/// * `output` - Output buffer for the HMAC signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(AzihsmStatus)` - On failure (e.g., buffer too small)
pub(crate) fn hmac_sign_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
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

/// Initializes a streaming HMAC verification operation
///
/// Creates a context for incrementally verifying an HMAC signature.
/// Use with `hmac_verify_update` and `hmac_verify_final`.
///
/// # Arguments
/// * `key_handle` - Handle to the HMAC key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the verification context
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid key)
pub(crate) fn hmac_verify_init(key_handle: AzihsmHandle) -> Result<AzihsmHandle, AzihsmStatus> {
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

/// Updates a streaming HMAC verification operation with additional data
///
/// Processes a chunk of data in an incremental HMAC signature verification.
///
/// # Arguments
/// * `ctx_handle` - Handle to the verification context
/// * `data` - Data chunk to include in the verification
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid context)
pub(crate) fn hmac_verify_update(
    ctx_handle: AzihsmHandle,
    data: &[u8],
) -> Result<(), AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmHmacVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::HmacVerifyStreamingCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;
    Ok(())
}

/// Finalizes a streaming HMAC verification operation
///
/// Completes the HMAC verification and checks if the signature matches.
///
/// # Arguments
/// * `ctx_handle` - Handle to the verification context
/// * `signature` - Expected HMAC signature to verify against
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn hmac_verify_final(
    ctx_handle: AzihsmHandle,
    signature: &[u8],
) -> Result<bool, AzihsmStatus> {
    // Take ownership of the context and finalize
    let mut ctx: Box<HsmHmacVerifyContext> =
        HANDLE_TABLE.free_handle(ctx_handle, HandleType::HmacVerifyStreamingCtx)?;

    // Perform the final verification operation
    let is_valid = ctx.finish(signature)?;

    Ok(is_valid)
}
