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

/// Generic helper function to perform ECC signing operation
fn sign_with_algo<A>(
    mut algo: A,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus>
where
    A: HsmSignOp<Key = HsmEccPrivateKey, Error = HsmError>,
{
    // Get the key from handle
    let key = &HsmEccPrivateKey::try_from(key_handle)?;

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

/// Generic helper function to perform ECC verification operation
fn verify_with_algo<A>(
    mut algo: A,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmStatus>
where
    A: HsmVerifyOp<Key = HsmEccPublicKey, Error = HsmError>,
{
    // Get the key from handle
    let key = &HsmEccPublicKey::try_from(key_handle)?;

    Ok(HsmVerifier::verify(&mut algo, key, data, sig)?)
}

/// Signs pre-hashed data using ECDSA
///
/// Single-shot operation that signs already-hashed data with an ECC private key.
///
/// # Arguments
/// * `key_handle` - Handle to the ECC private key
/// * `hash` - Pre-computed hash of the message
/// * `output` - Output buffer for the signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid key, buffer too small)
pub(crate) fn ecc_sign(
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    sign_with_algo(HsmEccSignAlgo::default(), key_handle, input, output)
}

/// Signs a message using ECDSA with automatic hashing
///
/// Single-shot operation that hashes the message and signs with an ECC private key.
///
/// # Arguments
/// * `hash_algo` - Hash algorithm to use for the message
/// * `key_handle` - Handle to the ECC private key
/// * `message` - Raw message to hash and sign
/// * `output` - Output buffer for the signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn ecc_hash_sign(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    sign_with_algo(HsmHashSignAlgo::new(hash_algo), key_handle, input, output)
}

/// Verifies an ECDSA signature on pre-hashed data
///
/// Single-shot operation that verifies a signature against already-hashed data.
///
/// # Arguments
/// * `key_handle` - Handle to the ECC public key
/// * `hash` - Pre-computed hash of the message
/// * `signature` - Signature to verify
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn ecc_verify(
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmStatus> {
    verify_with_algo(HsmEccSignAlgo::default(), key_handle, data, sig)
}

/// Verifies an ECDSA signature on a message with automatic hashing
///
/// Single-shot operation that hashes the message and verifies the signature.
///
/// # Arguments
/// * `hash_algo` - Hash algorithm to use for the message
/// * `key_handle` - Handle to the ECC public key
/// * `message` - Raw message to hash and verify
/// * `signature` - Signature to verify
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn ecc_hash_verify(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    verify_with_algo(HsmHashSignAlgo::new(hash_algo), key_handle, data, sig)
}

/// Initializes a streaming ECDSA signing operation
///
/// Creates a context for incrementally signing data with an ECC private key.
/// Use with `ecc_sign_update` and `ecc_sign_finish`.
///
/// # Arguments
/// * `hash_algo` - Hash algorithm to use
/// * `key_handle` - Handle to the ECC private key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the signing context
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn ecc_sign_init(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;

    // Get the key from handle
    let key = HsmEccPrivateKey::try_from(key_handle)?;

    // Create the signing algorithm
    let sign_algo = HsmHashSignAlgo::new(hash_algo);

    // Initialize the streaming signing context
    let ctx = HsmSigner::sign_init(sign_algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::EccSignCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Updates a streaming ECDSA signing operation with additional data
///
/// Processes a chunk of data in an incremental signing operation.
///
/// # Arguments
/// * `ctx_handle` - Handle to the signing context
/// * `data` - Data chunk to include in the signature
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn ecc_sign_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmEccSignContext = HANDLE_TABLE.as_mut(ctx_handle, HandleType::EccSignCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

/// Finishes a streaming ECDSA signing operation
///
/// Completes the signature computation and returns the final signature.
///
/// # Arguments
/// * `ctx_handle` - Handle to the signing context
/// * `output` - Output buffer for the signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn ecc_sign_finish(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get a reference to determine the required signature size
    let ctx_ref: &mut HsmEccSignContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::EccSignCtx)?;
    let required_size = ctx_ref.finish(None)?;

    // Check if output buffer is large enough
    let output_data = validate_output_buffer(output, required_size)?;

    // Perform the final signing operation
    let sig_len = ctx_ref.finish(Some(output_data))?;

    // Update the output buffer length with actual signature length
    output.len = sig_len as u32;

    Ok(())
}

/// Initializes a streaming ECDSA verification operation
///
/// Creates a context for incrementally verifying a signature with an ECC public key.
/// Use with `ecc_verify_update` and `ecc_verify_finish`.
///
/// # Arguments
/// * `hash_algo` - Hash algorithm to use
/// * `key_handle` - Handle to the ECC public key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the verification context
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn ecc_verify_init(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;

    // Get the key from handle
    let key = HsmEccPublicKey::try_from(key_handle)?;

    // Create the verification algorithm
    let verify_algo = HsmHashSignAlgo::new(hash_algo);

    // Initialize the streaming verification context
    let ctx = HsmVerifier::verify_init(verify_algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::EccVerifyCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Updates a streaming ECDSA verification operation with additional data
///
/// Processes a chunk of data in an incremental verification operation.
///
/// # Arguments
/// * `ctx_handle` - Handle to the verification context
/// * `data` - Data chunk to include in the verification
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn ecc_verify_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmEccVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::EccVerifyCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

/// Finishes a streaming ECDSA verification operation
///
/// Completes the verification and checks if the signature is valid.
///
/// # Arguments
/// * `ctx_handle` - Handle to the verification context
/// * `signature` - Signature to verify against
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn ecc_verify_finish(
    ctx_handle: AzihsmHandle,
    signature: &[u8],
) -> Result<bool, AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmEccVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::EccVerifyCtx)?;

    // Perform the final verification operation
    let is_valid = ctx.finish(signature)?;

    Ok(is_valid)
}
