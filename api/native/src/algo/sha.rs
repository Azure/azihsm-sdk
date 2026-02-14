// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;

use crate::AzihsmBuffer;
use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::validate_output_buffer;

/// Computes a SHA hash digest of the input data
///
/// Single-shot operation that computes the hash of the entire input.
///
/// # Arguments
/// * `session` - HSM session for the operation
/// * `hash_algo` - Hash algorithm to use (SHA-256, SHA-384, SHA-512, etc.)
/// * `data` - Input data to hash
/// * `output` - Output buffer for the hash digest
///
/// # Returns
/// * `Ok(())` - On successful hash computation
/// * `Err(AzihsmStatus)` - On failure (e.g., unsupported algorithm, buffer too small)
pub(crate) fn sha_digest(
    session: &HsmSession,
    hash_algo: HsmHashAlgo,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    let mut hash_algo = hash_algo;

    // Get the required output size by calling with None
    let required_size = HsmHasher::hash(session, &mut hash_algo, input, None)?;

    // Validate output buffer and get mutable slice
    let output_data = validate_output_buffer(output, required_size)?;

    // Perform the actual hash operation
    let bytes_written = HsmHasher::hash(session, &mut hash_algo, input, Some(output_data))?;

    // Update output buffer length to actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Initializes a streaming SHA hash operation
///
/// Creates a context for incrementally computing a hash digest.
/// Use with `sha_digest_update` and `sha_digest_finish`.
///
/// # Arguments
/// * `session` - HSM session for the operation
/// * `hash_algo` - Hash algorithm to use (SHA-256, SHA-384, SHA-512, etc.)
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the hash context
/// * `Err(AzihsmStatus)` - On failure (e.g., unsupported algorithm)
pub(crate) fn sha_digest_init(
    session: HsmSession,
    hash_algo: HsmHashAlgo,
) -> Result<AzihsmHandle, AzihsmStatus> {
    // Initialize streaming hash context
    let context = HsmHasher::hash_init(session, hash_algo)?;

    // Allocate handle for the context
    let handle = HANDLE_TABLE.alloc_handle(HandleType::ShaCtx, Box::new(context));

    Ok(handle)
}

/// Updates a streaming SHA hash operation with additional data
///
/// Processes a chunk of data in an incremental hash computation.
///
/// # Arguments
/// * `ctx_handle` - Handle to the hash context
/// * `data` - Data chunk to include in the hash
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid context)
pub(crate) fn sha_digest_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmHashContext = HANDLE_TABLE.as_mut(ctx_handle, HandleType::ShaCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

/// Finishes a streaming SHA hash operation
///
/// Completes the hash computation and returns the final digest.
///
/// # Arguments
/// * `ctx_handle` - Handle to the hash context
/// * `output` - Output buffer for the hash digest
///
/// # Returns
/// * `Ok(())` - On successful hash computation
/// * `Err(AzihsmStatus)` - On failure (e.g., buffer too small)
pub(crate) fn sha_digest_finish(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get a reference to determine the required digest size
    let ctx: &mut HsmHashContext = HANDLE_TABLE.as_mut(ctx_handle, HandleType::ShaCtx)?;
    let required_size = ctx.finish(None)?;

    // Validate output buffer and get mutable slice
    let output_data = validate_output_buffer(output, required_size)?;

    // Perform the final hash operation
    let digest_len = ctx.finish(Some(output_data))?;

    // Update output buffer length with actual digest length
    output.len = digest_len as u32;

    Ok(())
}
