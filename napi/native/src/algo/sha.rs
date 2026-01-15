// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use crate::AzihsmBuffer;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::validate_output_buffer;

/// Helper function to compute SHA digest of data
pub(crate) fn sha_digest(
    session: &HsmSession,
    hash_algo: HsmHashAlgo,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
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

/// Helper function to initialize a streaming SHA digest operation
pub(crate) fn sha_digest_init(
    session: HsmSession,
    hash_algo: HsmHashAlgo,
) -> Result<AzihsmHandle, AzihsmError> {
    // Initialize streaming hash context
    let context = HsmHasher::hash_init(session, hash_algo)?;

    // Allocate handle for the context
    let handle = HANDLE_TABLE.alloc_handle(HandleType::ShaStreamingCtx, Box::new(context));

    Ok(handle)
}

/// Helper function to update a streaming digest operation with more data
pub(crate) fn sha_digest_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmError> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmHashContext = HANDLE_TABLE.as_mut(ctx_handle, HandleType::ShaStreamingCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

/// Helper function to finalize a streaming digest operation and produce the digest
pub(crate) fn sha_digest_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    // Get a reference to determine the required digest size
    let ctx_ref: &mut HsmHashContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::ShaStreamingCtx)?;
    let required_size = ctx_ref.finish(None)?;

    // Validate output buffer and get mutable slice
    let output_data = validate_output_buffer(output, required_size)?;

    // Take ownership of the context and finalize
    let mut ctx: Box<HsmHashContext> =
        HANDLE_TABLE.free_handle(ctx_handle, HandleType::ShaStreamingCtx)?;

    // Perform the final hash operation
    let digest_len = ctx.finish(Some(output_data))?;

    // Update output buffer length with actual digest length
    output.len = digest_len as u32;

    Ok(())
}
