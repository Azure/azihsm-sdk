// Copyright (C) Microsoft Corporation. All rights reserved.

use algo::sha::*;
use api::HsmHashAlgo;
use azihsm_napi::HsmSession;

use super::*;

/// Compute cryptographic digest (hash) of data using the specified algorithm.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] data Pointer to data buffer to be hashed
/// @param[out] digest Pointer to digest output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// the function returns the AZIHSM_ERROR_INSUFFICIENT_BUFFER error.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_digest(
    sess_handle: AzihsmHandle,
    algo: *const AzihsmAlgo,
    data: *const AzihsmBuffer,
    digest: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let algo_spec = deref_ptr(algo)?;
        let input_buf = deref_ptr(data)?;
        let output_buf = deref_mut_ptr(digest)?;
        let session: HsmSession = HsmSession::try_from(sess_handle)?;
        let input_data: &[u8] = input_buf.try_into()?;

        // Match on algorithm ID and call appropriate handler
        match algo_spec.id {
            AzihsmAlgoId::Sha1 => {
                sha_digest(&session, HsmHashAlgo::Sha1, input_data, output_buf)?;
            }
            AzihsmAlgoId::Sha256 => {
                sha_digest(&session, HsmHashAlgo::Sha256, input_data, output_buf)?;
            }
            AzihsmAlgoId::Sha384 => {
                sha_digest(&session, HsmHashAlgo::Sha384, input_data, output_buf)?;
            }
            AzihsmAlgoId::Sha512 => {
                sha_digest(&session, HsmHashAlgo::Sha512, input_data, output_buf)?;
            }
            _ => return Err(AzihsmError::InvalidArgument),
        }

        Ok(())
    })
}

/// Initialize a streaming digest operation.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[out] ctx_handle Pointer to receive the digest context handle
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_digest_init(
    sess_handle: AzihsmHandle,
    algo: *const AzihsmAlgo,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_ptr(ctx_handle)?;
        let algo_spec = deref_ptr(algo)?;
        let ctx_handle_out = deref_mut_ptr(ctx_handle)?;

        // Get session from handle table
        let session: HsmSession = HsmSession::try_from(sess_handle)?;

        // Match on algorithm ID and call appropriate handler
        let handle = match algo_spec.id {
            AzihsmAlgoId::Sha1 => sha_digest_init(session, HsmHashAlgo::Sha1)?,
            AzihsmAlgoId::Sha256 => sha_digest_init(session, HsmHashAlgo::Sha256)?,
            AzihsmAlgoId::Sha384 => sha_digest_init(session, HsmHashAlgo::Sha384)?,
            AzihsmAlgoId::Sha512 => sha_digest_init(session, HsmHashAlgo::Sha512)?,
            _ => return Err(AzihsmError::InvalidArgument),
        };

        // Return the handle
        assign_ptr(ctx_handle_out, handle)?;

        Ok(())
    })
}

/// Update a streaming digest operation with more data.
///
/// @param[in] ctx_handle Handle to the digest context
/// @param[in] data Pointer to data buffer to digest
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_digest_update(
    ctx_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let data_buf = deref_ptr(data)?;
        let input_data: &[u8] = data_buf.try_into()?;
        let ctx_type = HandleType::try_from(ctx_handle)?;

        match ctx_type {
            HandleType::ShaStreamingCtx => {
                sha_digest_update(ctx_handle, input_data)?;
            }
            // Add support for other context types here as needed (HMAC, etc.)
            _ => Err(AzihsmError::InvalidHandle)?,
        }

        Ok(())
    })
}

/// Finalize a streaming digest operation and produce the digest.
///
/// @param[in] ctx_handle Handle to the digest context
/// @param[out] digest Pointer to digest output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// AZIHSM_ERROR_INSUFFICIENT_BUFFER is returned.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_digest_final(
    ctx_handle: AzihsmHandle,
    digest: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let digest_buf = deref_mut_ptr(digest)?;
        let ctx_type = HandleType::try_from(ctx_handle)?;

        match ctx_type {
            HandleType::ShaStreamingCtx => {
                sha_digest_final(ctx_handle, digest_buf)?;
            }
            // Add support for other context types here as needed (HMAC, etc.)
            _ => Err(AzihsmError::InvalidHandle)?,
        }

        Ok(())
    })
}
