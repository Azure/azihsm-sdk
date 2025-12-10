// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(unsafe_code)]

use crate::bindings::ffi_types::AzihsmAlgo;
use crate::bindings::ffi_types::AzihsmBuffer;
use crate::bindings::HANDLE_TABLE;
use crate::crypto::sha::ShaAlgo;
use crate::crypto::sha::ShaDigestStream;
use crate::crypto::DigestOp;
use crate::crypto::StreamingDigestOp;
use crate::types::AlgoId;
use crate::*;

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
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_digest(
    sess_handle: AzihsmHandle,
    algo: *const AzihsmAlgo,
    data: *const AzihsmBuffer,
    digest: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, data, digest);

        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;

        let algo_spec: &AzihsmAlgo = deref_const_ptr!(algo);

        let data_buf = deref_const_ptr!(data);

        let digest_buf = deref_mut_ptr!(digest);

        validate_buffer!(data_buf);

        let input_data = data_buf.as_slice()?;

        // Get Support hash function and required output length
        let mut sha_algo = ShaAlgo { algo: algo_spec.id };
        let required_len = sha_algo.digest_len()?;

        // Check if output buffer is sufficient, update length if needed
        let digest_data = prepare_output_buffer(digest_buf, required_len)?;

        // Perform the digest operation
        sha_algo.digest(session, input_data, digest_data)
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
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_digest_init(
    sess_handle: AzihsmHandle,
    algo: *const AzihsmAlgo,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, ctx_handle);

        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let algo_spec: &AzihsmAlgo = deref_const_ptr!(algo);

        // Create digest stream based on algorithm
        match algo_spec.id {
            AlgoId::Sha1 | AlgoId::Sha256 | AlgoId::Sha384 | AlgoId::Sha512 => {
                let sha_algo = ShaAlgo { algo: algo_spec.id };
                let digest_stream = session.digest_init(&sha_algo)?;

                write_to_out_ptr!(
                    ctx_handle,
                    HANDLE_TABLE
                        .alloc_handle(HandleType::ShaStreamingContext, Box::new(digest_stream))
                );
            }
            // Future: Add support for other digest algorithms
            _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
        }

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
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_digest_update(
    ctx_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(data);
        let data_buf = deref_const_ptr!(data);

        validate_buffer!(data_buf);
        let input_data = data_buf.as_slice()?;

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::ShaStreamingContext => {
                let sha_stream: &mut ShaDigestStream =
                    HANDLE_TABLE.as_mut(ctx_handle, HandleType::ShaStreamingContext)?;

                // Update digest with new data
                sha_stream.update(input_data)?;
            }
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
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
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_digest_final(
    ctx_handle: AzihsmHandle,
    digest: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(digest);
        let digest_buf = deref_mut_ptr!(digest);

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::ShaStreamingContext => {
                // Check what output size is needed
                let digest_stream_ref: &ShaDigestStream =
                    HANDLE_TABLE.as_ref(ctx_handle, HandleType::ShaStreamingContext)?;

                // Get required digest length
                let required_len = digest_stream_ref.digest_len() as u32;

                // Prepare output buffer (handles size query and validation)
                let digest_data = prepare_output_buffer(digest_buf, required_len)?;

                // Now that buffer is validated, take ownership and finalize
                let digest_stream: ShaDigestStream =
                    *HANDLE_TABLE.free_handle(ctx_handle, HandleType::ShaStreamingContext)?;

                // Finalize and get digest
                let bytes_written = digest_stream.finalize(digest_data)?;

                // Update output buffer length
                digest_buf.len = bytes_written as u32;
            }
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}
