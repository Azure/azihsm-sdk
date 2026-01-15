// Copyright (C) Microsoft Corporation. All rights reserved.

use api::HsmHashAlgo;
use api::HsmHasher;
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

        let mut hash_algo = match algo_spec.id {
            AzihsmAlgoId::Sha1 => HsmHashAlgo::Sha1,
            AzihsmAlgoId::Sha256 => HsmHashAlgo::Sha256,
            AzihsmAlgoId::Sha384 => HsmHashAlgo::Sha384,
            AzihsmAlgoId::Sha512 => HsmHashAlgo::Sha512,
            _ => return Err(AzihsmError::InvalidArgument),
        };

        // Get the required output size by calling with None
        let required_size = HsmHasher::hash(&session, &mut hash_algo, input_data, None)?;

        // Validate output buffer and get mutable slice
        let output_data = validate_output_buffer(output_buf, required_size)?;

        // Perform the actual hash operation
        let bytes_written =
            HsmHasher::hash(&session, &mut hash_algo, input_data, Some(output_data))?;

        // Update output buffer length to actual bytes written
        output_buf.len = bytes_written as u32;

        Ok(())
    })
}
