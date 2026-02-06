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
use crate::utils::validate_ptr;

/// AES CBC parameters.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoAesCbcParams {
    /// IV
    pub iv: [u8; 16],
}

impl<'a> TryFrom<&'a mut AzihsmAlgo> for &'a mut AzihsmAlgoAesCbcParams {
    type Error = AzihsmStatus;

    /// Extracts a mutable reference to AES-CBC parameters from the algorithm specification.
    ///
    /// # Safety
    /// The caller must ensure that `algo.params` points to valid `AzihsmAlgoAesCbcParams` data
    /// when the algorithm ID is AES-CBC or AES-CBC with padding.
    #[allow(unsafe_code)]
    fn try_from(algo: &'a mut AzihsmAlgo) -> Result<Self, Self::Error> {
        // Check for null pointer
        validate_ptr(algo.params)?;

        // Safety: algo.params is validated to be non-null
        let params = crate::utils::deref_mut_ptr::<AzihsmAlgoAesCbcParams>(
            algo.params as *mut AzihsmAlgoAesCbcParams,
        )?;

        Ok(params)
    }
}

/// AES CBC encryption context
pub(crate) struct AesCbcEncryptContext {
    context: HsmAesCbcEncryptContext,
    params: *mut AzihsmAlgoAesCbcParams,
}

impl AesCbcEncryptContext {
    /// Create a new encryption context
    fn new(ctx: HsmAesCbcEncryptContext, params: &mut AzihsmAlgoAesCbcParams) -> Self {
        Self {
            context: ctx,
            params: params as *mut AzihsmAlgoAesCbcParams,
        }
    }

    /// Update the context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.context.update(input, output)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Finalize the context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.context.finish(output)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Update the IV in the caller's parameters
    fn update_iv(&mut self) -> Result<(), AzihsmStatus> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.iv.copy_from_slice(self.context.algo().iv());
        Ok(())
    }
}

/// AES CBC decryption context
pub(crate) struct AesCbcDecryptContext {
    context: HsmAesCbcDecryptContext,
    params: *mut AzihsmAlgoAesCbcParams,
}

impl AesCbcDecryptContext {
    /// Create a new decryption context
    fn new(ctx: HsmAesCbcDecryptContext, params: &mut AzihsmAlgoAesCbcParams) -> Self {
        Self {
            context: ctx,
            params: params as *mut AzihsmAlgoAesCbcParams,
        }
    }

    /// Update the context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.context.update(input, output)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Finalize the context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.context.finish(output)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Update the IV in the caller's parameters
    fn update_iv(&mut self) -> Result<(), AzihsmStatus> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.iv.copy_from_slice(self.context.algo().iv());
        Ok(())
    }
}

/// Encrypt data using AES CBC
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CBC)
/// * `key_handle` - Handle to the AES key
/// * `plain_text` - Plaintext input buffer
/// * `cipher_text` - Ciphertext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_cbc_encrypt(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    plain_text: &[u8],
    cipher_text: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    if algo.id != AzihsmAlgoId::AesCbc && algo.id != AzihsmAlgoId::AesCbcPad {
        Err(AzihsmStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    let algo_id = algo.id;
    let params: &mut AzihsmAlgoAesCbcParams = algo.try_into()?;
    let iv = params.iv.to_vec();

    // Create AES-CBC algorithm based on padding mode
    let mut aes_algo = if algo_id == AzihsmAlgoId::AesCbcPad {
        HsmAesCbcAlgo::with_padding(iv)?
    } else {
        HsmAesCbcAlgo::with_no_padding(iv)?
    };

    // Query required output length first
    let required_len = HsmEncrypter::encrypt(&mut aes_algo, key, plain_text, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(cipher_text, required_len)?;

    // Perform actual encryption
    let written = HsmEncrypter::encrypt(&mut aes_algo, key, plain_text, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    cipher_text.len = written as u32;

    // Update the IV
    params.iv.copy_from_slice(aes_algo.iv());

    Ok(())
}

/// Decrypt data using AES CBC
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CBC)
/// * `key_handle` - Handle to the AES key
/// * `cipher_text` - Ciphertext input buffer
/// * `plain_text` - Plaintext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_cbc_decrypt(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    cipher_text: &[u8],
    plain_text: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    if algo.id != AzihsmAlgoId::AesCbc && algo.id != AzihsmAlgoId::AesCbcPad {
        Err(AzihsmStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    let algo_id = algo.id;
    let params: &mut AzihsmAlgoAesCbcParams = algo.try_into()?;
    let iv = params.iv.to_vec();

    // Create AES-CBC algorithm based on padding mode
    let mut aes_algo = if algo_id == AzihsmAlgoId::AesCbcPad {
        HsmAesCbcAlgo::with_padding(iv)?
    } else {
        HsmAesCbcAlgo::with_no_padding(iv)?
    };

    // Query required output length first
    let required_len = HsmDecrypter::decrypt(&mut aes_algo, key, cipher_text, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(plain_text, required_len)?;

    // Perform actual decryption
    let written = HsmDecrypter::decrypt(&mut aes_algo, key, cipher_text, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    plain_text.len = written as u32;

    // Update the IV
    params.iv.copy_from_slice(aes_algo.iv());

    Ok(())
}

/// Initialize AES CBC encryption
///
/// Creates an encryption context that can process data incrementally.
/// The context should be used with update and finalize operations.
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CBC or AES CBC with padding)
/// * `key_handle` - Handle to the AES key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the encryption context for subsequent operations
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn aes_cbc_encrypt_init(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    let algo_id = algo.id;
    let params: &mut AzihsmAlgoAesCbcParams = algo.try_into()?;
    let iv = params.iv.to_vec();

    // Create AES-CBC algorithm based on padding mode
    let aes_algo = if algo_id == AzihsmAlgoId::AesCbcPad {
        HsmAesCbcAlgo::with_padding(iv)?
    } else {
        HsmAesCbcAlgo::with_no_padding(iv)?
    };

    // Initialize context
    let encrypt_context = aes_algo.encrypt_init(key.clone())?;
    let context = AesCbcEncryptContext::new(encrypt_context, params);

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesCbcEncryptCtx, Box::new(context));

    Ok(ctx_handle)
}

/// Initialize AES CBC decryption
///
/// Creates a decryption context that can process data incrementally.
/// The context should be used with update and finalize operations.
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CBC or AES CBC with padding)
/// * `key_handle` - Handle to the AES key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the decryption context for subsequent operations
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn aes_cbc_decrypt_init(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    let algo_id = algo.id;
    let params: &mut AzihsmAlgoAesCbcParams = algo.try_into()?;
    let iv = params.iv.to_vec();

    // Create AES-CBC algorithm based on padding mode
    let aes_algo = if algo_id == AzihsmAlgoId::AesCbcPad {
        HsmAesCbcAlgo::with_padding(iv)?
    } else {
        HsmAesCbcAlgo::with_no_padding(iv)?
    };

    // Initialize context
    let decrypt_context = aes_algo.decrypt_init(key.clone())?;
    let context = AesCbcDecryptContext::new(decrypt_context, params);

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesCbcDecryptCtx, Box::new(context));

    Ok(ctx_handle)
}

/// Update AES CBC encryption with additional data
///
/// Processes a chunk of plaintext data in an encryption operation.
/// This function follows the two-phase pattern: first query the required buffer size,
/// then perform the actual operation if the buffer is sufficient.
///
/// # Arguments
/// * `ctx_handle` - Handle to the encryption context
/// * `input` - Reference to plaintext input buffer
/// * `output` - Mutable reference to ciphertext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_cbc_encrypt_update(
    ctx_handle: AzihsmHandle,
    input: &AzihsmBuffer,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the context from handle table
    let ctx: &mut AesCbcEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCbcEncryptCtx)?;

    // Get input data slice
    let input_slice: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = ctx.update(input_slice, None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the update operation. This will also update the IV in algo params in the context.
    let bytes_written = ctx.update(input_slice, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Update AES CBC decryption with additional data
///
/// Processes a chunk of ciphertext data in a decryption operation.
/// This function follows the two-phase pattern: first query the required buffer size,
/// then perform the actual operation if the buffer is sufficient.
///
/// # Arguments
/// * `ctx_handle` - Handle to the decryption context
/// * `input` - Reference to ciphertext input buffer
/// * `output` - Mutable reference to plaintext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_cbc_decrypt_update(
    ctx_handle: AzihsmHandle,
    input: &AzihsmBuffer,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the context from handle table
    let ctx: &mut AesCbcDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCbcDecryptCtx)?;

    // Get input data slice
    let input_slice: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = ctx.update(input_slice, None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the update operation. This will also update the IV in algo params in the context.
    let bytes_written = ctx.update(input_slice, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Finalize AES CBC encryption
///
/// Completes the encryption operation and processes any remaining data.
///
/// # Arguments
/// * `ctx_handle` - Handle to the encryption context
/// * `output` - Mutable reference to ciphertext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_cbc_encrypt_finish(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the context from handle table
    let ctx: &mut AesCbcEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCbcEncryptCtx)?;

    // Query required output length first
    let required_len = ctx.finish(None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the finalize operation. This will also update the IV in algo params in the context.
    let bytes_written = ctx.finish(Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Finalize AES CBC decryption
///
/// Completes the decryption operation and processes any remaining data.
///
/// # Arguments
/// * `ctx_handle` - Handle to the decryption context
/// * `output` - Mutable reference to plaintext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_cbc_decrypt_finish(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the context from handle table
    let ctx: &mut AesCbcDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCbcDecryptCtx)?;

    // Query required output length first
    let required_len = ctx.finish(None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the finalize operation. This will also update the IV in algo params in the context.
    let bytes_written = ctx.finish(Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}
