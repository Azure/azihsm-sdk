// Copyright (C) Microsoft Corporation. All rights reserved.

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
        let params = unsafe { &mut *(algo.params as *mut AzihsmAlgoAesCbcParams) };

        Ok(params)
    }
}

/// AES CBC encryption streaming context
struct AesCbcEncryptStreamingContext {
    context: HsmAesCbcEncryptContext,
    params: *mut AzihsmAlgoAesCbcParams,
}

impl AesCbcEncryptStreamingContext {
    /// Create a new encryption context
    fn new(ctx: HsmAesCbcEncryptContext, params: &mut AzihsmAlgoAesCbcParams) -> Self {
        Self {
            context: ctx,
            params: params as *mut AzihsmAlgoAesCbcParams,
        }
    }

    /// Helper to execute an operation on the context and update IV
    fn execute_and_update_iv<F>(&mut self, op: F) -> Result<usize, AzihsmStatus>
    where
        F: FnOnce(&mut HsmAesCbcEncryptContext) -> Result<usize, AzihsmStatus>,
    {
        let bytes_written = op(&mut self.context)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Update the streaming context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        self.execute_and_update_iv(|ctx| Ok(ctx.update(input, output)?))
    }

    /// Finalize the streaming context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        self.execute_and_update_iv(|ctx| Ok(ctx.finish(output)?))
    }

    /// Update the IV in the caller's parameters
    fn update_iv(&mut self) -> Result<(), AzihsmStatus> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.iv.copy_from_slice(self.context.algo().iv());
        Ok(())
    }
}

/// AES CBC decryption streaming context
struct AesCbcDecryptStreamingContext {
    context: HsmAesCbcDecryptContext,
    params: *mut AzihsmAlgoAesCbcParams,
}

impl AesCbcDecryptStreamingContext {
    /// Create a new decryption context
    fn new(ctx: HsmAesCbcDecryptContext, params: &mut AzihsmAlgoAesCbcParams) -> Self {
        Self {
            context: ctx,
            params: params as *mut AzihsmAlgoAesCbcParams,
        }
    }

    /// Helper to execute an operation on the context and update IV
    fn execute_and_update_iv<F>(&mut self, op: F) -> Result<usize, AzihsmStatus>
    where
        F: FnOnce(&mut HsmAesCbcDecryptContext) -> Result<usize, AzihsmStatus>,
    {
        let bytes_written = op(&mut self.context)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Update the streaming context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        self.execute_and_update_iv(|ctx| Ok(ctx.update(input, output)?))
    }

    /// Finalize the streaming context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        self.execute_and_update_iv(|ctx| Ok(ctx.finish(output)?))
    }

    /// Update the IV in the caller's parameters
    fn update_iv(&mut self) -> Result<(), AzihsmStatus> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.iv.copy_from_slice(self.context.algo().iv());
        Ok(())
    }
}

/// Common function for AES CBC encryption/decryption operations
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CBC)
/// * `key_handle` - Handle to the AES key
/// * `input` - Input data buffer
/// * `output` - Output data buffer
/// * `crypt_fn` - Function that performs the actual encryption or decryption
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
fn aes_cbc_crypt<F>(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
    crypt_fn: F,
) -> Result<(), AzihsmStatus>
where
    F: Fn(&mut HsmAesCbcAlgo, &HsmAesKey, &[u8], Option<&mut [u8]>) -> Result<usize, AzihsmStatus>,
{
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
        azihsm_api::HsmAesCbcAlgo::with_padding(iv)?
    } else {
        azihsm_api::HsmAesCbcAlgo::with_no_padding(iv)?
    };

    // Query required output length first
    let required_len = crypt_fn(&mut aes_algo, key, input, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(output, required_len)?;

    // Perform actual encryption or decryption
    let written = crypt_fn(&mut aes_algo, key, input, Some(output_buf))?;

    // Update output buffer length with actual bytes written.
    output.len = written as u32;

    // Update the IV
    params.iv.copy_from_slice(aes_algo.iv());

    Ok(())
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
    aes_cbc_crypt(
        algo,
        key_handle,
        plain_text,
        cipher_text,
        |aes_algo, key, input, output| Ok(HsmEncrypter::encrypt(aes_algo, key, input, output)?),
    )
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
    aes_cbc_crypt(
        algo,
        key_handle,
        cipher_text,
        plain_text,
        |aes_algo, key, input, output| Ok(HsmDecrypter::decrypt(aes_algo, key, input, output)?),
    )
}

/// Common function for initializing AES CBC streaming operations
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CBC or AES CBC with padding)
/// * `key_handle` - Handle to the AES key
/// * `init_fn` - Function that initializes the streaming context
/// * `handle_type` - The handle type for the streaming context
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the streaming context
/// * `Err(AzihsmStatus)` - On failure
fn aes_cbc_streaming_init_common<F, T>(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    init_fn: F,
    handle_type: HandleType,
) -> Result<AzihsmHandle, AzihsmStatus>
where
    F: FnOnce(HsmAesCbcAlgo, HsmAesKey, &mut AzihsmAlgoAesCbcParams) -> Result<T, AzihsmStatus>,
    T: 'static,
{
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

    // Initialize streaming context using the provided function
    let context = init_fn(aes_algo, key.clone(), params)?;

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(handle_type, Box::new(context));

    Ok(ctx_handle)
}

/// Initialize AES CBC streaming encryption
///
/// Creates a streaming encryption context that can process data incrementally.
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
    aes_cbc_streaming_init_common(
        algo,
        key_handle,
        |aes_algo, key, params| {
            Ok(AesCbcEncryptStreamingContext::new(
                aes_algo.encrypt_init(key)?,
                params,
            ))
        },
        HandleType::AesCbcEncryptStreamingCtx,
    )
}

/// Initialize AES CBC streaming decryption
///
/// Creates a streaming decryption context that can process data incrementally.
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
    aes_cbc_streaming_init_common(
        algo,
        key_handle,
        |aes_algo, key, params| {
            Ok(AesCbcDecryptStreamingContext::new(
                aes_algo.decrypt_init(key)?,
                params,
            ))
        },
        HandleType::AesCbcDecryptStreamingCtx,
    )
}

/// Common function for updating AES CBC streaming operations
///
/// Processes a chunk of data in a streaming operation.
/// This function follows the two-phase pattern: first query the required buffer size,
/// then perform the actual operation if the buffer is sufficient.
///
/// # Arguments
/// * `ctx_handle` - Handle to the streaming context
/// * `input` - Reference to input buffer
/// * `output` - Mutable reference to output buffer
/// * `handle_type` - The handle type for the streaming context
/// * `update_fn` - Function that performs the update operation on the context
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
fn aes_cbc_streaming_update_common<T, F>(
    ctx_handle: AzihsmHandle,
    input: &AzihsmBuffer,
    output: &mut AzihsmBuffer,
    handle_type: HandleType,
    mut update_fn: F,
) -> Result<(), AzihsmStatus>
where
    F: FnMut(&mut T, &[u8], Option<&mut [u8]>) -> Result<usize, AzihsmStatus>,
{
    // Get the streaming context from handle table
    let ctx: &mut T = HANDLE_TABLE.as_mut(ctx_handle, handle_type)?;

    // Get input data slice
    let input_slice: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = update_fn(ctx, input_slice, None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the update operation. This will also update the IV in algo params in the context.
    let bytes_written = update_fn(ctx, input_slice, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Update AES CBC streaming encryption with additional data
///
/// Processes a chunk of plaintext data in a streaming encryption operation.
/// This function follows the two-phase pattern: first query the required buffer size,
/// then perform the actual operation if the buffer is sufficient.
///
/// # Arguments
/// * `ctx_handle` - Handle to the streaming encryption context
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
    aes_cbc_streaming_update_common(
        ctx_handle,
        input,
        output,
        HandleType::AesCbcEncryptStreamingCtx,
        |ctx: &mut AesCbcEncryptStreamingContext, input_slice, output_slice| {
            ctx.update(input_slice, output_slice)
        },
    )
}

/// Update AES CBC streaming decryption with additional data
///
/// Processes a chunk of ciphertext data in a streaming decryption operation.
/// This function follows the two-phase pattern: first query the required buffer size,
/// then perform the actual operation if the buffer is sufficient.
///
/// # Arguments
/// * `ctx_handle` - Handle to the streaming decryption context
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
    aes_cbc_streaming_update_common(
        ctx_handle,
        input,
        output,
        HandleType::AesCbcDecryptStreamingCtx,
        |ctx: &mut AesCbcDecryptStreamingContext, input_slice, output_slice| {
            ctx.update(input_slice, output_slice)
        },
    )
}

/// Common function for finalizing AES CBC streaming operations
///
/// Completes the streaming operation and processes any remaining data.
///
/// # Arguments
/// * `ctx_handle` - Handle to the streaming context
/// * `output` - Mutable reference to output buffer
/// * `handle_type` - The handle type for the streaming context
/// * `finish_fn` - Function that performs the finalize operation on the context
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
fn aes_cbc_streaming_final_common<T, F>(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
    handle_type: HandleType,
    mut finish_fn: F,
) -> Result<(), AzihsmStatus>
where
    F: FnMut(&mut T, Option<&mut [u8]>) -> Result<usize, AzihsmStatus>,
{
    // Get the streaming context from handle table
    let ctx: &mut T = HANDLE_TABLE.as_mut(ctx_handle, handle_type)?;

    // Query required output length first
    let required_len = finish_fn(ctx, None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the finalize operation. This will also update the IV in algo params in the context.
    let bytes_written = finish_fn(ctx, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Finalize AES CBC streaming encryption
///
/// Completes the streaming encryption operation and processes any remaining data.
///
/// # Arguments
/// * `ctx_handle` - Handle to the streaming encryption context
/// * `output` - Mutable reference to ciphertext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_cbc_encrypt_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    aes_cbc_streaming_final_common(
        ctx_handle,
        output,
        HandleType::AesCbcEncryptStreamingCtx,
        |ctx: &mut AesCbcEncryptStreamingContext, output_slice| ctx.finish(output_slice),
    )
}

/// Finalize AES CBC streaming decryption
///
/// Completes the streaming decryption operation and processes any remaining data.
///
/// # Arguments
/// * `ctx_handle` - Handle to the streaming decryption context
/// * `output` - Mutable reference to plaintext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_cbc_decrypt_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    aes_cbc_streaming_final_common(
        ctx_handle,
        output,
        HandleType::AesCbcDecryptStreamingCtx,
        |ctx: &mut AesCbcDecryptStreamingContext, output_slice| ctx.finish(output_slice),
    )
}
