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

/// Size of the GCM initialization vector in bytes.
const GCM_IV_SIZE: usize = 12;

/// Size of the GCM authentication tag in bytes.
const GCM_TAG_SIZE: usize = 16;

/// AES GCM parameters.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoAesGcmParams {
    /// IV (12 bytes)
    pub iv: [u8; GCM_IV_SIZE],
    /// Authentication tag (16 bytes)
    /// For encryption: populated after operation completes.
    /// For decryption: must be provided before operation.
    pub tag: [u8; GCM_TAG_SIZE],
    /// Pointer to AAD data
    pub aad_ptr: *const u8,
    /// Length of AAD data
    pub aad_len: u32,
}

impl<'a> TryFrom<&'a mut AzihsmAlgo> for &'a mut AzihsmAlgoAesGcmParams {
    type Error = AzihsmStatus;

    /// Extracts a mutable reference to AES-GCM parameters from the algorithm specification.
    ///
    /// # Safety
    /// The caller must ensure that `algo.params` points to valid `AzihsmAlgoAesGcmParams` data
    /// when the algorithm ID is AES-GCM.
    #[allow(unsafe_code)]
    fn try_from(algo: &'a mut AzihsmAlgo) -> Result<Self, Self::Error> {
        // Check for null pointer
        validate_ptr(algo.params)?;

        // Safety: algo.params is validated to be non-null
        let params = unsafe { &mut *(algo.params as *mut AzihsmAlgoAesGcmParams) };

        Ok(params)
    }
}

impl AzihsmAlgoAesGcmParams {
    /// Extract AAD as an optional slice.
    ///
    /// # Safety
    /// The caller must ensure that `aad_ptr` points to valid memory for `aad_len` bytes.
    #[allow(unsafe_code)]
    fn aad(&self) -> Option<Vec<u8>> {
        if self.aad_ptr.is_null() || self.aad_len == 0 {
            None
        } else {
            // Safety: Caller ensures aad_ptr is valid for aad_len bytes
            let slice = unsafe { std::slice::from_raw_parts(self.aad_ptr, self.aad_len as usize) };
            Some(slice.to_vec())
        }
    }
}

/// AES GCM encryption context
struct AesGcmEncryptContext {
    context: HsmAesGcmEncryptContext,
    params: *mut AzihsmAlgoAesGcmParams,
}

impl AesGcmEncryptContext {
    /// Create a new encryption context
    fn new(ctx: HsmAesGcmEncryptContext, params: &mut AzihsmAlgoAesGcmParams) -> Self {
        Self {
            context: ctx,
            params: params as *mut AzihsmAlgoAesGcmParams,
        }
    }

    /// Update the context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.context.update(input, output)?;
        self.update_params()?;
        Ok(bytes_written)
    }

    /// Finalize the context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.context.finish(output)?;
        self.update_params()?;
        Ok(bytes_written)
    }

    /// Update the IV and tag in the caller's parameters
    fn update_params(&mut self) -> Result<(), AzihsmStatus> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.iv.copy_from_slice(self.context.algo().iv());
        if let Some(tag) = self.context.algo().tag() {
            params.tag.copy_from_slice(tag);
        }
        Ok(())
    }
}

/// AES GCM decryption context
struct AesGcmDecryptContext {
    context: HsmAesGcmDecryptContext,
    params: *mut AzihsmAlgoAesGcmParams,
}

impl AesGcmDecryptContext {
    /// Create a new decryption context
    fn new(ctx: HsmAesGcmDecryptContext, params: &mut AzihsmAlgoAesGcmParams) -> Self {
        Self {
            context: ctx,
            params: params as *mut AzihsmAlgoAesGcmParams,
        }
    }

    /// Update the context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.context.update(input, output)?;
        Ok(bytes_written)
    }

    /// Finalize the context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.context.finish(output)?;
        Ok(bytes_written)
    }
}

/// Encrypt data using AES GCM
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES GCM)
/// * `key_handle` - Handle to the AES-GCM key
/// * `plain_text` - Plaintext input buffer
/// * `cipher_text` - Ciphertext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_gcm_encrypt(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    plain_text: &[u8],
    cipher_text: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    if algo.id != AzihsmAlgoId::AesGcm {
        Err(AzihsmStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES-GCM key from handle table
    let key = &HsmAesGcmKey::try_from(key_handle)?;

    let params: &mut AzihsmAlgoAesGcmParams = algo.try_into()?;
    let iv = params.iv.to_vec();
    let aad = params.aad();

    // Create AES-GCM algorithm for encryption
    let mut aes_algo = HsmAesGcmAlgo::new_for_encryption(iv, aad)?;

    // Query required output length first
    let required_len = HsmEncrypter::encrypt(&mut aes_algo, key, plain_text, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(cipher_text, required_len)?;

    // Perform actual encryption
    let written = HsmEncrypter::encrypt(&mut aes_algo, key, plain_text, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    cipher_text.len = written as u32;

    // Update the IV and tag in params
    params.iv.copy_from_slice(aes_algo.iv());
    if let Some(tag) = aes_algo.tag() {
        params.tag.copy_from_slice(tag);
    }

    Ok(())
}

/// Decrypt data using AES GCM
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES GCM)
/// * `key_handle` - Handle to the AES-GCM key
/// * `cipher_text` - Ciphertext input buffer
/// * `plain_text` - Plaintext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_gcm_decrypt(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    cipher_text: &[u8],
    plain_text: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    if algo.id != AzihsmAlgoId::AesGcm {
        Err(AzihsmStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES-GCM key from handle table
    let key = &HsmAesGcmKey::try_from(key_handle)?;

    let params: &mut AzihsmAlgoAesGcmParams = algo.try_into()?;
    let iv = params.iv.to_vec();
    let tag = params.tag.to_vec();
    let aad = params.aad();

    // Create AES-GCM algorithm for decryption
    let mut aes_algo = HsmAesGcmAlgo::new_for_decryption(iv, tag, aad)?;

    // Query required output length first
    let required_len = HsmDecrypter::decrypt(&mut aes_algo, key, cipher_text, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(plain_text, required_len)?;

    // Perform actual decryption
    let written = HsmDecrypter::decrypt(&mut aes_algo, key, cipher_text, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    plain_text.len = written as u32;

    Ok(())
}

/// Initialize AES GCM encryption
///
/// Creates an encryption context that can process data incrementally.
/// The context should be used with update and finalize operations.
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES GCM)
/// * `key_handle` - Handle to the AES-GCM key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the encryption context for subsequent operations
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn aes_gcm_encrypt_init(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    // Get the AES-GCM key from handle table
    let key = &HsmAesGcmKey::try_from(key_handle)?;

    let params: &mut AzihsmAlgoAesGcmParams = algo.try_into()?;
    let iv = params.iv.to_vec();
    let aad = params.aad();

    // Create AES-GCM algorithm for encryption
    let aes_algo = HsmAesGcmAlgo::new_for_encryption(iv, aad)?;

    // Initialize context
    let encrypt_context = aes_algo.encrypt_init(key.clone())?;
    let context = AesGcmEncryptContext::new(encrypt_context, params);

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesGcmEncryptCtx, Box::new(context));

    Ok(ctx_handle)
}

/// Initialize AES GCM decryption
///
/// Creates a decryption context that can process data incrementally.
/// The context should be used with update and finalize operations.
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES GCM)
/// * `key_handle` - Handle to the AES-GCM key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the decryption context for subsequent operations
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn aes_gcm_decrypt_init(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    // Get the AES-GCM key from handle table
    let key = &HsmAesGcmKey::try_from(key_handle)?;

    let params: &mut AzihsmAlgoAesGcmParams = algo.try_into()?;
    let iv = params.iv.to_vec();
    let tag = params.tag.to_vec();
    let aad = params.aad();

    // Create AES-GCM algorithm for decryption
    let aes_algo = HsmAesGcmAlgo::new_for_decryption(iv, tag, aad)?;

    // Initialize context
    let decrypt_context = aes_algo.decrypt_init(key.clone())?;
    let context = AesGcmDecryptContext::new(decrypt_context, params);

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesGcmDecryptCtx, Box::new(context));

    Ok(ctx_handle)
}

/// Update AES GCM encryption with additional data
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
pub(crate) fn aes_gcm_encrypt_update(
    ctx_handle: AzihsmHandle,
    input: &AzihsmBuffer,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the context from handle table
    let ctx: &mut AesGcmEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesGcmEncryptCtx)?;

    // Get input data slice
    let input_slice: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = ctx.update(input_slice, None)?;

    // If no output expected, return early
    if required_len == 0 {
        output.len = 0;
        return Ok(());
    }

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the update operation. This will also update the params in the context.
    let bytes_written = ctx.update(input_slice, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Update AES GCM decryption with additional data
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
pub(crate) fn aes_gcm_decrypt_update(
    ctx_handle: AzihsmHandle,
    input: &AzihsmBuffer,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the context from handle table
    let ctx: &mut AesGcmDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesGcmDecryptCtx)?;

    // Get input data slice
    let input_slice: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = ctx.update(input_slice, None)?;

    // If no output expected, return early
    if required_len == 0 {
        output.len = 0;
        return Ok(());
    }

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the update operation.
    let bytes_written = ctx.update(input_slice, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Finalize AES GCM encryption
///
/// Completes the encryption operation and processes any remaining data.
/// After finalization, the authentication tag can be retrieved from the
/// algorithm parameters.
///
/// # Arguments
/// * `ctx_handle` - Handle to the encryption context
/// * `output` - Mutable reference to ciphertext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure
pub(crate) fn aes_gcm_encrypt_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the context from handle table
    let ctx: &mut AesGcmEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesGcmEncryptCtx)?;

    // Query required output length first
    let required_len = ctx.finish(None)?;

    // If no output expected, return early
    if required_len == 0 {
        output.len = 0;
        return Ok(());
    }

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the finalize operation. This will also update the params in the context.
    let bytes_written = ctx.finish(Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Finalize AES GCM decryption
///
/// Completes the decryption operation and processes any remaining data.
/// Authentication tag verification occurs during this operation.
///
/// # Arguments
/// * `ctx_handle` - Handle to the decryption context
/// * `output` - Mutable reference to plaintext output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmStatus)` on failure (including authentication failure)
pub(crate) fn aes_gcm_decrypt_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the context from handle table
    let ctx: &mut AesGcmDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesGcmDecryptCtx)?;

    // Query required output length first
    let required_len = ctx.finish(None)?;

    // If no output expected, return early
    if required_len == 0 {
        output.len = 0;
        return Ok(());
    }

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the finalize operation.
    let bytes_written = ctx.finish(Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}
