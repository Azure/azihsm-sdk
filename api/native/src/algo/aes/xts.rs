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

/// AES-XTS algorithm parameters.
///
/// This structure defines the parameters required for AES-XTS encryption/decryption,
/// including the sector number (tweak) and data unit length.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoAesXtsParams {
    /// Sector number (tweak value) in little-endian byte format.
    /// This is a 128-bit value that provides additional security by
    /// varying the encryption for each data unit.
    pub sector_num: [u8; 16],

    /// Data Unit Length in bytes.
    /// Specifies the size of each data unit to be encrypted/decrypted.
    /// Must be at least 16 bytes for XTS mode.
    pub data_unit_length: u32,
}
impl<'a> TryFrom<&'a mut AzihsmAlgo> for &'a mut AzihsmAlgoAesXtsParams {
    type Error = AzihsmStatus;

    #[allow(unsafe_code)]
    fn try_from(algo: &'a mut AzihsmAlgo) -> Result<Self, Self::Error> {
        // Check for null pointer
        validate_ptr(algo.params)?;

        // Safety: algo.params is validated to be non-null
        let params = unsafe { &mut *(algo.params as *mut AzihsmAlgoAesXtsParams) };

        Ok(params)
    }
}

/// Perform single-shot AES-XTS encryption.
///
/// This function encrypts plaintext using AES-XTS mode in a single operation.
/// The sector number (tweak) in the algorithm parameters is updated after encryption
/// to facilitate sequential encryption of multiple sectors.
///
/// # Arguments
///
/// * `algo` - Algorithm specification containing XTS parameters (sector number and DUL)
/// * `key_handle` - Handle to the AES-XTS encryption key
/// * `plain_text` - Plaintext data to encrypt (must be at least 16 bytes)
/// * `cipher_text` - Output buffer for ciphertext (same size as plaintext)
///
/// # Returns
///
/// * `Ok(())` - Encryption successful, ciphertext written to output buffer
/// * `Err(AzihsmStatus)` - Error occurred during encryption
///
/// # Errors
///
/// * `UnsupportedAlgorithm` - Algorithm ID is not AES-XTS
/// * `BufferTooSmall` - Output buffer is too small
/// * Other errors from key retrieval or encryption operation
pub(crate) fn aes_xts_encrypt(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    plain_text: &[u8],
    cipher_text: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Validate algorithm ID
    if algo.id != AzihsmAlgoId::AesXts {
        Err(AzihsmStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesXtsKey::try_from(key_handle)?;

    let params: &mut AzihsmAlgoAesXtsParams = algo.try_into()?;

    //Create AES-XTS algorithm using DUL from params; for single-shot encryption,
    let mut aes_xts_algo =
        HsmAesXtsAlgo::new(&params.sector_num, params.data_unit_length as usize)?;

    // get required output buffer size
    let cipher_text_size = aes_xts_algo.encrypt(key, plain_text, None)?;

    // validate output buffer
    let cipher_buffer = validate_output_buffer(cipher_text, cipher_text_size)?;

    // perform encryption
    let written = aes_xts_algo.encrypt(key, plain_text, Some(cipher_buffer))?;

    // set actual written size
    cipher_text.len = written as u32;

    //update sector number for next operation
    params.sector_num.copy_from_slice(&aes_xts_algo.tweak());

    Ok(())
}

/// Perform single-shot AES-XTS decryption.
///
/// This function decrypts ciphertext using AES-XTS mode in a single operation.
/// The sector number (tweak) in the algorithm parameters is updated after decryption
/// to facilitate sequential decryption of multiple sectors.
///
/// # Arguments
///
/// * `algo` - Algorithm specification containing XTS parameters (sector number and DUL)
/// * `key_handle` - Handle to the AES-XTS decryption key
/// * `cipher_text` - Ciphertext data to decrypt (must be at least 16 bytes)
/// * `plain_text` - Output buffer for plaintext (same size as ciphertext)
///
/// # Returns
///
/// * `Ok(())` - Decryption successful, plaintext written to output buffer
/// * `Err(AzihsmStatus)` - Error occurred during decryption
///
/// # Errors
///
/// * `BufferTooSmall` - Output buffer is too small
/// * Other errors from key retrieval or decryption operation
pub(crate) fn aes_xts_decrypt(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    cipher_text: &[u8],
    plain_text: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Validate algorithm ID
    if algo.id != AzihsmAlgoId::AesXts {
        return Err(AzihsmStatus::InvalidArgument);
    }
    // Get the AES key from handle table
    let key = &HsmAesXtsKey::try_from(key_handle)?;

    let params: &mut AzihsmAlgoAesXtsParams = algo.try_into()?;

    // create aes xts algorithm
    let mut aes_xts_algo =
        HsmAesXtsAlgo::new(&params.sector_num, params.data_unit_length as usize)?;

    // get required output buffer size
    let plain_text_size = aes_xts_algo.decrypt(key, cipher_text, None)?;

    // validate output buffer
    let plain_buffer = validate_output_buffer(plain_text, plain_text_size)?;

    // perform decryption
    let written = aes_xts_algo.decrypt(key, cipher_text, Some(plain_buffer))?;

    // set actual written size
    plain_text.len = written as u32;

    //update sector number for next operation
    params.sector_num.copy_from_slice(&aes_xts_algo.tweak());
    Ok(())
}

/// Streaming encryption context for AES-XTS mode.
///
/// This context maintains state for multi-part (streaming) AES-XTS encryption operations.
/// It holds a reference to the caller's algorithm parameters to enable automatic
/// sector number updates after each operation.
///
/// # Safety
///
/// The `params` pointer must remain valid for the lifetime of this context.
/// The caller is responsible for ensuring the pointed-to memory is not freed
/// while this context exists.
pub struct AesXtsEncryptContext {
    /// Inner encryption context managing the XTS algorithm state
    ctx: HsmAesXtsEncryptContext,
    /// Raw pointer to caller's algorithm parameters for in-place tweak updates
    params: *mut AzihsmAlgoAesXtsParams,
}
impl AesXtsEncryptContext {
    /// Create a new encryption context.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The underlying HSM encryption context
    /// * `params` - Mutable reference to algorithm parameters (stored as raw pointer)
    ///
    /// # Returns
    ///
    /// A new `AesXtsEncryptContext` instance
    fn new(ctx: HsmAesXtsEncryptContext, params: &mut AzihsmAlgoAesXtsParams) -> Self {
        Self {
            ctx,
            params: params as *mut AzihsmAlgoAesXtsParams,
        }
    }

    /// Update the encryption context with additional plaintext data.
    ///
    /// Processes input data and updates the sector number (tweak) in the caller's
    /// parameters after each operation.
    ///
    /// # Arguments
    ///
    /// * `input` - Plaintext data to encrypt
    /// * `output` - Optional output buffer; if `None`, only returns required size
    ///
    /// # Returns
    ///
    /// Number of bytes written (or required if `output` is `None`)
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.ctx.update(input, output)?;
        self.update_tweak()?;
        Ok(bytes_written)
    }

    /// Finalize the encryption operation.
    ///
    /// Completes the encryption and flushes any remaining data. Updates the
    /// sector number in the caller's parameters.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer; if `None`, only returns required size
    ///
    /// # Returns
    ///
    /// Number of bytes written (or required if `output` is `None`)
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.ctx.finish(output)?;
        self.update_tweak()?;
        Ok(bytes_written)
    }

    /// Update the sector number (tweak) in the caller's algorithm parameters.
    ///
    /// This propagates the updated tweak value from the internal context back to
    /// the caller's parameter structure, enabling proper sequential sector encryption.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Tweak successfully updated
    /// * `Err(AzihsmStatus)` - Error dereferencing the params pointer
    fn update_tweak(&mut self) -> Result<(), AzihsmStatus> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.sector_num.copy_from_slice(&self.ctx.algo().tweak());
        Ok(())
    }
}

/// Initialize a streaming AES-XTS encryption context.
///
/// Creates and allocates a new encryption context for multi-part AES-XTS encryption.
/// The context maintains a pointer to the algorithm parameters to enable automatic
/// sector number updates during streaming operations.
///
/// # Arguments
///
/// * `algo` - Algorithm specification containing XTS parameters
/// * `key_handle` - Handle to the AES-XTS encryption key
///
/// # Returns
///
/// * `Ok(AzihsmHandle)` - Handle to the newly created encryption context
/// * `Err(AzihsmStatus)` - Error occurred during initialization
///
/// # Errors
///
/// * `UnsupportedAlgorithm` - Algorithm ID is not AES-XTS
/// * Other errors from key retrieval or context creation
pub(crate) fn aes_xts_encrypt_init(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    if algo.id != AzihsmAlgoId::AesXts {
        Err(AzihsmStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesXtsKey::try_from(key_handle)?;

    let params: &mut AzihsmAlgoAesXtsParams = algo.try_into()?;

    // create aes xts algorithm
    let aes_xts_algo = HsmAesXtsAlgo::new(&params.sector_num, params.data_unit_length as usize)?;

    //Start XTS context management here for multi-part
    let hsm_ctx = aes_xts_algo.encrypt_init(key.clone())?;

    // Wrap in AesXtsEncryptContext to maintain params pointer
    let ctx = AesXtsEncryptContext::new(hsm_ctx, params);

    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesXtsEncryptCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Streaming decryption context for AES-XTS mode.
///
/// This context maintains state for multi-part (streaming) AES-XTS decryption operations.
/// It holds a reference to the caller's algorithm parameters to enable automatic
/// sector number updates after each operation.
///
/// # Safety
///
/// The `params` pointer must remain valid for the lifetime of this context.
/// The caller is responsible for ensuring the pointed-to memory is not freed
/// while this context exists.
pub struct AesXtsDecryptContext {
    /// Inner decryption context managing the XTS algorithm state
    ctx: HsmAesXtsDecryptContext,
    /// Raw pointer to caller's algorithm parameters for in-place tweak updates
    params: *mut AzihsmAlgoAesXtsParams,
}
impl AesXtsDecryptContext {
    /// Create a new decryption context.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The underlying HSM decryption context
    /// * `params` - Mutable reference to algorithm parameters (stored as raw pointer)
    ///
    /// # Returns
    ///
    /// A new `AesXtsDecryptContext` instance
    fn new(ctx: HsmAesXtsDecryptContext, params: &mut AzihsmAlgoAesXtsParams) -> Self {
        Self {
            ctx,
            params: params as *mut AzihsmAlgoAesXtsParams,
        }
    }
    /// Update the decryption context with additional ciphertext data.
    ///
    /// Processes input data and updates the sector number (tweak) in the caller's
    /// parameters after each operation.
    ///
    /// # Arguments
    ///
    /// * `input` - Ciphertext data to decrypt
    /// * `output` - Optional output buffer; if `None`, only returns required size
    ///
    /// # Returns
    ///
    /// Number of bytes written (or required if `output` is `None`)
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.ctx.update(input, output)?;
        self.update_tweak()?;
        Ok(bytes_written)
    }
    /// Finalize the decryption operation.
    ///
    /// Completes the decryption and flushes any remaining data. Updates the
    /// sector number in the caller's parameters.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer; if `None`, only returns required size
    ///
    /// # Returns
    ///
    /// Number of bytes written (or required if `output` is `None`)
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, AzihsmStatus> {
        let bytes_written = self.ctx.finish(output)?;
        self.update_tweak()?;
        Ok(bytes_written)
    }
    /// Update the sector number (tweak) in the caller's algorithm parameters.
    ///
    /// This propagates the updated tweak value from the internal context back to
    /// the caller's parameter structure, enabling proper sequential sector decryption.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Tweak successfully updated
    /// * `Err(AzihsmStatus)` - Error dereferencing the params pointer
    fn update_tweak(&mut self) -> Result<(), AzihsmStatus> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.sector_num.copy_from_slice(&self.ctx.algo().tweak());
        Ok(())
    }
}

/// Initialize a streaming AES-XTS decryption context.
///
/// Creates and allocates a new decryption context for multi-part AES-XTS decryption.
/// The context maintains a pointer to the algorithm parameters to enable automatic
/// sector number updates during streaming operations.
///
/// # Arguments
///
/// * `algo` - Algorithm specification containing XTS parameters
/// * `key_handle` - Handle to the AES-XTS decryption key
///
/// # Returns
///
/// * `Ok(AzihsmHandle)` - Handle to the newly created decryption context
/// * `Err(AzihsmStatus)` - Error occurred during initialization
///
/// # Errors
///
/// * `UnsupportedAlgorithm` - Algorithm ID is not AES-XTS
/// * Other errors from key retrieval or context creation
pub(crate) fn aes_xts_decrypt_init(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    if algo.id != AzihsmAlgoId::AesXts {
        Err(AzihsmStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesXtsKey::try_from(key_handle)?;

    let params: &mut AzihsmAlgoAesXtsParams = algo.try_into()?;

    // create aes xts algorithm
    let aes_xts_algo = HsmAesXtsAlgo::new(&params.sector_num, params.data_unit_length as usize)?;

    //Start XTS context management here for multi-part
    let hsm_ctx = aes_xts_algo.decrypt_init(key.clone())?;

    // Wrap in AesXtsDecryptContext to maintain params pointer
    let ctx = AesXtsDecryptContext::new(hsm_ctx, params);

    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesXtsDecryptCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Update streaming AES-XTS encryption with additional plaintext data.
///
/// Processes a chunk of plaintext through the streaming encryption context.
/// The sector number in the algorithm parameters is automatically updated after
/// processing to maintain proper tweak sequencing.
///
/// # Arguments
///
/// * `ctx_handle` - Handle to the streaming encryption context
/// * `input` - Input buffer containing plaintext data
/// * `output` - Output buffer for ciphertext (resized as needed)
///
/// # Returns
///
/// * `Ok(())` - Update successful, output buffer contains ciphertext
/// * `Err(AzihsmStatus)` - Error occurred during update
///
/// # Errors
///
/// * `InvalidHandle` - Invalid or wrong type of context handle
/// * `BufferTooSmall` - Output buffer is insufficient
/// * Other errors from encryption operation
pub(crate) fn aes_xts_encrypt_update(
    ctx_handle: AzihsmHandle,
    input: &AzihsmBuffer,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get the context from handle table
    let ctx: &mut AesXtsEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesXtsEncryptCtx)?;

    // Get input data slice
    let input_slice: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = ctx.update(input_slice, None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the update operation. This will also update the tweak in algo params in the context.
    let bytes_written = ctx.update(input_slice, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Finalize streaming AES-XTS encryption.
///
/// Completes the encryption operation and outputs any remaining ciphertext.
/// The sector number in the algorithm parameters is updated with the final tweak value.
///
/// # Arguments
///
/// * `ctx_handle` - Handle to the streaming encryption context (consumed)
/// * `output` - Output buffer for any remaining ciphertext
///
/// # Returns
///
/// * `Ok(())` - Finalization successful
/// * `Err(AzihsmStatus)` - Error occurred during finalization
///
/// # Errors
///
/// * `InvalidHandle` - Invalid or wrong type of context handle
/// * Other errors from encryption finalization
pub(crate) fn aes_xts_encrypt_finish(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    let ctx: &mut AesXtsEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesXtsEncryptCtx)?;

    // Validate output buffer
    let output_buffer = validate_output_buffer(output, 0)?;

    // Perform finish
    let bytes_written = ctx.finish(Some(output_buffer))?;

    // Set actual written size
    output.len = bytes_written as u32;

    Ok(())
}

/// Update streaming AES-XTS decryption with additional ciphertext data.
///
/// Processes a chunk of ciphertext through the streaming decryption context.
/// The sector number in the algorithm parameters is automatically updated after
/// processing to maintain proper tweak sequencing.
///
/// # Arguments
///
/// * `ctx_handle` - Handle to the streaming decryption context
/// * `input` - Input buffer containing ciphertext data
/// * `output` - Output buffer for plaintext (resized as needed)
///
/// # Returns
///
/// * `Ok(())` - Update successful, output buffer contains plaintext
/// * `Err(AzihsmStatus)` - Error occurred during update
///
/// # Errors
///
/// * `InvalidHandle` - Invalid or wrong type of context handle
/// * `BufferTooSmall` - Output buffer is insufficient
/// * Other errors from decryption operation
pub(crate) fn aes_xts_decrypt_update(
    ctx_handle: AzihsmHandle,
    input: &AzihsmBuffer,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    let ctx: &mut AesXtsDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesXtsDecryptCtx)?;

    // Get input data slice
    let input_slice: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = ctx.update(input_slice, None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the update operation. This will also update the tweak in algo params in the context.
    let bytes_written = ctx.update(input_slice, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}
/// Finalize streaming AES-XTS decryption.
///
/// Completes the decryption operation and outputs any remaining plaintext.
/// The sector number in the algorithm parameters is updated with the final tweak value.
///
/// # Arguments
///
/// * `ctx_handle` - Handle to the streaming decryption context (consumed)
/// * `output` - Output buffer for any remaining plaintext
///
/// # Returns
///
/// * `Ok(())` - Finalization successful
/// * `Err(AzihsmStatus)` - Error occurred during finalization
///
/// # Errors
///
/// * `InvalidHandle` - Invalid or wrong type of context handle
/// * Other errors from decryption finalization
pub(crate) fn aes_xts_decrypt_finish(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    let ctx: &mut AesXtsDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesXtsDecryptCtx)?;

    // Validate output buffer
    let output_buffer = validate_output_buffer(output, 0)?;

    // Perform finish
    let bytes_written = ctx.finish(Some(output_buffer))?;

    // Set actual written size
    output.len = bytes_written as u32;

    Ok(())
}
