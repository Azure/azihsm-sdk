// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use super::*;
use crate::AzihsmBuffer;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::HANDLE_TABLE;
use crate::crypto_enc_dec::CryptoOp;
use crate::handle_table::HandleType;
use crate::utils::validate_output_buffer;
use crate::utils::validate_ptr;

impl TryFrom<&AzihsmAlgo> for azihsm_napi::HsmAesKeyGenAlgo {
    type Error = AzihsmError;

    /// Converts a C FFI algorithm specification to HsmAesKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmAesKeyGenAlgo::default())
    }
}

/// Helper function to generate an AES key
pub(crate) fn aes_generate_key(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    key_props: HsmKeyProps,
) -> Result<AzihsmHandle, AzihsmError> {
    let mut aes_algo = HsmAesKeyGenAlgo::try_from(algo)?;
    let key = HsmKeyManager::generate_key(session, &mut aes_algo, key_props)?;
    let handle = HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(key));

    Ok(handle)
}

/// AES CBC parameters.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoAesCbcParams {
    /// IV
    pub iv: [u8; 16],
}

impl<'a> TryFrom<&'a mut AzihsmAlgo> for &'a mut AzihsmAlgoAesCbcParams {
    type Error = AzihsmError;

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

/// Wrapper for AES CBC streaming contexts (encryption or decryption)
struct AesCbcStreamingContext {
    context: AesCbcContext,
    params: *mut AzihsmAlgoAesCbcParams,
}

enum AesCbcContext {
    Encrypt(HsmAesCbcEncryptContext),
    Decrypt(HsmAesCbcDecryptContext),
}

impl AesCbcStreamingContext {
    /// Create a new encryption context
    fn new_encrypt(ctx: HsmAesCbcEncryptContext, params: &mut AzihsmAlgoAesCbcParams) -> Self {
        Self {
            context: AesCbcContext::Encrypt(ctx),
            params: params as *mut AzihsmAlgoAesCbcParams,
        }
    }

    /// Create a new decryption context
    fn new_decrypt(ctx: HsmAesCbcDecryptContext, params: &mut AzihsmAlgoAesCbcParams) -> Self {
        Self {
            context: AesCbcContext::Decrypt(ctx),
            params: params as *mut AzihsmAlgoAesCbcParams,
        }
    }

    /// Helper to execute an operation on the context and update IV
    fn execute_and_update_iv<F>(&mut self, op: F) -> Result<usize, AzihsmError>
    where
        F: FnOnce(&mut AesCbcContext) -> Result<usize, AzihsmError>,
    {
        let bytes_written = op(&mut self.context)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Update the streaming context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, AzihsmError> {
        self.execute_and_update_iv(|ctx| match ctx {
            AesCbcContext::Encrypt(c) => Ok(c.update(input, output)?),
            AesCbcContext::Decrypt(c) => Ok(c.update(input, output)?),
        })
    }

    /// Finalize the streaming context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, AzihsmError> {
        self.execute_and_update_iv(|ctx| match ctx {
            AesCbcContext::Encrypt(c) => Ok(c.finish(output)?),
            AesCbcContext::Decrypt(c) => Ok(c.finish(output)?),
        })
    }

    /// Get the current IV from the context
    fn iv(&self) -> &[u8] {
        match &self.context {
            AesCbcContext::Encrypt(ctx) => ctx.algo().iv(),
            AesCbcContext::Decrypt(ctx) => ctx.algo().iv(),
        }
    }

    /// Update the IV in the caller's parameters
    fn update_iv(&mut self) -> Result<(), AzihsmError> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.iv.copy_from_slice(self.iv());
        Ok(())
    }
}

/// Common function for AES encryption/decryption operations
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CBC)
/// * `key_handle` - Handle to the AES key
/// * `input` - Input data buffer (plaintext for encrypt, ciphertext for decrypt)
/// * `output` - Output data buffer (ciphertext for encrypt, plaintext for decrypt)
/// * `encrypt` - true for encryption, false for decryption
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmError)` on failure
pub(crate) fn aes_cbc_crypt(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    input: &AzihsmBuffer,
    output: &mut AzihsmBuffer,
    op: CryptoOp,
) -> Result<(), AzihsmError> {
    if algo.id != AzihsmAlgoId::AesCbc && algo.id != AzihsmAlgoId::AesCbcPad {
        Err(AzihsmError::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    let algo_id = algo.id;
    let params: &mut AzihsmAlgoAesCbcParams = algo.try_into()?;
    let iv = params.iv.to_vec();

    // Create AES-CBC algorithm based on padding mode
    let mut aes_algo = if algo_id == AzihsmAlgoId::AesCbcPad {
        azihsm_napi::HsmAesCbcAlgo::with_padding(iv)?
    } else {
        azihsm_napi::HsmAesCbcAlgo::with_no_padding(iv)?
    };

    // Get input data slice
    let input_data: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = if op == CryptoOp::Encrypt {
        HsmEncrypter::encrypt(&mut aes_algo, key, input_data, None)?
    } else {
        HsmDecrypter::decrypt(&mut aes_algo, key, input_data, None)?
    };

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(output, required_len)?;

    // Perform actual encryption or decryption
    let written = if op == CryptoOp::Encrypt {
        HsmEncrypter::encrypt(&mut aes_algo, key, input_data, Some(output_buf))?
    } else {
        HsmDecrypter::decrypt(&mut aes_algo, key, input_data, Some(output_buf))?
    };

    // Update output buffer length with actual bytes written.
    output.len = written as u32;

    // Update the IV
    params.iv.copy_from_slice(aes_algo.iv());

    Ok(())
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
/// * `Err(AzihsmError)` - On failure
pub(crate) fn aes_cbc_streaming_init(
    algo: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    op: CryptoOp,
) -> Result<AzihsmHandle, AzihsmError> {
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

    // Initialize streaming context based on operation type
    let context = if op == CryptoOp::Encrypt {
        AesCbcStreamingContext::new_encrypt(aes_algo.encrypt_init(key.clone())?, params)
    } else {
        AesCbcStreamingContext::new_decrypt(aes_algo.decrypt_init(key.clone())?, params)
    };

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesCbcStreamingCtx, Box::new(context));

    Ok(ctx_handle)
}

/// Update AES CBC streaming encryption with additional plaintext
///
/// Processes a chunk of plaintext data in a streaming encryption operation.
/// This function follows the two-phase pattern: first query the required buffer size,
/// then perform the actual encryption if the buffer is sufficient.
///
/// # Arguments
/// * `ctx_handle` - Handle to the encryption context
/// * `input` - Reference to input buffer
/// * `output` - Mutable reference to output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmError)` on failure
///
/// # Safety
/// This function dereferences raw pointers
pub(crate) fn aes_cbc_streaming_update(
    ctx_handle: AzihsmHandle,
    input: &AzihsmBuffer,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    // Get the streaming context from handle table
    let ctx: &mut AesCbcStreamingContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCbcStreamingCtx)?;

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

/// Finalize AES CBC streaming encryption/decryption
/// Completes the streaming operation and processes any remaining data.
///
/// # Arguments
/// * `ctx_handle` - Handle to the encryption/decryption context
/// * `output` - Mutable reference to output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(AzihsmError)` on failure
pub(crate) fn aes_cbc_streaming_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    // Get the streaming context from handle table
    let ctx: &mut AesCbcStreamingContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCbcStreamingCtx)?;

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
