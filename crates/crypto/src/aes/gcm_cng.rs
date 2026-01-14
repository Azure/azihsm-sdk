// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_void;

use windows::Win32::Security::Cryptography::*;

use super::*;

/// AES GCM (Galois/Counter Mode) algorithm implementation for Windows CNG backend.
pub struct CngAesGcmAlgo {
    aad: Option<Vec<u8>>,
    iv: Vec<u8>,
    tag: Vec<u8>,
    mac: Vec<u8>,
}

impl CngAesGcmAlgo {
    const IV_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    /// Creates a new AES-GCM algorithm instance for encryption.
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector (IV) for encryption.
    /// * `aad` - Optional additional authenticated data (AAD).
    ///
    /// # Returns
    ///
    /// Ok(Self) if the IV length is valid, otherwise an error.
    pub fn for_encrypt(iv: &[u8], aad: Option<&[u8]>) -> Result<Self, CryptoError> {
        if iv.len() != Self::IV_SIZE {
            return Err(CryptoError::GcmInvalidIvLength);
        }
        let iv = iv.to_vec();
        let tag = vec![0u8; Self::TAG_SIZE];
        let mac = vec![0u8; Self::TAG_SIZE];
        let aad = aad.map(|a| a.to_vec());
        Ok(Self { iv, tag, mac, aad })
    }

    /// Creates a new AES-GCM algorithm instance for decryption.
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector (IV) for decryption.
    /// * `aad` - Optional additional authenticated data (AAD).
    /// * `tag` - Authentication tag for decryption.
    ///
    /// # Returns
    ///
    /// Ok(Self) if the IV and tag lengths are valid, otherwise an error.
    pub fn for_decrypt(iv: &[u8], tag: &[u8], aad: Option<&[u8]>) -> Result<Self, CryptoError> {
        if iv.len() != Self::IV_SIZE {
            return Err(CryptoError::GcmInvalidIvLength);
        }
        if tag.len() != Self::TAG_SIZE {
            return Err(CryptoError::GcmInvalidTagLength);
        }
        let iv = iv.to_vec();
        let tag = tag.to_vec();
        let mac = vec![0u8; Self::TAG_SIZE];
        let aad = aad.map(|a| a.to_vec());
        Ok(Self { iv, tag, mac, aad })
    }

    /// Returns the IV used in the algorithm.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Returns the authentication tag used in the algorithm.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Returns the Windows CNG key handle for the given key.
    fn cipher(&self, key: &AesKey) -> Result<BCRYPT_KEY_HANDLE, CryptoError> {
        match key.size() {
            16 | 24 | 32 => Ok(key.gcm_handle()),
            _ => Err(CryptoError::GcmInvalidKeySize),
        }
    }

    /// Helper function to initialize BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure.
    ///
    /// # Returns
    ///
    /// Initialized BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure.
    fn create_auth_info(&mut self) -> BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        let (pb_auth_data, cb_auth_data) = if let Some(aad) = &self.aad {
            (aad.as_ptr() as *mut u8, aad.len() as u32)
        } else {
            (std::ptr::null_mut(), 0)
        };

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: self.iv.as_ptr() as *mut u8,
            cbNonce: self.iv.len() as u32,
            pbTag: self.tag.as_mut_ptr(),
            cbTag: self.tag.len() as u32,
            pbMacContext: self.mac.as_mut_ptr(),
            cbMacContext: self.mac.len() as u32,
            pbAuthData: pb_auth_data,
            cbAuthData: cb_auth_data,
            ..Default::default()
        }
    }
}

impl EncryptOp for AesGcmAlgo {
    type Key = AesKey;

    /// Encrypts the input data using AES-GCM.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption.
    /// * `input` - The plaintext data to encrypt.
    /// * `output` - Optional buffer to write the ciphertext to.
    ///
    /// # Returns
    ///
    /// Ok(usize) indicating the number of bytes written to output, or an error.
    #[allow(unsafe_code)]
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let expected_len = input.len();

        let Some(output) = output else {
            return Ok(expected_len);
        };

        if output.len() < expected_len {
            return Err(CryptoError::GcmBufferTooSmall);
        }

        let key_handle = self.cipher(key)?;

        // Set up authentication info structure
        let auth_info = self.create_auth_info();

        let mut written = 0u32;

        // SAFETY: Calling Windows CNG BCryptEncrypt API
        let status = unsafe {
            BCryptEncrypt(
                key_handle,
                Some(input),
                Some(&auth_info as *const _ as *const std::ffi::c_void),
                None,
                Some(output),
                &mut written,
                BCRYPT_FLAGS(0),
            )
        };

        status.ok().map_err(|_| CryptoError::GcmEncryptionFailed)?;

        Ok(written as usize)
    }
}

impl DecryptOp for AesGcmAlgo {
    type Key = AesKey;

    /// Decrypts the input data using AES-GCM.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption.
    /// * `input` - The ciphertext data to decrypt.
    /// * `output` - Optional buffer to write the plaintext to.
    ///
    /// # Returns
    ///
    /// Ok(usize) indicating the number of bytes written to output, or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - Authentication tag verification fails
    /// - The underlying Windows CNG operation fails
    #[allow(unsafe_code)]
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let expected_len = input.len();

        let Some(output) = output else {
            return Ok(expected_len);
        };

        if output.len() < expected_len {
            return Err(CryptoError::GcmBufferTooSmall);
        }

        let key_handle = self.cipher(key)?;

        // Set up authentication info structure
        let auth_info = self.create_auth_info();

        let mut written = 0u32;

        // SAFETY: Calling Windows CNG BCryptDecrypt API
        let status = unsafe {
            BCryptDecrypt(
                key_handle,
                Some(input),
                Some(&auth_info as *const _ as *const std::ffi::c_void),
                None,
                Some(output),
                &mut written,
                BCRYPT_FLAGS(0),
            )
        };

        status.ok().map_err(|_| CryptoError::GcmDecryptionFailed)?;

        Ok(written as usize)
    }
}

/// Implements streaming encryption for AES-GCM.
impl<'a> EncryptStreamingOp<'a> for CngAesGcmAlgo {
    type Key = AesKey;
    type Context = CngAesGcmEncryptContext;

    /// Initializes a streaming AES-GCM encryption context.
    ///
    /// Creates a context for processing data in multiple chunks. The authentication
    /// info structure is created once during initialization.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (128, 192, or 256 bits)
    ///
    /// # Returns
    ///
    /// A context implementing `EncryptOpContext` for streaming operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key size is invalid
    /// - The IV size is incorrect (must be 12 bytes)
    fn encrypt_init(mut self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let mut auth_info = self.create_auth_info();
        auth_info.dwFlags |= BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

        Ok(CngAesGcmEncryptContext {
            algo: self,
            key,
            auth_info,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-GCM encryption operations.
///
/// This structure maintains the state for a multi-step AES-GCM encryption operation.
/// It buffers at least one block of data to ensure proper finalization.
pub struct CngAesGcmEncryptContext {
    algo: CngAesGcmAlgo,
    key: AesKey,
    auth_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    block: AesBlock,
}

/// Implements streaming encryption operations for the AES-GCM encrypt context.
impl<'a> EncryptOpContext<'a> for CngAesGcmEncryptContext {
    type Algo = CngAesGcmAlgo;

    /// Processes a chunk of input data.
    ///buffers input data, keeping at least one block buffered for finalization.
    /// Data is encrypted in update() only if there's enough buffered data beyond one block.
    ///
    /// # Arguments
    ///
    /// * `input` - Input data chunk to process
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The underlying CNG encryption fails
    #[allow(unsafe_code)]
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.update_len(input);
        };

        let mut output_offset = 0;

        self.block.update(input, |data| {
            if output.len() - output_offset < data.len() {
                return Err(CryptoError::GcmBufferTooSmall);
            }

            let mut written = 0u32;
            self.auth_info.dwFlags |= BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

            // SAFETY: Calling Windows CNG BCryptEncrypt API
            let status = unsafe {
                BCryptEncrypt(
                    self.key.gcm_handle(),
                    Some(data),
                    Some(::std::ptr::addr_of!(self.auth_info) as *const c_void),
                    Some(self.algo.iv.as_mut_slice()),
                    Some(&mut output[output_offset..]),
                    &mut written,
                    BCRYPT_FLAGS(0),
                )
            };

            status.ok().map_err(|_| CryptoError::GcmEncryptionFailed)?;
            output_offset += written as usize;
            Ok(written as usize)
        })
    }

    /// Finalizes the encryption operation.
    ///
    /// This method encrypts any remaining buffered data and computes the authentication tag.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The underlying CNG encryption fails
    #[allow(unsafe_code)]
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.final_len();
        };

        // Clear the chaining flag for final call
        self.auth_info.dwFlags &= !BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

        self.block.r#final(|data| {
            if output.len() < data.len() {
                return Err(CryptoError::GcmBufferTooSmall);
            }

            if data.is_empty() {
                return Ok(0);
            }

            let mut written = 0u32;

            // SAFETY: Calling Windows CNG BCryptEncrypt API for final block
            let status = unsafe {
                BCryptEncrypt(
                    self.key.gcm_handle(),
                    Some(data),
                    Some(::std::ptr::addr_of!(self.auth_info) as *const c_void),
                    Some(self.algo.iv.as_mut_slice()),
                    Some(output),
                    &mut written,
                    BCRYPT_FLAGS(0),
                )
            };

            status.ok().map_err(|_| CryptoError::GcmEncryptionFailed)?;
            Ok(written as usize)
        })
    }

    /// Returns a reference to the underlying algorithm.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying algorithm.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying algorithm.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

/// Implements streaming decryption for AES-GCM.
impl<'a> DecryptStreamingOp<'a> for CngAesGcmAlgo {
    type Key = AesKey;
    type Context = CngAesGcmDecryptContext;

    /// Initializes a streaming AES-GCM decryption context.
    ///
    /// Creates a context for processing data in multiple chunks. The authentication
    /// info structure is created once during initialization.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (128, 192, or 256 bits)
    ///
    /// # Returns
    ///
    /// A context implementing `DecryptOpContext` for streaming operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key size is invalid
    /// - The IV size is incorrect (must be 12 bytes)
    /// - The tag size is incorrect (must be 16 bytes)
    fn decrypt_init(mut self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let auth_info = self.create_auth_info();
        Ok(CngAesGcmDecryptContext {
            algo: self,
            key,
            auth_info,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-GCM decryption operations.
///
/// This structure maintains the state for a multi-step AES-GCM decryption operation.
/// It buffers at least one block of data to ensure proper finalization.
pub struct CngAesGcmDecryptContext {
    algo: CngAesGcmAlgo,
    key: AesKey,
    auth_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    block: AesBlock,
}

/// Implements streaming decryption operations for the AES-GCM decrypt context.
impl<'a> DecryptOpContext<'a> for CngAesGcmDecryptContext {
    type Algo = CngAesGcmAlgo;

    /// Processes a chunk of input data.
    ///
    /// This method decrypts the input data incrementally.
    ///
    /// # Arguments
    ///
    /// * `input` - Input data chunk to decrypt
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The underlying CNG decryption fails
    #[allow(unsafe_code)]
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.update_len(input);
        };

        let mut output_offset = 0;

        self.block.update(input, |data| {
            if output.len() - output_offset < data.len() {
                return Err(CryptoError::GcmBufferTooSmall);
            }

            let mut written = 0u32;
            self.auth_info.dwFlags |= BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

            // SAFETY: Calling Windows CNG BCryptDecrypt API
            let status = unsafe {
                BCryptDecrypt(
                    self.key.gcm_handle(),
                    Some(data),
                    Some(::std::ptr::addr_of!(self.auth_info) as *const c_void),
                    Some(self.algo.iv.as_mut_slice()),
                    Some(&mut output[output_offset..]),
                    &mut written,
                    BCRYPT_FLAGS(0),
                )
            };

            status.ok().map_err(|_| CryptoError::GcmDecryptionFailed)?;
            output_offset += written as usize;
            Ok(written as usize)
        })
    }

    /// Finalizes the decryption operation.
    ///
    /// This method decrypts any remaining buffered data and verifies the authentication tag.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - Authentication tag verification fails
    /// - The underlying CNG decryption fails
    #[allow(unsafe_code)]
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.final_len();
        };

        self.block.r#final(|data| {
            if output.len() < data.len() {
                return Err(CryptoError::GcmBufferTooSmall);
            }

            let mut written = 0u32;
            self.auth_info.dwFlags &= !BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

            // SAFETY: Calling Windows CNG BCryptDecrypt API for final block
            let status = unsafe {
                BCryptDecrypt(
                    self.key.gcm_handle(),
                    Some(data),
                    Some(::std::ptr::addr_of!(self.auth_info) as *const c_void),
                    Some(self.algo.iv.as_mut_slice()),
                    Some(output),
                    &mut written,
                    BCRYPT_FLAGS(0),
                )
            };

            status.ok().map_err(|_| CryptoError::GcmDecryptionFailed)?;
            Ok(written as usize)
        })
    }

    /// Returns a reference to the underlying algorithm.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying algorithm.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying algorithm.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
