// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use std::slice;

use windows::core::PCWSTR;
use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography::*;

use super::*;

struct CngAlgoHandle {
    cng_algo_handle: BCRYPT_ALG_HANDLE,
}

impl Drop for CngAlgoHandle {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        //SAFETY: Must close algo provider on droping the handle
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(self.cng_algo_handle, 0);
        }
    }
}

struct CngKeyHandle {
    cng_key_handle: BCRYPT_KEY_HANDLE,
}

impl Drop for CngKeyHandle {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        //SAFETY: Must close key handle on droping the handle
        unsafe {
            let _ = BCryptDestroyKey(self.cng_key_handle);
        }
    }
}
//return data for helper functions in the code
struct CngAesCbcResult {
    output: Vec<u8>,
    iv: Vec<u8>,
}

pub struct AesCngCrypter {
    alg_handle: CngAlgoHandle,
    key_handle: CngKeyHandle,
    cipher_text: Vec<u8>,
    iv: Vec<u8>,
    buffer: Vec<u8>,                       // buffer to handle partial blocks
    enable_padding: Option<AesCbcPadding>, //indicate is padding enable as per PCKS#7 at finalize or not
}

pub struct AesCngDeCrypter {
    alg_handle: CngAlgoHandle,
    key_handle: CngKeyHandle,
    plain_text: Vec<u8>,
    iv: Vec<u8>,
    buffer: Vec<u8>,                       // to maintain partial blocks
    enable_padding: Option<AesCbcPadding>, // indicate if padding is enable as per PCKS#7  at finalize
}

#[allow(unsafe_code)]
fn pcwstr_to_u8_vec(pcwstr: PCWSTR) -> Vec<u8> {
    //SAFETY: use unsafe section to convert PCWSTR to vec
    unsafe {
        let mut len = 0;
        let ptr = pcwstr.0;

        // Count UTF-16 code units until null terminator
        while *ptr.add(len) != 0 {
            len += 1;
        }

        // Include null terminator
        let u16_slice = slice::from_raw_parts(ptr, len + 1);

        // Convert &[u16] to &[u8] by reinterpreting the memory
        let byte_ptr = u16_slice.as_ptr() as *const u8;
        let byte_len = u16_slice.len() * 2;

        slice::from_raw_parts(byte_ptr, byte_len).to_vec()
    }
}

// Helper to get block size from CNG algorithm handle
#[allow(unsafe_code)]
fn get_cng_block_size(alg_handle: BCRYPT_ALG_HANDLE) -> Result<usize, CryptoError> {
    let mut block_len: u32 = 0;
    let mut result_len: u32 = 0;
    // SAFETY: BCryptGetProperty is called with valid parameters to get block size
    let status = unsafe {
        BCryptGetProperty(
            alg_handle,
            BCRYPT_BLOCK_LENGTH,
            Some(std::slice::from_raw_parts_mut(
                (&mut block_len) as *mut u32 as *mut u8,
                4,
            )),
            &mut result_len,
            0,
        )
    };
    if !status.is_ok() || result_len != 4 {
        tracing::error!("Failed to get block size from CNG, status: {:?}", status);
        return Err(CryptoError::AesError);
    }
    Ok(block_len as usize)
}

// Helper to check IV size against CNG block size
#[allow(unsafe_code)]
fn cng_check_iv_size(alg_handle: BCRYPT_ALG_HANDLE, iv: &[u8]) -> Result<(), CryptoError> {
    let block_len = match get_cng_block_size(alg_handle) {
        Ok(size) => size,
        Err(e) => {
            tracing::error!("Failed to get block size from CNG, status: {:?}", e);
            return Err(e);
        }
    };
    if iv.len() != block_len {
        tracing::error!(
            "IV must be {} bytes for AES CBC, got {}",
            block_len,
            iv.len()
        );
        return Err(CryptoError::AesInvalidIVError);
    }
    Ok(())
}

/// Helper to open AES algorithm provider, set CBC chaining mode, and generate a symmetric key handle.
/// Returns (CngAlgoHandle, CngKeyHandle) on success.
#[allow(unsafe_code)]
fn cng_setup_aes_cbc_key(key: &[u8]) -> Result<(CngAlgoHandle, CngKeyHandle), CryptoError> {
    // Open algorithm provider
    let mut alg_handle = CngAlgoHandle {
        cng_algo_handle: BCRYPT_ALG_HANDLE::default(),
    };
    let dwflags = BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0);
    //SAFETY: call unsafe BCrypt open algo provider
    let status = unsafe {
        BCryptOpenAlgorithmProvider(
            &mut alg_handle.cng_algo_handle,
            BCRYPT_AES_ALGORITHM,
            None,
            dwflags,
        )
    };
    if status.is_err() {
        tracing::error!("BCryptOpenAlgorithmProvider failed: {:?}", status);
        return Err(CryptoError::AesError);
    }
    // Set chaining mode to CBC
    let mode = pcwstr_to_u8_vec(BCRYPT_CHAIN_MODE_CBC);
    //SAFETY: Set algo handle property
    let status = unsafe {
        BCryptSetProperty(
            alg_handle.cng_algo_handle.into(),
            BCRYPT_CHAINING_MODE,
            mode.as_slice(),
            0,
        )
    };
    if status.is_err() {
        tracing::error!("BCryptSetProperty failed: {:?}", status);
        return Err(CryptoError::AesError);
    }
    // Generate symmetric key handle
    let mut key_handle = CngKeyHandle {
        cng_key_handle: BCRYPT_KEY_HANDLE::default(),
    };
    //SAFETY: Generate symmetric key
    let status = unsafe {
        BCryptGenerateSymmetricKey(
            alg_handle.cng_algo_handle,
            &mut key_handle.cng_key_handle,
            None,
            key,
            0,
        )
    };
    if status.is_err() {
        tracing::error!("BCryptGenerateSymmetricKey failed: {:?}", status);
        return Err(CryptoError::AesError);
    }
    Ok((alg_handle, key_handle))
}

/// Internal helper for AES-CBC single-shot encrypt/decrypt using CNG.
/// Calls either BCryptEncrypt or BCryptDecrypt based on the operation.
#[allow(unsafe_code)]
fn cng_aes_cbc_crypt(
    key: &[u8],
    input: &[u8],
    iv: Option<&[u8]>,
    enable_pad: Option<AesCbcPadding>,
    is_encrypt: bool,
) -> Result<CngAesCbcResult, CryptoError> {
    let (alg_handle, key_handle) = cng_setup_aes_cbc_key(key)?;
    let block_size = get_cng_block_size(alg_handle.cng_algo_handle)?;
    // Prepare IV
    let mut iv_buf: Vec<u8> = match iv {
        Some(iv) => {
            cng_check_iv_size(alg_handle.cng_algo_handle, iv)?;
            iv.to_vec()
        }
        None => {
            if is_encrypt {
                let mut iv = vec![0u8; block_size];
                //SAFETY: Calling Bcrypt unsafe functions
                let status = unsafe {
                    BCryptGenRandom(
                        None, // Use system RNG
                        &mut iv,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                    )
                };
                if status != STATUS_SUCCESS {
                    tracing::error!("BCryptGenRandom for IV failed with status: {:?}", status);
                    return Err(CryptoError::AesEncryptError);
                }
                iv
            } else {
                tracing::error!("IV is None for decryption");
                return Err(CryptoError::AesInvalidIVError);
            }
        }
    };
    let padding_flag = match enable_pad {
        Some(_) => BCRYPT_BLOCK_PADDING,
        None => BCRYPT_FLAGS(0),
    };
    let mut out_len = 0u32;
    //SAFETY: Calling Bcrypt unsafe functions
    let status = unsafe {
        if is_encrypt {
            BCryptEncrypt(
                key_handle.cng_key_handle,
                Some(input),
                None,
                Some(iv_buf.as_mut_slice()),
                None,
                &mut out_len,
                padding_flag,
            )
        } else {
            BCryptDecrypt(
                key_handle.cng_key_handle,
                Some(input),
                None,
                Some(iv_buf.as_mut_slice()),
                None,
                &mut out_len,
                padding_flag,
            )
        }
    };
    if !status.is_ok() {
        tracing::error!(
            "BCrypt{} get length failed with status: {:?}",
            if is_encrypt { "Encrypt" } else { "Decrypt" },
            status
        );
        return Err(if is_encrypt {
            CryptoError::AesEncryptError
        } else {
            CryptoError::AesDecryptError
        });
    }
    let mut output = vec![0u8; out_len as usize];
    let mut iv_buf_copy = iv_buf.clone();
    //SAFETY: Calling Bcrypt unsafe functions
    let status = unsafe {
        if is_encrypt {
            BCryptEncrypt(
                key_handle.cng_key_handle,
                Some(input),
                None,
                Some(iv_buf_copy.as_mut_slice()),
                Some(output.as_mut_slice()),
                &mut out_len,
                padding_flag,
            )
        } else {
            BCryptDecrypt(
                key_handle.cng_key_handle,
                Some(input),
                None,
                Some(iv_buf_copy.as_mut_slice()),
                Some(output.as_mut_slice()),
                &mut out_len,
                padding_flag,
            )
        }
    };
    if !status.is_ok() {
        tracing::error!(
            "BCrypt{} operation failed with status: {:?}",
            if is_encrypt { "Encrypt" } else { "Decrypt" },
            status
        );
        return Err(if is_encrypt {
            CryptoError::AesEncryptError
        } else {
            CryptoError::AesDecryptError
        });
    }
    output.truncate(out_len as usize);
    Ok(CngAesCbcResult { output, iv: iv_buf })
}

impl AesCbcKeyOp for AesCbcKey {
    /// Generates a random AES key of the specified size.
    ///
    /// # Arguments
    /// * `key_size` - The desired AES key size.
    ///
    /// # Returns
    /// * `Result<AesKey, CryptoError>` - Ok with the generated key, or an error if random generation fails.
    #[allow(unsafe_code)]
    fn aes_cbc_generate_key(&self, key_size: AesKeySize) -> Result<AesKey, CryptoError> {
        let key_len = match key_size {
            AesKeySize::Aes128 => 16,
            AesKeySize::Aes192 => 24,
            AesKeySize::Aes256 => 32,
        };
        let mut key = vec![0u8; key_len];
        // SAFETY: BCryptGenRandom is called with a valid mutable buffer and system RNG.
        let status = unsafe {
            BCryptGenRandom(
                None, // Use system RNG
                &mut key,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptGenRandom failed with status: {:?}", status);
            return Err(CryptoError::AesKeyGenError);
        }
        Ok(AesKey { key })
    }

    /// Constructs an AES key from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `key` - A slice of bytes representing the AES key material.
    ///
    /// # Returns
    ///
    /// * `Result<AesKey, CryptoError>` - Returns `Ok` with the constructed `AesKey` on success,
    ///   or `Err(CryptoError)` if the key is invalid.
    fn from_slice(key: &[u8]) -> Result<AesKey, CryptoError> {
        // check if we got valid key length or not
        match key.len() {
            16 | 24 | 32 => Ok(AesKey { key: key.to_vec() }),
            _ => {
                tracing::error!("Invalid key length, received {}", key.len());
                Err(CryptoError::AesKeySizeError)
            }
        }
    }
}

impl AesCbcOp for AesKey {
    /// Encrypts data in a single shot using AES CBC mode.
    ///
    /// # Arguments
    /// * `data` - The plaintext data to encrypt.
    /// * `iv` - Optional initialization vector. If None, a random IV is generated.
    ///
    /// # Returns
    /// * `Result<AesCbcEncryptResult, CryptoError>` - Ok with ciphertext and IV, or an error if encryption fails.
    #[allow(unsafe_code)]
    fn aes_cbc_encrypt(
        &self,
        data: &[u8],
        iv: Option<&[u8]>,
        enable_pad: Option<AesCbcPadding>,
    ) -> Result<AesCbcEncryptResult, CryptoError> {
        let result = cng_aes_cbc_crypt(&self.key, data, iv, enable_pad, true)?;
        Ok(AesCbcEncryptResult {
            cipher_text: result.output,
            iv: result.iv,
        })
    }

    /// Initializes an AES CBC encryption context with the given IV.
    ///
    /// # Arguments
    /// * `iv` - Optional initialization vector as a byte vector. If None, a random IV is generated.
    ///
    /// # Returns
    /// * `Result<Self::Crypter, CryptoError>` - Ok with the encryption context, or an error if initialization fails.
    #[allow(unsafe_code)]
    fn aes_cbc_encrypt_init(
        &self,
        iv: Option<&[u8]>,
        enable_pad: Option<AesCbcPadding>,
    ) -> Result<impl AesCbcEncryptContextOp, CryptoError> {
        let (alg_handle, key_handle) = cng_setup_aes_cbc_key(self.key.as_slice())?;
        let block_size = get_cng_block_size(alg_handle.cng_algo_handle)?;
        let iv = match iv {
            Some(iv) => {
                cng_check_iv_size(alg_handle.cng_algo_handle, iv)?;
                iv.to_vec()
            }
            None => {
                let mut iv = vec![0u8; block_size];
                // SAFETY: Call Unsafe Random gen
                let status =
                    unsafe { BCryptGenRandom(None, &mut iv, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
                if status != STATUS_SUCCESS {
                    tracing::error!("BCryptGenRandom for IV failed with status: {:?}", status);
                    return Err(CryptoError::AesEncryptError);
                }
                iv
            }
        };
        Ok(AesCngCrypter {
            alg_handle,
            key_handle,
            cipher_text: Vec::new(),
            iv,
            buffer: Vec::new(),
            enable_padding: enable_pad,
        })
    }

    /// Decrypts data in a single shot using AES CBC mode.
    ///
    /// # Arguments
    /// * `cipher_text` - The ciphertext data to decrypt.
    /// * `iv` - Optional initialization vector. If None, an all-zero IV is used.
    ///
    /// # Returns
    /// * `Result<AesCbcDecryptResult, CryptoError>` - Ok with plaintext and IV, or an error if decryption fails.
    #[allow(unsafe_code)]
    fn aes_cbc_decrypt(
        &self,
        cipher_text: &[u8],
        iv: &[u8],
        enable_pad: Option<AesCbcPadding>,
    ) -> Result<AesCbcDecryptResult, CryptoError> {
        let result = cng_aes_cbc_crypt(&self.key, cipher_text, Some(iv), enable_pad, false)?;
        Ok(AesCbcDecryptResult {
            plain_text: result.output,
            iv: result.iv,
        })
    }

    /// Initializes an AES CBC decryption context with the given IV.
    ///
    /// # Arguments
    /// * `iv` - Optional initialization vector as a byte vector. If None or empty, returns an error.
    ///
    /// # Returns
    /// * `Result<Self::Decrypter, CryptoError>` - Ok with the decryption context, or an error if initialization fails.
    #[allow(unsafe_code)]
    fn aes_cbc_decrypt_init(
        &self,
        iv: &[u8],
        enable_pad: Option<AesCbcPadding>,
    ) -> Result<impl AesCbcDecryptContextOp, CryptoError> {
        let (alg_handle, key_handle) = cng_setup_aes_cbc_key(self.key.as_slice())?;
        let iv = match iv.is_empty() {
            false => {
                cng_check_iv_size(alg_handle.cng_algo_handle, iv)?;
                iv.to_vec()
            }
            true => {
                tracing::error!("IV must not be None or empty for decryption context");
                return Err(CryptoError::AesInvalidIVError);
            }
        };
        Ok(AesCngDeCrypter {
            alg_handle,
            key_handle,
            plain_text: Vec::new(),
            iv: iv.to_vec(),
            buffer: Vec::new(),
            enable_padding: enable_pad,
        })
    }
}

impl AesCbcEncryptContextOp for AesCngCrypter {
    /// Encrypts a chunk of plaintext in CBC mode and accumulates the ciphertext.
    ///
    /// # Arguments
    /// * `data` - The plaintext chunk to encrypt.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if successful, or an error if encryption fails.
    #[allow(unsafe_code)]
    fn aes_cbc_encrypt_update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        // Use self.alg_handle and self.key_handle for CNG operations.
        // iv should be maintainted for subsequent updates
        let block_size = get_cng_block_size(self.alg_handle.cng_algo_handle)?;
        self.buffer.extend_from_slice(data);

        // encrypt one block at a time, until we get partial block
        while self.buffer.len() >= block_size {
            //get a block
            let block = self.buffer.drain(..block_size).collect::<Vec<u8>>();
            let mut iv_clone = self.iv.clone();

            // Calculate output buffer size
            let mut out_len = 0u32;
            // SAFETY: BCryptEncrypt is called with valid parameters to get output buffer size for the chunk.
            let status = unsafe {
                BCryptEncrypt(
                    self.key_handle.cng_key_handle,
                    Some(&block),
                    None,
                    Some(iv_clone.as_mut_slice()),
                    None,
                    &mut out_len,
                    BCRYPT_FLAGS(0), // No padding as we are passing complete block
                )
            };
            if !status.is_ok() {
                tracing::error!(
                    "BCryptEncrypt (update) get length failed with status: {:?}",
                    status
                );
                return Err(CryptoError::AesEncryptError);
            }

            let mut chunk = vec![0u8; out_len as usize];
            // SAFETY: BCryptEncrypt is called with valid parameters to start encryption.
            let status = unsafe {
                BCryptEncrypt(
                    self.key_handle.cng_key_handle,
                    Some(&block),
                    None,
                    Some(iv_clone.as_mut_slice()),
                    Some(chunk.as_mut_slice()),
                    &mut out_len,
                    BCRYPT_FLAGS(0),
                )
            };
            if !status.is_ok() {
                tracing::error!(
                    "BCryptEncrypt (update) encryption failed with status: {:?}",
                    status
                );
                return Err(CryptoError::AesEncryptError);
            }
            //copy back iv for next update
            self.iv = iv_clone;
            chunk.truncate(out_len as usize);
            self.cipher_text.extend_from_slice(&chunk);
        }
        Ok(())
    }

    /// Finalizes the CBC encryption context, processes any remaining data, and writes the full ciphertext to the output buffer.
    ///
    /// # Returns
    /// * `Result<AesCbcEncryptResult, CryptoError>` - Ok with the AesCbcEncryptResult, or an error if encryption fails or the buffer is too small.
    #[allow(unsafe_code)]
    fn aes_cbc_encrypt_final(mut self) -> Result<AesCbcEncryptResult, CryptoError> {
        // Always call BCryptEncrypt with BCRYPT_BLOCK_PADDING, even if buffer is empty
        let block_size = get_cng_block_size(self.alg_handle.cng_algo_handle)?;
        let mut iv_clone = self.iv.clone();
        let mut out_len = 0u32;
        let mut chunk = vec![0u8; self.buffer.len() + block_size]; // Always at least one block for padding
                                                                   // Determine padding flag
        let padding_flag = match self.enable_padding {
            Some(_) => BCRYPT_BLOCK_PADDING,
            None => BCRYPT_FLAGS(0),
        };
        // SAFETY: BCryptEncrypt is called with valid parameters to get output buffer size for the chunk.
        let status = unsafe {
            BCryptEncrypt(
                self.key_handle.cng_key_handle,
                Some(&self.buffer),
                None,
                Some(iv_clone.as_mut_slice()),
                Some(chunk.as_mut_slice()),
                &mut out_len,
                padding_flag,
            )
        };
        if !status.is_ok() {
            tracing::error!(
                "BCryptEncrypt (final) encryption failed with status: {:?}",
                status
            );
            return Err(CryptoError::AesEncryptError);
        }
        chunk.truncate(out_len as usize);
        self.cipher_text.extend_from_slice(&chunk);
        self.buffer.clear();

        // Debug assertion: ciphertext must be block aligned
        debug_assert!(
            self.cipher_text.len().is_multiple_of(block_size),
            "aes_cbc_encrypt_final: ciphertext not block aligned: {}",
            self.cipher_text.len()
        );

        drop(self.key_handle);
        drop(self.alg_handle);

        Ok(AesCbcEncryptResult {
            cipher_text: self.cipher_text,
            iv: self.iv,
        })
    }
}

impl AesCbcDecryptContextOp for AesCngDeCrypter {
    /// Decrypts a chunk of ciphertext in CBC mode and accumulates the plaintext.
    ///
    /// # Arguments
    /// * `data` - The ciphertext chunk to decrypt.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if successful, or an error if decryption fails.
    #[allow(unsafe_code)]
    fn aes_cbc_decrypt_update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        // Accumulate incoming data into the buffer
        self.buffer.extend_from_slice(data);
        // Only decrypt full blocks (AES block size = 16)
        let block_size = get_cng_block_size(self.alg_handle.cng_algo_handle)?;
        // process update only if there is more than two blocks are available, this is to make sure
        // last block is available for final (CNG requirement)
        while self.buffer.len() >= block_size * 2 {
            // Take a full block out of the buffer
            let block = self.buffer.drain(..block_size).collect::<Vec<u8>>();
            // Prepare IV: for update, we assume IV is managed externally or by the context.
            let mut iv_buf = self.iv.clone();

            // Calculate output buffer size
            let mut out_len = 0u32;

            // SAFETY: BCryptDecrypt is called with valid parameters to get output buffer size for the chunk.
            let status = unsafe {
                BCryptDecrypt(
                    self.key_handle.cng_key_handle,
                    Some(&block),
                    None,
                    Some(iv_buf.as_mut_slice()),
                    None,
                    &mut out_len,
                    BCRYPT_FLAGS(0),
                )
            };
            if !status.is_ok() {
                tracing::error!(
                    "BCryptDecrypt (update) get length failed with status: {:?}",
                    status
                );
                return Err(CryptoError::AesDecryptError);
            }

            let mut chunk = vec![0u8; out_len as usize];

            // SAFETY: BCryptDecrypt is called with valid parameters to perform decryption of the chunk.
            let status = unsafe {
                BCryptDecrypt(
                    self.key_handle.cng_key_handle,
                    Some(&block),
                    None,
                    Some(iv_buf.as_mut_slice()),
                    Some(chunk.as_mut_slice()),
                    &mut out_len,
                    BCRYPT_FLAGS(0),
                )
            };
            if !status.is_ok() {
                tracing::error!(
                    "BCryptDecrypt (update) decryption failed with status: {:?}",
                    status
                );
                return Err(CryptoError::AesDecryptError);
            }
            //copy back update iv
            self.iv = iv_buf;
            chunk.truncate(out_len as usize);
            self.plain_text.extend_from_slice(&chunk);
        }
        Ok(())
    }

    /// Finalizes the CBC decryption context, processes any remaining data, and writes the full plaintext to the output buffer.
    ///
    /// # Returns
    /// * `Result<AesCbcDecryptResult, CryptoError>` - Ok with the number of bytes written, or an error if decryption fails or the buffer is too small.
    #[allow(unsafe_code)]
    fn aes_cbc_decrypt_final(mut self) -> Result<AesCbcDecryptResult, CryptoError> {
        // Decrypt any remaining data (may include padding)
        // Debug assertion: buffer must be block aligned
        let block_size = get_cng_block_size(self.alg_handle.cng_algo_handle)?;
        if !self.buffer.len().is_multiple_of(block_size) {
            tracing::error!(
                "aes_cbc_decrypt_final: buffer not block aligned: {}",
                self.buffer.len()
            );
            return Err(CryptoError::AesDecryptError);
        }
        let mut iv_buf = self.iv.clone();
        let mut out_len = 0u32;
        // Allocate enough space for the decrypted data (input + block size for padding)
        let mut chunk = vec![0u8; self.buffer.len() + block_size];

        let padding_flag = match self.enable_padding {
            Some(_) => BCRYPT_BLOCK_PADDING,
            None => BCRYPT_FLAGS(0),
        };
        // SAFETY: Decrypt final chunk with padding
        let status = unsafe {
            BCryptDecrypt(
                self.key_handle.cng_key_handle,
                Some(&self.buffer),
                None,
                Some(iv_buf.as_mut_slice()),
                Some(chunk.as_mut_slice()),
                &mut out_len,
                padding_flag,
            )
        };
        if !status.is_ok() {
            tracing::error!(
                "BCryptDecrypt (final) decryption failed with status: {:?}",
                status
            );
            return Err(CryptoError::AesDecryptError);
        }
        chunk.truncate(out_len as usize);
        self.plain_text.extend_from_slice(&chunk);
        self.buffer.clear();

        drop(self.key_handle);
        drop(self.alg_handle);
        Ok(AesCbcDecryptResult {
            plain_text: self.plain_text,
            iv: self.iv,
        })
    }
}
