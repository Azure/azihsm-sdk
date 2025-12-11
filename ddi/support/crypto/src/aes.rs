// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for AES Cryptographic Keys.

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and SymCrypt cannot be enabled at the same time.");

#[cfg(feature = "use-openssl")]
use openssl;
#[cfg(feature = "use-openssl")]
use openssl::cipher::Cipher;
#[cfg(feature = "use-openssl")]
use openssl::cipher::CipherRef;
#[cfg(feature = "use-openssl")]
use openssl::cipher_ctx::CipherCtx;
#[cfg(feature = "use-symcrypt")]
use symcrypt::cipher::AesExpandedKey;
#[cfg(feature = "use-symcrypt")]
use symcrypt::cipher::BlockCipherType;
#[cfg(feature = "use-symcrypt")]
use symcrypt::gcm::GcmExpandedKey;

use crate::rand::rand_bytes;
use crate::CryptoError;

/// The size of the AES CBC IV.
#[cfg(feature = "use-openssl")]
const AES_CBC_IV_SIZE: usize = 16;

/// The size of the AES GCM tag.
const AES_GCM_TAG_SIZE: usize = 16;

/// Supported AES algo.
#[derive(Debug, Clone, PartialEq)]
pub enum AesAlgo {
    /// CBC mode.
    Cbc,

    ///GCM mode.
    Gcm,
}

/// Supported AES mode.
#[derive(Debug, Clone, PartialEq)]
pub enum AesMode {
    /// Encrypt
    Encrypt,

    /// Decrypt
    Decrypt,
}

/// Supported AES Key size.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AesKeySize {
    /// 128-bit key.
    Aes128,

    /// 192-bit key.
    Aes192,

    /// 256-bit key.
    Aes256,
}

/// Result of the `encrypt/ decrypt`.
#[derive(Debug, PartialEq)]
pub struct AesEncryptDecryptResult {
    // Output data
    pub data: Vec<u8>,

    /// Output IV
    pub iv: Vec<u8>,
}

/// Result of the `encrypt`.
pub struct AesEncryptResult {
    pub cipher_text: Vec<u8>,
    /// Output IV (only available for CBC).
    pub iv: Option<Vec<u8>>,
}

/// Result of the `decrypt`.
pub struct AesDecryptResult {
    pub plain_text: Vec<u8>,
    /// Output IV (only available for CBC).
    pub iv: Option<Vec<u8>>,
}

/// Trait for AES operations.
pub trait AesOp {
    fn generate(size: AesKeySize) -> Result<Self, CryptoError>
    where
        Self: Sized;
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>
    where
        Self: Sized;

    fn encrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesEncryptResult, CryptoError>;
    fn decrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesDecryptResult, CryptoError>;

    fn encrypt_with_aad(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<AesEncryptResult, CryptoError>;
    fn decrypt_with_aad(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<AesDecryptResult, CryptoError>;

    fn size(&self) -> AesKeySize;
}

/// AES Key.
#[derive(Debug, Clone)]
pub struct AesKey {
    key: Vec<u8>,
    size: AesKeySize,
}

#[cfg(feature = "use-openssl")]
fn get_cipher(size: &AesKeySize, mode: &AesAlgo) -> Result<&'static CipherRef, CryptoError> {
    let cipher = match (size, mode) {
        (AesKeySize::Aes128, AesAlgo::Cbc) => Cipher::aes_128_cbc(),
        (AesKeySize::Aes192, AesAlgo::Cbc) => Cipher::aes_192_cbc(),
        (AesKeySize::Aes256, AesAlgo::Cbc) => Cipher::aes_256_cbc(),
        (AesKeySize::Aes128, AesAlgo::Gcm) => Cipher::aes_128_gcm(),
        (AesKeySize::Aes192, AesAlgo::Gcm) => Cipher::aes_192_gcm(),
        (AesKeySize::Aes256, AesAlgo::Gcm) => Cipher::aes_256_gcm(),
    };

    Ok(cipher)
}

impl AesOp for AesKey {
    /// Generate a new AES key with random bytes.
    fn generate(size: AesKeySize) -> Result<Self, CryptoError> {
        // Based on the provided key size, determine the number of bytes needed
        // in the key.
        let key_len = match size {
            AesKeySize::Aes128 => 16,
            AesKeySize::Aes192 => 24,
            AesKeySize::Aes256 => 32,
        };

        // Generate random bytes for the key, and pass it into the
        // `from_bytes()` function to create the `AesKey` object.
        let mut key_bytes = vec![0u8; key_len];
        rand_bytes(key_bytes.as_mut_slice()).map_err(|rand_error_stack| {
            tracing::error!(?rand_error_stack);
            CryptoError::AesGenerateError
        })?;
        Self::from_bytes(key_bytes.as_slice())
    }

    /// Create a `AesKey` instance from a raw key.
    ///
    /// # Arguments
    /// * `bytes` - The raw key.
    ///
    /// # Returns
    /// * `AesKey` - The created instance.
    ///
    /// # Errors
    /// * `CryptoError::InvalidArgument` - If the raw key has invalid size.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let size = match bytes.len() {
            16 => AesKeySize::Aes128,
            24 => AesKeySize::Aes192,
            32 => AesKeySize::Aes256,
            _ => Err(CryptoError::AesInvalidKeyLength)?,
        };

        Ok(Self {
            key: bytes.to_vec(),
            size,
        })
    }

    /// Get key size.
    fn size(&self) -> AesKeySize {
        self.size
    }

    /// AES encryption (backward compatible - no AAD support).
    fn encrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesEncryptResult, CryptoError> {
        self.encrypt_with_aad(data, algo, iv, None)
    }

    /// AES decryption (backward compatible - no AAD support).
    fn decrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesDecryptResult, CryptoError> {
        self.decrypt_with_aad(data, algo, iv, None)
    }

    /// AES encryption with AAD support.
    ///
    /// # Arguments
    /// * `data` - The data to be encrypted.
    /// * `algo` - AES algo (CBC or GCM).
    /// * `iv` - The IV value.
    /// * `aad` - Additional Authenticated Data (only for GCM mode).
    ///
    /// # Returns
    /// * `AesEncryptResult` - The encryption result.
    ///
    /// # Errors
    /// * `CryptoError::AesEncryptFailed` - If the encryption fails.
    /// * `CryptoError::InvalidParameter` - If AAD is provided with CBC mode.
    #[cfg(feature = "use-openssl")]
    fn encrypt_with_aad(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<AesEncryptResult, CryptoError> {
        match algo {
            AesAlgo::Cbc => {
                // CBC mode doesn't support AAD - throw error if provided
                if aad.is_some() {
                    tracing::error!("AAD is not supported in CBC mode");
                    return Err(CryptoError::InvalidParameter);
                }
                let cipher = get_cipher(&self.size, &algo)?;
                let mut ctx = CipherCtx::new().map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::AesEncryptFailed
                })?;
                let mut cipher_text = vec![0; data.len() + cipher.block_size()];

                ctx.encrypt_init(Some(cipher), None, None)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesEncryptFailed
                    })?;

                ctx.encrypt_init(None, Some(&self.key), iv)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesEncryptFailed
                    })?;

                // Do not support padding
                ctx.set_padding(false);

                let result = ctx.cipher_update(data, Some(&mut cipher_text));

                let count = result.map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::AesEncryptFailed
                })?;

                let rest =
                    ctx.cipher_final(&mut cipher_text[count..])
                        .map_err(|openssl_error_stack| {
                            tracing::error!(?openssl_error_stack);
                            CryptoError::AesEncryptFailed
                        })?;

                cipher_text.truncate(count + rest);

                let iv = if cipher_text.len() >= AES_CBC_IV_SIZE {
                    // The size of cipher text should be always 16-byte aligned.
                    let last_block = &cipher_text[(cipher_text.len() - AES_CBC_IV_SIZE)..];
                    Some(last_block.to_vec())
                } else {
                    // The cipher text is empty
                    None
                };

                Ok(AesEncryptResult { cipher_text, iv })
            }
            AesAlgo::Gcm => {
                let cipher = get_cipher(&self.size, &algo)?;
                let mut ctx = CipherCtx::new().map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::AesEncryptFailed
                })?;

                // For GCM, allocate space for data + 16 bytes for the authentication tag
                let mut cipher_text = vec![0; data.len() + 16];

                ctx.encrypt_init(Some(cipher), None, None)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesEncryptFailed
                    })?;

                ctx.encrypt_init(None, Some(&self.key), iv)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesEncryptFailed
                    })?;

                // Process AAD if provided for GCM
                if let Some(aad_data) = aad {
                    ctx.cipher_update(aad_data, None)
                        .map_err(|openssl_error_stack| {
                            tracing::error!(?openssl_error_stack);
                            CryptoError::AesEncryptFailed
                        })?;
                }

                let count = ctx
                    .cipher_update(data, Some(&mut cipher_text[..data.len()]))
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesEncryptFailed
                    })?;

                let _rest = ctx
                    .cipher_final(&mut cipher_text[count..data.len()])
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesEncryptFailed
                    })?;

                // For GCM, get the authentication tag
                let mut tag = [0u8; AES_GCM_TAG_SIZE];
                ctx.tag(&mut tag).map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::AesEncryptFailed
                })?;

                // Copy the tag to the end of cipher_text
                cipher_text[data.len()..data.len() + AES_GCM_TAG_SIZE].copy_from_slice(&tag);

                // For GCM, we don't return an IV since the nonce is managed differently
                Ok(AesEncryptResult {
                    cipher_text,
                    iv: None,
                })
            }
        }
    }

    #[cfg(feature = "use-symcrypt")]
    fn encrypt_with_aad(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<AesEncryptResult, CryptoError> {
        match algo {
            AesAlgo::Cbc => {
                // CBC mode doesn't support AAD - throw error if provided
                if aad.is_some() {
                    tracing::error!("AAD is not supported for AES CBC encryption");
                    return Err(CryptoError::InvalidParameter);
                }
                // TODO: figure out what to do when data is not a multiple of block size
                if !data.len().is_multiple_of(16) {
                    tracing::error!("Data length is not a multiple of block size (16)");
                    return Err(CryptoError::InvalidParameter);
                }
                let mut cipher_text = vec![0u8; data.len()];
                let mut chaining_value: [u8; 16] = match iv {
                    Some(init_vec) => init_vec.try_into().map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::AesEncryptFailed
                    })?,
                    None => return Err(CryptoError::AesEncryptFailed),
                };
                let aes_cbc = AesExpandedKey::new(&self.key).map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::AesEncryptFailed
                })?;
                aes_cbc
                    .aes_cbc_encrypt(&mut chaining_value, data, &mut cipher_text)
                    .map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::AesEncryptFailed
                    })?;
                let iv = Some(chaining_value.to_vec());
                Ok(AesEncryptResult { cipher_text, iv })
            }
            AesAlgo::Gcm => {
                let nonce = match iv {
                    Some(nonce_bytes) => {
                        if nonce_bytes.len() != 12 {
                            tracing::error!("Nonce length is not 12 bytes");
                            return Err(CryptoError::AesEncryptFailed);
                        }
                        let nonce_array: [u8; 12] =
                            nonce_bytes.try_into().map_err(|nonce_error_stack| {
                                tracing::error!(?nonce_error_stack);
                                CryptoError::AesEncryptFailed
                            })?;
                        nonce_array
                    }
                    None => return Err(CryptoError::AesEncryptFailed),
                };

                // Create a mutable buffer with the data for in-place encryption
                let mut buffer = data.to_vec();
                let mut tag = [0u8; AES_GCM_TAG_SIZE]; // GCM tag is 16 bytes

                let gcm_key = GcmExpandedKey::new(&self.key, BlockCipherType::AesBlock).map_err(
                    |symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::AesEncryptFailed
                    },
                )?;

                // Use AAD if provided, otherwise use empty slice
                let aad_data = aad.unwrap_or(&[]);

                gcm_key.encrypt_in_place(&nonce, aad_data, &mut buffer, &mut tag);

                // Append the tag to the cipher text
                buffer.extend_from_slice(&tag);

                // For GCM, we don't return an IV since the nonce is provided by the caller
                Ok(AesEncryptResult {
                    cipher_text: buffer,
                    iv: None,
                })
            }
        }
    }

    /// AES decryption with AAD support.
    ///
    /// # Arguments
    /// * `data` - The data to be encrypted.
    /// * `algo` - AES algo (CBC).
    /// * `iv` - The IV value.
    /// * `aad` - Additional Authenticated Data (only for GCM mode).
    ///
    /// # Returns
    /// * `AesDecryptResult` - The decryption result.
    ///
    /// # Errors
    /// * `CryptoError::AesDecryptFailed` - If the decryption fails.
    /// * `CryptoError::InvalidParameter` - If AAD is provided with CBC mode.
    #[cfg(feature = "use-openssl")]
    fn decrypt_with_aad(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<AesDecryptResult, CryptoError> {
        match algo {
            AesAlgo::Cbc => {
                // CBC mode doesn't support AAD - throw error if provided
                if aad.is_some() {
                    tracing::error!("AAD is not supported for AES CBC decryption");
                    return Err(CryptoError::InvalidParameter);
                }
                let cipher = get_cipher(&self.size, &algo)?;
                let mut ctx = CipherCtx::new().map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::AesDecryptFailed
                })?;
                let mut plain_text = vec![0; data.len() + cipher.block_size()];

                ctx.decrypt_init(Some(cipher), None, None)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesDecryptFailed
                    })?;

                ctx.decrypt_init(None, Some(&self.key), iv)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesDecryptFailed
                    })?;

                // Do not support padding
                ctx.set_padding(false);

                let count = ctx.cipher_update(data, Some(&mut plain_text)).map_err(
                    |openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesDecryptFailed
                    },
                )?;

                let rest =
                    ctx.cipher_final(&mut plain_text[count..])
                        .map_err(|openssl_error_stack| {
                            tracing::error!(?openssl_error_stack);
                            CryptoError::AesDecryptFailed
                        })?;

                plain_text.truncate(count + rest);

                let iv = if data.len() >= AES_CBC_IV_SIZE {
                    // The data size should be always 16-byte aligned.
                    let last_block = &data[(data.len() - AES_CBC_IV_SIZE)..];
                    Some(last_block.to_vec())
                } else {
                    // The data is empty
                    None
                };

                Ok(AesDecryptResult { plain_text, iv })
            }
            AesAlgo::Gcm => {
                // For GCM, the input data includes the tag (last 16 bytes)
                if data.len() < 16 {
                    tracing::error!("Data does not include the tag (last 16 bytes)");
                    return Err(CryptoError::AesDecryptFailed);
                }

                let cipher_data = &data[..data.len() - 16];
                let tag = &data[data.len() - 16..];

                let cipher = get_cipher(&self.size, &algo)?;
                let mut ctx = CipherCtx::new().map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::AesDecryptFailed
                })?;
                let mut plain_text = vec![0; cipher_data.len()];

                ctx.decrypt_init(Some(cipher), None, None)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesDecryptFailed
                    })?;

                ctx.decrypt_init(None, Some(&self.key), iv)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesDecryptFailed
                    })?;

                // Set the authentication tag for GCM
                ctx.set_tag(tag).map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::AesDecryptFailed
                })?;

                // Process AAD if provided for GCM
                if let Some(aad_data) = aad {
                    ctx.cipher_update(aad_data, None)
                        .map_err(|openssl_error_stack| {
                            tracing::error!(?openssl_error_stack);
                            CryptoError::AesDecryptFailed
                        })?;
                }

                let count = ctx
                    .cipher_update(cipher_data, Some(&mut plain_text))
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::AesDecryptFailed
                    })?;

                let rest =
                    ctx.cipher_final(&mut plain_text[count..])
                        .map_err(|openssl_error_stack| {
                            tracing::error!(?openssl_error_stack);
                            CryptoError::AesDecryptFailed
                        })?;

                plain_text.truncate(count + rest);

                // For GCM, we don't return an IV since the nonce is provided by the caller
                Ok(AesDecryptResult {
                    plain_text,
                    iv: None,
                })
            }
        }
    }

    #[cfg(feature = "use-symcrypt")]
    fn decrypt_with_aad(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<AesDecryptResult, CryptoError> {
        match algo {
            AesAlgo::Cbc => {
                // CBC mode doesn't support AAD - throw error if provided
                if aad.is_some() {
                    tracing::error!("AAD is not supported for AES CBC decryption");
                    return Err(CryptoError::InvalidParameter);
                }
                let mut plain_text: Vec<u8> = vec![0u8; data.len()];
                let mut chaining_value: [u8; 16] = match iv {
                    Some(init_vec) => init_vec.try_into().map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::AesDecryptFailed
                    })?,
                    None => return Err(CryptoError::AesDecryptFailed),
                };
                let aes_cbc = AesExpandedKey::new(&self.key).map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::AesDecryptFailed
                })?;
                aes_cbc
                    .aes_cbc_decrypt(&mut chaining_value, data, &mut plain_text)
                    .map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::AesDecryptFailed
                    })?;
                let iv = Some(chaining_value.to_vec());
                Ok(AesDecryptResult { plain_text, iv })
            }
            AesAlgo::Gcm => {
                let nonce = match iv {
                    Some(nonce_bytes) => {
                        if nonce_bytes.len() != 12 {
                            tracing::error!("Nonce length is not 12 bytes");
                            return Err(CryptoError::AesDecryptFailed);
                        }
                        let nonce_array: [u8; 12] = nonce_bytes
                            .try_into()
                            .map_err(|_| CryptoError::AesDecryptFailed)?;
                        nonce_array
                    }
                    None => return Err(CryptoError::AesDecryptFailed),
                };

                // For GCM, the input data includes the tag (last 16 bytes)
                if data.len() < 16 {
                    tracing::error!("Data does not include the tag (last 16 bytes)");
                    return Err(CryptoError::AesDecryptFailed);
                }

                let cipher_data = &data[..data.len() - 16];
                let tag = &data[data.len() - 16..];

                // Create a mutable buffer with the cipher data for in-place decryption
                let mut buffer = cipher_data.to_vec();

                let gcm_key = GcmExpandedKey::new(&self.key, BlockCipherType::AesBlock).map_err(
                    |symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::AesDecryptFailed
                    },
                )?;

                // Use AAD if provided, otherwise use empty slice
                let aad_data = aad.unwrap_or(&[]);

                gcm_key
                    .decrypt_in_place(&nonce, aad_data, &mut buffer, tag)
                    .map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::AesDecryptFailed
                    })?;

                // For GCM, we don't return an IV since the nonce is provided by the caller
                Ok(AesDecryptResult {
                    plain_text: buffer,
                    iv: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hex;
    use test_with_tracing::test;

    use super::*;

    struct AesTestParam<'a> {
        size: AesKeySize,
        algo: AesAlgo,
        key: &'a str,
        iv: &'a str,
        plain: &'a str,
        cipher: &'a str,
        aad: &'a str,
    }

    fn test_aes(params: AesTestParam<'_>) {
        let key = hex::decode(params.key).unwrap();
        let iv = hex::decode(params.iv).unwrap();
        let plain = hex::decode(params.plain).unwrap();
        let cipher = hex::decode(params.cipher).unwrap();
        let aad = if params.aad.is_empty() {
            None
        } else {
            Some(hex::decode(params.aad).unwrap())
        };

        let result = AesKey::from_bytes(&key);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.size, params.size);

        let result = key.encrypt_with_aad(&plain, params.algo.clone(), Some(&iv), aad.as_deref());
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.cipher_text, cipher);

        let result = key.decrypt_with_aad(&cipher, params.algo, Some(&iv), aad.as_deref());
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.plain_text, plain);
    }

    #[test]
    fn test_aes_128_cbc() {
        let params = AesTestParam {
            size: AesKeySize::Aes128,
            algo: AesAlgo::Cbc,
            key: "2b7e151628aed2a6abf7158809cf4f3c",
            iv: "000102030405060708090a0b0c0d0e0f",
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "7649abac8119b246cee98e9b12e9197d",
            aad: "",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_192_cbc() {
        let params = AesTestParam {
            size: AesKeySize::Aes192,
            algo: AesAlgo::Cbc,
            key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            iv: "000102030405060708090a0b0c0d0e0f",
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "4f021db243bc633d7178183a9fa071e8",
            aad: "",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_256_cbc() {
        let params = AesTestParam {
            size: AesKeySize::Aes256,
            algo: AesAlgo::Cbc,
            key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            iv: "000102030405060708090a0b0c0d0e0f",
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
            aad: "",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_128_gcm() {
        let params = AesTestParam {
            size: AesKeySize::Aes128,
            algo: AesAlgo::Gcm,
            key: "2b7e151628aed2a6abf7158809cf4f3c",
            iv: "000102030405060708090a0b", // 12 bytes for GCM
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "300e85b4962811d409e56a97d11aa3bdf3afd8d46eb670339a08a04cbf7e0353",
            aad: "",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_192_gcm() {
        let params = AesTestParam {
            size: AesKeySize::Aes192,
            algo: AesAlgo::Gcm,
            key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            iv: "000102030405060708090a0b", // 12 bytes for GCM
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "f7fac25148ee25d4ac55295c14123a5e7aee970411fe9eaa65244ed6ced12bed",
            aad: "",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_256_gcm() {
        let params = AesTestParam {
            size: AesKeySize::Aes256,
            algo: AesAlgo::Gcm,
            key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            iv: "000102030405060708090a0b", // 12 bytes for GCM
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "63a00fb1aa0404e84f9d3cb8fead8ec1b41c21e94e6d6f964e020159d955ab5c",
            aad: "",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_cbc_empty_input() {
        let params = AesTestParam {
            size: AesKeySize::Aes256,
            algo: AesAlgo::Cbc,
            key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            iv: "000102030405060708090a0b0c0d0e0f",
            plain: "",
            cipher: "",
            aad: "",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_cbc_output_iv() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let expected_plain = [1u8; 2048];

        let result = AesKey::from_bytes(&key);
        assert!(result.is_ok());
        let key = result.unwrap();

        // Test encryption
        let result = key.encrypt(&expected_plain, AesAlgo::Cbc, Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        let expected_cipher = result.cipher_text;
        assert!(result.iv.is_some());
        let expected_iv = result.iv.unwrap();

        let result = key.encrypt(&expected_plain[..1024], AesAlgo::Cbc, Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        let cipher_1 = result.cipher_text;
        assert!(result.iv.is_some());
        let output_iv_1 = result.iv.unwrap();

        let result = key.encrypt(&expected_plain[1024..], AesAlgo::Cbc, Some(&output_iv_1));
        assert!(result.is_ok());
        let result = result.unwrap();
        let cipher_2 = result.cipher_text;
        assert!(result.iv.is_some());
        let output_iv_2 = result.iv.unwrap();

        let cipher = [&cipher_1[..], &cipher_2[..]].concat();

        assert_eq!(output_iv_2, expected_iv);
        assert_eq!(cipher, expected_cipher);

        // Test decryption
        let result = key.decrypt(&cipher, AesAlgo::Cbc, Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        let output_plain = result.plain_text;
        assert!(result.iv.is_some());
        let expected_iv = result.iv.unwrap();
        assert_eq!(output_plain, expected_plain);

        let result = key.decrypt(&cipher[..1024], AesAlgo::Cbc, Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        let plain_1 = result.plain_text;
        assert!(result.iv.is_some());
        let output_iv_1 = result.iv.unwrap();

        let result = key.decrypt(&cipher[1024..], AesAlgo::Cbc, Some(&output_iv_1));
        assert!(result.is_ok());
        let result = result.unwrap();
        let plain_2 = result.plain_text;
        assert!(result.iv.is_some());
        let output_iv_2 = result.iv.unwrap();

        let plain = [&plain_1[..], &plain_2[..]].concat();

        assert_eq!(output_iv_2, expected_iv);
        assert_eq!(plain, expected_plain);
    }

    /// Tests the `generate` for AES keys.
    #[test]
    fn test_aes_generate() {
        for size in [AesKeySize::Aes128, AesKeySize::Aes192, AesKeySize::Aes256] {
            // Generate an AES key
            let result = AesKey::generate(size);
            assert!(result.is_ok());

            // Ensure the key size matches what we passed in
            let key = result.unwrap();
            assert_eq!(key.size(), size);
        }
    }

    /// Tests AES-GCM with AAD functionality.
    #[test]
    fn test_aes_gcm_with_aad() {
        let params = AesTestParam {
            size: AesKeySize::Aes128,
            algo: AesAlgo::Gcm,
            key: "feffe9928665731c6d6a8f9467308308",
            iv: "000102030405060708090a0b", // 12 bytes for GCM
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "9b3a396d63fa11dfaac2c661eb20a84aec6f65b8be52184c71079035c5cbc0e0",
            aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        };

        test_aes(params);
    }

    /// Tests that CBC mode rejects AAD.
    #[test]
    fn test_aes_cbc_rejects_aad() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let aad = hex::decode("feedfacedeadbeef").unwrap();

        let aes_key = AesKey::from_bytes(&key).unwrap();

        // Test that encryption with AAD and CBC mode returns an error
        let encrypt_result = aes_key.encrypt_with_aad(&plain, AesAlgo::Cbc, Some(&iv), Some(&aad));
        assert!(encrypt_result.is_err());
        assert_eq!(encrypt_result.err(), Some(CryptoError::InvalidParameter));

        // Test that decryption with AAD and CBC mode returns an error
        let decrypt_result = aes_key.decrypt_with_aad(&plain, AesAlgo::Cbc, Some(&iv), Some(&aad));
        assert!(decrypt_result.is_err());
        assert_eq!(decrypt_result.err(), Some(CryptoError::InvalidParameter));
    }
}
