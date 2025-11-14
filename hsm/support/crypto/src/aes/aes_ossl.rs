// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use openssl::rand::rand_bytes;
use openssl::symm::Cipher;
use openssl::symm::Crypter;

use super::*;

pub struct OsslDecrypter {
    decrypter: Crypter,
    plain_text: Vec<u8>,
    iv: Vec<u8>,
    block_size: usize,
}

pub struct OsslEncrypter {
    encrypter: Crypter,
    cipher_text: Vec<u8>, // store the cipher text
    iv: Vec<u8>,
    block_size: usize,
}

//return data for helper functions in the code
struct OsslAesCbcResult {
    output: Vec<u8>,
    iv: Vec<u8>,
}

/// Returns the key length in bytes for a given AES key size.
///
/// # Arguments
/// * `key_size` - The AES key size enum variant.
///
/// # Returns
/// * `usize` - The length of the key in bytes.
fn get_aes_key_len(key_size: AesKeySize) -> usize {
    match key_size {
        AesKeySize::Aes128 => 16,
        AesKeySize::Aes192 => 24,
        AesKeySize::Aes256 => 32,
    }
}

/// Returns the OpenSSL cipher type for a given key.
///
/// # Arguments
/// * `key` - The key as a byte slice.
///
/// # Returns
/// * `Result<Cipher, CryptoError>` - Ok with the cipher, or an error if the key length is invalid.
fn get_cipher_for_key(key: &[u8]) -> Result<openssl::symm::Cipher, CryptoError> {
    match key.len() {
        16 => Ok(Cipher::aes_128_cbc()),
        24 => Ok(Cipher::aes_192_cbc()),
        32 => Ok(Cipher::aes_256_cbc()),
        _ => {
            tracing::error!("Invalid AES key length: {}", key.len());
            Err(CryptoError::AesKeySizeError)
        }
    }
}

/// Internal helper for AES-CBC single-shot encrypt/decrypt using OpenSSL.
/// Calls either Encrypt or Decrypt mode based on the operation.
fn ossl_aes_cbc_crypt(
    key: &[u8],
    input: &[u8],
    iv: Option<&[u8]>,
    padding: Option<AesCbcPadding>,
    is_encrypt: bool,
) -> Result<OsslAesCbcResult, CryptoError> {
    let cipher = get_cipher_for_key(key)?;
    let iv = match iv {
        Some(iv) => {
            if iv.len() != cipher.block_size() {
                tracing::error!(
                    "IV length {} does not match block size {}",
                    iv.len(),
                    cipher.block_size()
                );
                return Err(CryptoError::AesInvalidIVError);
            }
            iv.to_vec()
        }
        None => {
            if is_encrypt {
                let mut new_iv = vec![0u8; cipher.block_size()];
                rand_bytes(&mut new_iv).map_err(|e| {
                    tracing::error!(error = ?e, "Failed to generate random IV");
                    CryptoError::AesError
                })?;
                new_iv
            } else {
                tracing::error!("IV is None for decryption");
                return Err(CryptoError::AesInvalidIVError);
            }
        }
    };
    let mode = if is_encrypt {
        openssl::symm::Mode::Encrypt
    } else {
        openssl::symm::Mode::Decrypt
    };
    let mut crypter = Crypter::new(cipher, mode, key, Some(&iv)).map_err(|e| {
        tracing::error!(error = ?e, "Failed to create OpenSSL Crypter");
        CryptoError::AesError
    })?;

    let padding_flag = padding.is_some();
    crypter.pad(padding_flag);
    let mut output = vec![0u8; input.len() + cipher.block_size()];
    let mut count = crypter.update(input, &mut output).map_err(|e| {
        tracing::error!(error = ?e, "OpenSSL {} update failed", if is_encrypt {"encryption"} else {"decryption"});
        CryptoError::AesError
    })?;
    count += crypter.finalize(&mut output[count..]).map_err(|e| {
        tracing::error!(error = ?e, "OpenSSL {} finalize failed", if is_encrypt {"encryption"} else {"decryption"});
        CryptoError::AesError
    })?;
    output.truncate(count);
    Ok(OsslAesCbcResult { output, iv })
}

impl AesCbcKeyOp for AesCbcKey {
    /// Generates a random AES key of the specified size.
    ///
    /// # Arguments
    /// * `key_size` - The desired AES key size.
    ///
    /// # Returns
    /// * `Result<AesKey, CryptoError>` - Ok with the generated key, or an error if random generation fails.
    fn aes_cbc_generate_key(&self, key_size: AesKeySize) -> Result<AesKey, CryptoError> {
        let key_len = get_aes_key_len(key_size);
        let mut key = vec![0u8; key_len];
        if let Err(e) = rand_bytes(&mut key) {
            tracing::error!(error = ?e, "Failed to generate random AES key");
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
    fn aes_cbc_encrypt(
        &self,
        data: &[u8],
        iv: Option<&[u8]>,
        enable_pad: Option<AesCbcPadding>,
    ) -> Result<AesCbcEncryptResult, CryptoError> {
        let result = ossl_aes_cbc_crypt(&self.key, data, iv, enable_pad, true)?;
        Ok(AesCbcEncryptResult {
            cipher_text: result.output,
            iv: result.iv,
        })
    }

    /// Initializes an AES CBC encryption context with the given IV.
    ///
    /// # Arguments
    /// * `iv` - Optional initialization vector as a byte slice. If None, a random IV is generated. If Some but empty, returns an error.
    ///
    /// # Returns
    /// * `Result<Self::Crypter, CryptoError>` - Ok with the encryption context, or an error if initialization fails.
    fn aes_cbc_encrypt_init(
        &self,
        iv: Option<&[u8]>,
        padding: Option<AesCbcPadding>,
    ) -> Result<impl AesCbcEncryptContextOp, CryptoError> {
        let cipher = get_cipher_for_key(&self.key)?;
        let iv = match iv {
            Some(v) => {
                if v.len() != cipher.block_size() {
                    tracing::error!(
                        "IV length {} does not match block size {}",
                        v.len(),
                        cipher.block_size()
                    );
                    return Err(CryptoError::AesInvalidIVError);
                }
                v.to_vec()
            }
            None => {
                let mut new_iv = vec![0u8; cipher.block_size()];
                rand_bytes(&mut new_iv).map_err(|e| {
                    tracing::error!(error = ?e, "Failed to generate random IV");
                    CryptoError::AesError
                })?;
                new_iv
            }
        };
        let mut encrypter =
            Crypter::new(cipher, openssl::symm::Mode::Encrypt, &self.key, Some(&iv)).map_err(
                |e| {
                    tracing::error!(error = ?e, "Failed to create OpenSSL Crypter for context");
                    CryptoError::AesError
                },
            )?;
        let padding_flag = padding.is_some();
        encrypter.pad(padding_flag);
        Ok(OsslEncrypter {
            encrypter,
            cipher_text: Vec::new(),
            iv,
            block_size: cipher.block_size(),
        })
    }

    /// Decrypts data in a single shot using AES CBC mode.
    ///
    /// # Arguments
    /// * `data` - The ciphertext data to decrypt.
    /// * `iv` - Optional initialization vector. If None, a random IV is generated (not recommended for decryption).
    ///
    /// # Returns
    /// * `Result<AesCbcDecryptResult, CryptoError>` - Ok with plaintext and IV, or an error if decryption fails.
    fn aes_cbc_decrypt(
        &self,
        data: &[u8],
        iv: &[u8],
        padding: Option<AesCbcPadding>,
    ) -> Result<AesCbcDecryptResult, CryptoError> {
        let result = ossl_aes_cbc_crypt(&self.key, data, Some(iv), padding, false)?;
        Ok(AesCbcDecryptResult {
            plain_text: result.output,
            iv: result.iv,
        })
    }

    /// Initializes an AES CBC decryption context with the given IV.
    ///
    /// # Arguments
    /// * `iv` - Optional initialization vector as a byte slice. If None or empty, returns an error.
    ///
    /// # Returns
    /// * `Result<Self::Decrypter, CryptoError>` - Ok with the decryption context, or an error if initialization fails.
    fn aes_cbc_decrypt_init(
        &self,
        iv: &[u8],
        padding: Option<AesCbcPadding>,
    ) -> Result<impl AesCbcDecryptContextOp, CryptoError> {
        let cipher = get_cipher_for_key(&self.key)?;
        let iv = match iv.is_empty() {
            false => {
                if iv.len() != cipher.block_size() {
                    tracing::error!(
                        "IV length {} does not match block size {}",
                        iv.len(),
                        cipher.block_size()
                    );
                    return Err(CryptoError::AesInvalidIVError);
                }
                iv
            }
            true => {
                tracing::error!("IV must not be None or empty for decryption context");
                return Err(CryptoError::AesInvalidIVError);
            }
        };
        let mut decrypter = Crypter::new(cipher, openssl::symm::Mode::Decrypt, &self.key, Some(iv))
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to create OpenSSL Crypter for context");
                CryptoError::AesError
            })?;
        let padding_flag = padding.is_some();
        decrypter.pad(padding_flag);
        Ok(OsslDecrypter {
            decrypter,
            plain_text: Vec::new(),
            iv: iv.to_vec(),
            block_size: cipher.block_size(),
        })
    }
}

impl AesCbcDecryptContextOp for OsslDecrypter {
    /// Decrypts a chunk of ciphertext in CBC mode and accumulates the plaintext.
    ///
    /// # Arguments
    /// * `data` - The ciphertext chunk to decrypt.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if successful, or an error if decryption fails.
    fn aes_cbc_decrypt_update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let block_size = self.block_size;
        let mut buf = vec![0u8; data.len() + block_size];
        let count = self.decrypter.update(data, &mut buf).map_err(|e| {
            tracing::error!(error = ?e, "OpenSSL context decryption update failed");
            CryptoError::AesError
        })?;
        self.plain_text.extend_from_slice(&buf[..count]);
        Ok(())
    }

    /// Finalizes the CBC decryption context, processes any remaining data, and writes the full plaintext to the output buffer.
    ///
    /// # Arguments
    /// * `plain_text` - Output buffer to receive the full decrypted plaintext. Must be large enough to hold the result.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if successful, or an error if decryption fails or the buffer is too small.
    fn aes_cbc_decrypt_final(mut self) -> Result<AesCbcDecryptResult, CryptoError> {
        let block_size = self.block_size;
        let mut buf = vec![0u8; block_size];
        let mut decrypter = self.decrypter;

        // Finalize and append any remaining decrypted data
        let count = decrypter.finalize(&mut buf).map_err(|e| {
            tracing::error!(error = ?e, "OpenSSL context decryption finalize failed");
            CryptoError::AesError
        })?;
        self.plain_text.extend_from_slice(&buf[..count]);
        let result: AesCbcDecryptResult = AesCbcDecryptResult {
            plain_text: self.plain_text,
            iv: self.iv,
        };

        Ok(result)
    }
}

impl AesCbcEncryptContextOp for OsslEncrypter {
    /// Encrypts a chunk of plaintext in CBC mode and accumulates the ciphertext.
    ///
    /// # Arguments
    /// * `data` - The plaintext chunk to encrypt.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if successful, or an error if encryption fails.
    fn aes_cbc_encrypt_update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let block_size = self.block_size;
        let mut buf = vec![0u8; data.len() + block_size];
        let count = self.encrypter.update(data, &mut buf).map_err(|e| {
            tracing::error!(error = ?e, "OpenSSL context encryption update failed");
            CryptoError::AesError
        })?;
        self.cipher_text.extend_from_slice(&buf[..count]);
        Ok(())
    }

    /// Finalizes the CBC encryption context, processes any remaining data, and writes the full ciphertext to the output buffer.
    ///
    /// # Arguments
    /// * `cipher_text` - Output buffer to receive the full encrypted ciphertext. Must be large enough to hold the result.
    ///
    /// # Returns
    /// * `Result<usize, CryptoError>` - Ok with the number of bytes written, or an error if encryption fails or the buffer is too small.
    fn aes_cbc_encrypt_final(mut self) -> Result<AesCbcEncryptResult, CryptoError> {
        let block_size = self.block_size;
        let mut buf = vec![0u8; block_size];
        let count = self.encrypter.finalize(&mut buf).map_err(|e| {
            tracing::error!(error = ?e, "OpenSSL context encryption finalize failed");
            CryptoError::AesError
        })?;
        self.cipher_text.extend_from_slice(&buf[..count]);
        //move the data to caller
        let result: AesCbcEncryptResult = AesCbcEncryptResult {
            cipher_text: self.cipher_text,
            iv: self.iv,
        };
        Ok(result)
    }
}
