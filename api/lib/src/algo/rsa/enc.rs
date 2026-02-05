// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto as crypto;

use super::*;

/// RSA Encryption Padding Schemes
pub(crate) enum HsmRsaEncryptPadding {
    /// PKCS#1 v1.5 padding
    Pkcs1,

    /// PKCS#1 OAEP padding
    Oaep,
}

/// RSA Encryption Algorithm
pub struct HsmRsaEncryptAlgo {
    padding: HsmRsaEncryptPadding,
    hash_algo: Option<HsmHashAlgo>,
    label: Option<Vec<u8>>,
}

impl HsmRsaEncryptAlgo {
    /// Create an RSA Encryption Algorithm with PKCS#1 v1.5 Padding
    ///
    /// # Returns
    ///
    /// Returns a new instance of `HsmRsaEncryptAlgo` configured for PKCS#1 v1.5 padding.
    pub fn with_pkcs1_padding() -> Self {
        Self {
            padding: HsmRsaEncryptPadding::Pkcs1,
            hash_algo: None,
            label: None,
        }
    }

    /// Create an RSA Encryption Algorithm with OAEP Padding
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use for OAEP padding.
    /// * `label` - An optional label to use in the OAEP padding.
    ///
    /// # Returns
    ///
    /// A new instance of `HsmRsaEncryptAlgo` configured for OAEP padding.
    pub fn with_oaep_padding(hash_algo: HsmHashAlgo, label: Option<&[u8]>) -> Self {
        Self {
            padding: HsmRsaEncryptPadding::Oaep,
            hash_algo: Some(hash_algo),
            label: label.map(|l| l.to_vec()),
        }
    }
}

impl HsmEncryptOp for HsmRsaEncryptAlgo {
    type Key = HsmRsaPublicKey;
    type Error = HsmError;

    /// Encrypts data using RSA encryption with the specified padding scheme.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for encryption.
    /// * `plaintext` - The data to encrypt.
    /// * `ciphertext` - Optional output buffer. If `None`, returns the required ciphertext
    ///   size. If provided, must be large enough to hold the ciphertext.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the ciphertext buffer, or the required
    /// buffer size if `ciphertext` is `None`.
    fn encrypt(
        &mut self,
        key: &Self::Key,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // check if key can encrypt
        if !key.can_encrypt() {
            return Err(HsmError::InvalidKey);
        }

        match self.padding {
            HsmRsaEncryptPadding::Pkcs1 => {
                let mut algo = crypto::RsaEncryptAlgo::with_pkcs1_padding();
                key.with_crypto_key(|crypto_key| {
                    crypto::Encrypter::encrypt(&mut algo, crypto_key, plaintext, ciphertext)
                        .map_hsm_err(HsmError::InternalError)
                })
            }
            HsmRsaEncryptPadding::Oaep => {
                let Some(hash_algo) = self.hash_algo else {
                    return Err(HsmError::InvalidArgument);
                };
                let mut algo = crypto::RsaEncryptAlgo::with_oaep_padding(
                    hash_algo.into(),
                    self.label.as_deref(),
                );
                key.with_crypto_key(|crypto_key| {
                    crypto::Encrypter::encrypt(&mut algo, crypto_key, plaintext, ciphertext)
                        .map_hsm_err(HsmError::InternalError)
                })
            }
        }
    }
}

impl HsmDecryptOp for HsmRsaEncryptAlgo {
    type Key = HsmRsaPrivateKey;
    type Error = HsmError;

    /// Decrypts data using RSA decryption with the specified padding scheme.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for decryption.
    /// * `ciphertext` - The data to decrypt.
    /// * `plaintext` - Optional output buffer. If `None`, returns the required plaintext
    ///   size. If provided, must be large enough to hold the plaintext.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the plaintext buffer, or the required
    /// buffer size if `plaintext` is `None`.
    fn decrypt(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // check if key can decrypt
        if !key.can_decrypt() {
            return Err(HsmError::InvalidKey);
        }

        let expected_len = key.size();
        let Some(plaintext) = plaintext else {
            return Ok(expected_len);
        };

        if ciphertext.len() != expected_len || plaintext.len() < expected_len {
            return Err(HsmError::InvalidArgument);
        }

        ddi::rsa_decrypt(key, ciphertext, plaintext)?;

        let decoded = match self.padding {
            HsmRsaEncryptPadding::Pkcs1 => decode_pkcs1(plaintext)?,
            HsmRsaEncryptPadding::Oaep => {
                let Some(hash_algo) = self.hash_algo else {
                    return Err(HsmError::InvalidArgument);
                };
                decode_oaep(expected_len, plaintext, hash_algo, self.label.as_deref())?
            }
        };

        if decoded.len() > plaintext.len() {
            return Err(HsmError::InternalError);
        }

        plaintext[..decoded.len()].copy_from_slice(&decoded);

        Ok(decoded.len())
    }
}

/// Decodes a PKCS#1 v1.5 padded plaintext buffer.
fn decode_pkcs1(plaintext: &mut [u8]) -> HsmResult<Vec<u8>> {
    let algo = crypto::Decoder::decode::<crypto::RsaPadPkcs1EncryptAlgo>(plaintext, ())
        .map_hsm_err(HsmError::InternalError)?;
    Ok(algo.message().to_vec())
}

/// Decodes an OAEP padded plaintext buffer.
fn decode_oaep(
    expected_len: usize,
    plaintext: &mut [u8],
    hash_algo: HsmHashAlgo,
    label: Option<&[u8]>,
) -> HsmResult<Vec<u8>> {
    let params = crypto::RsaPadOaepAlgoParams::new(expected_len, hash_algo.into(), label);
    let algo = crypto::Decoder::decode::<crypto::RsaPadOaepAlgo>(plaintext, params)
        .map_hsm_err(HsmError::InternalError)?;
    Ok(algo.message().to_vec())
}
