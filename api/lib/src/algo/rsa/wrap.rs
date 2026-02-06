// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto as crypto;

use super::*;

/// RSA AES wrap algorithm with specified hash algorithm.
pub struct HsmRsaAesWrapAlgo {
    hash_algo: HsmHashAlgo,
    kek_size: usize,
}

impl HsmRsaAesWrapAlgo {
    /// Creates a new instance of the RSA AES wrap algorithm with the specified hash algorithm
    /// and key size.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use (e.g., SHA-1, SHA-256).
    /// * `key_size` - The key size in bytes (e.g., 16, 24, 32).
    ///
    /// # Returns
    ///
    /// A new instance of `HsmRsaKeyRsaAesWrapAlgo`.
    pub fn new(hash_algo: HsmHashAlgo, key_size: usize) -> Self {
        Self {
            hash_algo,
            kek_size: key_size,
        }
    }
}

impl HsmEncryptOp for HsmRsaAesWrapAlgo {
    type Key = HsmRsaPublicKey;
    type Error = HsmError;

    /// Encrypts (wraps) a plaintext key using the specified RSA public key.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for encryption (wrapping).
    /// * `plaintext` - The plaintext key bytes to be wrapped.
    /// * `ciphertext` - Optional output buffer. If `None`, returns the required ciphertext size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the ciphertext buffer, or the required ciphertext
    /// size.
    fn encrypt(
        &mut self,
        key: &Self::Key,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // make sure key can wrap keys
        if !key.can_wrap() {
            return Err(HsmError::InvalidKey);
        }

        let mut algo = crypto::RsaAesKeyWrap::new(self.hash_algo.into(), self.kek_size);

        key.with_crypto_key(|crypto_key| {
            crypto::Encrypter::encrypt(&mut algo, crypto_key, plaintext, ciphertext)
                .map_hsm_err(HsmError::InternalError)
        })
    }
}
