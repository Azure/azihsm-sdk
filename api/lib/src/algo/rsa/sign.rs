// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto as crypto;

use super::*;

/// RSA Encryption Padding Schemes
pub(crate) enum HsmRsaSignPadding {
    /// PKCS#1 v1.5 padding
    Pkcs1,

    /// PKCS#1 Pss padding
    Pss,
}

/// RSA Signing Algorithm
pub struct HsmRsaSignAlgo {
    padding: HsmRsaSignPadding,
    hash_algo: HsmHashAlgo,
    salt_len: usize,
}

impl HsmRsaSignAlgo {
    /// Create an RSA Signing Algorithm with PKCS#1 v1.5 Padding
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use for signing.
    ///
    /// # Returns
    ///
    /// A new instance of `HsmRsaSignAlgo` configured for PKCS#1 v1.5 padding.
    pub fn with_pkcs1_padding(hash_algo: HsmHashAlgo) -> Self {
        Self {
            padding: HsmRsaSignPadding::Pkcs1,
            hash_algo,
            salt_len: 0,
        }
    }

    /// Create an RSA Signing Algorithm with PSS Padding
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use for signing.
    /// * `salt_len` - The length of the salt to use in the PSS padding.
    ///
    /// # Returns
    ///
    /// A new instance of `HsmRsaSignAlgo` configured for PSS padding.
    pub fn with_pss_padding(hash_algo: HsmHashAlgo, salt_len: usize) -> Self {
        Self {
            padding: HsmRsaSignPadding::Pss,
            hash_algo,
            salt_len,
        }
    }
}

impl HsmSignOp for HsmRsaSignAlgo {
    type Key = HsmRsaPrivateKey;
    type Error = HsmError;

    /// Creates an RSA signature over the provided hash in a single operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for signing.
    /// * `data` - The pre-computed message hash. The caller is responsible for hashing
    ///   the original message.
    /// * `signature` - Optional output buffer. If `None`, returns the required signature
    ///   size. If provided, must be large enough to hold the signature.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// size if `signature` is `None`.
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // check if key can sign
        if !key.can_sign() {
            return Err(HsmError::InvalidKey);
        }

        let expected_len = key.size();
        let Some(signature) = signature else {
            return Ok(expected_len);
        };

        if signature.len() != expected_len {
            return Err(HsmError::BufferTooSmall);
        }

        let data = match self.padding {
            HsmRsaSignPadding::Pkcs1 => {
                let mut algo =
                    crypto::RsaPadPkcs1SignAlgo::new(expected_len, self.hash_algo.into(), data);
                crypto::Encoder::encode_vec(&mut algo).map_hsm_err(HsmError::InternalError)?
            }
            HsmRsaSignPadding::Pss => {
                let mut algo = crypto::RsaPadPssAlgo::with_mgf1(
                    expected_len,
                    self.hash_algo.into(),
                    data,
                    self.salt_len,
                );
                crypto::Encoder::encode_vec(&mut algo).map_hsm_err(HsmError::InternalError)?
            }
        };

        ddi::rsa_sign(key, &data, signature)
    }
}

impl HsmVerifyOp for HsmRsaSignAlgo {
    type Key = HsmRsaPublicKey;
    type Error = HsmError;

    /// Verifies an RSA signature over the provided hash in a single operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for verification.
    /// * `data` - The pre-computed message hash. The caller is responsible for hashing
    ///   the original message.
    /// * `signature` - The signature to verify.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the signature is valid, or an error if it is invalid
    /// or if any other error occurs.
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        // check if key can verify
        if !key.can_verify() {
            return Err(HsmError::InvalidKey);
        }

        use azihsm_crypto::VerifyOp;
        let mut algo = match self.padding {
            HsmRsaSignPadding::Pkcs1 => {
                crypto::RsaSignAlgo::with_pkcs1_padding(self.hash_algo.into())
            }
            HsmRsaSignPadding::Pss => {
                crypto::RsaSignAlgo::with_pss_padding(self.hash_algo.into(), self.salt_len)
            }
        };

        key.with_crypto_key(|crypto_key| {
            algo.verify(crypto_key, data, signature)
                .map_hsm_err(HsmError::InternalError)
        })
    }
}
