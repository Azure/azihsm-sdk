// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto::*;

use super::*;

/// RSA Hashing and Signing Algorithm
pub struct HsmRsaHashSignAlgo {
    padding: HsmRsaSignPadding,
    hash_algo: HsmHashAlgo,
    salt_len: usize,
}

impl HsmRsaHashSignAlgo {
    /// Create an RSA Signing Algorithm with PKCS#1 v1.5 Padding
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use for signing.
    ///
    /// # Returns
    ///
    /// A new instance of `HsmRsaHashSignAlgo` configured for PKCS#1 v1.5 padding.
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
    /// A new instance of `HsmRsaHashSignAlgo` configured for PSS padding.
    pub fn with_pss_padding(hash_algo: HsmHashAlgo, salt_len: usize) -> Self {
        Self {
            padding: HsmRsaSignPadding::Pss,
            hash_algo,
            salt_len,
        }
    }

    /// Pads the given hash according to the selected RSA signing padding scheme.
    ///
    /// # Arguments
    ///
    /// * `hash` - The pre-computed message hash to pad.
    /// * `expected_len` - The expected length of the padded output.
    ///
    /// # Returns
    ///
    /// Returns the padded data as a vector of bytes.
    fn pad(&self, hash: &[u8], expected_len: usize) -> HsmResult<Vec<u8>> {
        match self.padding {
            HsmRsaSignPadding::Pkcs1 => {
                let mut algo = RsaPadPkcs1SignAlgo::new(expected_len, self.hash_algo.into(), hash);
                Encoder::encode_vec(&mut algo).map_hsm_err(HsmError::InternalError)
            }
            HsmRsaSignPadding::Pss => {
                let mut algo = RsaPadPssAlgo::with_mgf1(
                    expected_len,
                    self.hash_algo.into(),
                    hash,
                    self.salt_len,
                );
                Encoder::encode_vec(&mut algo).map_hsm_err(HsmError::InternalError)
            }
        }
    }

    /// Creates the RSA verification algorithm corresponding to the signing configuration.
    ///
    /// # Returns
    ///
    /// The `RsaSignAlgo` instance for verification.
    fn verify_algo(&self) -> RsaSignAlgo {
        match self.padding {
            HsmRsaSignPadding::Pkcs1 => RsaSignAlgo::with_pkcs1_padding(self.hash_algo.into()),
            HsmRsaSignPadding::Pss => {
                RsaSignAlgo::with_pss_padding(self.hash_algo.into(), self.salt_len)
            }
        }
    }

    /// Hashes the provided data using the configured hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash.
    ///
    /// # Returns
    ///
    /// Returns the computed hash as a vector of bytes.
    fn hash(&self, data: &[u8]) -> HsmResult<Vec<u8>> {
        let mut hash_algo = HashAlgo::from(self.hash_algo);
        Hasher::hash_vec(&mut hash_algo, data).map_hsm_err(HsmError::InternalError)
    }
}

impl HsmSignOp for HsmRsaHashSignAlgo {
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

        let hash = self.hash(data)?;
        let data = self.pad(&hash, expected_len)?;

        ddi::rsa_sign(key, &data, signature)
    }
}

impl HsmVerifyOp for HsmRsaHashSignAlgo {
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
    /// Returns `Ok(true)` if the signature is valid, or `Ok(false)` if it is invalid,
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

        let data = self.hash(data)?;
        key.with_crypto_key(|crypto_key| {
            let mut algo = self.verify_algo();
            algo.verify(crypto_key, &data, signature)
                .map_hsm_err(HsmError::InternalError)
        })
    }
}

impl HsmSignStreamingOp for HsmRsaHashSignAlgo {
    type Key = HsmRsaPrivateKey;
    type Error = HsmError;
    type Context = HsmRsaSignContext;

    /// Initializes a streaming RSA signature creation context.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for signing.
    ///
    /// # Returns
    ///
    /// Returns a context that can process data incrementally via update calls.
    ///
    /// # Errors
    ///
    /// Returns an error if the hash algorithm initialization fails.
    fn sign_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // check if key can sign
        if !key.can_sign() {
            return Err(HsmError::InvalidKey);
        }

        let hasher = Hasher::hash_init(HashAlgo::from(self.hash_algo))
            .map_hsm_err(HsmError::InternalError)?;
        Ok(HsmRsaSignContext {
            algo: self,
            hasher,
            key,
        })
    }
}

/// Context for streaming RSA signature creation.
pub struct HsmRsaSignContext {
    algo: HsmRsaHashSignAlgo,
    hasher: HashAlgoContext,
    key: HsmRsaPrivateKey,
}

impl HsmSignStreamingOpContext for HsmRsaSignContext {
    type Algo = HsmRsaHashSignAlgo;

    /// Processes a chunk of data for RSA signature generation.
    ///
    /// # Arguments
    ///
    /// * `data` - Data chunk to process.
    ///
    /// # Errors
    ///
    /// Returns an error if the hash update operation fails.
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmSignStreamingOp>::Error> {
        self.hasher
            .update(data)
            .map_hsm_err(HsmError::InternalError)
    }

    /// Finalizes the streaming RSA signature generation.
    ///
    /// # Arguments
    ///
    /// * `signature` - Optional output buffer. If `None`, returns the required signature size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// buffer size if `signature` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if signature generation fails.
    fn finish(
        &mut self,
        signature: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmSignStreamingOp>::Error> {
        let expected_len = self.key.size();
        let Some(signature) = signature else {
            return Ok(expected_len);
        };

        if signature.len() != expected_len {
            return Err(HsmError::BufferTooSmall);
        }

        let hash = self
            .hasher
            .finish_vec()
            .map_hsm_err(HsmError::InternalError)?;

        let data = self.algo.pad(&hash, expected_len)?;

        ddi::rsa_sign(&self.key, &data, signature)
    }
}

impl HsmVerifyStreamingOp for HsmRsaHashSignAlgo {
    type Key = HsmRsaPublicKey;
    type Error = HsmError;
    type Context = HsmRsaVerifyContext;

    /// Initializes a streaming RSA signature verification context.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for verification.
    ///
    /// # Returns
    ///
    /// Returns a context that can process data incrementally via update calls.
    ///
    /// # Errors
    ///
    /// Returns an error if the hash algorithm initialization fails.
    fn verify_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // check if key can verify
        if !key.can_verify() {
            return Err(HsmError::InvalidKey);
        }

        let hasher = Hasher::hash_init(HashAlgo::from(self.hash_algo))
            .map_hsm_err(HsmError::InternalError)?;
        Ok(HsmRsaVerifyContext {
            algo: self,
            hasher,
            key,
        })
    }
}

/// Context for streaming RSA signature verification.
pub struct HsmRsaVerifyContext {
    algo: HsmRsaHashSignAlgo,
    hasher: HashAlgoContext,
    key: HsmRsaPublicKey,
}

impl HsmVerifyStreamingOpContext for HsmRsaVerifyContext {
    type Algo = HsmRsaHashSignAlgo;

    /// Processes a chunk of data for RSA signature verification.
    ///
    /// # Arguments
    ///
    /// * `data` - Data chunk to process.
    ///
    /// # Errors
    ///
    /// Returns an error if the hash update operation fails.
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmVerifyStreamingOp>::Error> {
        self.hasher
            .update(data)
            .map_hsm_err(HsmError::InternalError)
    }

    /// Finalizes the streaming RSA signature verification.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if verification operation fails.
    fn finish(
        &mut self,
        signature: &[u8],
    ) -> Result<bool, <Self::Algo as HsmVerifyStreamingOp>::Error> {
        let mut algo = self.algo.verify_algo();

        let hash = self
            .hasher
            .finish_vec()
            .map_hsm_err(HsmError::InternalError)?;

        self.key.with_crypto_key(|crypto_key| {
            algo.verify(crypto_key, &hash, signature)
                .map_hsm_err(HsmError::InternalError)
        })
    }
}
