// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use openssl::hash;
use openssl::hash::Hasher;
use openssl::hash::MessageDigest;

use super::*;

///Implement HashContext for digest
impl HashContext for DigestContext {
    type Hasher = openssl::hash::Hasher;
    ///  SHA update hash with data.
    ///
    /// # Arguments
    /// * `hasher` - Initialized hasher context.
    /// * `data` - The data to be use to update the hash.
    ///
    /// # Returns
    /// * * OK on success
    ///
    /// # Errors
    /// * `CryptoError::ShaError` - If the SHA operation fails.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.hasher.update(data).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::ShaError
        })?;
        Ok(())
    }

    ///  SHA retrieve final computed hash and init hasher to default value.
    ///
    /// # Arguments
    /// * `hasher` - Initialized hasher context.
    /// * `hash` - Final computed hash value.
    ///
    /// # Returns
    /// * * OK on success
    ///
    /// # Errors
    /// * `CryptoError::ShaError` - If the SHA operation fails.
    fn finish(self, hash: &mut [u8]) -> Result<(), CryptoError> {
        let mut mutable_self = self;
        // We need to compare result size with hash size
        //since there is no way of retrieving Messagedigest from the hasher
        let digest = mutable_self
            .hasher
            .finish()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::ShaError
            })?;
        if digest.len() != hash.len() {
            tracing::error!("{}", CryptoError::ShaDigestSizeError);
            return Err(CryptoError::ShaDigestSizeError);
        }
        //copy out_digest to hash
        hash.copy_from_slice(&digest);
        Ok(())
    }
}

impl HashAlgo {
    /// Returns the corresponding `MessageDigest` variant for the current `HashAlgo`.
    ///
    /// # Parameters
    /// - `&self`: A reference to the `HashAlgo` enum instance.
    ///
    /// # Returns
    /// - `MessageDigest`: The OpenSSL `MessageDigest` variant that matches the hash algorithm.
    ///
    /// # Examples
    /// ```
    /// let algo = HashAlgo::Sha256;
    /// let digest = algo.message_digest_from_hash_algo();
    /// assert_eq!(digest, MessageDigest::sha256());
    /// ```
    pub fn message_digest_from_hash_algo(&self) -> MessageDigest {
        match self {
            HashAlgo::Sha1 => MessageDigest::sha1(),
            HashAlgo::Sha256 => MessageDigest::sha256(),
            HashAlgo::Sha384 => MessageDigest::sha384(),
            HashAlgo::Sha512 => MessageDigest::sha512(),
        }
    }
}

///Implement HashOp for digest
impl HashOp for HashAlgo {
    ///  SHA operation.
    ///
    /// # Arguments
    /// * `hash_algorithm` - The SHA algorithm (SHA-1/ SHA-256/ SHA-384/ SHA-512) to be used.
    /// * `data` - The data to be hashed.
    /// * `hash` - computed hash of the `data`
    /// # Returns
    /// * OK on success
    ///
    /// # Errors
    /// * `CryptoError::ShaError` - If the SHA operation fails.
    fn hash(&self, data: &[u8], hash: &mut [u8]) -> Result<(), CryptoError> {
        let md = self.message_digest_from_hash_algo();

        if hash.len() != md.size() {
            tracing::error!("{}", CryptoError::ShaDigestSizeError);
            return Err(CryptoError::ShaDigestSizeError);
        }
        let out_digest = hash::hash(md, data).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::ShaError
        })?;
        //copy out_digest to hash
        hash.copy_from_slice(&out_digest);
        Ok(())
    }

    ///  SHA Hasher initialization.
    ///
    /// # Arguments
    /// * `hash_algorithm` - The SHA algorithm (SHA-1/ SHA-256/ SHA-384/ SHA-512) to be used.
    /// # Returns
    /// * Hasher initialized with provided `hash_Algorithm`
    ///
    /// # Errors
    /// * `CryptoError::ShaError` - If the SHA operation fails.
    fn init(&self) -> Result<DigestContext, CryptoError> {
        let md = self.message_digest_from_hash_algo();
        let ossl_hasher = Hasher::new(md).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::ShaError
        })?;
        Ok(DigestContext {
            hasher: ossl_hasher,
        })
    }
}
