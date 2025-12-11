// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use windows::core::PCWSTR;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography;

use super::*;

impl HashAlgo {
    /// Helper to map HashAlgo to CNG hash algorithm identifier.
    ///
    /// # Arguments
    /// * `algo_handle` - The hash algorithm to map.
    ///
    /// # Returns
    /// * `Ok(PCWSTR)` - The CNG algorithm identifier for the hash algorithm.
    /// * `Err(CryptoError)` - If the algorithm is not supported.
    fn hash_algo_to_alg_id(&self) -> Result<PCWSTR, CryptoError> {
        match self {
            HashAlgo::Sha1 => Ok(Cryptography::BCRYPT_SHA1_ALGORITHM),
            HashAlgo::Sha256 => Ok(Cryptography::BCRYPT_SHA256_ALGORITHM),
            HashAlgo::Sha384 => Ok(Cryptography::BCRYPT_SHA384_ALGORITHM),
            HashAlgo::Sha512 => Ok(Cryptography::BCRYPT_SHA512_ALGORITHM),
        }
    }
}
struct CngHashHandler {
    hash_handle: Cryptography::BCRYPT_HASH_HANDLE,
}
struct CngAlgoHandler {
    algo_handle: Cryptography::BCRYPT_ALG_HANDLE,
}

impl Drop for CngHashHandler {
    /// Drops the CngHashHandler, releasing the CNG hash handle.
    ///
    /// # Safety
    /// Calls unsafe CNG function to destroy the hash handle.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: CNG Crypto module is unsafe, make sure to release the handlers
        unsafe {
            if Cryptography::BCryptDestroyHash(self.hash_handle) != STATUS_SUCCESS {
                tracing::error!("Failed to destroy hasher in Drop");
            }
        }
    }
}

impl Drop for CngAlgoHandler {
    /// Drops the CngAlgoHandler, releasing the CNG algorithm provider handle.
    ///
    /// # Safety
    /// Calls unsafe CNG function to close the algorithm provider handle.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: CNG Crypto module is unsafe, make sure to release the handlers
        unsafe {
            if Cryptography::BCryptCloseAlgorithmProvider(self.algo_handle, 0) != STATUS_SUCCESS {
                tracing::error!("Failed to close algorithm provider in Drop");
            }
        }
    }
}
pub struct CngHasher {
    cng_hash_handler: CngHashHandler,
    // algo handler has to be valid until hash handler lifetime because it is used by the hash handler indirectly.
    #[allow(unused)]
    cng_algo_handler: CngAlgoHandler,
}

impl HashContext for DigestContext {
    type Hasher = CngHasher;

    /// Updates the hash context with additional data.
    ///
    /// # Arguments
    /// * `data` - The data to update the hash with.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CryptoError)` if the update fails.
    #[allow(unsafe_code)]
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let status;
        //SAFETY: CNG Crypto module is unsafe function, make sure to release the handler
        unsafe {
            status =
                Cryptography::BCryptHashData(self.hasher.cng_hash_handler.hash_handle, data, 0);
        }
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to update hash : {:#X}", status.0);
            Err(CryptoError::ShaError)?
        }
        Ok(())
    }

    /// Finalizes the hash and writes the result to the provided buffer.
    ///
    /// # Arguments
    /// * `hash` - The buffer to write the final hash value to.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CryptoError)` if the operation fails or the buffer size is incorrect.
    #[allow(unsafe_code)]
    fn finish(self, hash: &mut [u8]) -> Result<(), CryptoError> {
        // Query the hash length property
        let mut hash_length: u32 = 0;
        let mut result_size: u32 = 0;

        let status;
        //SAFETY: CNG Crypto module is unsafe function, make sure to release the handler
        unsafe {
            status = Cryptography::BCryptGetProperty(
                self.hasher.cng_hash_handler.hash_handle,
                Cryptography::BCRYPT_HASH_LENGTH,
                Some(std::slice::from_raw_parts_mut(
                    &mut hash_length as *mut u32 as *mut u8,
                    std::mem::size_of::<u32>(),
                )),
                &mut result_size,
                0,
            );
        }
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to get hash length: {:#X}", status.0);
            Err(CryptoError::ShaError)?
        }
        if hash.len() != hash_length as usize {
            tracing::error!(
                "Hash buffer size ({}) does not match expected hash length ({})",
                hash.len(),
                hash_length
            );
            Err(CryptoError::ShaDigestSizeError)?
        } else {
            tracing::info!(
                "Hash buffer size ({}) mattches expected hash length ({})",
                hash.len(),
                hash_length
            );
        }
        let status;
        //SAFETY: call unsafe BcryptFInishHash function
        unsafe {
            //hasher is freedup in drop trait
            status =
                Cryptography::BCryptFinishHash(self.hasher.cng_hash_handler.hash_handle, hash, 0);
        }
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to finish hash: {:#X}", status.0);
            Err(CryptoError::ShaError)?
        }

        Ok(())
    }
}

// implement hashop for HashAlgo
impl HashOp for HashAlgo {
    /// Calculates the hash of the provided data using the specified algorithm.
    ///
    /// # Arguments
    /// * `data` - The data to hash.
    /// * `algo` - The hash algorithm to use.
    /// * `hash` - The buffer to write the hash output to.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CryptoError)` if the operation fails or the buffer size is incorrect.
    #[allow(unsafe_code)]
    fn hash(&self, data: &[u8], hash: &mut [u8]) -> Result<(), CryptoError> {
        let dwflags = Cryptography::BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0);
        let hash_size = match self {
            HashAlgo::Sha1 => 20,
            HashAlgo::Sha256 => 32,
            HashAlgo::Sha384 => 48,
            HashAlgo::Sha512 => 64,
        };
        // check if supplied hash size is same as expected
        if hash_size != hash.len() {
            tracing::error!("Invalid hash size :{:#X}", hash.len());
            Err(CryptoError::ShaDigestSizeError)?
        }
        // Use the helper to get the algorithm identifier
        let algo_identifier = self.hash_algo_to_alg_id()?;
        let mut algo_handle = Cryptography::BCRYPT_ALG_HANDLE::default();
        let status: NTSTATUS;
        //SAFETY: CNG Crypto module is unsafe function, make sure to release the handler
        unsafe {
            status = Cryptography::BCryptOpenAlgorithmProvider(
                &mut algo_handle,
                algo_identifier,
                None,
                dwflags,
            );
        }
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to open algo handle : {:#X}", status.0);
            Err(CryptoError::ShaError)?
        }
        let status: NTSTATUS;
        //SAFETY: calculate hash by calling unsafe Windows CNG BCryptHash
        unsafe {
            status = Cryptography::BCryptHash(algo_handle, None, data, hash);
        }
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to calculate handle : {:#X}", status.0);
            Err(CryptoError::ShaError)?
        }

        Ok(())
    }

    /// Initializes a new hash context for the specified algorithm.
    ///
    /// # Arguments
    /// * `hash_algorithm` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(DigestContext)` with the initialized context on success.
    /// * `Err(CryptoError)` if initialization fails.
    #[allow(unsafe_code)]
    fn init(&self) -> Result<DigestContext, CryptoError> {
        let mut cng_algo_provider = CngAlgoHandler {
            algo_handle: Cryptography::BCRYPT_ALG_HANDLE::default(),
        };
        let mut cng_hasher = CngHashHandler {
            hash_handle: Cryptography::BCRYPT_HASH_HANDLE::default(),
        };
        let dwflags = Cryptography::BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0);

        // Use the helper to get the algorithm identifier
        let algo_identifier = self.hash_algo_to_alg_id()?;

        let status: NTSTATUS;
        //SAFETY: Call unsafe Windows CNG BCryptOpenAlgorithmProvider
        unsafe {
            status = Cryptography::BCryptOpenAlgorithmProvider(
                &mut cng_algo_provider.algo_handle,
                algo_identifier,
                None,
                dwflags,
            );
        }

        if status != STATUS_SUCCESS {
            tracing::error!("Failed to open algo handle : {:#X}", status.0);
            Err(CryptoError::ShaError)?
        }

        //open new hasher
        let status: NTSTATUS;
        //SAFETY: Call unsafe windows CNG BCryptCreateHash call to create new hasher
        unsafe {
            status = Cryptography::BCryptCreateHash(
                cng_algo_provider.algo_handle,
                &mut cng_hasher.hash_handle,
                None,
                None,
                dwflags.0,
            );
            if status != STATUS_SUCCESS {
                tracing::error!("Failed to create a hasher : {:#X}", status.0);
                Err(CryptoError::ShaError)?
            }
        }

        Ok(DigestContext {
            hasher: CngHasher {
                cng_hash_handler: cng_hasher,
                cng_algo_handler: cng_algo_provider,
            },
        })
    }
}
