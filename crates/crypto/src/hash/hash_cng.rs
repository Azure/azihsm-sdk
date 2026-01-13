// Copyright (C) Microsoft Corporation. All rights reserved.

//! Windows CNG (Cryptography Next Generation) hash implementations.
//!
//! This module provides hash algorithm implementations using Windows CNG APIs.
//! It supports SHA-1, SHA-256, SHA-384, and SHA-512 algorithms through a unified
//! interface that implements the `HashOp` and `HashStreamingOp` traits.
//!
//! The implementation uses Windows-specific BCrypt APIs for cryptographic operations
//! and provides both one-shot hashing and incremental hashing capabilities.

use windows::Win32::Security::Cryptography::*;

use super::*;

/// Generic CNG hash implementation.
///
/// This structure provides a hash implementation using Windows CNG APIs.
/// It stores the hash algorithm selection and the corresponding Windows CNG
/// algorithm handle for efficient hash operations.
#[derive(Clone)]
pub struct CngHashAlgo {
    bcrypt_algo: BCRYPT_ALG_HANDLE,
    size: usize,
}

impl CngHashAlgo {
    /// Creates a new instance of the CNG hash implementation.
    ///
    /// Initializes the hash implementation with the specified algorithm and
    /// obtains the corresponding Windows CNG algorithm handle.
    ///
    /// # Arguments
    ///
    /// * `algo` - The hash algorithm to use
    ///
    /// # Returns
    ///
    /// A new `CngHash` instance ready to perform hash operations.
    fn new(bcrypt_algo: BCRYPT_ALG_HANDLE, size: usize) -> Self {
        Self { bcrypt_algo, size }
    }

    /// Creates a new SHA-1 hash instance.
    ///
    /// # Returns
    ///
    /// A new `CngHash` instance configured for SHA-1 hashing.
    ///
    /// # Security Warning
    ///
    /// SHA-1 is cryptographically broken and should not be used for security-sensitive
    /// applications. Use SHA-256 or stronger algorithms instead.
    pub fn sha1() -> Self {
        Self::new(BCRYPT_SHA1_ALG_HANDLE, 20)
    }

    /// Creates a new SHA-256 hash instance.
    ///
    /// SHA-256 is part of the SHA-2 family and provides 256-bit hash values.
    /// It is recommended for most cryptographic applications.
    ///
    /// # Returns
    ///
    /// A new `CngHash` instance configured for SHA-256 hashing.
    pub fn sha256() -> Self {
        Self::new(BCRYPT_SHA256_ALG_HANDLE, 32)
    }

    /// Creates a new SHA-384 hash instance.
    ///
    /// SHA-384 is part of the SHA-2 family and provides 384-bit hash values.
    /// It is a truncated version of SHA-512 and is suitable for high-security applications.
    ///
    /// # Returns
    ///
    /// A new `CngHash` instance configured for SHA-384 hashing.
    pub fn sha384() -> Self {
        Self::new(BCRYPT_SHA384_ALG_HANDLE, 48)
    }

    /// Creates a new SHA-512 hash instance.
    ///
    /// SHA-512 is part of the SHA-2 family and provides 512-bit hash values.
    /// It is suitable for high-security applications requiring larger hash outputs.
    ///
    /// # Returns
    ///
    /// A new `CngHash` instance configured for SHA-512 hashing.
    pub fn sha512() -> Self {
        Self::new(BCRYPT_SHA512_ALG_HANDLE, 64)
    }
    /// Returns the hash output size in bytes for this algorithm.
    ///
    /// This method provides the size of the hash digest produced by this
    /// hash algorithm without performing any cryptographic operations.
    ///
    /// # Returns
    ///
    /// The hash output size in bytes:
    /// - SHA-1: 20 bytes
    /// - SHA-256: 32 bytes
    /// - SHA-384: 48 bytes
    /// - SHA-512: 64 bytes    
    pub fn size(&self) -> usize {
        self.size
    }

    /// Converts the hash algorithm enum to the Windows CNG algorithm identifier.
    ///
    /// # Returns
    ///
    /// The corresponding Windows CNG hash algorithm constant.
    pub(crate) fn algo_id(&self) -> windows::core::PCWSTR {
        match self.bcrypt_algo {
            BCRYPT_SHA1_ALG_HANDLE => BCRYPT_SHA1_ALGORITHM,
            BCRYPT_SHA256_ALG_HANDLE => BCRYPT_SHA256_ALGORITHM,
            BCRYPT_SHA384_ALG_HANDLE => BCRYPT_SHA384_ALGORITHM,
            BCRYPT_SHA512_ALG_HANDLE => BCRYPT_SHA512_ALGORITHM,
            _ => unreachable!("Invalid bcrypt algorithm handle"),
        }
    }

    pub(crate) fn handle(&self) -> BCRYPT_ALG_HANDLE {
        self.bcrypt_algo
    }

    /// Retrieves the hash length for the specified algorithm.
    ///
    /// This function queries the Windows CNG API to determine the output size
    /// of the hash algorithm in bytes.
    ///
    /// # Parameters
    ///
    /// * `handle` - The BCrypt algorithm handle to query
    ///
    /// # Returns
    ///
    /// Returns `Ok(usize)` containing the hash length in bytes, or `Err(CryptoError)`
    /// if the property could not be retrieved.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn hash_size(handle: BCRYPT_ALG_HANDLE) -> Result<usize, CryptoError> {
        let mut hash_len = [0u8; std::mem::size_of::<u32>()];
        let mut result_len: u32 = hash_len.len() as u32;
        //SAFETY: Calling Windows CNG API directly
        let status = unsafe {
            BCryptGetProperty(
                handle,
                BCRYPT_HASH_LENGTH,
                Some(&mut hash_len),
                &mut result_len,
                0,
            )
        };

        status.ok().map_err(|_| CryptoError::HashGetPropertyError)?;

        Ok(u32::from_le_bytes(hash_len) as usize)
    }

    pub(crate) fn der_algo(&self) -> DerDigestAlgo {
        match self.bcrypt_algo {
            BCRYPT_SHA1_ALG_HANDLE => DerDigestAlgo::Sha1,
            BCRYPT_SHA256_ALG_HANDLE => DerDigestAlgo::Sha256,
            BCRYPT_SHA384_ALG_HANDLE => DerDigestAlgo::Sha384,
            BCRYPT_SHA512_ALG_HANDLE => DerDigestAlgo::Sha512,
            _ => unreachable!("Invalid bcrypt algorithm handle"),
        }
    }
}

impl HashOp for CngHashAlgo {
    /// Performs a one-shot hash operation on the provided data.
    ///
    /// This method computes the hash of the input data using the specified algorithm.
    /// If a hash buffer is provided, the result is written to it. If no buffer is
    /// provided, only the required buffer size is returned.
    ///
    /// # Parameters
    ///
    /// * `data` - The input data to hash
    /// * `hash` - Optional mutable buffer to store the hash result
    ///
    /// # Returns
    ///
    /// Returns the hash length in bytes. If a hash buffer was provided and the
    /// operation succeeded, the hash will be written to the buffer.
    ///
    /// # Errors
    ///
    /// * `CryptoError::HashBufferTooSmall` - If the provided buffer is too small
    /// * `CryptoError::HashError` - If the hash operation fails
    /// * `CryptoError::HashGetPropertyError` - If hash length retrieval fails
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn hash(&mut self, data: &[u8], hash: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let hash_len = Self::hash_size(self.bcrypt_algo)?;
        if let Some(hash) = hash {
            if hash.len() < hash_len {
                Err(CryptoError::HashBufferTooSmall)?;
            }
            //SAFETY: Calling Windows CNG API directly
            let status = unsafe { BCryptHash(self.bcrypt_algo, None, data, hash) };
            status.ok().map_err(|_| CryptoError::HashError)?;
        }
        Ok(hash_len)
    }
}

impl HashStreamingOp for CngHashAlgo {
    type Context = CngHashAlgoContext;
    /// Initializes a new hash context for incremental hashing.
    ///
    /// This method creates a new hash context that can be used for incremental
    /// hash operations (update/finalize pattern). The context maintains the
    /// internal state of the hash algorithm across multiple update calls.
    ///
    /// # Returns
    ///
    /// Returns a `CngHashContext` that implements `HashOpContext` for incremental
    /// hash operations.
    ///
    /// # Errors
    ///
    /// * `CryptoError::HashInitError` - If the hash context creation fails
    /// * `CryptoError::HashGetPropertyError` - If hash length retrieval fails
    fn hash_init(self) -> Result<Self::Context, CryptoError> {
        let handle = CngHashHandle::new(self.bcrypt_algo)?;
        Ok(CngHashAlgoContext { algo: self, handle })
    }
}

/// Streaming hash context for incremental hash operations using Windows CNG.
///
/// This structure represents an active hash context that allows data to be
/// processed in chunks through multiple `update` calls before finalizing the
/// hash with `finish`. It maintains the internal state of the hash algorithm
/// across multiple update operations.
///
/// The context consumes itself when `finish` is called, preventing reuse of
/// the same context for multiple hash operations.
pub struct CngHashAlgoContext {
    algo: CngHashAlgo,
    handle: CngHashHandle,
}

impl HashOpContext for CngHashAlgoContext {
    type Algo = CngHashAlgo;

    /// Updates the hash context with additional data.
    ///
    /// This method processes the provided data and updates the internal hash state.
    /// It can be called multiple times to process data in chunks.
    ///
    /// # Parameters
    ///
    /// * `data` - The data to process and add to the hash
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `Err(CryptoError::HashUpdateError)` if
    /// the update operation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        //SAFETY: Calling Windows CNG API directly
        let status = unsafe { BCryptHashData(self.handle.handle(), data, 0) };
        status.ok().map_err(|_| CryptoError::HashUpdateError)
    }

    /// Finalizes the hash operation and produces the final hash value.
    ///
    /// This method completes the hash operation and produces the final hash output.
    /// After calling this method, the hash context is consumed and cannot be used
    /// for further operations.
    ///
    /// # Parameters
    ///
    /// * `hash` - Optional mutable buffer to store the final hash result
    ///
    /// # Returns
    ///
    /// Returns the hash length in bytes. If a hash buffer was provided and the
    /// operation succeeded, the final hash will be written to the buffer.
    ///
    /// # Errors
    ///
    /// * `CryptoError::HashBufferTooSmall` - If the provided buffer is too small
    /// * `CryptoError::HashFinalizeError` - If the finalization operation fails
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn finish(&mut self, hash: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let len = self.algo().size();
        if let Some(hash) = hash {
            if hash.len() < len {
                Err(CryptoError::HashBufferTooSmall)?;
            }
            //SAFETY: Calling Windows CNG API directly
            let status = unsafe { BCryptFinishHash(self.handle.handle(), hash, 0) };
            status.ok().map_err(|_| CryptoError::HashFinishError)?;
        }
        Ok(len)
    }

    /// Returns a reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `OsslHash` algorithm instance.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `OsslHash` algorithm instance.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// The `OsslHash` algorithm instance.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

/// RAII wrapper for Windows CNG hash handles.
///
/// This structure provides automatic cleanup of CNG hash handles through
/// the Drop trait, ensuring that resources are properly released when
/// the handle goes out of scope.
struct CngHashHandle {
    /// The underlying Windows CNG hash handle
    handle: BCRYPT_HASH_HANDLE,
}

impl CngHashHandle {
    /// Creates a new CNG hash handle for the specified algorithm.
    ///
    /// This method initializes a new hash handle that can be used for
    /// incremental hash operations with the Windows CNG APIs.
    ///
    /// # Parameters
    ///
    /// * `algo` - The BCrypt algorithm handle specifying which hash algorithm to use
    ///
    /// # Returns
    ///
    /// Returns `Ok(CngHashHandle)` on success, or `Err(CryptoError::HashInitError)`
    /// if the handle creation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn new(algo: BCRYPT_ALG_HANDLE) -> Result<Self, CryptoError> {
        let mut handle = BCRYPT_HASH_HANDLE::default();
        //SAFETY: Calling Windows CNG API directly
        let status = unsafe { BCryptCreateHash(algo, &mut handle, None, None, 0) };
        status.ok().map_err(|_| CryptoError::HashInitError)?;
        Ok(Self { handle })
    }

    /// Returns the underlying BCrypt hash handle.
    ///
    /// This method provides access to the raw Windows CNG hash handle
    /// for use with CNG API functions.
    ///
    /// # Returns
    ///
    /// The `BCRYPT_HASH_HANDLE` for this hash context.
    fn handle(&self) -> BCRYPT_HASH_HANDLE {
        self.handle
    }
}

impl Drop for CngHashHandle {
    /// Automatically cleans up the CNG hash handle when dropped.
    ///
    /// This method ensures that Windows CNG resources are properly released
    /// when the handle is no longer needed. Any errors during cleanup are
    /// silently ignored as there's no meaningful way to handle them during drop.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        //SAFETY: Calling Windows CNG API directly
        let _ = unsafe { BCryptDestroyHash(self.handle) };
    }
}

impl Clone for CngHashHandle {
    #[allow(unsafe_code)]
    fn clone(&self) -> Self {
        let mut handle = BCRYPT_HASH_HANDLE::default();
        //SAFETY: Duplicate the existing hash handle
        let status = unsafe { BCryptDuplicateHash(self.handle, &mut handle, None, 0) };
        if status.is_err() {
            // Clone cannot fail.
            panic!("Failed to duplicate CNG hash handle");
        }
        Self { handle }
    }
}
