// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG (Cryptography Next Generation) HMAC implementations.
//!
//! This module provides Hash-based Message Authentication Code (HMAC) implementations
//! using Windows CNG APIs. HMAC combines a cryptographic hash function with a secret
//! key to provide message authentication and integrity verification.
//!
//! # Supported Algorithms
//!
//! - **HMAC-SHA1**: Legacy HMAC with SHA-1 (deprecated for security-critical applications)
//! - **HMAC-SHA256**: Secure HMAC with SHA-256 (recommended for most applications)
//! - **HMAC-SHA384**: Secure HMAC with SHA-384 (for larger output requirements)
//! - **HMAC-SHA512**: Secure HMAC with SHA-512 (maximum security level)
//!
//! # Features
//!
//! - Key generation with cryptographically secure random bytes
//! - Key import/export from byte arrays
//! - One-shot signing and verification operations
//! - Incremental signing and verification for streaming data
//! - Automatic resource cleanup via RAII patterns
//!
//! # Security Considerations
//!
//! - HMAC keys should be generated using cryptographically secure random number generators
//! - Key sizes should be at least as long as the hash function's output
//! - HMAC-SHA1 should only be used for compatibility with legacy systems
//! - Use constant-time comparison when verifying signatures to prevent timing attacks

use windows::Win32::Security::Cryptography::*;

use super::*;

pub struct CngHmacAlgo {
    _hash: HashAlgo,
    algo_handle: BCRYPT_ALG_HANDLE,
}

impl CngHmacAlgo {
    pub fn new(hash: HashAlgo) -> Self {
        Self {
            algo_handle: Self::hmac_handle(&hash),
            _hash: hash,
        }
    }

    #[allow(unsafe_code)]
    fn sig_len(&self) -> Result<usize, CryptoError> {
        let mut hash_len = [0u8; std::mem::size_of::<u32>()];
        let mut result_len: u32 = hash_len.len() as u32;

        //SAFETY: Calling windows CNG API directly.
        let status = unsafe {
            BCryptGetProperty(
                self.algo_handle,
                BCRYPT_HASH_LENGTH,
                Some(&mut hash_len),
                &mut result_len,
                0,
            )
        };

        status.ok().map_err(|_| CryptoError::HmacGetPropertyError)?;

        Ok(u32::from_le_bytes(hash_len) as usize)
    }

    fn hmac_handle(hash: &HashAlgo) -> BCRYPT_ALG_HANDLE {
        match hash.handle() {
            BCRYPT_SHA1_ALG_HANDLE => BCRYPT_HMAC_SHA1_ALG_HANDLE,
            BCRYPT_SHA256_ALG_HANDLE => BCRYPT_HMAC_SHA256_ALG_HANDLE,
            BCRYPT_SHA384_ALG_HANDLE => BCRYPT_HMAC_SHA384_ALG_HANDLE,
            BCRYPT_SHA512_ALG_HANDLE => BCRYPT_HMAC_SHA512_ALG_HANDLE,
            _ => panic!("Unsupported hash algorithm for HMAC"),
        }
    }
}

impl SignOp for CngHmacAlgo {
    type Key = HmacKey;

    #[allow(unsafe_code)]
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let sig_len = self.sig_len()?;
        if let Some(signature) = signature {
            if signature.len() < sig_len {
                return Err(CryptoError::HmacBufferTooSmall);
            }
            // SAFETY: Calling Windows CNG BCryptHash for one-shot HMAC.
            // - self.algo_handle is a valid BCRYPT_ALG_HANDLE for HMAC algorithm
            // - key.as_bytes() provides the HMAC key with valid lifetime
            // - data is the input message to authenticate
            // - signature buffer has been validated to have sufficient size (sig_len)
            let status =
                unsafe { BCryptHash(self.algo_handle, Some(key.as_bytes()), data, signature) };
            status.ok().map_err(|_| CryptoError::HmacSignError)?;
        }

        Ok(sig_len)
    }
}

impl<'a> SignStreamingOp<'a> for CngHmacAlgo {
    type Key = HmacKey;
    type Context = CngHmacAlgoSignContext;

    fn sign_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Ok(CngHmacAlgoSignContext {
            signer: CngHmacHandle::new(self.algo_handle, key.as_bytes())?,
            algo: self,
        })
    }
}

/// HMAC signing context for incremental signing operations.
///
/// This structure maintains the state for an incremental HMAC signing operation,
/// allowing data to be processed in chunks through multiple `update` calls
/// before finalizing the signature with `finish`.
pub struct CngHmacAlgoSignContext {
    /// Reference to the CNG HMAC instance
    algo: CngHmacAlgo,
    /// Handle to the CNG HMAC object
    signer: CngHmacHandle,
}

impl<'a> SignStreamingOpContext<'a> for CngHmacAlgoSignContext {
    type Algo = CngHmacAlgo;

    /// Updates the HMAC context with additional data.
    ///
    /// This method processes the provided data and updates the internal HMAC state.
    /// It can be called multiple times to process data in chunks.
    ///
    /// # Parameters
    ///
    /// * `data` - The data to process and add to the HMAC computation
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `Err(CryptoError::HmacSignUpdateError)`
    /// if the update operation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        //SAFETY: Calling Windows CNG API directly.
        let status = unsafe { BCryptHashData(self.signer.handle(), data, 0) };
        status.ok().map_err(|_| CryptoError::HmacSignUpdateError)
    }

    /// Finalizes the HMAC signing operation and produces the signature.
    ///
    /// This method completes the HMAC computation and produces the final signature.
    /// After calling this method, the signing context is consumed and cannot be
    /// used for further operations.
    ///
    /// # Parameters
    ///
    /// * `sig` - Optional mutable buffer to store the signature
    ///
    /// # Returns
    ///
    /// Returns the signature length in bytes. If a signature buffer was provided
    /// and the operation succeeded, the signature will be written to the buffer.
    ///
    /// # Errors
    ///
    /// * `CryptoError::HmacBufferTooSmall` - If the provided buffer is too small
    /// * `CryptoError::HmacSignFinishError` - If the finalization operation fails
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn finish(&mut self, sig: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let sig_len = self.algo.sig_len()?;
        if let Some(sig) = sig {
            if sig.len() < sig_len {
                return Err(CryptoError::HmacBufferTooSmall);
            }
            //SAFETY: Calling Windows CNG API directly.
            let status = unsafe { BCryptFinishHash(self.signer.handle(), sig, 0) };
            status.ok().map_err(|_| CryptoError::HmacSignFinishError)?;
        }
        Ok(sig_len)
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

impl VerifyOp for CngHmacAlgo {
    type Key = HmacKey;

    #[allow(unsafe_code)]
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let sig_len = self.sig_len()?;
        let mut result = vec![0u8; sig_len];
        self.sign(key, data, Some(&mut result))?;
        Ok(result == signature)
    }
}

impl<'a> VerifyStreamingOp<'a> for CngHmacAlgo {
    type Key = HmacKey;
    type Context = CngHmacAlgoVerifyContext;

    fn verify_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Ok(CngHmacAlgoVerifyContext {
            verifier: CngHmacHandle::new(self.algo_handle, key.as_bytes())?,
            algo: self,
            _key: key,
        })
    }
}

/// HMAC verification context for incremental verification operations.
///
/// This structure maintains the state for an incremental HMAC verification operation,
/// allowing data to be processed in chunks through multiple `update` calls
/// before finalizing the verification with `finish`.
pub struct CngHmacAlgoVerifyContext {
    /// Reference to the CNG HMAC instance
    algo: CngHmacAlgo,
    /// HMAC Key
    _key: HmacKey,
    /// Handle to the CNG HMAC object
    verifier: CngHmacHandle,
}

impl<'a> VerifyStreamingOpContext<'a> for CngHmacAlgoVerifyContext {
    type Algo = CngHmacAlgo;
    /// Updates the HMAC verification context with additional data.
    ///
    /// This method processes the provided data and updates the internal HMAC state.
    /// It can be called multiple times to process data in chunks.
    ///
    /// # Parameters
    ///
    /// * `data` - The data to process and add to the HMAC computation
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `Err(CryptoError::HmacVerifyUpdateError)`
    /// if the update operation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        //SAFETY: Calling Windows CNG APIs directly
        let status = unsafe { BCryptHashData(self.verifier.handle(), data, 0) };
        status.ok().map_err(|_| CryptoError::HmacVerifyUpdateError)
    }

    /// Finalizes the HMAC verification operation and checks the signature.
    ///
    /// This method completes the HMAC computation, produces the final signature,
    /// and compares it with the provided signature. After calling this method,
    /// the verification context is consumed and cannot be used for further operations.
    ///
    /// # Parameters
    ///
    /// * `sig` - The signature to verify against
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature matches, `Ok(false)` if it does not match.
    ///
    /// # Errors
    ///
    /// * `CryptoError::HmacVerifyFinishError` - If the finalization operation fails
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn finish(&mut self, sig: &[u8]) -> Result<bool, CryptoError> {
        let sig_len = self.algo.sig_len()?;
        let mut actual_sig = vec![0u8; sig_len];
        //SAFETY: Calling Windows CNG APIs directly
        let status = unsafe { BCryptFinishHash(self.verifier.handle(), &mut actual_sig, 0) };
        status
            .ok()
            .map_err(|_| CryptoError::HmacVerifyFinishError)?;
        Ok(actual_sig == sig)
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

/// RAII wrapper for Windows CNG HMAC handles.
///
/// This structure provides automatic cleanup of CNG HMAC handles through
/// the Drop trait, ensuring that resources are properly released when
/// the handle goes out of scope.
struct CngHmacHandle {
    /// The underlying Windows CNG hash handle (used for HMAC operations)
    handle: BCRYPT_HASH_HANDLE,
}

impl CngHmacHandle {
    /// Creates a new CNG HMAC handle for the specified algorithm and key.
    ///
    /// This method initializes a new HMAC handle that can be used for
    /// incremental HMAC operations with the Windows CNG APIs. The key is
    /// incorporated into the handle during initialization.
    ///
    /// # Parameters
    ///
    /// * `algo` - The BCrypt algorithm handle specifying which HMAC algorithm to use
    /// * `key` - The HMAC key bytes to use for the operation
    ///
    /// # Returns
    ///
    /// Returns `Ok(CngHmacHandle)` on success, or `Err(CryptoError::HmacInitError)`
    /// if the handle creation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn new(algo: BCRYPT_ALG_HANDLE, key: &[u8]) -> Result<Self, CryptoError> {
        let mut handle = BCRYPT_HASH_HANDLE::default();
        //SAFETY: Calling Windows CNG APIs directly
        let status = unsafe { BCryptCreateHash(algo, &mut handle, None, Some(key), 0) };
        status.ok().map_err(|_| CryptoError::HmacInitError)?;
        Ok(Self { handle })
    }

    /// Returns the underlying BCrypt hash handle.
    ///
    /// This method provides access to the raw Windows CNG hash handle
    /// for use with CNG API functions. The handle is configured for HMAC
    /// operations with the key provided during initialization.
    ///
    /// # Returns
    ///
    /// The `BCRYPT_HASH_HANDLE` for this HMAC context.
    fn handle(&self) -> BCRYPT_HASH_HANDLE {
        self.handle
    }
}

impl Drop for CngHmacHandle {
    /// Automatically cleans up the CNG HMAC handle when dropped.
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
        //SAFETY: Calling Windows CNG API directly.
        let _ = unsafe { BCryptDestroyHash(self.handle) };
    }
}

impl Clone for CngHmacHandle {
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
