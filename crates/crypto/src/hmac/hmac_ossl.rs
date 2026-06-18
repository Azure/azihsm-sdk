// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based HMAC implementation for Linux systems.
//!
//! This module provides concrete implementations of HMAC operations using
//! the OpenSSL cryptographic library. It serves as the Linux-specific backend
//! for the platform-agnostic HMAC interface defined in the parent module.
//!
//! # Supported Algorithms
//!
//! - **HMAC-SHA1**: Legacy algorithm (20-byte output, use with caution)
//! - **HMAC-SHA256**: Recommended for most applications (32-byte output)
//! - **HMAC-SHA384**: High security applications (48-byte output)
//! - **HMAC-SHA512**: Maximum security applications (64-byte output)
//!
//! # libctx isolation
//!
//! The MAC is computed through the `EVP_MAC` API fetched from the crate-private
//! [`crate::libctx`] (default-provider-only), **not** via `openssl::sign::Signer`
//! / `PKey::hmac`. `PKey::hmac` has no libctx parameter and binds the key to the
//! process default libctx; on OpenSSL 3.5 the resulting bare `HMAC` / digest
//! fetch resolves to the `azihsm` provider and re-enters it during the HSM
//! session open. Fetching the MAC explicitly from our private libctx keeps both
//! the MAC and its underlying digest on the default provider. The `openssl`
//! crate (0.10.x) ships no `EVP_MAC` wrapper, so this is done over `openssl-sys`.

use std::marker::PhantomData;
use std::os::raw::c_char;
use std::ptr;

use foreign_types::ForeignTypeRef;
use openssl_sys as ffi;
use zeroize::Zeroizing;

use super::*;
use crate::libctx::OSSL_SUCCESS;
use crate::libctx::crypto_libctx;

/// An HMAC computation bound to the crate-private libctx via `EVP_MAC`.
///
/// Owns an `EVP_MAC` and its `EVP_MAC_CTX`. The key bytes are copied into the
/// context by `EVP_MAC_init`, so this type borrows nothing and can outlive the
/// key it was created from.
struct IsolatedHmac {
    /// The fetched `EVP_MAC` ("HMAC"). Kept alive for the whole lifetime of
    /// `ctx`; freed after `ctx` in `Drop`.
    mac: *mut ffi::EVP_MAC,
    /// The MAC context carrying the keyed, digest-configured state.
    ctx: *mut ffi::EVP_MAC_CTX,
}

impl IsolatedHmac {
    /// Fetches `HMAC` from the private libctx, creates a context, and keys it
    /// with `key` configured for `hash`'s digest.
    ///
    /// Uses the `EVP_MAC` C API directly: the `openssl` crate ships no `EVP_MAC`
    /// wrapper, and (as on the Windows CNG backends) unavoidable crypto-library
    /// FFI is the only way to bind the MAC to a non-default libctx.
    #[allow(unsafe_code)]
    fn new(hash: &HashAlgo, key: &[u8]) -> Result<Self, CryptoError> {
        // NUL-terminated names for the C API.
        const HMAC_NAME: &[u8] = b"HMAC\0";
        // OSSL_MAC_PARAM_DIGEST.
        const DIGEST_PARAM: &[u8] = b"digest\0";

        let digest_name = hash.md_name()?; // canonical name, no trailing NUL
        let libctx = crypto_libctx().as_ptr();

        // SAFETY: all pointers are checked for NULL before use; `this` owns the
        // MAC + ctx so any early return after its construction frees them via
        // `Drop`. The param array is freed before returning.
        unsafe {
            let mac = ffi::EVP_MAC_fetch(libctx, HMAC_NAME.as_ptr() as *const c_char, ptr::null());
            if mac.is_null() {
                return Err(CryptoError::HmacInitError);
            }
            let ctx = ffi::EVP_MAC_CTX_new(mac);
            if ctx.is_null() {
                ffi::EVP_MAC_free(mac);
                return Err(CryptoError::HmacInitError);
            }
            // From here, `this` owns both handles; errors free them on drop.
            let this = IsolatedHmac { mac, ctx };

            let bld = ffi::OSSL_PARAM_BLD_new();
            if bld.is_null() {
                return Err(CryptoError::HmacInitError);
            }
            let pushed = ffi::OSSL_PARAM_BLD_push_utf8_string(
                bld,
                DIGEST_PARAM.as_ptr() as *const c_char,
                digest_name.as_ptr() as *const c_char,
                digest_name.len(),
            );
            if pushed != OSSL_SUCCESS {
                ffi::OSSL_PARAM_BLD_free(bld);
                return Err(CryptoError::HmacInitError);
            }
            let params = ffi::OSSL_PARAM_BLD_to_param(bld);
            ffi::OSSL_PARAM_BLD_free(bld);
            if params.is_null() {
                return Err(CryptoError::HmacInitError);
            }
            let ok = ffi::EVP_MAC_init(ctx, key.as_ptr(), key.len(), params);
            ffi::OSSL_PARAM_free(params);
            if ok != OSSL_SUCCESS {
                return Err(CryptoError::HmacInitError);
            }
            Ok(this)
        }
    }

    /// Feeds `data` into the MAC.
    #[allow(unsafe_code)]
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        // SAFETY: `self.ctx` is a valid, initialised EVP_MAC_CTX.
        let ok = unsafe { ffi::EVP_MAC_update(self.ctx, data.as_ptr(), data.len()) };
        if ok == OSSL_SUCCESS {
            Ok(())
        } else {
            Err(CryptoError::HmacSignUpdateError)
        }
    }

    /// Finalises the MAC into `out` (must be at least the MAC size). Returns the
    /// number of bytes written.
    #[allow(unsafe_code)]
    fn finish(&mut self, out: &mut [u8]) -> Result<usize, CryptoError> {
        // `outl` is a pure C out-parameter: `EVP_MAC_final` writes the number of
        // bytes produced and never reads it, so it starts uninitialised and
        // carries no initial value into the call.
        let mut outl = std::mem::MaybeUninit::<usize>::uninit();
        // SAFETY: `out` is valid for `out.len()` bytes; `outl` is a valid
        // `*mut size_t` that receives the number of bytes written.
        let ok =
            unsafe { ffi::EVP_MAC_final(self.ctx, out.as_mut_ptr(), outl.as_mut_ptr(), out.len()) };
        if ok == OSSL_SUCCESS {
            // SAFETY: a successful `EVP_MAC_final` initialised `outl`.
            Ok(unsafe { outl.assume_init() })
        } else {
            Err(CryptoError::HmacSignFinishError)
        }
    }
}

impl Drop for IsolatedHmac {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: free the context before the MAC it was created from. Both are
        // non-NULL once an `IsolatedHmac` exists.
        unsafe {
            ffi::EVP_MAC_CTX_free(self.ctx);
            ffi::EVP_MAC_free(self.mac);
        }
    }
}

/// Extracts the raw HMAC key bytes from an [`HmacKey`] into a buffer that is
/// zeroized on drop.
///
/// `EVP_MAC_init` copies the key into the MAC context, so callers can let the
/// returned buffer drop as soon as the [`IsolatedHmac`] is built. [`Zeroizing`]
/// wipes the plaintext copy on every path — success or error — keeping key
/// material in process memory for as short a time as possible. (The old
/// `Signer`/`PKey` path never materialised a plaintext copy; the `EVP_MAC` FFI
/// does, so this restores that hygiene.)
fn key_bytes(key: &HmacKey) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    key.pkey()
        .raw_private_key()
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::HmacKeyError)
}

/// OpenSSL-backed HMAC operation provider.
///
/// Configures and executes HMAC operations using OpenSSL's `EVP_MAC`, isolated
/// to the crate-private libctx. Supports both single-shot and streaming
/// interfaces for signing and verification.
pub struct OsslHmacAlgo {
    /// The hash algorithm to use for HMAC.
    hash: HashAlgo,
}

impl OsslHmacAlgo {
    /// Creates a new HMAC operation provider from a hash instance.
    ///
    /// This only stores the algorithm configuration; no `EVP_MAC` context is
    /// created until a signing or verification operation runs.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash instance specifying the digest used by the HMAC PRF.
    ///
    /// # Returns
    ///
    /// A new `OsslHmacAlgo` configured for the specified hash algorithm.
    pub fn new(hash: HashAlgo) -> Self {
        Self { hash }
    }
}

/// Implements single-operation HMAC signing.
impl SignOp for OsslHmacAlgo {
    type Key = HmacKey;

    /// Computes an HMAC over `data` in a single call.
    ///
    /// When `signature` is `None`, no MAC is computed and only the required
    /// buffer size (the digest output length) is returned.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key.
    /// * `data` - The data to authenticate.
    /// * `signature` - Optional output buffer. If `None`, only the required size
    ///   is returned.
    ///
    /// # Returns
    ///
    /// The number of bytes written to `signature` (the MAC length), or the
    /// required buffer size when `signature` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::HmacBufferTooSmall` - the output buffer is smaller than
    ///   the MAC length.
    /// - `CryptoError::HmacKeyError` - the key bytes could not be extracted.
    /// - `CryptoError::HmacInitError` / `CryptoError::HmacSignFinishError` - the
    ///   `EVP_MAC` operation failed.
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let len = self.hash.size();
        if let Some(signature) = signature {
            if signature.len() < len {
                return Err(CryptoError::HmacBufferTooSmall);
            }

            let key = key_bytes(key)?;
            let mut mac = IsolatedHmac::new(&self.hash, &key)?;
            mac.update(data)?;
            mac.finish(&mut signature[..len])?;
        }

        Ok(len)
    }
}

/// Implements streaming HMAC signing.
impl<'a> SignStreamingOp<'a> for OsslHmacAlgo {
    type Key = HmacKey;
    type Context = OsslHmacAlgoSignContext<'a>;

    /// Initializes a streaming HMAC signing context.
    ///
    /// Keys an `EVP_MAC` context up front so data can be fed incrementally via
    /// `update()` and finalized with `finish()`. The key is copied into the
    /// context, so the returned context borrows nothing from `key`.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key.
    ///
    /// # Returns
    ///
    /// A streaming context implementing `SignStreamingOpContext`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::HmacKeyError` - the key bytes could not be extracted.
    /// - `CryptoError::HmacInitError` - the `EVP_MAC` context could not be keyed.
    fn sign_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let key = key_bytes(&key)?;
        let mac = IsolatedHmac::new(&self.hash, &key)?;
        Ok(OsslHmacAlgoSignContext {
            mac,
            algo: self,
            _marker: PhantomData,
        })
    }
}

/// Streaming context for HMAC signing operations.
///
/// The `'a` parameter is vestigial — the key is copied into the underlying
/// `EVP_MAC_CTX`, so nothing is borrowed — but is retained to satisfy the
/// platform-agnostic trait signature.
pub struct OsslHmacAlgoSignContext<'a> {
    /// libctx-isolated MAC state.
    mac: IsolatedHmac,
    /// Algorithm configuration.
    algo: OsslHmacAlgo,
    _marker: PhantomData<&'a ()>,
}

impl<'a> SignStreamingOpContext<'a> for OsslHmacAlgoSignContext<'a> {
    type Algo = OsslHmacAlgo;

    /// Feeds a chunk of data into the running HMAC.
    ///
    /// # Arguments
    ///
    /// * `data` - The next chunk of data to authenticate.
    ///
    /// # Errors
    ///
    /// `CryptoError::HmacSignUpdateError` if the `EVP_MAC` update fails.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.mac.update(data)
    }

    /// Finalizes the HMAC over all data fed via `update()`.
    ///
    /// When `signature` is `None`, nothing is finalized and only the required
    /// buffer size (the MAC length) is returned.
    ///
    /// # Arguments
    ///
    /// * `signature` - Optional output buffer. If `None`, only the required size
    ///   is returned.
    ///
    /// # Returns
    ///
    /// The number of bytes written to `signature`, or the required buffer size
    /// when `signature` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::HmacBufferTooSmall` - the output buffer is too small.
    /// - `CryptoError::HmacSignFinishError` - the `EVP_MAC` finalization failed.
    fn finish(&mut self, signature: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let len = self.algo.hash.size();
        if let Some(signature) = signature {
            if signature.len() < len {
                return Err(CryptoError::HmacBufferTooSmall);
            }
            self.mac.finish(&mut signature[..len])?;
        }
        Ok(len)
    }

    /// Returns a reference to the underlying hash algorithm.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying hash algorithm.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying hash algorithm.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

/// Implements single-operation HMAC verification.
impl VerifyOp for OsslHmacAlgo {
    type Key = HmacKey;

    /// Verifies an HMAC by recomputing it over `data` and comparing.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key.
    /// * `data` - The data that was authenticated.
    /// * `signature` - The expected MAC to check against.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the recomputed MAC matches `signature`, `Ok(false)`
    /// otherwise.
    ///
    /// # Errors
    ///
    /// - `CryptoError::HmacKeyError` - the key bytes could not be extracted.
    /// - `CryptoError::HmacInitError` / `CryptoError::HmacSignFinishError` - the
    ///   `EVP_MAC` recomputation failed.
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let mut result = vec![0u8; self.hash.size()];

        let key = key_bytes(key)?;
        let mut mac = IsolatedHmac::new(&self.hash, &key)?;
        mac.update(data)?;
        mac.finish(&mut result)?;

        // Constant-time MAC comparison so verification doesn't leak how many
        // leading bytes match via timing. The length check compares public MAC
        // sizes (not secret); `memcmp::eq` requires equal lengths.
        Ok(result.len() == signature.len() && openssl::memcmp::eq(&result, signature))
    }
}

/// Implements streaming HMAC verification.
impl<'a> VerifyStreamingOp<'a> for OsslHmacAlgo {
    /// The HMAC key type used for this verification operation.
    type Key = HmacKey;

    /// The context type for streaming HMAC verification.
    type Context = OsslHmacAlgoVerifyContext<'a>;

    /// Initializes a streaming HMAC verification context.
    ///
    /// Keys an `EVP_MAC` context up front so data can be fed incrementally via
    /// `update()` and checked with `finish()`. The key is copied into the
    /// context.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key.
    ///
    /// # Returns
    ///
    /// A streaming context implementing `VerifyStreamingOpContext`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::HmacKeyError` - the key bytes could not be extracted.
    /// - `CryptoError::HmacVerifyInitError` - the `EVP_MAC` context could not be
    ///   keyed.
    fn verify_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let key = key_bytes(&key)?;
        let mac =
            IsolatedHmac::new(&self.hash, &key).map_err(|_| CryptoError::HmacVerifyInitError)?;
        Ok(OsslHmacAlgoVerifyContext {
            mac,
            algo: self,
            _marker: PhantomData,
        })
    }
}

/// Streaming context for HMAC verification operations.
///
/// As with the sign context, the `'a` parameter is vestigial (the key is copied
/// into the `EVP_MAC_CTX`).
pub struct OsslHmacAlgoVerifyContext<'a> {
    /// libctx-isolated MAC state.
    mac: IsolatedHmac,
    /// Algorithm configuration.
    algo: OsslHmacAlgo,
    _marker: PhantomData<&'a ()>,
}

impl<'a> VerifyStreamingOpContext<'a> for OsslHmacAlgoVerifyContext<'a> {
    /// The signature algorithm type associated with this context.
    type Algo = OsslHmacAlgo;

    /// Feeds a chunk of data into the running HMAC.
    ///
    /// # Arguments
    ///
    /// * `data` - The next chunk of data to authenticate.
    ///
    /// # Errors
    ///
    /// `CryptoError::HmacVerifyUpdateError` if the `EVP_MAC` update fails.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.mac
            .update(data)
            .map_err(|_| CryptoError::HmacVerifyUpdateError)
    }

    /// Finalizes and checks the signature by recomputing the MAC over all data
    /// fed via `update()` and comparing it to `signature`.
    ///
    /// # Arguments
    ///
    /// * `signature` - The expected MAC to check against.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the recomputed MAC matches, `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// `CryptoError::HmacVerifyFinishError` if the `EVP_MAC` finalization fails.
    fn finish(&mut self, signature: &[u8]) -> Result<bool, CryptoError> {
        let mut result = vec![0u8; self.algo.hash.size()];

        self.mac
            .finish(&mut result)
            .map_err(|_| CryptoError::HmacVerifyFinishError)?;

        // Constant-time comparison (see the one-shot `verify`).
        Ok(result.len() == signature.len() && openssl::memcmp::eq(&result, signature))
    }

    /// Returns a reference to the underlying hash algorithm.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying hash algorithm.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying hash algorithm.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
