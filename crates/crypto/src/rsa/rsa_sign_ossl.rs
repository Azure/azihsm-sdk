// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA signature generation and verification with pre-hashed data using OpenSSL.
//!
//! This module provides RSA signing and verification operations for pre-hashed digests
//! using the OpenSSL library. It supports both PKCS#1 v1.5 and PSS (Probabilistic
//! Signature Scheme) padding modes.
//!
//! **Note**: This module operates on message digests (hashes), not raw message data.
//! The caller must hash the message before passing it to the sign/verify operations.
//!
//! # Padding Schemes
//!
//! - **PKCS#1 v1.5**: Traditional deterministic padding scheme, widely supported
//! - **PSS**: Probabilistic padding with stronger security properties, recommended for new applications
//!
//! # Security Considerations
//!
//! - PSS padding is recommended over PKCS#1 v1.5 for new applications
//! - Use SHA-256 or stronger hash algorithms for message digests
//! - For PSS, salt length should typically match the hash output length
//! - PKCS#1 v1.5 is deterministic and may be vulnerable to certain attacks
//! - Always hash messages before signing (this module expects pre-computed digests)

use std::os::raw::c_int;
use std::ptr;

use foreign_types::ForeignTypeRef;
use openssl::rsa::*;
use openssl_sys as ffi;

use super::*;
use crate::libctx::OSSL_SUCCESS;
use crate::libctx::PkeyCtx;

/// RSA signing and verification context for pre-hashed data using OpenSSL.
///
/// This structure manages the configuration for RSA signature operations on message
/// digests (hashes), including padding scheme selection, hash algorithm identification,
/// and PSS-specific parameters.
///
/// **Important**: This context operates on pre-computed message digests, not raw messages.
/// The caller must hash the message using the appropriate hash algorithm before calling
/// sign or verify operations.
///
/// # Padding Configuration
///
/// The context can be configured for:
/// - **PKCS#1 v1.5**: Traditional deterministic padding for digests
/// - **PSS**: Probabilistic signature scheme with configurable salt length
///
/// # Trait Implementations
///
/// - `SignOp`: Signs a pre-computed message digest
/// - `VerifyOp`: Verifies a signature against a pre-computed message digest
pub struct OsslRsaSignAlgo {
    /// The padding scheme to use (PKCS#1 or PSS).
    padding: Padding,
    /// The hash instance to use.
    hash: Option<HashAlgo>,
    /// The salt length for PSS padding (ignored for PKCS#1).
    salt_len: usize,
}

impl SignOp for OsslRsaSignAlgo {
    type Key = RsaPrivateKey;

    /// Generates an RSA signature for a pre-hashed message digest.
    ///
    /// This operation signs a message digest (hash) that has already been computed
    /// by the caller. The digest size must match the output size of the hash algorithm
    /// configured for this signing context.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for signing
    /// * `data` - The pre-computed message digest (hash output)
    /// * `signature` - Optional buffer for the signature. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the signature buffer, or the required buffer size
    /// if `signature` is `None`. The signature size equals the key size in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RsaSignError` if:
    /// - The digest size doesn't match the expected hash output size
    /// - The OpenSSL signing operation fails
    /// - The signature buffer is too small
    #[allow(unsafe_code)]
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // Fetch the signature digest (and MGF1 digest for PSS) from the
        // crate-private libctx so it never resolves to azihsm; kept alive for
        // the whole op via `md`.
        let md = self.fetch_md()?;

        // Build the sign ctx in the crate-private libctx (default-provider only)
        // via `PkeyCtx` so the RSA op fetch never resolves to azihsm on OpenSSL
        // 3.5. See [`crate::libctx`].
        //
        // SAFETY: the key's `EVP_PKEY*` outlives `ctx` (the `PkeyCtx` guard frees
        // it on drop on every path); the signature length is sized from the
        // first `EVP_PKEY_sign` (sig=NULL) query; `md` outlives the call.
        let len = unsafe {
            let ctx = PkeyCtx::from_pkey(key.pkey().as_ptr()).ok_or(CryptoError::RsaError)?;
            if ffi::EVP_PKEY_sign_init(ctx.as_ptr()) != OSSL_SUCCESS {
                return Err(CryptoError::RsaSignError);
            }
            self.configure_ctx(ctx.as_ptr(), md.as_ref())?;
            // Mirror `PkeyCtx::sign`: a single `EVP_PKEY_sign`. With no buffer,
            // sig=NULL and siglen=0 yields the required size; with a buffer,
            // siglen starts at its length and is updated to the bytes written.
            // Any failure (including a too-small buffer) maps to `RsaSignError`.
            let mut siglen = signature.as_ref().map_or(0, |b| b.len());
            let sig_ptr = signature.map_or(ptr::null_mut(), |b| b.as_mut_ptr());
            if ffi::EVP_PKEY_sign(
                ctx.as_ptr(),
                sig_ptr,
                &mut siglen,
                data.as_ptr(),
                data.len(),
            ) != OSSL_SUCCESS
            {
                return Err(CryptoError::RsaSignError);
            }
            siglen
        };

        Ok(len)
    }
}

impl VerifyOp for OsslRsaSignAlgo {
    type Key = RsaPublicKey;

    /// Verifies an RSA signature against a pre-computed message digest.
    ///
    /// This operation verifies that a signature is valid for a given message digest (hash)
    /// that has already been computed by the caller. The digest must be computed using
    /// the same hash algorithm configured for this verification context.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for verification
    /// * `data` - The pre-computed message digest (hash output)
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for the given digest, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error only for setup/configuration failures before the final
    /// OpenSSL verify step (for example context creation, `verify_init`, or
    /// padding/hash configuration).
    ///
    /// Any error from the final OpenSSL `verify` call is treated as an invalid
    /// signature and returns `Ok(false)` (fail-closed).
    #[allow(unsafe_code)]
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        // Fetch the signature digest (and MGF1 digest for PSS) from the
        // crate-private libctx so it never resolves to azihsm; kept alive for
        // the whole op via `md`.
        let md = self.fetch_md()?;

        // Build the verify ctx in the crate-private libctx (default-provider
        // only) via `PkeyCtx` so the RSA op fetch never resolves to azihsm on
        // OpenSSL 3.5. See [`crate::libctx`].
        //
        // SAFETY: the key's `EVP_PKEY*` outlives `ctx` (the `PkeyCtx` guard frees
        // it on drop on every path); `data`/`signature` are valid for the call;
        // `md` outlives it.
        let valid = unsafe {
            let ctx = PkeyCtx::from_pkey(key.pkey().as_ptr()).ok_or(CryptoError::RsaError)?;
            if ffi::EVP_PKEY_verify_init(ctx.as_ptr()) != OSSL_SUCCESS {
                return Err(CryptoError::RsaVerifyError);
            }
            self.configure_ctx(ctx.as_ptr(), md.as_ref())?;
            // After successful setup, `EVP_PKEY_verify` returns 1 for a valid
            // signature; anything else (0 invalid, negative error, malformed
            // signature) is treated as invalid (fail-closed), matching the prior
            // `Err(_) => Ok(false)` behaviour.
            ffi::EVP_PKEY_verify(
                ctx.as_ptr(),
                signature.as_ptr(),
                signature.len(),
                data.as_ptr(),
                data.len(),
            ) == OSSL_SUCCESS
        };

        Ok(valid)
    }
}

impl VerifyRecoverOp for OsslRsaSignAlgo {
    type Key = RsaPublicKey;

    /// Verifies an RSA signature and recovers the signed message digest.
    ///
    /// This operation verifies a signature and recovers the original message digest
    /// (hash) that was signed. The recovered digest must match the expected hash output
    /// size for the configured hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for verification
    /// * `signature` - The signature to verify and recover from
    /// * `output` - Optional buffer to receive the recovered digest. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The OpenSSL verification or recovery operation fails
    /// - The output buffer is too small
    #[allow(unsafe_code)]
    fn verify_recover(
        &mut self,
        key: &Self::Key,
        signature: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // Fetch the signature digest (and MGF1 digest for PSS) from the
        // crate-private libctx so it never resolves to azihsm; kept alive for
        // the whole op via `md`.
        let md = self.fetch_md()?;

        // Build the recover ctx in the crate-private libctx (default-provider
        // only) via `PkeyCtx` so the RSA op fetch never resolves to azihsm on
        // OpenSSL 3.5. See [`crate::libctx`].
        //
        // SAFETY: the key's `EVP_PKEY*` outlives `ctx` (the `PkeyCtx` guard frees
        // it on drop on every path); `signature` is valid for the call; `md`
        // outlives it.
        let len = unsafe {
            let ctx = PkeyCtx::from_pkey(key.pkey().as_ptr()).ok_or(CryptoError::RsaError)?;
            if ffi::EVP_PKEY_verify_recover_init(ctx.as_ptr()) != OSSL_SUCCESS {
                return Err(CryptoError::RsaVerifyError);
            }
            self.configure_ctx(ctx.as_ptr(), md.as_ref())?;
            // Mirror `PkeyCtx::verify_recover`: a single call with the output
            // length pre-seeded (buffer length, or 0 when querying).
            let mut written = output.as_ref().map_or(0, |b| b.len());
            let out_ptr = output.map_or(ptr::null_mut(), |b| b.as_mut_ptr());
            if ffi::EVP_PKEY_verify_recover(
                ctx.as_ptr(),
                out_ptr,
                &mut written,
                signature.as_ptr(),
                signature.len(),
            ) != OSSL_SUCCESS
            {
                return Err(CryptoError::RsaVerifyError);
            }
            written
        };

        Ok(len)
    }
}

impl OsslRsaSignAlgo {
    /// Creates a new RSA signing operation with no padding.
    ///
    /// This is a low-level operation that performs raw RSA signing without any padding
    /// or hashing. It should only be used when implementing custom padding schemes or
    /// for specific cryptographic protocols.
    ///
    /// # Security Warning
    ///
    /// Raw RSA operations without padding are vulnerable to various attacks and should
    /// not be used for general-purpose signing. Use PKCS#1 or PSS padding instead.
    ///
    /// # Returns
    ///
    /// A new signing context configured for raw RSA operations.
    pub fn with_no_padding() -> Self {
        Self {
            padding: Padding::NONE,
            hash: None,
            salt_len: 0,
        }
    }
    /// Creates a new RSA signing operation with PKCS#1 v1.5 padding.
    ///
    /// PKCS#1 v1.5 is the traditional RSA signature padding scheme. It is deterministic
    /// and widely supported but has weaker security properties than PSS.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash instance to use (SHA-256 or stronger recommended)
    ///
    /// # Returns
    ///
    /// A new `OsslRsaSigning` instance configured for PKCS#1 v1.5 padding.
    ///
    /// # Security Considerations
    ///
    /// - PKCS#1 v1.5 is deterministic, which can be a security concern in some contexts
    /// - Consider using PSS padding for new applications
    /// - Use SHA-256 or stronger hash algorithms
    pub fn with_pkcs1_padding(hash: HashAlgo) -> Self {
        Self {
            padding: Padding::PKCS1,
            hash: Some(hash),
            salt_len: 0,
        }
    }

    /// Creates a new RSA signing operation with PSS padding.
    ///
    /// PSS (Probabilistic Signature Scheme) is a randomized padding scheme with
    /// stronger security properties than PKCS#1 v1.5. It is recommended for new applications.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash instance to use (SHA-256 or stronger recommended)
    /// * `salt_len` - The salt length in bytes (typically matches hash output length)
    ///
    /// # Returns
    ///
    /// A new `OsslRsaSigning` instance configured for PSS padding.
    ///
    /// # Security Considerations
    ///
    /// - PSS provides stronger security guarantees than PKCS#1 v1.5
    /// - Salt length typically matches the hash output length for optimal security
    /// - PSS is randomized, providing better protection against certain attacks
    /// - Use SHA-256 or stronger hash algorithms
    pub fn with_pss_padding(hash: HashAlgo, salt_len: usize) -> Self {
        Self {
            padding: Padding::PKCS1_PSS,
            hash: Some(hash),
            salt_len,
        }
    }

    /// Fetches the configured signature digest from the crate-private libctx so
    /// it never resolves to azihsm, returning `None` when no hash is configured
    /// (raw no-padding signing). The returned `Md` owns its `EVP_MD` and must be
    /// kept alive for the whole operation.
    fn fetch_md(&self) -> Result<Option<openssl::md::Md>, CryptoError> {
        match &self.hash {
            Some(hash) => Ok(Some(
                openssl::md::Md::fetch(Some(crate::libctx::crypto_libctx()), hash.md_name()?, None)
                    .map_err(|_| CryptoError::RsaSetPropertyError)?,
            )),
            None => Ok(None),
        }
    }

    /// Applies the padding configuration to an `EVP_PKEY_CTX` created from the
    /// crate-private libctx and already initialised for the sign/verify
    /// operation.
    ///
    /// Replicates the prior `configure_pkey_ctx` logic via the raw
    /// `EVP_PKEY_CTX_set_*` controls: padding mode, then (when a hash is
    /// configured) the signature digest, and for PSS the salt length and MGF1
    /// digest. `md` carries the digest fetched from the private libctx and must
    /// outlive this call.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RsaSetPropertyError` for any control failure, as
    /// before.
    ///
    /// # Safety
    ///
    /// `ctx` must be a valid `EVP_PKEY_CTX` initialised for the operation and
    /// `md` (if `Some`) must point to a live `EVP_MD`.
    #[allow(unsafe_code)]
    unsafe fn configure_ctx(
        &self,
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        md: Option<&openssl::md::Md>,
    ) -> Result<(), CryptoError> {
        // SAFETY: `ctx` is a valid, initialised `EVP_PKEY_CTX` and `md` (if
        // `Some`) points to a live `EVP_MD`, per this fn's contract.
        unsafe {
            if ffi::EVP_PKEY_CTX_set_rsa_padding(ctx, self.padding.as_raw()) != OSSL_SUCCESS {
                return Err(CryptoError::RsaSetPropertyError);
            }

            if let Some(md) = md {
                if ffi::EVP_PKEY_CTX_set_signature_md(ctx, md.as_ptr()) != OSSL_SUCCESS {
                    return Err(CryptoError::RsaSetPropertyError);
                }

                if self.padding == Padding::PKCS1_PSS {
                    // `set_rsa_pss_saltlen` takes a `c_int`; reject salt lengths
                    // that don't fit rather than letting `as` truncate.
                    let saltlen = c_int::try_from(self.salt_len)
                        .map_err(|_| CryptoError::RsaSetPropertyError)?;
                    if ffi::EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen) != OSSL_SUCCESS {
                        return Err(CryptoError::RsaSetPropertyError);
                    }
                    if ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md.as_ptr()) != OSSL_SUCCESS {
                        return Err(CryptoError::RsaSetPropertyError);
                    }
                }
            }
        }

        Ok(())
    }
}
