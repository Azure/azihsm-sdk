// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA signature generation and verification using OpenSSL.
//!
//! This module provides RSA signing and verification operations using the OpenSSL
//! library. It supports both PKCS#1 v1.5 and PSS (Probabilistic Signature Scheme)
//! padding modes for both one-shot and streaming operations.
//!
//! # Padding Schemes
//!
//! - **PKCS#1 v1.5**: Traditional deterministic padding scheme, widely supported
//! - **PSS**: Probabilistic padding with stronger security properties, recommended for new applications
//!
//! # Operation Modes
//!
//! - **One-shot**: Sign or verify entire message in a single operation
//! - **Streaming**: Process large messages incrementally using init/update/finish pattern
//!
//! # Security Considerations
//!
//! - PSS padding is recommended over PKCS#1 v1.5 for new applications
//! - Use SHA-256 or stronger hash algorithms
//! - For PSS, salt length should typically match the hash output length
//! - PKCS#1 v1.5 is deterministic and may be vulnerable to certain attacks

use openssl::md_ctx::*;
use openssl::rsa::*;

use super::*;

// Libctx-aware digest-sign/verify init. The `openssl` crate's
// `MdCtx::digest_sign_init`/`digest_verify_init` call the legacy
// `EVP_DigestSignInit`/`EVP_DigestVerifyInit`, which fetch the digest and RSA
// signature op from the *process default* libctx regardless of the key — on
// OpenSSL 3.5 that resolves to the azihsm provider and re-enters it during the
// HSM session open. The `_ex` variants take an explicit `OSSL_LIB_CTX`, so the
// digest/signature fetch is pinned to the crate-private libctx
// (default-provider only) and never lands on azihsm. These symbols exist in
// OpenSSL 3.0+ libcrypto but are not bound by openssl-sys 0.9.x, so they are
// declared here. See [`crate::libctx`].
#[allow(unsafe_code)]
unsafe extern "C" {
    fn EVP_DigestSignInit_ex(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
        mdname: *const std::os::raw::c_char,
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        props: *const std::os::raw::c_char,
        pkey: *mut openssl_sys::EVP_PKEY,
        params: *const openssl_sys::OSSL_PARAM,
    ) -> std::os::raw::c_int;

    fn EVP_DigestVerifyInit_ex(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
        mdname: *const std::os::raw::c_char,
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        props: *const std::os::raw::c_char,
        pkey: *mut openssl_sys::EVP_PKEY,
        params: *const openssl_sys::OSSL_PARAM,
    ) -> std::os::raw::c_int;
}

/// RSA signing and verification context using OpenSSL.
///
/// This structure manages the configuration for RSA signature operations,
/// including padding scheme selection, hash algorithm, and PSS-specific parameters.
///
/// # Padding Configuration
///
/// The context can be configured for:
/// - **PKCS#1 v1.5**: Traditional deterministic padding
/// - **PSS**: Probabilistic signature scheme with configurable salt length
///
/// # Trait Implementations
///
/// - `SignOp`: One-shot signature generation
/// - `SignStreamingOp`: Streaming signature generation for large messages
/// - `VerifyOp`: One-shot signature verification
/// - `VerifyStreamingOp`: Streaming signature verification for large messages
pub struct OsslRsaHashSignAlgo {
    /// The padding scheme to use (PKCS#1 or PSS).
    padding: Padding,
    /// The hash instance to use.
    hash: HashAlgo,
    /// The salt length for PSS padding (ignored for PKCS#1).
    salt_len: usize,
}

impl SignOp for OsslRsaHashSignAlgo {
    type Key = RsaPrivateKey;

    /// Generates an RSA signature for the given data.
    ///
    /// This is a one-shot operation that signs the entire message in a single call.
    /// The data is hashed using the configured hash algorithm before signing.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for signing
    /// * `data` - The message to sign
    /// * `signature` - Optional buffer for the signature. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the signature buffer, or the required buffer size
    /// if `signature` is `None`. The signature size equals the key size in bytes.
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        fn len(ctx: &mut MdCtxRef, data: &[u8]) -> Result<usize, CryptoError> {
            ctx.digest_sign(data, None)
                .map_err(|_| CryptoError::RsaError)
        }

        let mut ctx = MdCtx::new().map_err(|_| CryptoError::RsaError)?;
        self.digest_sign_init_isolated(&mut ctx, key)?;

        let sig_len = len(&mut ctx, data)?;

        if let Some(signature) = signature {
            if signature.len() < sig_len {
                return Err(CryptoError::RsaBufferTooSmall);
            }
            let len = ctx
                .digest_sign(data, Some(&mut signature[..sig_len]))
                .map_err(|_| CryptoError::RsaSignError)?;
            return Ok(len);
        }

        Ok(sig_len)
    }
}

impl<'a> SignStreamingOp<'a> for OsslRsaHashSignAlgo {
    type Key = RsaPrivateKey;
    type Context = OsslRsaHashSignAlgoSignContext;

    /// Initializes a streaming signature operation.
    ///
    /// Creates a signing context that can process data incrementally using
    /// the update/finish pattern. Useful for signing large messages that
    /// don't fit in memory.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for signing
    ///
    /// # Returns
    ///
    /// A streaming context that can be updated with message data and finalized.
    fn sign_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let mut ctx = MdCtx::new().map_err(|_| CryptoError::RsaError)?;
        self.digest_sign_init_isolated(&mut ctx, &key)?;
        Ok(OsslRsaHashSignAlgoSignContext { algo: self, ctx })
    }
}

/// Streaming context for RSA signature generation.
///
/// This context manages the incremental hashing and signature generation process.
/// Data can be added using `update()` and the signature finalized with `finish()`.
pub struct OsslRsaHashSignAlgoSignContext {
    algo: OsslRsaHashSignAlgo,
    ctx: MdCtx,
}

impl<'a> SignStreamingOpContext<'a> for OsslRsaHashSignAlgoSignContext {
    type Algo = OsslRsaHashSignAlgo;
    /// Adds more data to the message being signed.
    ///
    /// Can be called multiple times to process the message incrementally.
    ///
    /// # Arguments
    ///
    /// * `data` - The next chunk of message data to include in the signature
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.ctx
            .digest_sign_update(data)
            .map_err(|_| CryptoError::RsaSignUpdateError)
    }

    /// Finalizes the signature generation.
    ///
    /// Completes the hashing process and generates the RSA signature.
    ///
    /// # Arguments
    ///
    /// * `signature` - Optional buffer for the signature. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the signature buffer, or the required buffer size.
    fn finish(&mut self, signature: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        fn len(ctx: &mut MdCtxRef) -> Result<usize, CryptoError> {
            ctx.digest_sign_final(None)
                .map_err(|_| CryptoError::RsaError)
        }

        let sig_len = len(&mut self.ctx)?;
        if let Some(signature) = signature {
            if signature.len() < sig_len {
                return Err(CryptoError::RsaBufferTooSmall);
            }
            let len = self
                .ctx
                .digest_sign_final(Some(&mut signature[..sig_len]))
                .map_err(|_| CryptoError::RsaSignFinishError)?;
            return Ok(len);
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

impl VerifyOp for OsslRsaHashSignAlgo {
    type Key = RsaPublicKey;

    /// Verifies an RSA signature for the given data.
    ///
    /// This is a one-shot operation that verifies the signature against the entire
    /// message in a single call. The data is hashed using the configured hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for verification
    /// * `data` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` if invalid.
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let mut ctx = MdCtx::new().map_err(|_| CryptoError::RsaError)?;
        self.digest_verify_init_isolated(&mut ctx, key)?;
        ctx.digest_verify(data, signature)
            .map_err(|_| CryptoError::RsaVerifyError)
    }
}

impl<'a> VerifyStreamingOp<'a> for OsslRsaHashSignAlgo {
    type Key = RsaPublicKey;
    type Context = OsslRsaHashSignAlgoVerifyContext;

    /// Initializes a streaming verification operation.
    ///
    /// Creates a verification context that can process data incrementally using
    /// the update/finish pattern. Useful for verifying signatures on large messages.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for verification
    ///
    /// # Returns
    ///
    /// A streaming context that can be updated with message data and finalized.
    fn verify_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let mut ctx = MdCtx::new().map_err(|_| CryptoError::RsaError)?;
        self.digest_verify_init_isolated(&mut ctx, &key)?;
        Ok(OsslRsaHashSignAlgoVerifyContext {
            algo: self,
            md_ctx: ctx,
        })
    }
}

/// Streaming context for RSA signature verification.
///
/// This context manages the incremental hashing and signature verification process.
/// Data can be added using `update()` and the verification finalized with `finish()`.
pub struct OsslRsaHashSignAlgoVerifyContext {
    /// The underlying signing algorithm.
    algo: OsslRsaHashSignAlgo,
    md_ctx: MdCtx,
}

impl<'a> VerifyStreamingOpContext<'a> for OsslRsaHashSignAlgoVerifyContext {
    type Algo = OsslRsaHashSignAlgo;
    /// Adds more data to the message being verified.
    ///
    /// Can be called multiple times to process the message incrementally.
    ///
    /// # Arguments
    ///
    /// * `data` - The next chunk of message data to include in the verification
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.md_ctx
            .digest_verify_update(data)
            .map_err(|_| CryptoError::RsaVerifyUpdateError)
    }

    /// Finalizes the signature verification.
    ///
    /// Completes the hashing process and verifies the RSA signature.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify against the accumulated message data
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` if invalid.
    fn finish(&mut self, signature: &[u8]) -> Result<bool, CryptoError> {
        self.md_ctx
            .digest_verify_final(signature)
            .map_err(|_| CryptoError::RsaVerifyFinishError)
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

impl OsslRsaHashSignAlgo {
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
            hash,
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
    /// * `hash_algo` - The hash algorithm to use (SHA-256 or stronger recommended)
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
            hash,
            salt_len,
        }
    }

    /// Initialises `ctx` for digest-signing in the crate-private libctx and
    /// applies the padding configuration.
    ///
    /// Replaces `MdCtx::digest_sign_init` (which uses the legacy, default-libctx
    /// `EVP_DigestSignInit`) with `EVP_DigestSignInit_ex` pinned to the private
    /// libctx, so neither the digest nor the RSA signature op can resolve to
    /// azihsm. Subsequent `digest_sign`/`digest_sign_update`/`digest_sign_final`
    /// calls operate on the same already-initialised context and do not
    /// re-fetch.
    #[allow(unsafe_code)]
    fn digest_sign_init_isolated(
        &self,
        ctx: &mut MdCtxRef,
        key: &RsaPrivateKey,
    ) -> Result<(), CryptoError> {
        use std::ptr;

        use foreign_types::ForeignTypeRef;
        use openssl_sys as ffi;

        let mdname =
            std::ffi::CString::new(self.hash.md_name()?).map_err(|_| CryptoError::RsaError)?;

        // SAFETY: `ctx` and the key pkey are valid; `pctx` is owned by `ctx`
        // and must not be freed here. `mdname` outlives the call.
        unsafe {
            let mut pctx: *mut ffi::EVP_PKEY_CTX = ptr::null_mut();
            if EVP_DigestSignInit_ex(
                ctx.as_ptr(),
                &mut pctx,
                mdname.as_ptr(),
                crate::libctx::crypto_libctx_ptr(),
                ptr::null(),
                key.pkey().as_ptr(),
                ptr::null(),
            ) != 1
            {
                return Err(CryptoError::RsaError);
            }
            self.configure_ctx(pctx)
        }
    }

    /// Initialises `ctx` for digest-verifying in the crate-private libctx and
    /// applies the padding configuration. See [`Self::digest_sign_init_isolated`].
    #[allow(unsafe_code)]
    fn digest_verify_init_isolated(
        &self,
        ctx: &mut MdCtxRef,
        key: &RsaPublicKey,
    ) -> Result<(), CryptoError> {
        use std::ptr;

        use foreign_types::ForeignTypeRef;
        use openssl_sys as ffi;

        let mdname =
            std::ffi::CString::new(self.hash.md_name()?).map_err(|_| CryptoError::RsaError)?;

        // SAFETY: `ctx` and the key pkey are valid; `pctx` is owned by `ctx`
        // and must not be freed here. `mdname` outlives the call.
        unsafe {
            let mut pctx: *mut ffi::EVP_PKEY_CTX = ptr::null_mut();
            if EVP_DigestVerifyInit_ex(
                ctx.as_ptr(),
                &mut pctx,
                mdname.as_ptr(),
                crate::libctx::crypto_libctx_ptr(),
                ptr::null(),
                key.pkey().as_ptr(),
                ptr::null(),
            ) != 1
            {
                return Err(CryptoError::RsaError);
            }
            self.configure_ctx(pctx)
        }
    }

    /// Applies the padding configuration to the `EVP_PKEY_CTX` produced by the
    /// digest-sign/verify init: padding mode, and for PSS the salt length and
    /// MGF1 digest. Replicates the prior `configure_pkey_ctx` logic via the raw
    /// `EVP_PKEY_CTX_set_*` controls.
    ///
    /// # Safety
    ///
    /// `pctx` must be the valid, init-owned `EVP_PKEY_CTX` for `ctx`.
    #[allow(unsafe_code)]
    unsafe fn configure_ctx(
        &self,
        pctx: *mut openssl_sys::EVP_PKEY_CTX,
    ) -> Result<(), CryptoError> {
        use foreign_types::ForeignType;
        use openssl_sys as ffi;

        // SAFETY: `pctx` is the valid, init-owned `EVP_PKEY_CTX` for the
        // operation, per this fn's contract. `md` (when PSS) outlives its use.
        unsafe {
            if ffi::EVP_PKEY_CTX_set_rsa_padding(pctx, self.padding.as_raw()) != 1 {
                return Err(CryptoError::RsaSetPropertyError);
            }
            if self.padding == Padding::PKCS1_PSS {
                // `set_rsa_pss_saltlen` takes a `c_int`; reject salt lengths that
                // don't fit rather than letting `as` truncate.
                let saltlen = std::os::raw::c_int::try_from(self.salt_len)
                    .map_err(|_| CryptoError::RsaSetPropertyError)?;
                if ffi::EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltlen) != 1 {
                    return Err(CryptoError::RsaSetPropertyError);
                }
                // Fetch the MGF1 digest from the private libctx so it never
                // resolves to azihsm. `pctx` is a provider ctx, so
                // `EVP_PKEY_CTX_set_rsa_mgf1_md` forwards the digest by *name*
                // (`EVP_MD_get0_name`): the provider copies that name and
                // re-fetches its own md synchronously inside this call, so `md`
                // does not need to outlive it (no dangling pointer at sign time).
                let md = openssl::md::Md::fetch(
                    Some(crate::libctx::crypto_libctx()),
                    self.hash.md_name()?,
                    None,
                )
                .map_err(|_| CryptoError::RsaSetPropertyError)?;
                if ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md.as_ptr()) != 1 {
                    return Err(CryptoError::RsaSetPropertyError);
                }
            }
        }
        Ok(())
    }
}
