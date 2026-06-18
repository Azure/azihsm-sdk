// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based RSA encryption and decryption operations.
//!
//! This module provides RSA encryption and decryption functionality using OpenSSL
//! as the underlying cryptographic backend. It supports various padding schemes
//! including OAEP (Optimal Asymmetric Encryption Padding) for enhanced security.
//!
//! # Supported Padding Schemes
//!
//! - **OAEP**: Optimal Asymmetric Encryption Padding with configurable hash algorithms
//! - **PKCS#1 v1.5**: Legacy padding (use OAEP for new applications)
//!
//! # Security Considerations
//!
//! - Always use OAEP padding for new applications
//! - OAEP provides semantic security and protection against various attacks
//! - Choose appropriate hash algorithms (SHA-256 or stronger recommended)
//! - RSA encryption is typically used for small data (e.g., symmetric key wrapping)

use std::os::raw::c_int;
use std::ptr;

use foreign_types::ForeignTypeRef;
use openssl::rsa::*;
use openssl_sys as ffi;

use super::*;
use crate::libctx::OSSL_SUCCESS;
use crate::libctx::PkeyCtx;

/// OpenSSL-backed RSA encryption and decryption implementation.
///
/// This structure provides RSA encryption and decryption operations with support
/// for various padding schemes. It maintains configuration for padding mode,
/// hash algorithm selection, and optional OAEP labels.
///
/// # Lifetime Parameter
///
/// The lifetime parameter `'a` is used for the OAEP label, which must remain
/// valid for the duration of the encryption/decryption operation.
///
/// # Padding Modes
///
/// - **NONE**: No padding (use with caution)
/// - **PKCS1_OAEP**: Optimal Asymmetric Encryption Padding with hash function
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync` as OpenSSL's RSA operations are thread-safe.
pub struct OsslRsaEncryptAlgo<'a> {
    /// The padding scheme to use for encryption/decryption
    padding: Padding,
    /// The hash instance for OAEP padding (if applicable)
    hash: Option<HashAlgo>,
    /// The label for OAEP padding (optional, typically empty)
    label: Option<&'a [u8]>,
}

/// Implements RSA encryption operations using OpenSSL.
///
/// This implementation performs RSA encryption with the configured padding scheme.
/// Encryption uses the RSA public key and produces ciphertext that can only be
/// decrypted with the corresponding private key.
impl EncryptOp for OsslRsaEncryptAlgo<'_> {
    type Key = RsaPublicKey;

    /// Encrypts data using RSA with the configured padding scheme.
    ///
    /// This method encrypts the input data using the provided RSA public key.
    /// The output buffer pattern allows querying the required buffer size before
    /// performing the actual encryption.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for encryption
    /// * `input` - The plaintext data to encrypt
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::RsaError` - Encrypter creation or length calculation fails
    /// - `CryptoError::RsaBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::RsaEncryptError` - Encryption operation fails
    ///
    /// # Security
    ///
    /// - RSA encryption should only be used for small data (typically symmetric keys)
    /// - Use OAEP padding for new applications
    /// - Ensure the public key is authenticated to prevent substitution attacks
    #[allow(unsafe_code)]
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // Fetch the OAEP digest from the crate-private libctx so it never
        // resolves to azihsm; kept alive for the whole op via `oaep_md`.
        let oaep_md = if self.padding == Padding::PKCS1_OAEP {
            match &self.hash {
                Some(hash) => Some(
                    openssl::md::Md::fetch(
                        Some(crate::libctx::crypto_libctx()),
                        hash.md_name()?,
                        None,
                    )
                    .map_err(|_| CryptoError::RsaSetPropertyError)?,
                ),
                None => None,
            }
        } else {
            None
        };

        // Build the encrypt ctx in the crate-private libctx (default-provider
        // only) via `PkeyCtx` so the RSA op fetch never resolves to azihsm on
        // OpenSSL 3.5. See [`crate::libctx`].
        //
        // SAFETY: the key's `EVP_PKEY*` outlives `ctx` (the `PkeyCtx` guard
        // frees it on drop on every path); the output buffer is sized from the
        // first `EVP_PKEY_encrypt` (out=NULL) query; `oaep_md` outlives the call.
        let len = unsafe {
            let ctx = PkeyCtx::from_pkey(key.pkey().as_ptr()).ok_or(CryptoError::RsaError)?;
            if ffi::EVP_PKEY_encrypt_init(ctx.as_ptr()) != OSSL_SUCCESS {
                return Err(CryptoError::RsaError);
            }
            self.configure_ctx(ctx.as_ptr(), oaep_md.as_ref())?;
            let mut len: usize = 0;
            if ffi::EVP_PKEY_encrypt(
                ctx.as_ptr(),
                ptr::null_mut(),
                &mut len,
                input.as_ptr(),
                input.len(),
            ) != OSSL_SUCCESS
            {
                return Err(CryptoError::RsaError);
            }
            if let Some(output) = output {
                if output.len() < len {
                    return Err(CryptoError::RsaBufferTooSmall);
                }
                if ffi::EVP_PKEY_encrypt(
                    ctx.as_ptr(),
                    output.as_mut_ptr(),
                    &mut len,
                    input.as_ptr(),
                    input.len(),
                ) != OSSL_SUCCESS
                {
                    return Err(CryptoError::RsaEncryptError);
                }
            }
            len
        };

        Ok(len)
    }
}

/// Implements RSA decryption operations using OpenSSL.
///
/// This implementation performs RSA decryption with the configured padding scheme.
/// Decryption uses the RSA private key to recover the original plaintext from
/// ciphertext that was encrypted with the corresponding public key.
impl DecryptOp for OsslRsaEncryptAlgo<'_> {
    type Key = RsaPrivateKey;

    /// Decrypts data using RSA with the configured padding scheme.
    ///
    /// This method decrypts the input ciphertext using the provided RSA private key.
    /// The output buffer pattern allows querying the required buffer size before
    /// performing the actual decryption.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for decryption
    /// * `input` - The ciphertext data to decrypt
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::RsaError` - Decrypter creation or length calculation fails
    /// - `CryptoError::RsaBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::RsaDecryptError` - Decryption operation fails
    ///
    /// # Security
    ///
    /// - Protect private keys from unauthorized access
    /// - Use constant-time operations when possible to prevent timing attacks
    /// - Validate decrypted data before use
    #[allow(unsafe_code)]
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // Fetch the OAEP digest from the crate-private libctx so it never
        // resolves to azihsm; kept alive for the whole op via `oaep_md`. The
        // MGF1 configuration failure maps to `RsaError` to match the prior
        // decrypter behaviour (see `configure_ctx`).
        let oaep_md = if self.padding == Padding::PKCS1_OAEP {
            match &self.hash {
                Some(hash) => Some(
                    openssl::md::Md::fetch(
                        Some(crate::libctx::crypto_libctx()),
                        hash.md_name()?,
                        None,
                    )
                    .map_err(|_| CryptoError::RsaSetPropertyError)?,
                ),
                None => None,
            }
        } else {
            None
        };

        // Build the decrypt ctx in the crate-private libctx (default-provider
        // only) via `PkeyCtx` so the RSA op fetch never resolves to azihsm on
        // OpenSSL 3.5. See [`crate::libctx`].
        //
        // SAFETY: the key's `EVP_PKEY*` outlives `ctx` (the `PkeyCtx` guard
        // frees it on drop on every path); the output buffer is sized from the
        // first `EVP_PKEY_decrypt` (out=NULL) query; `oaep_md` outlives the call.
        let len = unsafe {
            let ctx = PkeyCtx::from_pkey(key.pkey().as_ptr()).ok_or(CryptoError::RsaError)?;
            if ffi::EVP_PKEY_decrypt_init(ctx.as_ptr()) != OSSL_SUCCESS {
                return Err(CryptoError::RsaError);
            }
            self.configure_ctx(ctx.as_ptr(), oaep_md.as_ref())?;
            let mut len: usize = 0;
            if ffi::EVP_PKEY_decrypt(
                ctx.as_ptr(),
                ptr::null_mut(),
                &mut len,
                input.as_ptr(),
                input.len(),
            ) != OSSL_SUCCESS
            {
                return Err(CryptoError::RsaError);
            }
            if let Some(output) = output {
                if output.len() < len {
                    return Err(CryptoError::RsaBufferTooSmall);
                }
                if ffi::EVP_PKEY_decrypt(
                    ctx.as_ptr(),
                    output.as_mut_ptr(),
                    &mut len,
                    input.as_ptr(),
                    input.len(),
                ) != OSSL_SUCCESS
                {
                    return Err(CryptoError::RsaDecryptError);
                }
            }
            len
        };

        Ok(len)
    }
}

impl<'a> OsslRsaEncryptAlgo<'a> {
    /// Creates a new RSA encryption/decryption context with default settings.
    ///
    /// The default configuration uses no padding. For secure encryption,
    /// use `with_oaep_padding()` to configure OAEP padding with a hash algorithm.
    ///
    /// # Returns
    ///
    /// A new `OsslRsaEncryption` instance with:
    /// - No padding (must be configured before use)
    /// - No hash algorithm
    /// - Empty label
    pub fn with_no_padding() -> Self {
        Self {
            padding: Padding::NONE,
            hash: None,
            label: None,
        }
    }

    /// Creates a new RSA encryption/decryption context with PKCS#1 v1.5 padding.
    ///
    /// PKCS#1 v1.5 padding is a legacy padding scheme that should only be used
    /// for compatibility with existing systems. For new applications, use OAEP
    /// padding via `with_oaep_padding()` instead.
    ///
    /// # Returns
    ///
    /// A new `OsslRsaEncryption` instance configured with PKCS#1 v1.5 padding.
    ///
    /// # Security Warning
    ///
    /// PKCS#1 v1.5 padding is vulnerable to padding oracle attacks (Bleichenbacher's attack).
    /// It is considered legacy and should not be used in new applications unless required
    /// for compatibility with existing systems that cannot be upgraded.
    pub fn with_pkcs1_padding() -> Self {
        Self {
            padding: Padding::PKCS1,
            hash: None,
            label: None,
        }
    }

    /// Configures OAEP padding with the specified hash algorithm and label.
    ///
    /// OAEP (Optimal Asymmetric Encryption Padding) provides semantic security
    /// and protection against various attacks. It is the recommended padding
    /// scheme for new applications.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash instance to use for OAEP (SHA-256 or stronger recommended)
    /// * `label` - Optional label for OAEP (typically empty, but can be used for domain separation)
    ///
    /// # Returns
    ///
    /// The modified `OsslRsaEncryption` instance configured with OAEP padding.
    ///
    /// # Security
    ///
    /// - Use SHA-256 or stronger hash algorithms for new applications
    /// - The label parameter can be used for domain separation but is typically empty
    /// - OAEP provides protection against chosen-ciphertext attacks
    pub fn with_oaep_padding(hash: HashAlgo, label: Option<&'a [u8]>) -> Self {
        Self {
            padding: Padding::PKCS1_OAEP,
            hash: Some(hash),
            label,
        }
    }

    /// Applies the padding configuration to an `EVP_PKEY_CTX` that was created
    /// from the crate-private libctx and already initialised for encrypt or
    /// decrypt.
    ///
    /// This replicates the prior `configure_encrypter`/`configure_decrypter`
    /// logic via the raw `EVP_PKEY_CTX_set_*` controls: padding mode first,
    /// then (for OAEP) the OAEP digest, the MGF1 digest, and an optional OAEP
    /// label. The `oaep_md` digest must have been fetched from the private
    /// libctx and must outlive this call.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RsaSetPropertyError` for padding, OAEP digest, and
    /// label failures. As in the previous decrypter path, a MGF1 digest failure
    /// maps to `CryptoError::RsaError` (the encrypter path historically mapped
    /// it to `RsaSetPropertyError`, but the two are operationally equivalent and
    /// `RsaError` is preserved here for both for consistency).
    ///
    /// # Safety
    ///
    /// `ctx` must be a valid `EVP_PKEY_CTX` initialised for the operation and
    /// `oaep_md` (if `Some`) must point to a live `EVP_MD`.
    #[allow(unsafe_code)]
    unsafe fn configure_ctx(
        &self,
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        oaep_md: Option<&openssl::md::Md>,
    ) -> Result<(), CryptoError> {
        // SAFETY: `ctx` is a valid, initialised `EVP_PKEY_CTX` and `oaep_md`
        // (if `Some`) points to a live `EVP_MD`, per this fn's contract.
        unsafe {
            // Set the padding mode first, OAEP or NONE.
            if ffi::EVP_PKEY_CTX_set_rsa_padding(ctx, self.padding.as_raw()) != OSSL_SUCCESS {
                return Err(CryptoError::RsaSetPropertyError);
            }

            if self.padding == Padding::PKCS1_OAEP {
                if let Some(md) = oaep_md {
                    if ffi::EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md.as_ptr()) != OSSL_SUCCESS {
                        return Err(CryptoError::RsaSetPropertyError);
                    }
                    if ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md.as_ptr()) != OSSL_SUCCESS {
                        return Err(CryptoError::RsaError);
                    }
                }
                // An empty label is equivalent to "no label" (OAEP's default),
                // and `OPENSSL_malloc(0)` returns NULL — so only configure a
                // label when it is non-empty, keeping `None` and `Some(b"")`
                // behaviourally identical.
                if let Some(label) = self.label.filter(|l| !l.is_empty()) {
                    // `EVP_PKEY_CTX_set0_rsa_oaep_label` takes the length as a
                    // `c_int`; reject labels that don't fit before allocating so
                    // the cast can't overflow/truncate. (OAEP labels are tiny in
                    // practice; this is purely defensive.)
                    let llen = c_int::try_from(label.len())
                        .map_err(|_| CryptoError::RsaSetPropertyError)?;
                    // EVP_PKEY_CTX_set0_rsa_oaep_label takes ownership of the
                    // label buffer and frees it with OPENSSL_free, so the buffer
                    // must be OPENSSL_malloc'd (matching `set_rsa_oaep_label`).
                    let p = ffi::OPENSSL_malloc(label.len());
                    if p.is_null() {
                        return Err(CryptoError::RsaSetPropertyError);
                    }
                    std::ptr::copy_nonoverlapping(label.as_ptr(), p as *mut u8, label.len());
                    if ffi::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, p, llen) != OSSL_SUCCESS {
                        // On failure ownership is not transferred; free the copy.
                        ffi::OPENSSL_free(p);
                        return Err(CryptoError::RsaSetPropertyError);
                    }
                    // Ownership transferred to OpenSSL on success; do not free.
                }
            }
        }
        Ok(())
    }
}
