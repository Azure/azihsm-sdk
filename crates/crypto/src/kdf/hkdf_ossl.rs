// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based HKDF implementation for Linux systems.
//!
//! This module provides concrete implementations of HKDF (HMAC-based Key Derivation Function)
//! operations using the OpenSSL cryptographic library. It serves as the Linux-specific backend
//! for the platform-agnostic HKDF interface defined in the parent module.
//!
//! # HKDF Overview
//!
//! HKDF is a key derivation function specified in RFC 5869 that extracts and expands
//! key material. It consists of two phases:
//!
//! - **Extract**: Derives a pseudorandom key (PRK) from input keying material (IKM) and salt
//! - **Expand**: Expands the PRK into multiple output keys using optional context information
//!
//! # Supported Modes
//!
//! - **ExtractAndExpand**: Full HKDF operation (Extract → Expand)
//! - **Extract**: Only performs Extract phase, outputs PRK
//! - **Expand**: Only performs Expand phase, requires PRK as input
//!
//! # Supported Hash Algorithms
//!
//! - **HMAC-SHA1**: Legacy algorithm (20-byte PRK, use with caution)
//! - **HMAC-SHA256**: Recommended for most applications (32-byte PRK)
//! - **HMAC-SHA384**: High security applications (48-byte PRK)
//! - **HMAC-SHA512**: Maximum security applications (64-byte PRK)
//!
//! # Platform Integration
//!
//! - Leverages OpenSSL's optimized HKDF implementations
//! - Uses system-provided OpenSSL for security updates
//! - Provides memory-safe Rust wrappers around OpenSSL APIs
//! - Zero-copy design using slice references

use openssl::md::*;

use super::*;

/// OpenSSL-backed HKDF operation provider.
///
/// This structure configures and executes HKDF (HMAC-based Key Derivation Function)
/// operations using OpenSSL's cryptographic primitives. It supports Extract-only,
/// Expand-only, and full Extract-then-Expand modes as specified in RFC 5869.
///
/// # Lifetime Parameters
///
/// The `'a` lifetime ensures that all borrowed data (hash reference, salt, info)
/// remains valid for the duration of the HKDF operation. This enables zero-copy
/// operation without heap allocations for these parameters.
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync` as it only stores configuration data.
/// Actual cryptographic operations are performed through OpenSSL APIs.
///
/// # Security
///
/// - Uses OpenSSL's HKDF implementation following RFC 5869
/// - Supports proper salt usage in Extract phase
/// - Allows context binding through info parameter in Expand phase
pub struct OsslHkdfAlgo<'a> {
    /// Message digest context for OpenSSL
    md: &'a MdRef,
    /// HKDF derivation mode
    mode: HkdfMode,
    /// Optional salt for extract phase
    salt: Option<&'a [u8]>,
    /// Optional info for expand phase
    info: Option<&'a [u8]>,
}

impl<'a> OsslHkdfAlgo<'a> {
    /// Creates a new HKDF operation provider from a hash instance.
    ///
    /// This constructor configures the HKDF provider but does not perform any
    /// cryptographic operations. Actual key derivation occurs when calling
    /// the `derive()` method.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash instance specifying the algorithm to use for HKDF
    /// * `mode` - The HKDF mode (Extract, Expand, or ExtractAndExpand)
    /// * `salt` - Optional salt for Extract phase (recommended for Extract modes)
    /// * `info` - Optional context/application-specific info for Expand phase
    /// * `derived_length` - Desired output length (defaults to hash output size)
    ///
    /// # Returns
    ///
    /// A new `OsslHkdf` instance configured for the specified parameters.
    pub fn new(
        mode: HkdfMode,
        hash: &'a HashAlgo,
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Self {
        Self {
            md: hash.md(),
            mode,
            salt,
            info,
        }
    }
}

/// Converts platform-agnostic HKDF mode to OpenSSL-specific mode constant.
///
/// This conversion enables the platform-agnostic HKDF interface to map
/// to OpenSSL's specific mode enumeration for HKDF operations.
impl From<HkdfMode> for openssl::pkey_ctx::HkdfMode {
    fn from(mode: HkdfMode) -> Self {
        match mode {
            HkdfMode::Extract => openssl::pkey_ctx::HkdfMode::EXTRACT_ONLY,
            HkdfMode::ExtractAndExpand => openssl::pkey_ctx::HkdfMode::EXTRACT_THEN_EXPAND,
            HkdfMode::Expand => openssl::pkey_ctx::HkdfMode::EXPAND_ONLY,
        }
    }
}

/// Implements HKDF key derivation operation.
///
/// This implementation uses OpenSSL's HKDF functionality to derive key material
/// according to RFC 5869 specification. It supports all three derivation modes
/// and handles the complete lifecycle of the derivation operation.
impl<'a> DeriveOp for OsslHkdfAlgo<'a> {
    type Key = GenericSecretKey;
    type DerivedKey = GenericSecretKey;

    /// Derives key material using the HKDF algorithm.
    ///
    /// Depending on the configured mode, this performs:
    /// - **Extract**: HMAC-Extract(salt, IKM) → PRK
    /// - **Expand**: HKDF-Expand(PRK, info, L) → OKM
    /// - **ExtractAndExpand**: Extract followed by Expand
    ///
    /// # Arguments
    ///
    /// * `key` - Input key material (IKM) for Extract modes, or PRK for Expand mode
    ///
    /// # Returns
    ///
    /// The derived key material as a `GenericSecretKey`:
    /// - For Extract: Pseudorandom key (PRK) of hash output size
    /// - For Expand/ExtractAndExpand: Output key material (OKM) of requested length
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::HkdfError` - HKDF context creation fails
    /// - `CryptoError::HkdfInitError` - HKDF property setting or key setting fails
    /// - `CryptoError::HkdfDeriveError` - HKDF derivation operation fails
    /// - `CryptoError::InvalidKeySize` - Key material extraction fails
    fn derive(&self, key: &Self::Key, derive_len: usize) -> Result<Self::DerivedKey, CryptoError> {
        // Extract key bytes
        let key_bytes = key.to_vec()?;

        // Create and configure HKDF context
        let mut ctx = openssl::pkey_ctx::PkeyCtx::new_id(openssl::pkey::Id::HKDF)
            .map_err(|_| CryptoError::HkdfError)?;
        self.configure_pkey_ctx(&mut ctx)?;

        // Set input keying material
        ctx.set_hkdf_key(&key_bytes)
            .map_err(|_| CryptoError::HkdfSetPropertyError)?;

        // Derive the key
        let mut derived_key = vec![0u8; derive_len];
        let derived_size = ctx
            .derive(Some(&mut derived_key))
            .map_err(|_| CryptoError::HkdfDeriveError)?;

        // Return only the actual derived bytes
        GenericSecretKey::from_bytes(&derived_key[..derived_size])
    }
}

impl<'a> OsslHkdfAlgo<'a> {
    /// Configures OpenSSL PkeyCtx with HKDF parameters.
    ///
    /// This method sets up the OpenSSL context with the hash algorithm, salt,
    /// and info parameters required for HKDF derivation. The initialization
    /// sequence is critical: `derive_init()` must be called before setting
    /// any HKDF-specific parameters.
    ///
    /// # Arguments
    ///
    /// * `pkey_ctx` - The OpenSSL public key context to configure
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful configuration.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HkdfInitError` if any OpenSSL property setting fails.
    fn configure_pkey_ctx<T>(
        &self,
        pkey_ctx: &mut openssl::pkey_ctx::PkeyCtx<T>,
    ) -> Result<(), CryptoError> {
        // Call derive_init() BEFORE setting any HKDF parameters
        pkey_ctx
            .derive_init()
            .map_err(|_| CryptoError::HkdfSetPropertyError)?;

        // Set message digest
        pkey_ctx
            .set_hkdf_md(self.md)
            .map_err(|_| CryptoError::HkdfSetPropertyError)?;

        // Set HKDF mode
        pkey_ctx
            .set_hkdf_mode(self.mode.into())
            .map_err(|_| CryptoError::HkdfSetPropertyError)?;
        // Set salt if provided
        if let Some(salt) = self.salt {
            pkey_ctx
                .set_hkdf_salt(salt)
                .map_err(|_| CryptoError::HkdfSetPropertyError)?;
        }

        // Set info if provided
        if let Some(info) = self.info {
            pkey_ctx
                .add_hkdf_info(info)
                .map_err(|_| CryptoError::HkdfSetPropertyError)?;
        }

        Ok(())
    }
}
