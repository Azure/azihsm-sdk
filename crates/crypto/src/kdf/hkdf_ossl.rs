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
        let key_bytes = key.to_vec()?;

        let mode = match self.mode {
            HkdfMode::Extract => openssl::kdf::HkdfMode::ExtractOnly,
            HkdfMode::ExtractAndExpand => openssl::kdf::HkdfMode::ExtractAndExpand,
            HkdfMode::Expand => openssl::kdf::HkdfMode::ExpandOnly,
        };
        // Extract-only yields the PRK (exactly one digest block); the expand
        // modes yield the requested length. Reject a mismatched requested
        // length for Extract so behavior matches the Windows (CNG) backend
        // instead of silently ignoring `derive_len`.
        let out_len = match self.mode {
            HkdfMode::Extract => {
                if derive_len != self.md.size() {
                    return Err(CryptoError::HmacInvalidDerivedKeyLength);
                }
                self.md.size()
            }
            _ => derive_len,
        };
        let mut out = vec![0u8; out_len];

        // `kdf::hkdf` fetches "HKDF" and its digest from the crate-private libctx
        // (default-provider only), so the derivation never resolves to the azihsm
        // provider on OpenSSL 3.5. `self.md` only supplies the digest name. See
        // [`crate::libctx`].
        openssl::kdf::hkdf(
            self.md,
            &key_bytes,
            self.salt,
            self.info,
            mode,
            Some(crate::libctx::crypto_libctx()),
            &mut out,
        )
        .map_err(|_| CryptoError::HkdfDeriveError)?;

        GenericSecretKey::from_bytes(&out)
    }
}
