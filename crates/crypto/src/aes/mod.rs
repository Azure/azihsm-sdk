// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES (Advanced Encryption Standard) Cipher Block Chaining (CBC) implementation.
//!
//! This module provides a platform-agnostic interface for AES-CBC encryption and decryption
//! operations. It abstracts over platform-specific implementations (OpenSSL on Linux and
//! Cryptography Next Generation (CNG) on Windows) to provide a unified API for AES-CBC
//! operations.
//!
//! # Features
//!
//! - **Multi-platform support**: Automatically selects the appropriate backend based on the target OS
//! - **Key management**: Supports AES-128, AES-192, and AES-256 key sizes
//! - **Flexible encryption/decryption**: Supports both padded (PKCS#7) and unpadded operations
//! - **Memory-safe operations**: All operations are performed through safe Rust interfaces
//!
//! # Architecture
//!
//! The module is structured around several key traits:
//!
//! - [`AesKeyOp`]: Defines basic key operations (size, access to key bytes)
//! - [`AesCbcOp`]: Defines encryption/decryption operations
//! - [`AesCbcKeyGenOp`]: Defines key generation and creation from raw bytes
//!
//! # Platform Implementations
//!
//! - **Linux**: Uses OpenSSL via the `aes_cbc_ossl` module
//! - **Windows**: Uses Windows CNG via the `aes_cbc_cng` module
//!
//! # Security Considerations
//!
//! - Always use a cryptographically secure random number generator for IVs
//! - Never reuse the same key-IV pair for different plaintexts
//! - Consider using authenticated encryption modes (like AES-GCM) for new applications
//! - Ensure proper key management and storage practices

mod block;

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod key_ossl;
        mod ecb_ossl;
        mod cbc_ossl;
        mod xts_ossl;
        mod gcm_ossl;
    } else if #[cfg(target_os = "windows")] {
        mod key_cng;
        mod ecb_cng;
        mod cbc_cng;
        mod xts_cng;
        mod gcm_cng;

    } else {
        compile_error!("Unsupported target OS for AES-CBC implementation");
    }
}

mod kw;
mod kwp;

use block::*;
pub use kw::AesKeyWrapAlgo;
pub use kwp::AesKeyWrapPadAlgo;

pub(crate) use super::*;

define_type!(pub AesKey, key_ossl::OsslAesKey, key_cng::CngAesKey);
define_type!(pub AesXtsKey, key_ossl::OsslAesXtsKey, key_cng::CngAesXtsKey);
define_type!(pub AesCbcAlgo, cbc_ossl::OsslAesCbcAlgo, cbc_cng::CngAesCbcAlgo);
define_type!(pub AesEcbAlgo, ecb_ossl::OsslAesEcbAlgo, ecb_cng::CngAesEcbAlgo);
define_type!(pub AesXtsAlgo, xts_ossl::OsslAesXtsAlgo, xts_cng::CngAesXtsAlgo);
define_type!(pub AesGcmAlgo, gcm_ossl::OsslAesGcmAlgo, gcm_cng::CngAesGcmAlgo);

/// Test module for AES-CBC functionality.
///
/// Contains comprehensive tests for:
/// - Key generation and creation
/// - Encryption and decryption operations
/// - Streaming operations with contexts
/// - Edge cases and error conditions
/// - Cross-platform compatibility
#[cfg(test)]
mod tests;
