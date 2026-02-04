// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic hash function implementations.
//!
//! This module provides a unified interface for various cryptographic hash functions
//! including SHA-1, SHA-256, SHA-384, and SHA-512. The implementation abstracts over
//! platform-specific backends to provide consistent APIs across different operating systems.
//!
//! # Supported Hash Functions
//!
//! - **SHA-1**: 160-bit hash (deprecated for cryptographic use, provided for compatibility)
//! - **SHA-256**: 256-bit hash from the SHA-2 family
//! - **SHA-384**: 384-bit hash from the SHA-2 family  
//! - **SHA-512**: 512-bit hash from the SHA-2 family
//!
//! # Architecture
//!
//! The module provides two main operation modes:
//!
//! ## One-shot Operations
//!
//! For hashing complete data available in memory.
//!
//! ## Streaming Operations
//!
//! For processing large data or data available in chunks.
//!
//! # Platform Support
//!
//! - **Linux**: Uses OpenSSL implementations for optimal performance and security
//! - **Windows**: Platform-specific implementation (future)
//!
//! # Security Considerations
//!
//! - **SHA-1**: Cryptographically broken, use only for non-security purposes
//! - **SHA-2 family**: Currently secure for cryptographic applications
//! - All implementations use platform-optimized code when available
//! - Hardware acceleration is utilized when supported by the platform

use super::*;

#[cfg(target_os = "linux")]
mod hash_ossl;

#[cfg(target_os = "windows")]
mod hash_cng;

define_type!(pub HashAlgo, hash_ossl::OsslHashAlgo, hash_cng::CngHashAlgo);
define_type!(pub HashAlgoContext, hash_ossl::OsslHashAlgoContext, hash_cng::CngHashAlgoContext);

#[cfg(test)]
mod tests;
