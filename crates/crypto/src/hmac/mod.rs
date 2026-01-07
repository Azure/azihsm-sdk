// Copyright (C) Microsoft Corporation. All rights reserved.

//! HMAC (Hash-based Message Authentication Code) implementation.
//!
//! This module provides a comprehensive interface for HMAC operations including
//! key generation, message authentication, and verification. HMAC combines a
//! cryptographic hash function with a secret key to provide both data integrity
//! and authentication.
//!
//! # Supported Hash Functions
//!
//! - **SHA-1**: Legacy hash function (use with caution in security-critical applications)
//! - **SHA-256**: Recommended for most applications
//! - **SHA-384**: High security applications requiring larger output
//! - **SHA-512**: Maximum security applications
//!
//! # Key Operations
//!
//! The module supports both key generation from random data and key derivation
//! from existing byte arrays. Keys are wrapped in a type-safe container that
//! prevents misuse across different HMAC algorithms.
//!
//! # Authentication Modes
//!
//! ## One-shot Operations
//! For complete data available in memory, providing efficient single-call
//! authentication and verification.
//!
//! ## Streaming Operations  
//! For large datasets or data arriving in chunks, maintaining internal state
//! across multiple update operations.
//!
//! # Platform Support
//!
//! - **Linux**: Uses OpenSSL implementations for optimal performance
//! - **Windows**: Platform-specific implementation (future)
//!
//! # Security Considerations
//!
//! - Keys should be generated using cryptographically secure random data
//! - Key sizes should match or exceed the hash function's output size
//! - Constant-time verification is used to prevent timing attacks
//! - Keys are securely handled and zeroized when dropped

use super::*;

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod key_ossl;
        mod hmac_ossl;
    } else if #[cfg(target_os = "windows")] {
        mod key_cng;
        mod hmac_cng;
    } else {
        compile_error!("Unsupported target OS for AES-CBC implementation");
    }
}

define_type!(pub HmacKey, key_ossl::OsslHmacKey, key_cng::CngHmacKey);
define_type!(pub HmacAlgo, hmac_ossl::OsslHmacAlgo, hmac_cng::CngHmacAlgo);
define_type!(pub HmacAlgoSignContext<'a>, hmac_ossl::OsslHmacAlgoSignContext<'a>, hmac_cng::CngHmacAlgoSignContext);
define_type!(pub HmacAlgoVerifyContext<'a>, hmac_ossl::OsslHmacAlgoVerifyContext<'a>, hmac_cng::CngHmacAlgoVerifyContext);

#[cfg(test)]
mod tests;
