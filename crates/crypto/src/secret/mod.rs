// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generic secret key implementations.
//!
//! This module provides generic implementations of symmetric (secret) keys that
//! can be used across various cryptographic operations. These keys represent raw
//! key material and implement standard key management operations.
//!
//! # Purpose
//!
//! The secret key types in this module serve as building blocks for higher-level
//! cryptographic operations, providing:
//!
//! - Generic containers for symmetric key material
//! - Standard key management operations (generation, import, export)
//! - Type-safe key handling through trait implementations
//! - Platform-agnostic key representation
//!
//! # Use Cases
//!
//! Secret keys from this module are suitable for:
//! - Symmetric encryption algorithms (AES, ChaCha20)
//! - Message authentication codes (HMAC)
//! - Key derivation inputs
//! - Key wrapping and unwrapping operations
//!
//! # Security Considerations
//!
//! - Keys should be generated using cryptographically secure random sources
//! - Key material should be zeroized from memory when no longer needed
//! - Keys should be encrypted before storage or transmission
//! - Access to key material should be restricted and audited
//! - Key lifetime should be limited based on usage and security policy
mod key;

pub use key::*;

use super::*;
