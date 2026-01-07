// Copyright (C) Microsoft Corporation. All rights reserved.

//! Core cryptographic operation traits.
//!
//! This module defines the fundamental trait interfaces for cryptographic operations
//! throughout the library. These traits provide abstraction over algorithm-specific
//! implementations, enabling generic programming and consistent APIs.
//!
//! # Trait Categories
//!
//! ## Key Management Traits
//!
//! - [`key`]: Core key traits and markers (Key, SecretKey, PrivateKey, PublicKey)
//! - [`key_gen`]: Key generation operations
//!
//! ## Cryptographic Operation Traits
//!
//! - [`encryption`]: Encryption and decryption operations
//! - [`hashing`]: Hash computation operations
//! - [`signing`]: Digital signature creation and verification
//! - [`derivation`]: Key derivation operations
//! - [`wrapping`]: Key wrapping and unwrapping operations
//!
//! # Design Principles
//!
//! ## Marker Traits
//!
//! Marker traits like `SecretKey`, `PrivateKey`, and `PublicKey` provide
//! type-level guarantees about key usage, preventing misuse at compile time.
//!
//! ## Operation Traits
//!
//! Operation traits follow consistent patterns:
//! - Single-operation traits for one-shot processing
//! - Streaming operation traits for incremental processing
//! - Context traits for maintaining operation state
//!
//! ## Buffer Patterns
//!
//! Most operations use an optional buffer pattern:
//! - `None`: Query required buffer size
//! - `Some(buffer)`: Perform actual operation
//!
//! This enables efficient memory management and pre-allocation.
//!
//! # Trait Relationships
//!
//! Traits are organized hierarchically:
//! - Base marker traits (Key, SymmetricKey, etc.)
//! - Operation-specific traits building on markers
//! - Streaming context traits for stateful operations
//!
//! # Implementation Guidelines
//!
//! When implementing these traits:
//! - Follow the documented error conditions precisely
//! - Maintain consistent behavior across platforms
//! - Use platform-optimized implementations when available
//! - Ensure thread-safety where documented
//! - Clear sensitive data from memory when appropriate
mod derivation;
mod encoding;
mod encryption;
mod hashing;
mod key;
mod signing;
mod wrapping;

pub use derivation::*;
pub use encoding::*;
pub use encryption::*;
pub use hashing::*;
pub use key::*;
pub use signing::*;
pub use wrapping::*;

use super::*;
