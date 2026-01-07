// Copyright (C) Microsoft Corporation. All rights reserved.

//! High-level cryptographic operation wrappers.
//!
//! This module provides unified, high-level interfaces for common cryptographic
//! operations. Each wrapper consolidates algorithm-specific implementations behind
//! a consistent API, simplifying usage and reducing boilerplate code.
//!
//! # Operation Types
//!
//! - [`hasher`]: Hash computation (one-shot and streaming)
//! - [`encrypter`]: Encryption operations (one-shot and streaming)
//! - [`decrypter`]: Decryption operations (one-shot and streaming)
//! - [`signer`]: Digital signature creation (one-shot and streaming)
//! - [`verifier`]: Digital signature verification (one-shot and streaming)
//!
//! # Design Philosophy
//!
//! The operation wrappers in this module:
//!
//! - Abstract over algorithm-specific implementations
//! - Provide both one-shot and streaming APIs where applicable
//! - Use consistent method naming and parameter patterns
//! - Support buffer size queries before actual operations
//! - Include convenience methods that return owned `Vec<u8>` results
//!
//! # Usage Patterns
//!
//! ## One-Shot Operations
//!
//! For complete data available in memory, use direct methods that
//! process everything in a single call.
//!
//! ## Streaming Operations
//!
//! For large data or data arriving in chunks:
//! 1. Initialize a context with an `_init` method
//! 2. Process chunks with `update` calls
//! 3. Finalize with `finish` to produce the result
//!
//! ## Buffer Management
//!
//! All operations support two buffer patterns:
//! - Pass `None` to query required buffer size
//! - Pass `Some(buffer)` to perform the actual operation
//!
//! # Thread Safety
//!
//! Operation contexts are not thread-safe. Each context should be used
//! from a single thread. For concurrent operations, create separate contexts.
mod hasher;

mod decrypter;
mod encrypter;

mod signer;
mod verifier;

mod unwrapper;
mod wrapper;

mod deriver;

mod decoder;
mod encoder;

pub use decoder::*;
pub use decrypter::*;
pub use deriver::*;
pub use encoder::*;
pub use encrypter::*;
pub use hasher::*;
pub use signer::*;
pub use unwrapper::*;
pub use verifier::*;
pub use wrapper::*;

use super::*;
