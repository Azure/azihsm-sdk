// Copyright (C) Microsoft Corporation. All rights reserved.

//! HMAC key types and signing/verification algorithms.
//!
//! This module provides HSM-backed HMAC primitives:
//! - [`HsmHmacKey`]: an HSM-managed key handle with associated properties.
//! - [`HsmHmacAlgo`]: single-shot sign/verify.
//! - Streaming sign/verify contexts that buffer input and then delegate to the
//!   single-shot operation.
//!
//! # Limits
//!
//! The underlying DDI request uses a fixed-size MBOR byte array for the message
//! buffer (currently 1024 bytes). The streaming context buffers data in memory
//! and will only succeed if the final message fits within that DDI limit.

mod key;
mod sign;

use super::*;
pub use key::*;
pub use sign::*;
