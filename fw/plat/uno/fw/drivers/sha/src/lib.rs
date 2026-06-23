// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(clippy::new_without_default)]
//! Async firmware driver for the SHA cryptographic engine.
//!
//! Supports SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
//! and SHA-512/256.
//! A single SHA hardware command is in flight at a time; concurrent
//! callers are serialized via an async mutex-like semantic embedded
//! in the driver.
//!
//! Firmware populates a 32-byte command descriptor in DTCM and writes
//! its address into `COMMAND`. The hardware fetches the message and
//! optional digest state via DMA, performs the transform, and posts
//! completion status. An IRQ is asserted whenever any SHA status flag
//! is set; NVIC interrupt enabling is the caller's responsibility.
//!
//! # Example
//!
//! ```ignore
//! use azihsm_fw_hsm_pal_traits::DmaBuf;
//!
//! let sha = static_init!(ShaDriver<32>, ShaDriver::init());
//! let mut message = *b"abc";
//! let mut digest = [0u8; 32];
//! sha.digest(ShaRequest {
//!     mode: ShaMode::Sha256,
//!     message: unsafe { DmaBuf::from_raw(&message) },
//!     digest: unsafe { DmaBuf::from_raw_mut(&mut digest) },
//!     auto_pad: true,
//!     byte_count: 3,
//!     load_digest: false,
//!     initial_digest: None,
//!     dont_truncate: false,
//!     digest_byte_swap: false,
//!     check_digest: false,
//!     ref_digest: None,
//! }).await?;
//! ```

mod api;
mod error;

pub use api::*;
pub use error::*;
