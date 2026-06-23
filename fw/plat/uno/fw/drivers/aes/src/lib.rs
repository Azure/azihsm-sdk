// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(clippy::new_without_default)]
//! Async firmware driver for the AES cryptographic engine.
//!
//! Supports AES-128/192/256 in ECB and CBC modes (encrypt or decrypt).
//! A single AES hardware command is in flight at a time; concurrent
//! callers are serialized via an async mutex-like semantic embedded
//! in the driver.
//!
//! Firmware populates a 24-byte [`AesCommandDesc`] in DTCM and writes
//! its address into `COMMAND`. The hardware fetches key, IV, and
//! message via DMA, performs the transform, and posts completion
//! status (COMPLETE or an error flag). An IRQ is asserted if
//! [`AesDriver::init`] was called with `interrupt=true`.
//!
//! # Example
//!
//! ```ignore
//! let aes = static_init!(AesDriver<32>, AesDriver::init(true));
//! // `key`, `iv`, `plaintext`, and `ciphertext` must live in a
//! // DMA-addressable region (branded as `DmaBuf`).
//! aes.encrypt_decrypt(AesRequest {
//!     mode: AesMode::Cbc,
//!     op: AesOp::Encrypt,
//!     key,
//!     iv: Some(iv),
//!     update_iv: false,
//!     message: plaintext,
//!     result: ciphertext,
//! }).await?;
//! ```

mod api;
mod error;
pub use api::*;
pub use error::*;
