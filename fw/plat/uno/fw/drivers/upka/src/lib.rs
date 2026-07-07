// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(clippy::new_without_default)]
//! Async firmware driver for the PKA public key accelerator.
//!
//! Manages 16 hardware PKA engines as a shared pool. Each engine
//! can execute one ECC or RSA command at a time. The driver distributes
//! work across engines automatically.
//!
//! Three API patterns:
//! - **Convenience methods**: acquire + execute + wipe + release (single call)
//! - **Scoped**: hold a [`UpkaEngine`] in a local alloc, then call [`UpkaEngine::release`]
//! - **Handle**: `acquire_any()` or `acquire_engine()` returns [`UpkaEngine`]

mod api;
mod engine;
mod error;
mod executor;
mod opcode;
mod pool;
mod scheduler;
mod types;

pub use api::*;
pub use engine::*;
pub use error::*;
pub use opcode::hash_size;
pub use opcode::hsm_point_size;
pub use types::*;
