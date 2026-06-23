// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![warn(clippy::cast_possible_truncation)]
#![warn(clippy::arithmetic_side_effects)]

//! Safe Rust abstractions for building OpenSSL 1.1.x engines.
//! No HSM-specific logic. Linux only.

#[cfg(all(target_os = "linux", feature = "engine"))]
pub mod engine;
#[cfg(all(target_os = "linux", feature = "engine"))]
pub mod error;

pub use openssl_sys_engine as ffi;
