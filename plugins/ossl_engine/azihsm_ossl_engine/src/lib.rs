// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![warn(clippy::cast_possible_truncation)]
#![warn(clippy::arithmetic_side_effects)]

//! Azure Integrated HSM -- OpenSSL 1.1.x Engine. Linux only.

/// File mode for secret material the engine writes (the cached MOBK and the
/// log file): owner read/write only, no group/other. Mirrors the provider's
/// 0600 hardening.
#[cfg(all(target_os = "linux", feature = "engine"))]
pub(crate) const SECRET_FILE_MODE: u32 = 0o600;

// `context` is `pub` so the engine's HSM-open API (EngineData and its
// open_hsm_* methods) is public crate API rather than dead code. The cdylib
// entry point (`bind_helper`) constructs an EngineData and parks it in the
// ENGINE's ex_data.
#[cfg(all(target_os = "linux", feature = "engine"))]
pub mod context;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod logging;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod uri;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod keyload;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod sign;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod keygen;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod derive;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod hkdf;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod asn1;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod engine_impl;

/// Integration-test helpers (masked-key generation). Gated behind `integration`;
/// not part of the production engine.
#[cfg(all(target_os = "linux", feature = "engine", feature = "integration"))]
pub mod integration;
