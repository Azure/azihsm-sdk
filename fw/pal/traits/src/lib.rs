// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(async_fn_in_trait)]

mod cert;
mod crypto;
mod error;
mod gdma;
mod io;
mod pal;
mod part;
mod session;
mod vault;

pub use cert::*;
pub use crypto::*;
pub use error::*;
pub use gdma::*;
pub use io::*;
pub use pal::*;
pub use part::*;
pub use session::*;
pub use vault::*;

/// Partition identifier — a `u8` index into the HSM's partition table.
///
/// Used to select which partition a session or key belongs to.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HsmPartId(u8);

/// Key identifier — a `u16` index into the vault's key table.
///
/// Returned by [`HsmVault::vault_key_create`] and used by all
/// subsequent key operations.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HsmKeyId(u16);

/// Session identifier — a `u16` index into the HSM's session table.
///
/// Returned by [`HsmSession::session_create`] and used by all
/// subsequent session operations.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HsmSessId(u16);
