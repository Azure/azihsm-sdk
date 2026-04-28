// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform Abstraction Layer (PAL) trait definitions for the Azure
//! Integrated HSM firmware.
//!
//! This crate is the **central contract** between the platform-agnostic
//! HSM core (`azihsm_fw_hsm_core`) and platform-specific implementations
//! (e.g., `azihsm_fw_hsm_pal_std` for host-native simulation,
//! `azihsm_fw_hsm_pal_ocelot` for hardware).  It is `#![no_std]` and
//! has zero external dependencies beyond `open_enum`, so it compiles on
//! bare-metal targets.
//!
//! # Trait hierarchy
//!
//! The root trait is [`HsmPal`], a supertrait that bundles all required
//! capabilities:
//!
//! ```text
//! HsmPal
//!  ├── HsmIoController      — I/O submission and completion
//!  ├── HsmGdmaController    — host↔device memory copies
//!  ├── HsmPartitionManager  — partition lifecycle
//!  ├── HsmCertStore         — per-partition certificate chains
//!  ├── HsmSessionManager    — session allocation and state
//!  ├── HsmVault             — key storage and metadata
//!  └── HsmCrypto            — cryptographic operations
//!       ├── HsmRng          — random number generation
//!       ├── HsmHash         — SHA digest
//!       ├── HsmHmac         — HMAC sign/verify
//!       ├── HsmAes          — AES encrypt/decrypt
//!       ├── HsmEcc          — ECC keygen/sign/verify/ECDH
//!       ├── HsmRsa          — RSA keygen/mod_exp
//!       └── HsmKdf          — HKDF and KBKDF key derivation
//! ```
//!
//! # Identifier newtypes
//!
//! Three lightweight newtypes — [`HsmPartId`], [`HsmKeyId`], and
//! [`HsmSessId`] — prevent accidental mixing of partition, key, and
//! session indices.  Each wraps a small integer and provides
//! zero-cost [`From`] / [`Into`] conversions.
//!
//! # Error model
//!
//! All fallible operations return [`HsmResult<T>`], which is
//! `Result<T, HsmError>`.  [`HsmError`] is an [`open_enum`] over `u32`
//! with ~200 named variants covering DDI-level, PAL-level, and
//! cryptographic error codes.

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

/// Partition identifier — an opaque `u8` index into the HSM's partition
/// table.
///
/// Each HSM supports a fixed number of partitions (typically 65).  A
/// `HsmPartId` uniquely selects one partition for session, vault, and
/// certificate operations.
///
/// # Conversions
///
/// ```
/// # use azihsm_fw_hsm_pal_traits::HsmPartId;
/// let pid = HsmPartId::from(3u8);
/// assert_eq!(u8::from(pid), 3);
/// ```
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HsmPartId(u8);

impl From<u8> for HsmPartId {
    /// Create a partition identifier from a raw `u8` index.
    #[inline]
    fn from(v: u8) -> Self {
        Self(v)
    }
}

impl From<HsmPartId> for u8 {
    /// Extract the raw `u8` index from a partition identifier.
    #[inline]
    fn from(id: HsmPartId) -> Self {
        id.0
    }
}

/// Key identifier — an opaque `u16` index into the vault's key table.
///
/// Returned by [`HsmVault::vault_key_create`] and passed to all
/// subsequent key operations (load, delete, attribute queries).  The
/// value is only meaningful within the vault that created it.
///
/// # Conversions
///
/// ```
/// # use azihsm_fw_hsm_pal_traits::HsmKeyId;
/// let kid = HsmKeyId::from(42u16);
/// assert_eq!(u16::from(kid), 42);
/// ```
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HsmKeyId(u16);

impl From<u16> for HsmKeyId {
    /// Create a key identifier from a raw `u16` index.
    #[inline]
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl From<HsmKeyId> for u16 {
    /// Extract the raw `u16` index from a key identifier.
    #[inline]
    fn from(id: HsmKeyId) -> Self {
        id.0
    }
}

/// Session identifier — an opaque `u16` slot index into the per-partition
/// session table.
///
/// Returned by [`HsmSessionManager::session_create`] and used by all
/// subsequent session operations (state query, deletion).  A session ID
/// is only valid within the partition that allocated it.
///
/// In the standard PAL, slot indices range from 0 to 7 (8 sessions per
/// partition).
///
/// # Conversions
///
/// ```
/// # use azihsm_fw_hsm_pal_traits::HsmSessId;
/// let sid = HsmSessId::from(5u16);
/// assert_eq!(u16::from(sid), 5);
/// ```
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HsmSessId(u16);

impl From<u16> for HsmSessId {
    /// Create a session identifier from a raw `u16` slot index.
    #[inline]
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl From<HsmSessId> for u16 {
    /// Extract the raw `u16` slot index from a session identifier.
    #[inline]
    fn from(id: HsmSessId) -> Self {
        id.0
    }
}
