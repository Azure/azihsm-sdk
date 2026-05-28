// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform Abstraction Layer (PAL) trait definitions for the Azure
//! Integrated HSM firmware.
//!
//! This crate is the **central contract** between the platform-agnostic
//! HSM core (`azihsm_fw_hsm_core`) and platform-specific implementations
//! (e.g. `azihsm_fw_hsm_pal_std` for host-native simulation,
//! `azihsm_fw_hsm_pal_ocelot` for hardware).  It is `#![no_std]` and
//! has no external dependencies beyond `open_enum`, so it compiles on
//! bare-metal targets.
//!
//! # Trait hierarchy
//!
//! The root trait is [`HsmPal`], a supertrait that bundles all required
//! capabilities:
//!
//! ```text
//! HsmPal
//!  ├── HsmAlloc            — per-IO bump-allocator scopes (DTCM and DMA SRAM)
//!  ├── HsmIoController     — I/O submission and completion
//!  ├── HsmGdmaController   — host↔device memory copies
//!  ├── HsmPartitionManager — partition lifecycle
//!  ├── HsmPartitionLock    — per-partition async mutex
//!  ├── HsmCertStore        — per-partition certificate chains
//!  ├── HsmSessionManager   — session allocation and state
//!  ├── HsmVault            — key storage and metadata
//!  └── HsmCrypto           — cryptographic operations
//!       ├── HsmRng         — random number generation
//!       ├── HsmHash        — SHA digest
//!       ├── HsmHmac        — HMAC sign/verify
//!       ├── HsmAes         — AES encrypt/decrypt
//!       ├── HsmEcc         — ECC keygen/sign/verify/ECDH
//!       ├── HsmRsa         — RSA keygen/mod_exp
//!       └── HsmKdf         — HKDF and KBKDF key derivation
//! ```
//!
//! # Identifier newtypes
//!
//! Three lightweight newtypes — [`HsmPartId`], [`HsmKeyId`], and
//! [`HsmSessId`] — prevent accidental mixing of partition, key, and
//! session indices.  Each wraps a small integer, is
//! `#[repr(transparent)]`, and provides zero-cost [`From`] / [`Into`]
//! conversions to/from its underlying primitive.
//!
//! # Error model
//!
//! All fallible operations return [`HsmResult<T>`], which is a type
//! alias for `Result<T, HsmError>`.  [`HsmError`] is an
//! [`open_enum`] over `u32` with ~200 named variants covering
//! DDI-level, PAL-level, and cryptographic error codes; the numeric
//! values are wire-stable and reused as DDI status codes on the host
//! protocol.
//!
//! # Conventions
//!
//! The following conventions are used uniformly across all PAL
//! sub-traits in this crate:
//!
//! ## `&self` + interior mutability
//!
//! Every method takes `&self`.  PAL implementations are expected to
//! use plain `Cell`/`RefCell` (or static `UnsafeCell`-backed slots)
//! for shared state — the firmware is single-core and cooperatively
//! scheduled, so there are no atomics and no `&mut self` requirement.
//!
//! ## Implicit partition scoping via `HsmIo`
//!
//! Methods that operate on partition-scoped state (sessions, vault
//! keys, certificate chains, partition metadata) take an
//! `&impl HsmIo` handle rather than an explicit [`HsmPartId`].  The
//! partition is resolved internally via [`HsmIo::pid`].  This makes
//! cross-partition access impossible by construction and keeps the
//! call sites uniform.
//!
//! ## Query/copy pattern for variable-length output
//!
//! Methods that return raw bytes into a caller buffer accept
//! `out: Option<&mut [u8]>`:
//!
//! - `out = None` — query mode: returns the required size without
//!   copying.
//! - `out = Some(buf)` — copy mode: writes the data into `buf[..size]`
//!   and returns the same `size`.  `buf.len()` must be ≥ `size` or
//!   the call returns [`HsmError::InvalidArg`].
//!
//! ## RAII guards for fallible-creation operations
//!
//! [`HsmVault::vault_key_create`] and
//! [`HsmSessionManager::session_create`] return guards
//! ([`VaultKeyGuard`], [`SessionGuard`]) that auto-rollback on drop
//! and require an explicit `dismiss()` call to commit.  This makes it
//! safe for callers to perform additional fallible work between
//! creation and commit (e.g. encoding the response buffer) without
//! leaking partial state on the error path.

#![no_std]
#![allow(async_fn_in_trait)]

mod alloc;
mod cert;
mod crypto;
mod error;
mod gdma;
mod io;
mod lock;
mod pal;
mod part;
mod session;
mod vault;

pub use alloc::*;

pub use cert::*;
pub use crypto::*;
pub use error::*;
pub use gdma::*;
pub use io::*;
pub use lock::*;
pub use pal::*;
pub use part::*;
pub use session::*;
pub use vault::*;

/// Partition identifier — an opaque `u8` index into the HSM's
/// partition table.
///
/// Each HSM build supports a fixed number of partitions (typically up
/// to 65).  A `HsmPartId` uniquely selects one partition for session,
/// vault, and certificate operations.  Within the firmware, partition
/// IDs are usually obtained indirectly through [`HsmIo::pid`] rather
/// than being constructed directly.
///
/// `#[repr(transparent)]` over `u8` so a slice of `HsmPartId` is
/// layout-compatible with `&[u8]`.
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
    /// Wraps a raw `u8` index into a [`HsmPartId`].
    ///
    /// # Parameters
    ///
    /// - `v` — partition index in `0..HSM_NUM_PARTITIONS`.  Out-of-range
    ///   values are accepted here and rejected later by the trait
    ///   method that consumes them (typically with
    ///   [`HsmError::InvalidArg`]).
    ///
    /// # Returns
    ///
    /// A [`HsmPartId`] wrapping `v`.
    #[inline]
    fn from(v: u8) -> Self {
        Self(v)
    }
}

impl From<HsmPartId> for u8 {
    /// Unwraps a [`HsmPartId`] to its raw `u8` index.
    ///
    /// # Parameters
    ///
    /// - `id` — partition identifier.
    ///
    /// # Returns
    ///
    /// The underlying `u8` slot index.
    #[inline]
    fn from(id: HsmPartId) -> Self {
        id.0
    }
}

/// Key identifier — an opaque `u16` index into the vault's key table.
///
/// Returned by [`HsmVault::vault_key_create`] (via the
/// [`VaultKeyGuard`] handle) and passed to all subsequent key
/// operations (lookup, delete, attribute queries).  The value is only
/// meaningful within the vault that created it; do not reuse a key
/// ID across partitions.
///
/// `#[repr(transparent)]` over `u16`.
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
    /// Wraps a raw `u16` index into a [`HsmKeyId`].
    ///
    /// # Parameters
    ///
    /// - `v` — vault key-table index.
    ///
    /// # Returns
    ///
    /// A [`HsmKeyId`] wrapping `v`.
    #[inline]
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl From<HsmKeyId> for u16 {
    /// Unwraps a [`HsmKeyId`] to its raw `u16` index.
    ///
    /// # Parameters
    ///
    /// - `id` — key identifier.
    ///
    /// # Returns
    ///
    /// The underlying `u16` table index.
    #[inline]
    fn from(id: HsmKeyId) -> Self {
        id.0
    }
}

/// Session identifier — an opaque `u16` slot index into the
/// per-partition session table.
///
/// Returned by [`HsmSessionManager::session_create`] (via the
/// [`SessionGuard`] handle) and used by all subsequent session
/// operations (state query, deletion).  A session ID is only valid
/// within the partition that allocated it.
///
/// In the standard PAL, slot indices range from 0 to 7 (8 sessions
/// per partition).  Hardware builds may use a different cap.
///
/// `#[repr(transparent)]` over `u16`.
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
    /// Wraps a raw `u16` slot index into a [`HsmSessId`].
    ///
    /// # Parameters
    ///
    /// - `v` — session-table slot index.
    ///
    /// # Returns
    ///
    /// A [`HsmSessId`] wrapping `v`.
    #[inline]
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl From<HsmSessId> for u16 {
    /// Unwraps a [`HsmSessId`] to its raw `u16` slot index.
    ///
    /// # Parameters
    ///
    /// - `id` — session identifier.
    ///
    /// # Returns
    ///
    /// The underlying `u16` slot index.
    #[inline]
    fn from(id: HsmSessId) -> Self {
        id.0
    }
}
