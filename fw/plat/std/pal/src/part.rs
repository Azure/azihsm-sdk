// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition management for the standard (host-native) PAL.
//!
//! Implements the [`HsmPartitionManager`] trait from
//! `azihsm_fw_hsm_pal_traits` for [`StdHsmPal`] and provides sideband
//! partition allocation/deallocation via [`PartCommand`].
//!
//! ## Architecture
//!
//! The partition table lives on the Embassy thread inside [`StdHsmPal`],
//! stored in an [`UnsafeCell`] to allow the `&self` trait methods to
//! return borrowed slices tied to the PAL's lifetime. This is safe
//! because the Embassy executor is single-threaded — no concurrent
//! access is possible.
//!
//! Sideband commands ([`PartCommand::Alloc`] / [`PartCommand::Free`])
//! arrive from the user-facing [`StdHsm`] via an `async_channel` and
//! are processed by a dedicated Embassy task. These commands mutate
//! the partition table through [`part_alloc_internal`] and
//! [`part_free_internal`], which obtain `&mut` access through the
//! `UnsafeCell`. Because Embassy tasks only interleave at `.await`
//! points and the trait read methods are synchronous, no aliasing
//! violations can occur.
//!
//! ## Partition lifecycle
//!
//! ```text
//! Disabled ──► part_alloc ──► Uninitialized ──► (future: Initialized)
//!    ▲                              │
//!    └────────── part_free ─────────┘
//! ```
//!
//! ## Resource budget
//!
//! The total `res_count` across all allocated partitions must not exceed
//! [`MAX_RESOURCES`] (65). Each allocation request is checked against
//! the current sum.
//!
//! [`StdHsm`]: azihsm_fw_hsm_std::StdHsm
//! [`part_alloc_internal`]: StdHsmPal::part_alloc_internal
//! [`part_free_internal`]: StdHsmPal::part_free_internal

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::Rng;

use super::*;
use crate::cert::MAX_CERT_DER_LEN;

/// Total number of partitions supported by the HSM.
pub const NUM_PARTITIONS: usize = 65;

/// Maximum total resources across all partitions.
pub const MAX_RESOURCES: u8 = 65;

/// Length of a partition's random identity blob in bytes.
const PART_ID_LEN: usize = 16;

/// Size of a single P-384 coordinate (x or y) in bytes.
const P384_COORD_SIZE: usize = 48;

/// Size of the raw public key (x ∥ y) in bytes.
pub(crate) const P384_PUB_KEY_LEN: usize = P384_COORD_SIZE * 2;

/// Maximum size of a PKCS#8 DER-encoded P-384 private key.
const P384_PRIV_KEY_DER_MAX: usize = 256;

/// A single partition's state and cryptographic material.
///
/// All fields use fixed-size inline storage to avoid heap allocations
/// and simplify the lifetime model for borrowed trait returns.
pub(crate) struct PartitionEntry {
    /// Current lifecycle state.
    pub(crate) state: PartState,

    /// Number of resources allocated to this partition.
    res_count: u8,

    /// 16-byte random identity blob, generated on allocation.
    id: [u8; PART_ID_LEN],

    /// Raw ECC P-384 public key (x ∥ y coordinates, 96 bytes).
    pub(crate) pub_key: [u8; P384_PUB_KEY_LEN],

    /// PKCS#8 DER-encoded ECC P-384 private key.
    priv_key_der: [u8; P384_PRIV_KEY_DER_MAX],

    /// Actual length of valid data in `priv_key_der`.
    priv_key_len: usize,

    /// Cached DER-encoded partition leaf certificate (lazily generated).
    pub(crate) leaf_cert: [u8; MAX_CERT_DER_LEN],

    /// Length of valid data in `leaf_cert` (0 = not yet generated).
    pub(crate) leaf_cert_len: usize,
}

impl Default for PartitionEntry {
    fn default() -> Self {
        Self {
            state: PartState::Disabled,
            res_count: 0,
            id: [0u8; PART_ID_LEN],
            pub_key: [0u8; P384_PUB_KEY_LEN],
            priv_key_der: [0u8; P384_PRIV_KEY_DER_MAX],
            priv_key_len: 0,
            leaf_cert: [0u8; MAX_CERT_DER_LEN],
            leaf_cert_len: 0,
        }
    }
}

/// Table of all partition entries.
///
/// Stored in an [`UnsafeCell`] on [`StdHsmPal`] so that `&self` trait
/// methods can return borrowed slices into the entries.
pub(crate) struct PartitionTable {
    /// Fixed array of partition entries indexed by `pid`.
    ///
    /// Boxed to avoid 155KB+ on the stack during construction and moves.
    pub(crate) entries: Box<[PartitionEntry; NUM_PARTITIONS]>,
}

impl Default for PartitionTable {
    fn default() -> Self {
        Self {
            entries: Box::new(core::array::from_fn(|_| PartitionEntry::default())),
        }
    }
}

/// A sideband command sent from [`StdHsm`] to the Embassy thread for
/// partition allocation or deallocation.
///
/// Each command carries a oneshot reply channel so the caller can
/// `await` the result.
///
/// [`StdHsm`]: azihsm_fw_hsm_std::StdHsm
pub enum PartCommand {
    /// Allocate a partition: generate a random ID and ECC-384 key pair,
    /// assign resources, and transition from `Disabled` to `Uninitialized`.
    Alloc {
        /// Partition index (must be < [`NUM_PARTITIONS`]).
        pid: u8,
        /// Number of resources to allocate.
        res_count: u8,
        /// Oneshot channel for the allocation result.
        reply: tokio::sync::oneshot::Sender<HsmResult<()>>,
    },

    /// Free a partition: zeroize all cryptographic material, release
    /// resources, and transition back to `Disabled`.
    Free {
        /// Partition index (must be < [`NUM_PARTITIONS`]).
        pid: u8,
        /// Oneshot channel for the free result.
        reply: tokio::sync::oneshot::Sender<HsmResult<()>>,
    },
}

// ---------------------------------------------------------------------------
// HsmPartitionManager trait implementation (read-only, called by core)
// ---------------------------------------------------------------------------

impl HsmPartitionManager for StdHsmPal {
    /// Returns the current state of the partition at index `pid`.
    ///
    /// # Errors
    ///
    /// Returns [`PART_INVALID_PID`] if `pid >= NUM_PARTITIONS`.
    fn part_state(&self, pid: u8) -> HsmResult<PartState> {
        // SAFETY: Embassy is single-threaded. This synchronous method
        // completes without yielding, so no concurrent mutation occurs.
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(PART_INVALID_PID);
        }
        Ok(table.entries[idx].state)
    }

    /// Returns the resource count allocated to the partition at `pid`.
    ///
    /// # Errors
    ///
    /// - [`PART_INVALID_PID`] if `pid >= NUM_PARTITIONS`.
    /// - [`PART_NOT_ALLOCATED`] if the partition is [`Disabled`](PartState::Disabled).
    fn part_res_count(&self, pid: u8) -> HsmResult<u8> {
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(PART_INVALID_PID);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Disabled {
            return Err(PART_NOT_ALLOCATED);
        }
        Ok(entry.res_count)
    }

    /// Returns the 16-byte identity blob for the partition at `pid`.
    ///
    /// # Errors
    ///
    /// - [`PART_INVALID_PID`] if `pid >= NUM_PARTITIONS`.
    /// - [`PART_NOT_ALLOCATED`] if the partition is [`Disabled`](PartState::Disabled).
    fn part_id(&self, pid: u8) -> HsmResult<PartId<'_>> {
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(PART_INVALID_PID);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Disabled {
            return Err(PART_NOT_ALLOCATED);
        }
        Ok(&entry.id)
    }

    /// Returns the identity key pair (public, private) for `pid`.
    ///
    /// The public key is the raw x ∥ y coordinates (96 bytes for P-384).
    /// The private key is PKCS#8 DER-encoded.
    ///
    /// # Errors
    ///
    /// - [`PART_INVALID_PID`] if `pid >= NUM_PARTITIONS`.
    /// - [`PART_NOT_ALLOCATED`] if the partition is [`Disabled`](PartState::Disabled).
    fn part_id_key(&self, pid: u8) -> HsmResult<PartIdKey<'_>> {
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(PART_INVALID_PID);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Disabled {
            return Err(PART_NOT_ALLOCATED);
        }
        Ok((&entry.pub_key, &entry.priv_key_der[..entry.priv_key_len]))
    }
}

// ---------------------------------------------------------------------------
// Internal partition alloc / free (called by part_cmd_task on Embassy thread)
// ---------------------------------------------------------------------------

impl StdHsmPal {
    /// Allocate a partition: generate identity and ECC-384 key pair.
    ///
    /// # Preconditions
    ///
    /// - `pid < NUM_PARTITIONS`
    /// - Partition must be in [`Disabled`](PartState::Disabled) state.
    /// - `sum(res_count) + res_count <= MAX_RESOURCES`
    ///
    /// On success the partition transitions to [`Uninitialized`](PartState::Uninitialized).
    ///
    /// # Safety invariant
    ///
    /// Must only be called from the Embassy thread (single-threaded executor).
    /// No trait read borrows can be alive across the `.await` boundary that
    /// delivers the [`PartCommand`] to this method.
    pub fn part_alloc_internal(&self, pid: u8, res_count: u8) -> HsmResult<()> {
        // SAFETY: Single-threaded Embassy — no concurrent readers.
        let table = unsafe { &mut *self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(PART_INVALID_PID);
        }
        if table.entries[idx].state != PartState::Disabled {
            return Err(PART_ALREADY_ALLOCATED);
        }

        // Check resource budget before mutating.
        let total: u16 = table.entries.iter().map(|e| e.res_count as u16).sum();
        if total + res_count as u16 > MAX_RESOURCES as u16 {
            return Err(PART_RESOURCE_EXHAUSTED);
        }

        let entry = &mut table.entries[idx];

        // Generate 16-byte random identity.
        Rng::rand_bytes(&mut entry.id).map_err(|_| RNG_FAILURE)?;

        // Generate ECC P-384 key pair.
        let key = EccPrivateKey::from_curve(EccCurve::P384).map_err(|_| PART_KEY_GEN_FAILURE)?;

        // Export public key coordinates (x ∥ y).
        let (x_buf, y_buf) = entry.pub_key.split_at_mut(P384_COORD_SIZE);
        key.coord(Some((x_buf, y_buf)))
            .map_err(|_| PART_KEY_GEN_FAILURE)?;

        // Export private key as PKCS#8 DER.
        let len = key
            .to_bytes(Some(&mut entry.priv_key_der))
            .map_err(|_| PART_KEY_GEN_FAILURE)?;
        entry.priv_key_len = len;

        entry.res_count = res_count;
        entry.state = PartState::Uninitialized;

        Ok(())
    }

    /// Free a partition: zeroize cryptographic material and release resources.
    ///
    /// # Preconditions
    ///
    /// - `pid < NUM_PARTITIONS`
    /// - Partition must NOT be in [`Disabled`](PartState::Disabled) state.
    ///
    /// On success the partition transitions to [`Disabled`](PartState::Disabled).
    ///
    /// # Safety invariant
    ///
    /// Must only be called from the Embassy thread (single-threaded executor).
    pub fn part_free_internal(&self, pid: u8) -> HsmResult<()> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(PART_INVALID_PID);
        }
        if table.entries[idx].state == PartState::Disabled {
            return Err(PART_NOT_ALLOCATED);
        }

        let entry = &mut table.entries[idx];

        // Zeroize sensitive material.
        entry.id.fill(0);
        entry.pub_key.fill(0);
        entry.priv_key_der[..entry.priv_key_len].fill(0);
        entry.priv_key_len = 0;
        entry.leaf_cert[..entry.leaf_cert_len].fill(0);
        entry.leaf_cert_len = 0;
        entry.res_count = 0;
        entry.state = PartState::Disabled;

        Ok(())
    }
}
