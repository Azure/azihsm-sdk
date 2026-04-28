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
//! ## Resource allocation
//!
//! Each partition is assigned a **resource bitmask** (`u128`) where each
//! set bit represents one vault table (resource).  There are 65 total
//! resources (bits 0..64).  A global bitmask on [`PartitionTable`]
//! tracks which resources are already allocated across all partitions
//! to prevent double-allocation.  `popcount(res_mask)` gives the
//! partition's table count (= what [`part_res_count`] returns).
//!
//! [`StdHsm`]: azihsm_fw_hsm_std::StdHsm
//! [`part_alloc_internal`]: StdHsmPal::part_alloc_internal
//! [`part_free_internal`]: StdHsmPal::part_free_internal

use azihsm_crypto::*;

use super::*;
use crate::cert::MAX_CERT_DER_LEN;
use crate::drivers::session::SessionTable;
use crate::drivers::vault::KeyVault;

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
/// Each partition entry holds all per-partition data in fixed-size
/// inline buffers.  This avoids heap allocations, simplifies the
/// lifetime model for borrowed trait returns, and mirrors the
/// fixed-slot storage model used by the hardware HSM.
///
/// ## Memory layout
///
/// | Field | Size | Description |
/// |-------|------|-------------|
/// | `state` | 1 B | Lifecycle state (`Disabled` / `Uninitialized`) |
/// | `res_mask` | 16 B | Resource bitmask (each bit = one vault table) |
/// | `id` | 16 B | Random identity blob |
/// | `pub_key` | 96 B | Raw P-384 public key (x ∥ y) |
/// | `priv_key_der` | 256 B | PKCS#8 DER-encoded P-384 private key |
/// | `leaf_cert` | 2 KB | Cached DER-encoded partition leaf certificate |
/// | `session_table` | 2 B | Bitmask session allocator |
///
/// ## Zeroization
///
/// When a partition is freed via [`part_free_internal`], all
/// cryptographic material (`id`, `pub_key`, `priv_key_der`,
/// `leaf_cert`) is explicitly zeroed before the state transitions
/// back to `Disabled`.
///
/// [`part_free_internal`]: StdHsmPal::part_free_internal
pub(crate) struct PartitionEntry {
    /// Current lifecycle state.
    pub(crate) state: PartState,

    /// Resource bitmask — each set bit corresponds to one vault table
    /// assigned to this partition.  `count_ones()` gives the table count.
    res_mask: u128,

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

    /// Per-partition session table for tracking allocated sessions.
    pub(crate) session_table: SessionTable,

    /// Per-partition key vault — number of tables determined by
    /// `res_mask.count_ones()` at allocation time.
    pub(crate) vault: KeyVault,
}

impl Default for PartitionEntry {
    fn default() -> Self {
        Self {
            state: PartState::Disabled,
            res_mask: 0,
            id: [0u8; PART_ID_LEN],
            pub_key: [0u8; P384_PUB_KEY_LEN],
            priv_key_der: [0u8; P384_PRIV_KEY_DER_MAX],
            priv_key_len: 0,
            leaf_cert: [0u8; MAX_CERT_DER_LEN],
            leaf_cert_len: 0,
            session_table: SessionTable::new(),
            vault: KeyVault::new(0),
        }
    }
}

/// Table of all partition entries.
///
/// Stored in an [`UnsafeCell`] on [`StdHsmPal`] so that `&self` trait
/// methods can return borrowed slices into the entries.  The table is
/// heap-allocated (boxed) because `NUM_PARTITIONS × sizeof(PartitionEntry)`
/// exceeds 155 KB — too large for the stack during construction and
/// moves.
///
/// # Thread safety
///
/// Not `Sync` — the [`UnsafeCell`] wrapper on `StdHsmPal` prevents
/// sharing across threads.  All access occurs on the single-threaded
/// Embassy executor.
pub(crate) struct PartitionTable {
    /// Fixed array of partition entries indexed by `pid`.
    ///
    /// Boxed to avoid 155KB+ on the stack during construction and moves.
    pub(crate) entries: Box<[PartitionEntry; NUM_PARTITIONS]>,

    /// Global resource bitmask — union of all partitions' `res_mask` values.
    ///
    /// Used to detect double-allocation: a new partition's `res_mask` must
    /// not overlap with this value (`res_mask & global_res_mask == 0`).
    global_res_mask: u128,
}

impl Default for PartitionTable {
    fn default() -> Self {
        Self {
            entries: Box::new(core::array::from_fn(|_| PartitionEntry::default())),
            global_res_mask: 0,
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
        /// Resource bitmask — each set bit assigns one vault table to
        /// this partition.  Must not overlap with any already-allocated
        /// resource (checked against [`PartitionTable::global_res_mask`]).
        res_mask: u128,
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
    fn part_state(&self, pid: u8) -> HsmResult<PartState> {
        // SAFETY: Embassy is single-threaded. This synchronous method
        // completes without yielding, so no concurrent mutation occurs.
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        Ok(table.entries[idx].state)
    }

    /// Returns the resource count allocated to the partition at `pid`.
    fn part_res_count(&self, pid: u8) -> HsmResult<u8> {
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }
        Ok(entry.res_mask.count_ones() as u8)
    }

    /// Returns the 16-byte identity blob for the partition at `pid`.
    fn part_id(&self, pid: u8) -> HsmResult<PartId<'_>> {
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }
        Ok(&entry.id)
    }

    /// Returns the identity key pair (public, private) for `pid`.
    fn part_id_key(&self, pid: u8) -> HsmResult<PartIdKey<'_>> {
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }
        Ok((&entry.pub_key, &entry.priv_key_der[..entry.priv_key_len]))
    }
}

// ---------------------------------------------------------------------------
// Shared partition access helpers (used by vault.rs, session.rs, etc.)
// ---------------------------------------------------------------------------

impl StdHsmPal {
    /// Borrow an active partition entry immutably.
    ///
    /// # Safety
    ///
    /// Accesses `UnsafeCell<PartitionTable>` — safe because Embassy is
    /// single-threaded and this is a synchronous (non-async) method.
    pub(crate) fn active_part(&self, pid: HsmPartId) -> HsmResult<&PartitionEntry> {
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state == PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }
        Ok(&table.entries[idx])
    }

    /// Borrow an active partition entry mutably.
    ///
    /// # Safety
    ///
    /// Accesses `UnsafeCell<PartitionTable>` — safe because Embassy is
    /// single-threaded and this is a synchronous (non-async) method.
    #[allow(clippy::mut_from_ref)]
    pub(crate) fn active_part_mut(&self, pid: HsmPartId) -> HsmResult<&mut PartitionEntry> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state == PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }
        Ok(&mut table.entries[idx])
    }
}

// ---------------------------------------------------------------------------
// Internal partition alloc / free (called by part_cmd_task on Embassy thread)
// ---------------------------------------------------------------------------

impl StdHsmPal {
    /// Allocate a partition: generate identity and ECC-384 key pair.
    ///
    /// # Parameters
    ///
    /// - `pid` — partition index (must be < [`NUM_PARTITIONS`]).
    /// - `res_mask` — bitmask of resources (vault tables) to assign.
    ///   Each set bit corresponds to one table.  Only bits 0..64 are
    ///   valid (65 resources total).
    ///
    /// # Preconditions
    ///
    /// - Partition must be in [`Disabled`](PartState::Disabled) state.
    /// - `res_mask` must not overlap with the global resource mask
    ///   (no double-allocation).
    ///
    /// On success the partition transitions to [`Uninitialized`](PartState::Uninitialized).
    ///
    /// # Safety invariant
    ///
    /// Must only be called from the Embassy thread (single-threaded executor).
    /// No trait read borrows can be alive across the `.await` boundary that
    /// delivers the [`PartCommand`] to this method.
    pub fn part_alloc_internal(&self, pid: u8, res_mask: u128) -> HsmResult<()> {
        // SAFETY: Single-threaded Embassy — no concurrent readers.
        let table = unsafe { &mut *self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state != PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }

        // Validate: only bits 0..64 allowed (65 resources).
        let valid_bits: u128 = (1u128 << MAX_RESOURCES) - 1;
        if res_mask & !valid_bits != 0 {
            return Err(HsmError::InvalidArg);
        }

        // Check for double-allocation — no overlap with global mask.
        if res_mask & table.global_res_mask != 0 {
            return Err(HsmError::NotEnoughSpace);
        }

        let entry = &mut table.entries[idx];

        // Generate 16-byte random identity.
        Rng::rand_bytes(&mut entry.id).map_err(|_| HsmError::InternalError)?;

        // Generate ECC P-384 key pair.
        let key = EccPrivateKey::from_curve(EccCurve::P384).map_err(|_| HsmError::InternalError)?;

        // Export public key coordinates (x ∥ y).
        let (x_buf, y_buf) = entry.pub_key.split_at_mut(P384_COORD_SIZE);
        key.coord(Some((x_buf, y_buf)))
            .map_err(|_| HsmError::InternalError)?;

        // Export private key as PKCS#8 DER.
        let len = key
            .to_bytes(Some(&mut entry.priv_key_der))
            .map_err(|_| HsmError::InternalError)?;
        entry.priv_key_len = len;

        entry.res_mask = res_mask;
        entry.vault = KeyVault::new(res_mask.count_ones() as usize);
        table.global_res_mask |= res_mask;
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
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state == PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }

        let entry = &mut table.entries[idx];

        // Zeroize sensitive material.
        entry.id.fill(0);
        entry.pub_key.fill(0);
        entry.priv_key_der[..entry.priv_key_len].fill(0);
        entry.priv_key_len = 0;
        entry.leaf_cert[..entry.leaf_cert_len].fill(0);
        entry.leaf_cert_len = 0;

        // Release resources from global mask.
        table.global_res_mask &= !entry.res_mask;
        entry.res_mask = 0;

        entry.session_table = SessionTable::new();
        entry.vault = KeyVault::new(0);
        entry.state = PartState::Disabled;

        Ok(())
    }
}
