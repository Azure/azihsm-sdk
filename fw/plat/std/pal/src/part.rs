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
use azihsm_fw_hsm_pal_traits::PART_POLICY_LEN;

use super::*;
use crate::cert::MAX_CERT_DER_LEN;
use crate::drivers::session::SessionTable;
use crate::drivers::vault::KeyVault;

/// Total number of partitions supported by the HSM.
pub const NUM_PARTITIONS: usize = 65;

/// Maximum total resources across all partitions.
pub const MAX_RESOURCES: u8 = 65;

/// Length of the per-partition random nonce in bytes.
const NONCE_LEN: usize = 32;

/// Maximum size of the sealed BK3 blob in bytes.
const SEALED_BK3_SIZE: usize = 512;

/// Length of a partition's random identity blob in bytes.
const PART_ID_LEN: usize = 16;

/// Length of the per-partition Unique Device Secret in bytes.
const UDS_LEN: usize = 32;

/// Length of an uncompressed SEC1 P-384 public key.
const P384_PUB_SEC1_LEN: usize = 1 + P384_PUB_KEY_LEN;

/// Length of a POTA SHA-384 thumbprint in bytes.
const POTA_THUMBPRINT_LEN: usize = 48;

/// Size of a single P-384 coordinate (x or y) in bytes.
const P384_COORD_SIZE: usize = 48;

/// Size of the raw public key (x ∥ y) in bytes.
pub(crate) const P384_PUB_KEY_LEN: usize = P384_COORD_SIZE * 2;

/// Length of the per-partition VM launch GUID in bytes.
///
/// Matches the prior reference firmware's `VmLaunchGuid` size
/// (16 bytes).
const VM_LAUNCH_GUID_LEN: usize = 16;

/// Hardcoded std PAL VM launch GUID returned by
/// [`HsmPartitionManager::part_vm_launch_guid`].
///
/// Real hardware reads this from the platform's launch-context table;
/// the emulator returns a fixed value so tests are deterministic.
const STD_VM_LAUNCH_GUID: [u8; VM_LAUNCH_GUID_LEN] = [
    0x53, 0x74, 0x64, 0x56, 0x4d, 0x4c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x47, 0x75, 0x69, 0x64, 0x00,
];

/// Hardcoded std PAL SVN returned by [`HsmPartitionManager::part_svn`].
const STD_SVN: u64 = 0;

/// Length of a single backup-key seed (`MFGR_SEED`, `DEV_OWNER_SEED`)
/// row in bytes.
const BK_SEED_LEN: usize = 32;

/// Hardcoded std PAL `MFGR_SEED` row 0 — manufacturer-provisioned
/// 32 B seed exposed through [`PartPropId::MFGR_SEED`] at `idx = 0`.
///
/// Real hardware exposes a 64-row table indexed by SVN; the std PAL
/// emulator provisions only row 0 because the simulator models a
/// single SVN.  The bytes are taken from the prior reference firmware
/// so derived masking keys are bit-compatible with persisted
/// `Masked_BK_BOOT` blobs across emulator and real hardware.
const STD_MFGR_SEED_ROW0: [u8; BK_SEED_LEN] = [
    0x9b, 0x4e, 0x4e, 0xb7, 0xad, 0xab, 0xdc, 0xd6, 0xb4, 0xd5, 0x07, 0xeb, 0x68, 0xeb, 0x26, 0x99,
    0x2a, 0xbb, 0xca, 0xb5, 0x5c, 0xfb, 0x77, 0x3b, 0xc4, 0xd0, 0xa8, 0x8c, 0x21, 0x02, 0xb0, 0xac,
];

/// Hardcoded std PAL `DEV_OWNER_SEED` row 0 — device-owner-provisioned
/// 32 B seed exposed through [`PartPropId::DEV_OWNER_SEED`] at
/// `idx = 0`.
///
/// Real hardware exposes a 64-row table indexed by `bks2_index`; the
/// std PAL emulator provisions only row 0 because the simulator
/// models a single partition lineage.  The bytes are taken from the
/// prior reference firmware for bit-compatibility.
const STD_DEV_OWNER_SEED_ROW0: [u8; BK_SEED_LEN] = [
    0xad, 0x1a, 0x17, 0xe9, 0xed, 0x38, 0x27, 0x5e, 0x8b, 0x30, 0x5d, 0xb8, 0x19, 0x0f, 0x82, 0xb6,
    0x2d, 0xa2, 0x5a, 0xc6, 0xf0, 0x70, 0xa3, 0xe1, 0x75, 0x9c, 0x61, 0x92, 0xcc, 0xf4, 0x19, 0xa3,
];

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
/// | `gen` | 4 B | Incarnation counter (bumped on alloc / free) |
/// | `res_mask` | 16 B | Resource bitmask (each bit = one vault table) |
/// | `id` | 16 B | Random identity blob |
/// | `pub_key` | 96 B | Raw P-384 public key (x ∥ y) |
/// | `priv_key` | 48 B | Raw HSM P-384 private scalar |
/// | `leaf_cert` | 2 KB | Cached DER-encoded partition leaf certificate |
/// | `session_table` | 2 B | Bitmask session allocator |
///
/// ## Generation counter
///
/// `gen` increments on every `part_alloc_internal` and
/// `part_free_internal` call.  RAII guards (`StdVaultKeyGuard`,
/// `StdSessionGuard`) capture the value at create time and refuse to
/// roll back if the partition has since been freed and reallocated —
/// otherwise a stale guard could delete unrelated state from a
/// re-incarnated partition.
///
/// ## Zeroization
///
/// When a partition is freed via [`part_free_internal`], all
/// cryptographic material (`id`, `pub_key`, `priv_key`,
/// `leaf_cert`) is explicitly zeroed before the state transitions
/// back to `Disabled`.
///
/// [`part_free_internal`]: StdHsmPal::part_free_internal
pub(crate) struct PartitionEntry {
    /// Current lifecycle state.
    pub(crate) state: PartState,

    /// Partition incarnation counter.  Bumped on every alloc and free.
    pub(crate) gen: u32,

    /// Resource bitmask — each set bit corresponds to one vault table
    /// assigned to this partition.  `count_ones()` gives the table count.
    res_mask: u128,

    /// 16-byte random identity blob, generated on allocation.
    id: [u8; PART_ID_LEN],

    /// Vault key ID for the partition's identity ECC-384 private key.
    id_key_id: Option<HsmKeyId>,

    /// Raw public key coordinates (x ∥ y, 96 bytes) for identity key.
    pub(crate) id_pub_key: [u8; P384_PUB_KEY_LEN],

    /// Cached DER-encoded partition leaf certificate (lazily generated).
    pub(crate) leaf_cert: [u8; MAX_CERT_DER_LEN],

    /// Length of valid data in `leaf_cert` (0 = not yet generated).
    pub(crate) leaf_cert_len: usize,

    /// Per-partition session table for tracking allocated sessions.
    pub(crate) session_table: SessionTable,

    /// Per-partition key vault — number of tables determined by
    /// `res_mask.count_ones()` at allocation time.
    pub(crate) vault: KeyVault,

    /// Vault key ID for the establish-credential encryption ECC-384 key.
    /// `None` before enable or after one-time clear.
    establish_cred_key_id: Option<HsmKeyId>,

    /// DER-encoded public key for establish-credential encryption.
    establish_cred_pub_key: [u8; P384_PUB_KEY_LEN],

    /// Vault key ID for the session encryption ECC-384 key.
    /// `None` before enable.
    session_enc_key_id: Option<HsmKeyId>,

    /// Raw public key coordinates (x ∥ y) for session encryption.
    session_enc_pub_key: [u8; P384_PUB_KEY_LEN],

    /// 32-byte random nonce, generated on enable and refreshable.
    nonce: [u8; NONCE_LEN],

    /// Sealed BK3 blob — up to 512 bytes of opaque data.
    sealed_bk3: [u8; SEALED_BK3_SIZE],

    /// Length of valid data in `sealed_bk3` (0 = not yet stored).
    sealed_bk3_len: u32,

    /// `BK_BOOT` boot-key material, generated during partition enable.
    ///
    /// On the std PAL this is opaque random bytes; on real hardware it
    /// is derived from `BKS1` / `BKS2`.  Never exposed outside the
    /// PAL — application code only sees `Masked_BK_BOOT` (and only
    /// indirectly, through the masked outputs produced from it).
    bk_boot: [u8; BK_BOOT_LEN],

    /// `Masked_BK_BOOT` — `BK_BOOT` enveloped with a platform-derived
    /// `BKx` masking key.
    ///
    /// Populated by the application layer (the DDI `InitBk3` handler)
    /// — the PAL only provides the fixed-size storage slot and the
    /// raw `BK_BOOT` material via
    /// [`HsmPartitionManager::part_bk_boot`].  Cleared on disable /
    /// free via [`StdHsmPal::clear_enabled_state`].
    masked_bk_boot: [u8; MASKED_BK_BOOT_LEN],

    /// Length of valid data in `masked_bk_boot` (0 = not yet
    /// populated).
    ///
    /// Set by the application layer when it writes the masked envelope
    /// into [`PartitionEntry::masked_bk_boot`]; reset to 0 on every
    /// disable / free via [`StdHsmPal::clear_enabled_state`].
    masked_bk_boot_len: u32,

    /// VM launch GUID, set during partition enable.
    ///
    /// On the std PAL this is a fixed constant
    /// ([`STD_VM_LAUNCH_GUID`]); on real hardware it is sourced from
    /// the platform.  Zeroed on disable / free.
    vm_launch_guid: [u8; VM_LAUNCH_GUID_LEN],

    /// BK3 initialization state for the current partition incarnation.
    ///
    /// `false` on every enable; set to `true` by a successful
    /// `part_mark_bk3_initialized`.  Acts as the authoritative
    /// one-shot gate for `InitBk3`.
    bk3_initialized: bool,

    /// User credential blob (`id ‖ pin`, 16 + 16 = 32 bytes).  Zeroed
    /// until set via the `CREDENTIAL` property.
    credential: [u8; 32],

    /// Whether the user credential has been set for this incarnation.
    credential_set: bool,

    /// BK3 session key (48 bytes), derived during EstablishCredential.
    bk3_session: [u8; 48],

    /// Whether `bk3_session` has been populated.
    bk3_session_set: bool,

    /// Vault key ID of the partition masking key (MK).
    mk_key_id: Option<HsmKeyId>,

    /// Vault key ID of the partition unwrapping key.
    unwrapping_key_id: Option<HsmKeyId>,

    /// Crypto Officer PSK.  `None` while the well-known default
    /// applies; set to `Some` once `part_psk_set(psk_id=0, ..)` is
    /// invoked.
    psk_co: Option<[u8; PSK_LEN]>,

    /// Crypto User PSK.  `None` while the well-known default applies;
    /// set to `Some` once `part_psk_set(psk_id=1, ..)` is invoked.
    psk_cu: Option<[u8; PSK_LEN]>,

    /// Vault key ID of the Partition Trust Anchor private key.
    pta_key_id: Option<HsmKeyId>,

    /// Vault key ID of the Partition Unique Machine Secret (UMS),
    /// bound by `PartInit`.  `None` until the one-shot
    /// [`HsmPartitionManager::part_set_ums_key`] succeeds; cleared on
    /// `part_disable`.
    ups_key_id: Option<HsmKeyId>,

    /// SEC1 uncompressed P-384 public key for the Partition Trust Anchor.
    pta_pub_sec1: Option<[u8; P384_PUB_SEC1_LEN]>,

    /// Raw partition policy bytes bound by PartInit.
    part_policy_buf: Option<[u8; PART_POLICY_LEN]>,

    /// POTA SHA-384 thumbprint bound by PartInit.
    pota_thumbprint: Option<[u8; POTA_THUMBPRINT_LEN]>,

    /// Per-incarnation Unique Device Secret used by PartInit KDFs.
    uds: [u8; UDS_LEN],
}

impl Default for PartitionEntry {
    fn default() -> Self {
        Self {
            state: PartState::Unallocated,
            gen: 0,
            res_mask: 0,
            id: [0u8; PART_ID_LEN],
            id_key_id: None,
            id_pub_key: [0u8; P384_PUB_KEY_LEN],
            leaf_cert: [0u8; MAX_CERT_DER_LEN],
            leaf_cert_len: 0,
            session_table: SessionTable::new(),
            vault: KeyVault::new(0),
            establish_cred_key_id: None,
            establish_cred_pub_key: [0u8; P384_PUB_KEY_LEN],
            session_enc_key_id: None,
            session_enc_pub_key: [0u8; P384_PUB_KEY_LEN],
            nonce: [0u8; NONCE_LEN],
            sealed_bk3: [0u8; SEALED_BK3_SIZE],
            sealed_bk3_len: 0,
            bk_boot: [0u8; BK_BOOT_LEN],
            masked_bk_boot: [0u8; MASKED_BK_BOOT_LEN],
            masked_bk_boot_len: 0,
            vm_launch_guid: [0u8; VM_LAUNCH_GUID_LEN],
            bk3_initialized: false,
            credential: [0u8; 32],
            credential_set: false,
            bk3_session: [0u8; 48],
            bk3_session_set: false,
            mk_key_id: None,
            unwrapping_key_id: None,
            psk_co: None,
            psk_cu: None,
            pta_key_id: None,
            ups_key_id: None,
            pta_pub_sec1: None,
            part_policy_buf: None,
            pota_thumbprint: None,
            uds: [0u8; UDS_LEN],
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
    /// resources, and transition to `Unallocated`.
    Free {
        pid: u8,
        reply: tokio::sync::oneshot::Sender<HsmResult<()>>,
    },

    /// Enable a partition: create internal ECC-384 key pairs and nonce.
    /// Transitions `Allocated | Disabled → Enabled`.
    Enable {
        pid: u8,
        reply: tokio::sync::oneshot::Sender<HsmResult<()>>,
    },

    /// Disable a partition: clear internal keys, nonce, vault, sessions.
    /// Transitions `Enabled → Disabled`.
    Disable {
        pid: u8,
        reply: tokio::sync::oneshot::Sender<HsmResult<()>>,
    },
}

// ---------------------------------------------------------------------------
// HsmPartitionManager trait implementation (read-only, called by core)
// ---------------------------------------------------------------------------

impl HsmPartitionManager for StdHsmPal {
    // ─── Property API ──────────────────────────────────────────────────
    //
    // Forwarding shims to the inherent `prop_*` implementations on
    // [`StdHsmPal`] declared in [`crate::part_prop`].  All validation,
    // lifecycle gating, and dispatch into [`PartitionEntry`] lives in
    // that module; the methods below exist solely to attach the
    // implementation to the trait.

    fn part_prop_get_u8(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u8> {
        self.prop_get_u8(io, id, idx)
    }

    fn part_prop_set_u8(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u8,
    ) -> HsmResult<()> {
        self.prop_set_u8(io, id, idx, value)
    }

    fn part_prop_get_u16(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u16> {
        self.prop_get_u16(io, id, idx)
    }

    fn part_prop_set_u16(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u16,
    ) -> HsmResult<()> {
        self.prop_set_u16(io, id, idx, value)
    }

    fn part_prop_get_u32(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u32> {
        self.prop_get_u32(io, id, idx)
    }

    fn part_prop_set_u32(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u32,
    ) -> HsmResult<()> {
        self.prop_set_u32(io, id, idx, value)
    }

    fn part_prop_get_u64(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u64> {
        self.prop_get_u64(io, id, idx)
    }

    fn part_prop_set_u64(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u64,
    ) -> HsmResult<()> {
        self.prop_set_u64(io, id, idx, value)
    }

    fn part_prop_get_bool(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<bool> {
        self.prop_get_bool(io, id, idx)
    }

    fn part_prop_set_bool(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: bool,
    ) -> HsmResult<()> {
        self.prop_set_bool(io, id, idx, value)
    }

    fn part_prop_get_bytes<'a>(
        &'a self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
    ) -> HsmResult<&'a DmaBuf> {
        self.prop_get_bytes(io, id, idx)
    }

    fn part_prop_set_bytes(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        data: &DmaBuf,
    ) -> HsmResult<()> {
        self.prop_set_bytes(io, id, idx, data)
    }

    fn part_prop_clear(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<()> {
        self.prop_clear(io, id, idx)
    }
}

// ---------------------------------------------------------------------------
// Shared partition access helpers (used by vault.rs, session.rs, etc.)
// ---------------------------------------------------------------------------

impl StdHsmPal {
    /// Borrow the `PartitionTable` through the `UnsafeCell`.  Safe
    /// because the std PAL runs on a single-threaded Embassy executor
    /// (see the module-level architecture note).
    #[allow(clippy::mut_from_ref)]
    #[inline]
    fn table_mut(&self) -> &mut PartitionTable {
        unsafe { &mut *self.part_table.get() }
    }

    #[inline]
    fn table(&self) -> &PartitionTable {
        unsafe { &*self.part_table.get() }
    }

    /// Validate `pid` and return its array index, or `InvalidArg`.
    #[inline]
    fn part_idx(pid: HsmPartId) -> HsmResult<usize> {
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        Ok(idx)
    }

    /// Borrow a partition whose state passes `accept`.
    fn part_if(
        &self,
        pid: HsmPartId,
        accept: impl FnOnce(PartState) -> bool,
    ) -> HsmResult<&PartitionEntry> {
        let idx = Self::part_idx(pid)?;
        let entry = &self.table().entries[idx];
        if !accept(entry.state) {
            return Err(HsmError::InvalidArg);
        }
        Ok(entry)
    }

    /// Mutable counterpart to [`Self::part_if`].
    #[allow(clippy::mut_from_ref)]
    fn part_if_mut(
        &self,
        pid: HsmPartId,
        accept: impl FnOnce(PartState) -> bool,
    ) -> HsmResult<&mut PartitionEntry> {
        let idx = Self::part_idx(pid)?;
        let entry = &mut self.table_mut().entries[idx];
        if !accept(entry.state) {
            return Err(HsmError::InvalidArg);
        }
        Ok(entry)
    }

    /// Returns the partition incarnation counter.
    ///
    /// Captured by RAII guards (`StdVaultKeyGuard`, `StdSessionGuard`)
    /// at create time; if the value differs at drop time, the guard
    /// has outlived its partition incarnation and skips rollback to
    /// avoid corrupting a re-allocated partition.
    pub(crate) fn partition_gen(&self, pid: HsmPartId) -> u32 {
        let Ok(idx) = Self::part_idx(pid) else {
            return 0;
        };
        self.table().entries[idx].gen
    }

    /// Borrow a partition entry that is not Unallocated.
    pub(crate) fn active_part(&self, pid: HsmPartId) -> HsmResult<&PartitionEntry> {
        self.part_if(pid, |s| s != PartState::Unallocated)
    }

    /// Borrow a partition entry that is not Unallocated (mutable).
    #[allow(clippy::mut_from_ref)]
    pub(crate) fn active_part_mut(&self, pid: HsmPartId) -> HsmResult<&mut PartitionEntry> {
        self.part_if_mut(pid, |s| s != PartState::Unallocated)
    }

    /// Borrow a partition that is actively serving host traffic.
    ///
    /// "Serving" means [`PartState::Enabled`] or
    /// [`PartState::Initializing`] — i.e. the partition is bound to a
    /// caller's incarnation and may legitimately expose per-incarnation
    /// secrets (PSK, UDS).  Stricter than [`Self::active_part`] (which
    /// permits Allocated and Disabled too) so that PSK/UDS reads cannot
    /// leak across the allocate/enable boundary.
    fn serving_part(&self, pid: HsmPartId) -> HsmResult<&PartitionEntry> {
        self.part_if(pid, |s| {
            matches!(s, PartState::Enabled | PartState::Initializing)
        })
    }

    /// Mutable counterpart to [`Self::serving_part`].
    #[allow(clippy::mut_from_ref)]
    fn serving_part_mut(&self, pid: HsmPartId) -> HsmResult<&mut PartitionEntry> {
        self.part_if_mut(pid, |s| {
            matches!(s, PartState::Enabled | PartState::Initializing)
        })
    }
}

// ---------------------------------------------------------------------------
// Internal partition lifecycle (called by part_cmd_task on Embassy thread)
// ---------------------------------------------------------------------------

impl StdHsmPal {
    /// Allocate a partition: generate identity and ECC-384 key pair.
    ///
    /// Transitions `Unallocated → Allocated`.
    pub async fn part_alloc_internal(&self, pid: u8, res_mask: u128) -> HsmResult<()> {
        let table = self.table_mut();
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state != PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }

        // Validate before mutating anything.
        let valid_bits: u128 = (1u128 << MAX_RESOURCES) - 1;
        if res_mask & !valid_bits != 0 {
            return Err(HsmError::InvalidArg);
        }
        if res_mask & table.global_res_mask != 0 {
            return Err(HsmError::NotEnoughSpace);
        }

        // Generate identity outside the table borrow — no partial state on failure.
        let mut id = [0u8; PART_ID_LEN];
        Rng::rand_bytes(&mut id).map_err(|_| HsmError::InternalError)?;

        // Reserve resources + create vault so keygen has somewhere to store.
        let entry = &mut table.entries[idx];
        // Bump the partition incarnation counter so RAII guards captured
        // against the prior incarnation refuse to roll back.
        entry.gen = entry.gen.wrapping_add(1);
        entry.res_mask = res_mask;
        entry.vault = KeyVault::new(res_mask.count_ones() as usize);
        table.global_res_mask |= res_mask;

        // Generate identity ECC P-384 key pair.
        let id_attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_sign(true);
        let mut id_pub = [0u8; P384_PUB_KEY_LEN];
        let id_result = self
            .create_internal_ecc384_key(
                idx as u8,
                HsmVaultKeyKind::Ecc384Private,
                id_attrs,
                HsmEccPct::SignVerify,
                &mut id_pub,
            )
            .await;

        // Commit or rollback.
        let table = self.table_mut();
        let entry = &mut table.entries[idx];
        match id_result {
            Ok(id_kid) => {
                entry.id = id;
                entry.id_key_id = Some(id_kid);
                entry.id_pub_key = id_pub;
                entry.state = PartState::Allocated;
            }
            Err(e) => {
                // Rollback: release resources.
                table.global_res_mask &= !res_mask;
                entry.res_mask = 0;
                entry.vault = KeyVault::new(0);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Enable a partition: create internal ECC-384 key pairs and nonce.
    ///
    /// Transitions `Allocated | Disabled → Enabled`.
    pub async fn part_enable_internal(&self, pid: u8) -> HsmResult<()> {
        let table = self.table_mut();
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let state = table.entries[idx].state;
        if state != PartState::Allocated && state != PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }

        let attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_derive(true);

        // If the identity key was wiped (e.g., by a prior part_disable),
        // regenerate it before any other key — mirrors real hardware
        // where NSSR/erase always provisions a fresh partition identity
        // key.  Must be created first so it lands in the same vault
        // slot the `id_key_id` field was originally bound to.
        if table.entries[idx].id_key_id.is_none() {
            let id_attrs = HsmVaultKeyAttrs::new()
                .with_internal(true)
                .with_local(true)
                .with_sign(true);
            let mut id_pub = [0u8; P384_PUB_KEY_LEN];
            let id_kid = self
                .create_internal_ecc384_key(
                    pid,
                    HsmVaultKeyKind::Ecc384Private,
                    id_attrs,
                    HsmEccPct::SignVerify,
                    &mut id_pub,
                )
                .await?;
            let table = self.table_mut();
            let entry = &mut table.entries[idx];
            entry.id_key_id = Some(id_kid);
            entry.id_pub_key = id_pub;
            // Defensive: a `GetCertificate` request that slipped in
            // between `part_disable` and here would have rebuilt the
            // leaf-cert cache over the zeroed `id_pub_key`.  Invalidate
            // again so the next request rebuilds against the fresh key.
            entry.leaf_cert[..entry.leaf_cert_len].fill(0);
            entry.leaf_cert_len = 0;
        }

        // Generate establish-credential encryption ECC-384 key pair.
        let mut ec_pub = [0u8; P384_PUB_KEY_LEN];
        let ec_kid = self
            .create_internal_ecc384_key(
                pid,
                HsmVaultKeyKind::EstablishCred,
                attrs,
                HsmEccPct::KeyAgreement,
                &mut ec_pub,
            )
            .await?;

        let table = self.table_mut();
        let entry = &mut table.entries[idx];
        entry.establish_cred_key_id = Some(ec_kid);
        entry.establish_cred_pub_key = ec_pub;

        // Generate session encryption ECC-384 key pair.
        let mut se_pub = [0u8; P384_PUB_KEY_LEN];
        let se_result = self
            .create_internal_ecc384_key(
                pid,
                HsmVaultKeyKind::SessionEncryption,
                attrs,
                HsmEccPct::KeyAgreement,
                &mut se_pub,
            )
            .await;

        let table = self.table_mut();
        let entry = &mut table.entries[idx];
        match se_result {
            Ok(se_kid) => {
                entry.session_enc_key_id = Some(se_kid);
                entry.session_enc_pub_key = se_pub;
            }
            Err(e) => {
                let _ = entry.vault.delete(ec_kid);
                entry.establish_cred_key_id = None;
                entry.establish_cred_pub_key.fill(0);
                return Err(e);
            }
        }

        // Generate 32-byte random nonce.
        if Rng::rand_bytes(&mut entry.nonce).is_err() {
            // Rollback both keys.
            Self::clear_enabled_state(entry);
            return Err(HsmError::InternalError);
        }

        // Generate per-partition `BK_BOOT`; real hardware derives this
        // from BKS1/BKS2, the emulator uses random bytes.
        if Rng::rand_bytes(&mut entry.bk_boot).is_err() {
            Self::clear_enabled_state(entry);
            return Err(HsmError::BkBootGenerationFailed);
        }

        entry.vm_launch_guid = STD_VM_LAUNCH_GUID;
        entry.bk3_initialized = false;
        entry.uds = derive_sim_uds(pid);

        entry.state = PartState::Enabled;
        Ok(())
    }

    /// Disable a partition: clear internal keys, nonce, vault, sessions.
    ///
    /// Transitions `Enabled → Disabled`.
    pub fn part_disable_internal(&self, pid: u8) -> HsmResult<()> {
        let table = self.table_mut();
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if !matches!(
            table.entries[idx].state,
            PartState::Enabled | PartState::Initializing
        ) {
            return Err(HsmError::InvalidArg);
        }

        Self::clear_enabled_state(&mut table.entries[idx]);
        table.entries[idx].state = PartState::Disabled;
        Ok(())
    }

    /// Free a partition: zeroize all material and release resources.
    ///
    /// Accepts `Allocated | Enabled | Disabled → Unallocated`.
    /// If `Enabled`, implicitly clears internal keys first.
    pub fn part_free_internal(&self, pid: u8) -> HsmResult<()> {
        let table = self.table_mut();
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }

        let entry = &mut table.entries[idx];

        // Bump the partition incarnation counter so RAII guards captured
        // before this free refuse to roll back into the next incarnation.
        entry.gen = entry.gen.wrapping_add(1);

        // If enabled, clear internal keys/nonce/vault/sessions first.
        if matches!(entry.state, PartState::Enabled | PartState::Initializing) {
            Self::clear_enabled_state(entry);
        }

        // Zeroize identity material.
        entry.id.fill(0);
        if let Some(kid) = entry.id_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.id_pub_key.fill(0);
        entry.leaf_cert[..entry.leaf_cert_len].fill(0);
        entry.leaf_cert_len = 0;

        // Release resources.
        table.global_res_mask &= !entry.res_mask;
        entry.res_mask = 0;
        entry.vault = KeyVault::new(0);
        entry.state = PartState::Unallocated;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Generate an ECC P-384 key pair, store the raw HSM-format private
    /// key (scalar `d`, 48 bytes) in the vault, and write raw public key
    /// coordinates (x ∥ y) into `pub_key_out`.
    ///
    /// Bypasses [`HsmEcc::ecc_gen_keypair`] (which now requires an
    /// `HsmIo` and a scoped allocator) and drives the
    /// [`StdEcc`](crate::drivers::ecc::StdEcc) driver directly — this
    /// helper runs from the partition lifecycle task where neither
    /// an IO context nor a scoped allocator exists.
    ///
    /// Returns the vault key ID.
    async fn create_internal_ecc384_key(
        &self,
        pid: u8,
        kind: HsmVaultKeyKind,
        attrs: HsmVaultKeyAttrs,
        _pct: HsmEccPct,
        pub_key_out: &mut [u8; P384_PUB_KEY_LEN],
    ) -> HsmResult<HsmKeyId> {
        let (pk, pubk) = self.ecc.gen_keypair(EccCurve::P384).await?;

        // Export private key as raw HSM scalar bytes (48 B for P-384).
        let priv_len = pk.hsm_bytes_len();
        let mut priv_buf = vec![0u8; priv_len];
        pk.to_hsm_bytes(&mut priv_buf[..priv_len])
            .map_err(|_| HsmError::EccExportError)?;

        // Export raw P-384 public key coordinates (x ∥ y) in big-endian
        // form — matches OpenSSL conventions and is the form expected by
        // internal consumers (cert generation, POTA hash).  Wire-facing
        // PAL accessors (e.g. [`part_establish_cred_pub_key`]) handle
        // BE→LE conversion at the response boundary.
        let half = P384_PUB_KEY_LEN / 2;
        let (x_buf, y_buf) = pub_key_out.split_at_mut(half);
        pubk.coord(Some((x_buf, y_buf)))
            .map_err(|_| HsmError::EccExportError)?;

        // Store raw HSM private-key bytes in vault.
        let table = self.table_mut();
        let entry = &mut table.entries[pid as usize];
        entry
            .vault
            .create(&priv_buf[..priv_len], kind, None, attrs, &[])
    }

    /// Clear all state associated with an enabled partition (internal keys,
    /// nonce, vault keys, sessions, boot-key material, BK3 state).  Does
    /// NOT change the state field.
    ///
    /// This is the single clearing site shared by `part_disable_internal`
    /// and `part_free_internal`; it mirrors the prior reference
    /// firmware's `clear_partition_info` grouping so that
    /// `Masked_BK_BOOT`, `sealed_bk3`, `vm_launch_guid`, and BK3 init
    /// state are all zeroized together whenever the partition's
    /// enabled lifecycle ends.
    fn clear_enabled_state(entry: &mut PartitionEntry) {
        // Drop a vault-backed key if present and best-effort delete its
        // backing slot.  Vault errors are ignored: the slot is about
        // to be overwritten or released wholesale.
        fn drop_key(vault: &mut KeyVault, kid: &mut Option<HsmKeyId>) {
            if let Some(k) = kid.take() {
                let _ = vault.delete(k);
            }
        }

        // Zeroize an `Option<[u8; N]>` payload in place before
        // dropping the `Some`, so the bytes that live inside the
        // entry struct are overwritten (not just the discriminant —
        // `Option<[u8; N]>` has no niche, so payload storage is
        // stable).
        fn drop_secret<const N: usize>(slot: &mut Option<[u8; N]>) {
            if let Some(buf) = slot.as_mut() {
                buf.fill(0);
            }
            *slot = None;
        }

        // Vault-backed keys whose ids live in this entry.  `id_key_id`
        // is taken (rather than vault-deleted) so `part_enable_internal`
        // knows to regenerate the identity key on the next enable; the
        // vault itself is cleared wholesale below.
        drop_key(&mut entry.vault, &mut entry.establish_cred_key_id);
        drop_key(&mut entry.vault, &mut entry.session_enc_key_id);
        drop_key(&mut entry.vault, &mut entry.mk_key_id);
        drop_key(&mut entry.vault, &mut entry.unwrapping_key_id);
        drop_key(&mut entry.vault, &mut entry.pta_key_id);
        drop_key(&mut entry.vault, &mut entry.ups_key_id);
        entry.id_key_id = None;

        // Public-key mirrors and other non-secret fixed buffers.
        entry.establish_cred_pub_key.fill(0);
        entry.session_enc_pub_key.fill(0);
        entry.nonce.fill(0);
        entry.leaf_cert[..entry.leaf_cert_len].fill(0);
        entry.leaf_cert_len = 0;

        // Drop the vault and per-partition session table.
        entry.vault.clear();
        entry.session_table = SessionTable::new();

        // Variable-length opaque blobs — zeroize only the valid
        // prefix to keep `clear_enabled_state` proportional to
        // touched bytes.
        entry.sealed_bk3[..entry.sealed_bk3_len as usize].fill(0);
        entry.sealed_bk3_len = 0;
        entry.masked_bk_boot[..entry.masked_bk_boot_len as usize].fill(0);
        entry.masked_bk_boot_len = 0;

        // Boot-key + BK3-incarnation state — mirrors the prior
        // reference firmware's `clear_partition_info` zeroize
        // grouping.
        entry.bk_boot.fill(0);
        entry.vm_launch_guid.fill(0);
        entry.bk3_initialized = false;

        // Caller-presented secrets and per-session derived material.
        entry.credential.fill(0);
        entry.credential_set = false;
        entry.bk3_session.fill(0);
        entry.bk3_session_set = false;

        // Provisioning material (write-once fields bound by PartInit).
        drop_secret(&mut entry.pta_pub_sec1);
        drop_secret(&mut entry.part_policy_buf);
        drop_secret(&mut entry.pota_thumbprint);

        // Rotated PSK material.
        drop_secret(&mut entry.psk_co);
        drop_secret(&mut entry.psk_cu);
    }
}

/// Derive a deterministic emulator UDS keyed on the partition slot id.
///
/// The std PAL has no fused per-device secret, so we synthesise a UDS
/// from `pid` alone.  Because the derivation depends only on the slot
/// id (not on an incarnation counter or wall-clock time), the value is
/// **stable across enable/disable cycles for the same slot** — which
/// matches the spec's expectation that UDS is a per-device root
/// secret, not a per-incarnation one.
fn derive_sim_uds(pid: u8) -> [u8; UDS_LEN] {
    let mut uds = [0u8; UDS_LEN];
    for (i, b) in uds.iter_mut().enumerate() {
        *b = pid ^ 0x55 ^ (i as u8).wrapping_mul(0x3d);
    }
    uds
}

// ═════════════════════════════════════════════════════════════════════════
// Property-API routing layer (formerly part_prop.rs)
// ═════════════════════════════════════════════════════════════════════════

// ─── Validation helpers ──────────────────────────────────────────────────

/// Resolve the meta for an id, validate idx, and validate that the
/// expected wire-kind matches the one declared by the property.
fn validate_meta(id: PartPropId, idx: u16, expected: ExpectedKind) -> HsmResult<PartPropMeta> {
    let meta = id.meta().ok_or(HsmError::InvalidArg)?;
    if idx >= meta.cardinality {
        return Err(HsmError::InvalidArg);
    }
    if !expected.matches(meta.kind) {
        return Err(HsmError::InvalidArg);
    }
    Ok(meta)
}

fn validate_set(
    id: PartPropId,
    idx: u16,
    expected: ExpectedKind,
    bytes_len: Option<usize>,
) -> HsmResult<PartPropMeta> {
    let meta = validate_meta(id, idx, expected)?;
    if meta.access != PartPropAccess::Rw {
        return Err(HsmError::InvalidArg);
    }
    if let Some(n) = bytes_len {
        match meta.kind {
            PartPropKind::FixedBytes { len } if n == usize::from(len) => {}
            PartPropKind::VarBytes { max } if n <= usize::from(max) => {}
            _ => return Err(HsmError::InvalidArg),
        }
    }
    Ok(meta)
}

fn validate_clear(id: PartPropId, idx: u16) -> HsmResult<PartPropMeta> {
    let meta = id.meta().ok_or(HsmError::InvalidArg)?;
    if idx >= meta.cardinality {
        return Err(HsmError::InvalidArg);
    }
    if meta.access != PartPropAccess::Rw {
        return Err(HsmError::InvalidArg);
    }
    if meta.default != PartPropDefault::AbsentUntilSet {
        return Err(HsmError::InvalidArg);
    }
    Ok(meta)
}

/// Caller-side expectation of the wire-kind for a typed accessor.
#[derive(Clone, Copy)]
enum ExpectedKind {
    U8,
    U16,
    U32,
    U64,
    Bool,
    Bytes,
}

impl ExpectedKind {
    fn matches(self, kind: PartPropKind) -> bool {
        matches!(
            (self, kind),
            (ExpectedKind::U8, PartPropKind::U8)
                | (ExpectedKind::U16, PartPropKind::U16)
                | (ExpectedKind::U32, PartPropKind::U32)
                | (ExpectedKind::U64, PartPropKind::U64)
                | (ExpectedKind::Bool, PartPropKind::Bool)
                | (
                    ExpectedKind::Bytes,
                    PartPropKind::FixedBytes { .. } | PartPropKind::VarBytes { .. }
                )
        )
    }
}

// ─── std PAL constants mirrored by RO props ──────────────────────────────

/// `FW_SEED` returned via [`PartPropId::FW_SEED`].  Length matches
/// the property's `FixedBytes { len: 48 }` (the SHA-384-sized seed
/// used by std-PAL masking-key derivation).
const STD_FW_SEED48: [u8; 48] = [0x42u8; 48];

// ─── DmaBuf branding ─────────────────────────────────────────────────────

/// Brand a borrowed byte slice from the partition table as a
/// `&DmaBuf`.  Safe on the std PAL because the partition table is
/// host-heap-resident; no real DMA constraints apply.
#[inline(always)]
fn dma(buf: &[u8]) -> &DmaBuf {
    // SAFETY: std PAL has no DMA-region constraint.
    unsafe { DmaBuf::from_raw(buf) }
}

/// Resolve a row of an indexed PAL-global seed table
/// ([`PartPropId::MFGR_SEED`] / [`PartPropId::DEV_OWNER_SEED`]).
///
/// The std PAL emulator provisions only row 0 of each table; other
/// `idx` values (still within `0..cardinality`) return
/// [`HsmError::PartPropNotFound`] to signal "no row provisioned for
/// this PAL".
fn std_indexed_seed_row(id: PartPropId, idx: u16) -> HsmResult<&'static [u8]> {
    match (id, idx) {
        (PartPropId::MFGR_SEED, 0) => Ok(&STD_MFGR_SEED_ROW0),
        (PartPropId::DEV_OWNER_SEED, 0) => Ok(&STD_DEV_OWNER_SEED_ROW0),
        (PartPropId::MFGR_SEED | PartPropId::DEV_OWNER_SEED, _) => Err(HsmError::PartPropNotFound),
        _ => Err(HsmError::InternalError),
    }
}

// ─── PartitionEntry property dispatch ────────────────────────────────────

impl PartitionEntry {
    /// Apply a caller-driven STATE transition through the property API.
    ///
    /// The internal device-command lifecycle (`part_alloc_internal`,
    /// `part_enable_internal`, `part_disable_internal`,
    /// `part_free_internal`) drives all other transitions; the prop
    /// API only exposes the single caller-facing one:
    /// `Enabled → Initializing`, which additionally requires the four
    /// write-once provisioning fields (PTA key, UMS key, policy,
    /// POTA thumbprint) to be present.  Any other source/target pair
    /// is rejected with [`HsmError::InvalidArg`].
    fn transition_state_via_prop(&mut self, target: PartState) -> HsmResult<()> {
        match (self.state, target) {
            (PartState::Enabled, PartState::Initializing) => {
                if self.pta_key_id.is_none()
                    || self.ups_key_id.is_none()
                    || self.part_policy_buf.is_none()
                    || self.pota_thumbprint.is_none()
                {
                    return Err(HsmError::InvalidArg);
                }
                self.state = PartState::Initializing;
                Ok(())
            }
            // No-op writes (same state) are accepted as a convenience.
            (cur, tgt) if cur == tgt => Ok(()),
            // All other transitions are PAL-internal — reject from the
            // prop API.
            _ => Err(HsmError::InvalidArg),
        }
    }

    /// Translate `id` to the matching scalar field on this entry.
    /// All values are widened to `u32` for a uniform return type;
    /// the trait wrapper narrows back to the requested kind.
    fn prop_get_scalar(&self, id: PartPropId) -> HsmResult<u32> {
        match id {
            PartPropId::STATE => Ok(u32::from(self.state as u8)),
            PartPropId::GEN => Ok(self.gen),
            PartPropId::RES_COUNT => Ok(self.res_mask.count_ones()),
            PartPropId::BK3_INITIALIZED => Ok(u32::from(self.bk3_initialized)),
            PartPropId::BKS2_ID => Ok(0),
            PartPropId::ID_KEY_ID => key_id_to_u32(self.id_key_id),
            PartPropId::MK_KEY_ID => key_id_to_u32(self.mk_key_id),
            PartPropId::UPS_KEY_ID => key_id_to_u32(self.ups_key_id),
            PartPropId::PTA_KEY_ID => key_id_to_u32(self.pta_key_id),
            PartPropId::RSA_UNWRAPPING_KEY_ID => key_id_to_u32(self.unwrapping_key_id),
            PartPropId::SESSION_ENC_KEY_ID => key_id_to_u32(self.session_enc_key_id),
            PartPropId::ESTABLISH_CRED_KEY_ID => key_id_to_u32(self.establish_cred_key_id),
            _ => Err(HsmError::InvalidArg),
        }
    }

    /// Write a scalar property; `value` is in the property's native
    /// width, already validated by the trait wrapper.
    fn prop_set_scalar(&mut self, id: PartPropId, value: u32) -> HsmResult<()> {
        match id {
            PartPropId::STATE => {
                let target = PartState::from_u8(value as u8).ok_or(HsmError::InvalidArg)?;
                self.transition_state_via_prop(target)
            }
            PartPropId::MK_KEY_ID => {
                self.mk_key_id = Some(HsmKeyId::from(value as u16));
                Ok(())
            }
            PartPropId::UPS_KEY_ID => {
                if self.ups_key_id.is_some() {
                    return Err(HsmError::UpsKeyAlreadySet);
                }
                self.ups_key_id = Some(HsmKeyId::from(value as u16));
                Ok(())
            }
            PartPropId::PTA_KEY_ID => {
                if self.pta_key_id.is_some() {
                    return Err(HsmError::PtaKeyAlreadySet);
                }
                self.pta_key_id = Some(HsmKeyId::from(value as u16));
                Ok(())
            }
            PartPropId::SESSION_ENC_KEY_ID => {
                self.session_enc_key_id = Some(HsmKeyId::from(value as u16));
                Ok(())
            }
            PartPropId::ESTABLISH_CRED_KEY_ID => {
                self.establish_cred_key_id = Some(HsmKeyId::from(value as u16));
                Ok(())
            }
            PartPropId::BK3_INITIALIZED => {
                // One-shot gate: false→true is the only legal
                // transition.  Re-asserting true returns
                // Bk3AlreadyInitialized; clearing back to false is
                // rejected (reset happens PAL-internally on free /
                // NSSR).
                let want = value != 0;
                if !want {
                    return Err(HsmError::InvalidArg);
                }
                if self.bk3_initialized {
                    return Err(HsmError::Bk3AlreadyInitialized);
                }
                self.bk3_initialized = true;
                Ok(())
            }
            // GEN/SVN/RES_COUNT/ID_KEY_ID/RSA_UNWRAPPING_KEY_ID are Ro
            // — rejected by validate_set.  Non-scalar ids — rejected
            // by the kind check.
            _ => Err(HsmError::InvalidArg),
        }
    }

    /// Read a u64-scalar property.
    fn prop_get_scalar_u64(&self, id: PartPropId) -> HsmResult<u64> {
        match id {
            PartPropId::SVN => Ok(STD_SVN),
            _ => Err(HsmError::InvalidArg),
        }
    }

    /// Write a u64-scalar property.
    fn prop_set_scalar_u64(&mut self, _id: PartPropId, _value: u64) -> HsmResult<()> {
        // SVN is Ro — rejected by validate_set.
        Err(HsmError::InvalidArg)
    }

    /// Borrow the bytes of a present byte property, or
    /// `Err(PartPropNotFound)` if the slot is absent.
    fn prop_get_bytes(&self, id: PartPropId) -> HsmResult<&[u8]> {
        match id {
            PartPropId::ID => Ok(&self.id),
            PartPropId::UDS => Ok(&self.uds),
            PartPropId::FW_SEED => Ok(&STD_FW_SEED48),
            PartPropId::PSK_CO => Ok(self
                .psk_co
                .as_ref()
                .map(|a| a.as_slice())
                .unwrap_or(DEFAULT_PSK_CO.as_slice())),
            PartPropId::PSK_CU => Ok(self
                .psk_cu
                .as_ref()
                .map(|a| a.as_slice())
                .unwrap_or(DEFAULT_PSK_CU.as_slice())),
            PartPropId::CREDENTIAL => {
                if !self.credential_set {
                    return Err(HsmError::PartPropNotFound);
                }
                // CREDENTIAL is 32 B: id (16) ‖ pin (16) — returned as
                // the full blob.  Consumers in `fw/core/lib` (e.g.
                // `part_verify_credential`) compare both halves in
                // constant time.
                Ok(&self.credential)
            }
            PartPropId::NONCE => Ok(&self.nonce),
            PartPropId::SEALED_BK3 => {
                let n = self.sealed_bk3_len as usize;
                if n == 0 {
                    return Err(HsmError::PartPropNotFound);
                }
                Ok(&self.sealed_bk3[..n])
            }
            PartPropId::MASKED_BK_BOOT => {
                let n = self.masked_bk_boot_len as usize;
                if n == 0 {
                    return Err(HsmError::PartPropNotFound);
                }
                Ok(&self.masked_bk_boot[..n])
            }
            PartPropId::BK_BOOT => Ok(&self.bk_boot),
            PartPropId::VM_LAUNCH_GUID => Ok(&self.vm_launch_guid),
            PartPropId::ID_PUB_KEY => Ok(&self.id_pub_key),
            PartPropId::SESSION_ENC_PUB_KEY => Ok(&self.session_enc_pub_key),
            PartPropId::ESTABLISH_CRED_PUB_KEY => Ok(&self.establish_cred_pub_key),
            PartPropId::PTA_PUB_SEC1 => self
                .pta_pub_sec1
                .as_ref()
                .map(|a| a.as_slice())
                .ok_or(HsmError::PartPropNotFound),
            PartPropId::BK3_SESSION => {
                if !self.bk3_session_set {
                    return Err(HsmError::PartPropNotFound);
                }
                Ok(&self.bk3_session)
            }
            PartPropId::POLICY => self
                .part_policy_buf
                .as_ref()
                .map(|a| a.as_slice())
                .ok_or(HsmError::PartPropNotFound),
            PartPropId::POTA_THUMBPRINT => self
                .pota_thumbprint
                .as_ref()
                .map(|a| a.as_slice())
                .ok_or(HsmError::PartPropNotFound),
            _ => Err(HsmError::InvalidArg),
        }
    }

    /// Write a byte property; `data` length already validated.
    fn prop_set_bytes(&mut self, id: PartPropId, data: &[u8]) -> HsmResult<()> {
        match id {
            PartPropId::PSK_CO => {
                if let Some(prev) = self.psk_co.as_mut() {
                    prev.fill(0);
                }
                let mut buf = [0u8; PSK_LEN];
                buf.copy_from_slice(data);
                self.psk_co = Some(buf);
                Ok(())
            }
            PartPropId::PSK_CU => {
                if let Some(prev) = self.psk_cu.as_mut() {
                    prev.fill(0);
                }
                let mut buf = [0u8; PSK_LEN];
                buf.copy_from_slice(data);
                self.psk_cu = Some(buf);
                Ok(())
            }
            PartPropId::CREDENTIAL => {
                // Write-once per credential lifecycle: production
                // re-set is rejected with `VaultAppLimitReached`,
                // matching the reference firmware's
                // `verify_cred_is_not_set` invariant.  Internal reset
                // (partition free / NSSR) goes through `prop_clear` /
                // direct field zeroing, not this path.
                if self.credential_set {
                    return Err(HsmError::VaultAppLimitReached);
                }
                // Reject all-zero id or pin halves — that value is the
                // sentinel `verify_user_cred_is_set` uses for "unset",
                // so accepting it would corrupt the lifecycle.
                if data[..16] == [0u8; 16] || data[16..32] == [0u8; 16] {
                    return Err(HsmError::InvalidAppCredentials);
                }
                self.credential.fill(0);
                self.credential.copy_from_slice(&data[..32]);
                self.credential_set = true;
                Ok(())
            }
            PartPropId::SEALED_BK3 => {
                // Write-once per power cycle: a second SetSealedBk3
                // without an intervening clear (free / NSSR /
                // explicit `prop_clear`) returns `SealedBk3AlreadySet`
                // to preserve the wire-visible legacy behaviour.
                if self.sealed_bk3_len != 0 {
                    return Err(HsmError::SealedBk3AlreadySet);
                }
                self.sealed_bk3.fill(0);
                self.sealed_bk3[..data.len()].copy_from_slice(data);
                self.sealed_bk3_len = data.len() as u32;
                Ok(())
            }
            PartPropId::MASKED_BK_BOOT => {
                self.masked_bk_boot.fill(0);
                self.masked_bk_boot[..data.len()].copy_from_slice(data);
                self.masked_bk_boot_len = data.len() as u32;
                Ok(())
            }
            PartPropId::POLICY => {
                if self.part_policy_buf.is_some() {
                    return Err(HsmError::InvalidArg);
                }
                let mut buf = [0u8; PART_POLICY_LEN];
                buf.copy_from_slice(data);
                self.part_policy_buf = Some(buf);
                Ok(())
            }
            PartPropId::POTA_THUMBPRINT => {
                if self.pota_thumbprint.is_some() {
                    return Err(HsmError::InvalidArg);
                }
                let mut buf = [0u8; 48];
                buf.copy_from_slice(data);
                self.pota_thumbprint = Some(buf);
                Ok(())
            }
            PartPropId::PTA_PUB_SEC1 => {
                if self.pta_pub_sec1.is_some() {
                    return Err(HsmError::InvalidArg);
                }
                let mut buf = [0u8; P384_PUB_SEC1_LEN];
                buf.copy_from_slice(data);
                self.pta_pub_sec1 = Some(buf);
                Ok(())
            }
            PartPropId::BK3_SESSION => {
                self.bk3_session.fill(0);
                self.bk3_session.copy_from_slice(data);
                self.bk3_session_set = true;
                Ok(())
            }
            PartPropId::NONCE => {
                self.nonce.copy_from_slice(data);
                Ok(())
            }
            // ID/UDS/FW_SEED/BK_BOOT/VM_LAUNCH_GUID are Ro —
            // rejected by validate_set.  Others are non-byte kinds.
            _ => Err(HsmError::InvalidArg),
        }
    }

    /// Reset a property to its absent state.  Only `AbsentUntilSet`
    /// props reach here (enforced by validate_clear).
    fn prop_clear(&mut self, id: PartPropId) -> HsmResult<()> {
        match id {
            // Scalar Rw + Abs.
            PartPropId::MK_KEY_ID => {
                self.mk_key_id = None;
                Ok(())
            }
            PartPropId::UPS_KEY_ID => {
                self.ups_key_id = None;
                Ok(())
            }
            PartPropId::PTA_KEY_ID => {
                self.pta_key_id = None;
                Ok(())
            }
            PartPropId::SESSION_ENC_KEY_ID => {
                self.session_enc_key_id = None;
                Ok(())
            }
            PartPropId::ESTABLISH_CRED_KEY_ID => {
                self.establish_cred_key_id = None;
                Ok(())
            }
            // Byte Rw + Abs.
            PartPropId::PSK_CO => {
                if let Some(prev) = self.psk_co.as_mut() {
                    prev.fill(0);
                }
                self.psk_co = None;
                Ok(())
            }
            PartPropId::PSK_CU => {
                if let Some(prev) = self.psk_cu.as_mut() {
                    prev.fill(0);
                }
                self.psk_cu = None;
                Ok(())
            }
            PartPropId::CREDENTIAL => {
                self.credential.fill(0);
                self.credential_set = false;
                Ok(())
            }
            PartPropId::SEALED_BK3 => {
                self.sealed_bk3.fill(0);
                self.sealed_bk3_len = 0;
                Ok(())
            }
            PartPropId::MASKED_BK_BOOT => {
                self.masked_bk_boot.fill(0);
                self.masked_bk_boot_len = 0;
                Ok(())
            }
            PartPropId::POLICY => {
                self.part_policy_buf = None;
                Ok(())
            }
            PartPropId::POTA_THUMBPRINT => {
                self.pota_thumbprint = None;
                Ok(())
            }
            PartPropId::PTA_PUB_SEC1 => {
                self.pta_pub_sec1 = None;
                Ok(())
            }
            PartPropId::BK3_SESSION => {
                self.bk3_session.fill(0);
                self.bk3_session_set = false;
                Ok(())
            }
            _ => Err(HsmError::InvalidArg),
        }
    }
}

fn key_id_to_u32(opt: Option<HsmKeyId>) -> HsmResult<u32> {
    opt.map(|k| u32::from(u16::from(k)))
        .ok_or(HsmError::PartPropNotFound)
}

// ─── StdHsmPal inherent property impls ───────────────────────────────────

impl StdHsmPal {
    /// Borrow `&PartitionEntry` for the calling partition with the
    /// lifecycle gate appropriate for reading the property.
    ///
    /// - STATE: any state (including Unallocated) — direct array access.
    /// - sensitive: Enabled | Initializing (via `serving_part`).
    /// - other:    Allocated | Initializing | Enabled | Disabled
    ///   (via `active_part`).
    fn prop_borrow_get(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        meta: &PartPropMeta,
    ) -> HsmResult<&PartitionEntry> {
        if id == PartPropId::STATE {
            let idx = Self::part_idx(io.pid())?;
            return Ok(&self.table().entries[idx]);
        }
        if meta.sensitive {
            self.serving_part(io.pid())
        } else {
            self.active_part(io.pid())
        }
    }

    /// Mutable counterpart of [`Self::prop_borrow_get`].  Writes use
    /// the same gating but always need at least Allocated.
    #[allow(clippy::mut_from_ref)]
    fn prop_borrow_set(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        meta: &PartPropMeta,
    ) -> HsmResult<&mut PartitionEntry> {
        if id == PartPropId::STATE {
            let idx = Self::part_idx(io.pid())?;
            return Ok(&mut self.table_mut().entries[idx]);
        }
        if meta.sensitive {
            self.serving_part_mut(io.pid())
        } else {
            self.active_part_mut(io.pid())
        }
    }

    pub(crate) fn prop_get_u8(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u8> {
        let meta = validate_meta(id, idx, ExpectedKind::U8)?;
        let entry = self.prop_borrow_get(io, id, &meta)?;
        Ok(entry.prop_get_scalar(id)? as u8)
    }

    pub(crate) fn prop_set_u8(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u8,
    ) -> HsmResult<()> {
        let meta = validate_set(id, idx, ExpectedKind::U8, None)?;
        let entry = self.prop_borrow_set(io, id, &meta)?;
        entry.prop_set_scalar(id, u32::from(value))
    }

    pub(crate) fn prop_get_u16(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u16> {
        let meta = validate_meta(id, idx, ExpectedKind::U16)?;
        let entry = self.prop_borrow_get(io, id, &meta)?;
        Ok(entry.prop_get_scalar(id)? as u16)
    }

    pub(crate) fn prop_set_u16(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u16,
    ) -> HsmResult<()> {
        let meta = validate_set(id, idx, ExpectedKind::U16, None)?;
        let entry = self.prop_borrow_set(io, id, &meta)?;
        entry.prop_set_scalar(id, u32::from(value))
    }

    pub(crate) fn prop_get_u32(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u32> {
        let meta = validate_meta(id, idx, ExpectedKind::U32)?;
        let entry = self.prop_borrow_get(io, id, &meta)?;
        entry.prop_get_scalar(id)
    }

    pub(crate) fn prop_set_u32(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u32,
    ) -> HsmResult<()> {
        let meta = validate_set(id, idx, ExpectedKind::U32, None)?;
        let entry = self.prop_borrow_set(io, id, &meta)?;
        entry.prop_set_scalar(id, value)
    }

    pub(crate) fn prop_get_u64(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u64> {
        let meta = validate_meta(id, idx, ExpectedKind::U64)?;
        let entry = self.prop_borrow_get(io, id, &meta)?;
        entry.prop_get_scalar_u64(id)
    }

    pub(crate) fn prop_set_u64(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u64,
    ) -> HsmResult<()> {
        let meta = validate_set(id, idx, ExpectedKind::U64, None)?;
        let entry = self.prop_borrow_set(io, id, &meta)?;
        entry.prop_set_scalar_u64(id, value)
    }

    pub(crate) fn prop_get_bool(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
    ) -> HsmResult<bool> {
        let meta = validate_meta(id, idx, ExpectedKind::Bool)?;
        let entry = self.prop_borrow_get(io, id, &meta)?;
        Ok(entry.prop_get_scalar(id)? != 0)
    }

    pub(crate) fn prop_set_bool(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: bool,
    ) -> HsmResult<()> {
        let meta = validate_set(id, idx, ExpectedKind::Bool, None)?;
        let entry = self.prop_borrow_set(io, id, &meta)?;
        entry.prop_set_scalar(id, u32::from(value))
    }

    pub(crate) fn prop_get_bytes<'a>(
        &'a self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
    ) -> HsmResult<&'a DmaBuf> {
        let meta = validate_meta(id, idx, ExpectedKind::Bytes)?;
        // Sensitive PAL-global indexed seeds (MFGR_SEED / DEV_OWNER_SEED)
        // are not held per-partition: gate via the standard
        // `prop_borrow_get` (so the sensitive-prop serving-partition
        // check still runs) and then dispatch to the global row table.
        if matches!(id, PartPropId::MFGR_SEED | PartPropId::DEV_OWNER_SEED) {
            let _ = self.prop_borrow_get(io, id, &meta)?;
            let bytes = std_indexed_seed_row(id, idx)?;
            return Ok(dma(bytes));
        }
        let entry = self.prop_borrow_get(io, id, &meta)?;
        let bytes = entry.prop_get_bytes(id)?;
        if let PartPropKind::FixedBytes { len } = meta.kind {
            if bytes.len() != usize::from(len) {
                return Err(HsmError::InternalError);
            }
        }
        Ok(dma(bytes))
    }

    pub(crate) fn prop_set_bytes(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        data: &DmaBuf,
    ) -> HsmResult<()> {
        let meta = validate_set(id, idx, ExpectedKind::Bytes, Some(data.len()))?;
        let entry = self.prop_borrow_set(io, id, &meta)?;
        entry.prop_set_bytes(id, data)
    }

    pub(crate) fn prop_clear(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<()> {
        let meta = validate_clear(id, idx)?;
        let entry = self.prop_borrow_set(io, id, &meta)?;
        entry.prop_clear(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_entry() -> PartitionEntry {
        PartitionEntry::default()
    }

    #[test]
    fn validate_meta_rejects_unknown_id() {
        let bad = PartPropId::from(0xFFFFu16);
        assert!(matches!(
            validate_meta(bad, 0, ExpectedKind::U8),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn validate_meta_rejects_idx_out_of_range() {
        assert!(matches!(
            validate_meta(PartPropId::STATE, 1, ExpectedKind::U8),
            Err(HsmError::InvalidArg)
        ));
        // Indexed seed props have cardinality 64; idx == 64 is OOB.
        assert!(matches!(
            validate_meta(PartPropId::MFGR_SEED, 64, ExpectedKind::Bytes),
            Err(HsmError::InvalidArg)
        ));
        assert!(matches!(
            validate_meta(PartPropId::DEV_OWNER_SEED, 64, ExpectedKind::Bytes),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn indexed_seed_row0_returns_provisioned_bytes() {
        // Row 0 is the only provisioned row in the std PAL.
        let row = std_indexed_seed_row(PartPropId::MFGR_SEED, 0).unwrap();
        assert_eq!(row, &STD_MFGR_SEED_ROW0[..]);
        let row = std_indexed_seed_row(PartPropId::DEV_OWNER_SEED, 0).unwrap();
        assert_eq!(row, &STD_DEV_OWNER_SEED_ROW0[..]);
    }

    #[test]
    fn indexed_seed_unprovisioned_rows_return_not_found() {
        for idx in [1u16, 5, 63] {
            assert!(matches!(
                std_indexed_seed_row(PartPropId::MFGR_SEED, idx),
                Err(HsmError::PartPropNotFound)
            ));
            assert!(matches!(
                std_indexed_seed_row(PartPropId::DEV_OWNER_SEED, idx),
                Err(HsmError::PartPropNotFound)
            ));
        }
    }

    #[test]
    fn validate_meta_rejects_kind_mismatch() {
        // STATE is U8; asking via U32 must fail.
        assert!(matches!(
            validate_meta(PartPropId::STATE, 0, ExpectedKind::U32),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn validate_set_rejects_ro_props() {
        // GEN is Ro.
        assert!(matches!(
            validate_set(PartPropId::GEN, 0, ExpectedKind::U32, None),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn validate_set_rejects_bad_bytes_len() {
        // POLICY is FixedBytes{PART_POLICY_LEN}; wrong len rejected.
        assert!(matches!(
            validate_set(
                PartPropId::POLICY,
                0,
                ExpectedKind::Bytes,
                Some(PART_POLICY_LEN + 1)
            ),
            Err(HsmError::InvalidArg)
        ));
        // SEALED_BK3 is VarBytes{SEALED_BK3_MAX_LEN}; over max rejected.
        assert!(matches!(
            validate_set(
                PartPropId::SEALED_BK3,
                0,
                ExpectedKind::Bytes,
                Some(usize::from(SEALED_BK3_MAX_LEN) + 1)
            ),
            Err(HsmError::InvalidArg)
        ));
        // SEALED_BK3 accepts <= max (including zero).
        assert!(validate_set(PartPropId::SEALED_BK3, 0, ExpectedKind::Bytes, Some(0)).is_ok());
    }

    #[test]
    fn validate_clear_rejects_required_present() {
        // NONCE is Required + Ro.
        assert!(matches!(
            validate_clear(PartPropId::NONCE, 0),
            Err(HsmError::InvalidArg)
        ));
        // PSK_CO is Required + Rw; clear still rejected.
        assert!(matches!(
            validate_clear(PartPropId::PSK_CO, 0),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn scalar_round_trip_mk_key_id() {
        let mut e = fresh_entry();
        // Absent until set.
        assert!(matches!(
            e.prop_get_scalar(PartPropId::MK_KEY_ID),
            Err(HsmError::PartPropNotFound)
        ));
        e.prop_set_scalar(PartPropId::MK_KEY_ID, 0x4242).unwrap();
        assert_eq!(e.prop_get_scalar(PartPropId::MK_KEY_ID).unwrap(), 0x4242u32);
        e.prop_clear(PartPropId::MK_KEY_ID).unwrap();
        assert!(matches!(
            e.prop_get_scalar(PartPropId::MK_KEY_ID),
            Err(HsmError::PartPropNotFound)
        ));
    }

    #[test]
    fn scalar_state_round_trip() {
        let mut e = fresh_entry();
        assert_eq!(e.prop_get_scalar(PartPropId::STATE).unwrap(), 0); // Unallocated
                                                                      // No-op writes (same → same) are accepted.
        e.prop_set_scalar(PartPropId::STATE, PartState::Unallocated as u32)
            .unwrap();
        // Invalid state byte rejected.
        assert!(matches!(
            e.prop_set_scalar(PartPropId::STATE, 250),
            Err(HsmError::InvalidArg)
        ));
        // Caller-facing transition Unallocated → Enabled is rejected
        // (must go through PAL-internal lifecycle methods).
        assert!(matches!(
            e.prop_set_scalar(PartPropId::STATE, PartState::Enabled as u32),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn scalar_state_enabled_to_initializing_requires_provisioning_fields() {
        let mut e = fresh_entry();
        e.state = PartState::Enabled;
        // Missing all four write-once fields → reject.
        assert!(matches!(
            e.prop_set_scalar(PartPropId::STATE, PartState::Initializing as u32),
            Err(HsmError::InvalidArg)
        ));
        // Set the four required fields then transition.
        e.pta_key_id = Some(HsmKeyId::from(1u16));
        e.ups_key_id = Some(HsmKeyId::from(2u16));
        e.part_policy_buf = Some([0u8; PART_POLICY_LEN]);
        e.pota_thumbprint = Some([0u8; 48]);
        e.prop_set_scalar(PartPropId::STATE, PartState::Initializing as u32)
            .unwrap();
        assert_eq!(
            e.prop_get_scalar(PartPropId::STATE).unwrap(),
            PartState::Initializing as u32
        );
    }

    #[test]
    fn scalar_state_other_transitions_rejected_via_prop() {
        let mut e = fresh_entry();
        e.state = PartState::Enabled;
        // Enabled → Disabled must go through part_disable_internal.
        assert!(matches!(
            e.prop_set_scalar(PartPropId::STATE, PartState::Disabled as u32),
            Err(HsmError::InvalidArg)
        ));
        // Enabled → Allocated is nonsense.
        assert!(matches!(
            e.prop_set_scalar(PartPropId::STATE, PartState::Allocated as u32),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn bytes_round_trip_policy() {
        let mut e = fresh_entry();
        assert!(matches!(
            e.prop_get_bytes(PartPropId::POLICY),
            Err(HsmError::PartPropNotFound)
        ));
        let payload = [0xABu8; PART_POLICY_LEN];
        e.prop_set_bytes(PartPropId::POLICY, &payload).unwrap();
        assert_eq!(e.prop_get_bytes(PartPropId::POLICY).unwrap(), &payload[..]);
        e.prop_clear(PartPropId::POLICY).unwrap();
        assert!(matches!(
            e.prop_get_bytes(PartPropId::POLICY),
            Err(HsmError::PartPropNotFound)
        ));
    }

    #[test]
    fn bytes_round_trip_sealed_bk3_var() {
        let mut e = fresh_entry();
        let payload = [0x12u8; 40];
        e.prop_set_bytes(PartPropId::SEALED_BK3, &payload).unwrap();
        assert_eq!(
            e.prop_get_bytes(PartPropId::SEALED_BK3).unwrap(),
            &payload[..]
        );
        e.prop_clear(PartPropId::SEALED_BK3).unwrap();
        assert!(matches!(
            e.prop_get_bytes(PartPropId::SEALED_BK3),
            Err(HsmError::PartPropNotFound)
        ));
    }

    #[test]
    fn sensitive_set_zeroizes_prior() {
        let mut e = fresh_entry();
        // Prime CREDENTIAL with payload A, clear, then set payload B,
        // confirming the entire id/pin region is rewritten cleanly.
        // `prop_set_bytes` is now write-once, so reuse requires an
        // explicit `prop_clear` between sets.
        let payload_a = [0xAAu8; 32];
        let mut payload_b = [0u8; 32];
        for (i, b) in payload_b.iter_mut().enumerate() {
            *b = (i as u8) | 0x80;
        }
        e.prop_set_bytes(PartPropId::CREDENTIAL, &payload_a)
            .unwrap();
        e.prop_clear(PartPropId::CREDENTIAL).unwrap();
        e.prop_set_bytes(PartPropId::CREDENTIAL, &payload_b)
            .unwrap();
        let stored = e.prop_get_bytes(PartPropId::CREDENTIAL).unwrap();
        assert_eq!(stored, &payload_b[..]);
        // Clear zeroes the full 32 B blob.
        e.prop_clear(PartPropId::CREDENTIAL).unwrap();
        assert!(matches!(
            e.prop_get_bytes(PartPropId::CREDENTIAL),
            Err(HsmError::PartPropNotFound)
        ));
        assert_eq!(&e.credential[..], &[0u8; 32]);
    }

    #[test]
    fn credential_prop_set_is_write_once() {
        let mut e = fresh_entry();
        let payload = [0x5Au8; 32];
        e.prop_set_bytes(PartPropId::CREDENTIAL, &payload).unwrap();
        // Second set without an intervening clear is rejected.
        assert!(matches!(
            e.prop_set_bytes(PartPropId::CREDENTIAL, &payload),
            Err(HsmError::VaultAppLimitReached)
        ));
    }

    #[test]
    fn credential_prop_set_rejects_zero_halves() {
        let mut e = fresh_entry();
        // Zero id half.
        let mut payload = [0u8; 32];
        payload[16..].copy_from_slice(&[0x33u8; 16]);
        assert!(matches!(
            e.prop_set_bytes(PartPropId::CREDENTIAL, &payload),
            Err(HsmError::InvalidAppCredentials)
        ));
        // Zero pin half.
        let mut payload = [0u8; 32];
        payload[..16].copy_from_slice(&[0x33u8; 16]);
        assert!(matches!(
            e.prop_set_bytes(PartPropId::CREDENTIAL, &payload),
            Err(HsmError::InvalidAppCredentials)
        ));
        // Both zero.
        assert!(matches!(
            e.prop_set_bytes(PartPropId::CREDENTIAL, &[0u8; 32]),
            Err(HsmError::InvalidAppCredentials)
        ));
    }

    #[test]
    fn psk_get_returns_default_when_absent() {
        let e = fresh_entry();
        assert_eq!(
            e.prop_get_bytes(PartPropId::PSK_CO).unwrap(),
            DEFAULT_PSK_CO.as_slice()
        );
        assert_eq!(
            e.prop_get_bytes(PartPropId::PSK_CU).unwrap(),
            DEFAULT_PSK_CU.as_slice()
        );
    }

    // ── Phase A new-id coverage ────────────────────────────────────

    #[test]
    fn bk3_initialized_one_shot_transition() {
        let mut e = fresh_entry();
        // Reads via scalar widening (Bool maps to 0/1 in prop_get_scalar).
        assert_eq!(e.prop_get_scalar(PartPropId::BK3_INITIALIZED).unwrap(), 0);
        // First true write succeeds.
        e.prop_set_scalar(PartPropId::BK3_INITIALIZED, 1).unwrap();
        assert_eq!(e.prop_get_scalar(PartPropId::BK3_INITIALIZED).unwrap(), 1);
        assert!(e.bk3_initialized);
        // Re-asserting true returns Bk3AlreadyInitialized.
        assert!(matches!(
            e.prop_set_scalar(PartPropId::BK3_INITIALIZED, 1),
            Err(HsmError::Bk3AlreadyInitialized)
        ));
        // Clearing back to false is rejected.
        assert!(matches!(
            e.prop_set_scalar(PartPropId::BK3_INITIALIZED, 0),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn bk3_initialized_accepts_bool_writes() {
        // The trait-level Bool setter (validate_set with ExpectedKind::Bool)
        // is now accepted because BK3_INITIALIZED is Rw.
        assert!(validate_set(PartPropId::BK3_INITIALIZED, 0, ExpectedKind::Bool, None).is_ok());
        // U8-kind requests are rejected by the kind mismatch.
        assert!(matches!(
            validate_set(PartPropId::BK3_INITIALIZED, 0, ExpectedKind::U8, None),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn bks2_id_returns_constant_zero() {
        let e = fresh_entry();
        assert_eq!(e.prop_get_scalar(PartPropId::BKS2_ID).unwrap(), 0);
    }

    #[test]
    fn bks2_id_is_read_only() {
        assert!(matches!(
            validate_set(PartPropId::BKS2_ID, 0, ExpectedKind::U16, None),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn id_pub_key_returns_fixed_size_buffer() {
        let mut e = fresh_entry();
        e.id_pub_key[0] = 0xAA;
        let got = e.prop_get_bytes(PartPropId::ID_PUB_KEY).unwrap();
        assert_eq!(got.len(), 96);
        assert_eq!(got[0], 0xAA);
    }

    #[test]
    fn id_pub_key_is_read_only() {
        assert!(matches!(
            validate_set(PartPropId::ID_PUB_KEY, 0, ExpectedKind::Bytes, Some(96)),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn session_enc_pub_key_returns_field() {
        let mut e = fresh_entry();
        e.session_enc_pub_key[1] = 0x5A;
        let got = e.prop_get_bytes(PartPropId::SESSION_ENC_PUB_KEY).unwrap();
        assert_eq!(got.len(), 96);
        assert_eq!(got[1], 0x5A);
    }

    #[test]
    fn establish_cred_pub_key_returns_field() {
        let mut e = fresh_entry();
        e.establish_cred_pub_key[95] = 0x77;
        let got = e
            .prop_get_bytes(PartPropId::ESTABLISH_CRED_PUB_KEY)
            .unwrap();
        assert_eq!(got.len(), 96);
        assert_eq!(got[95], 0x77);
    }

    #[test]
    fn pta_pub_sec1_round_trip() {
        let mut e = fresh_entry();
        assert!(matches!(
            e.prop_get_bytes(PartPropId::PTA_PUB_SEC1),
            Err(HsmError::PartPropNotFound)
        ));
        let payload = [0x33u8; P384_PUB_SEC1_LEN];
        e.prop_set_bytes(PartPropId::PTA_PUB_SEC1, &payload)
            .unwrap();
        assert_eq!(
            e.prop_get_bytes(PartPropId::PTA_PUB_SEC1).unwrap(),
            &payload[..]
        );
        e.prop_clear(PartPropId::PTA_PUB_SEC1).unwrap();
        assert!(matches!(
            e.prop_get_bytes(PartPropId::PTA_PUB_SEC1),
            Err(HsmError::PartPropNotFound)
        ));
    }

    #[test]
    fn pta_pub_sec1_wrong_size_rejected() {
        assert!(matches!(
            validate_set(
                PartPropId::PTA_PUB_SEC1,
                0,
                ExpectedKind::Bytes,
                Some(P384_PUB_SEC1_LEN - 1)
            ),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn bk3_session_round_trip_and_zeroize() {
        let mut e = fresh_entry();
        assert!(matches!(
            e.prop_get_bytes(PartPropId::BK3_SESSION),
            Err(HsmError::PartPropNotFound)
        ));
        let payload = [0x9Eu8; 48];
        e.prop_set_bytes(PartPropId::BK3_SESSION, &payload).unwrap();
        assert_eq!(
            e.prop_get_bytes(PartPropId::BK3_SESSION).unwrap(),
            &payload[..]
        );
        e.prop_clear(PartPropId::BK3_SESSION).unwrap();
        assert!(matches!(
            e.prop_get_bytes(PartPropId::BK3_SESSION),
            Err(HsmError::PartPropNotFound)
        ));
        // Clear must zeroize the backing field.
        assert_eq!(&e.bk3_session[..], &[0u8; 48]);
    }

    #[test]
    fn bk3_session_marked_sensitive_in_catalogue() {
        let meta = PartPropId::BK3_SESSION.meta().unwrap();
        assert!(meta.sensitive);
    }
}
