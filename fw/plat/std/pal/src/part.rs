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
pub(crate) const VM_LAUNCH_GUID_LEN: usize = 16;

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

/// Length of a single backup-key seed (`BKS1`, `BKS2`) row used by
/// [`HsmPartitionManager::derive_masking_key`] in bytes.
const BK_SEED_LEN: usize = 32;

/// Hardcoded std PAL firmware boot seed used as the KDK input to
/// [`HsmPartitionManager::derive_masking_key`].
///
/// Real hardware reads this from a one-time-programmed, device-bound
/// hardware register that is not visible outside the secure-world
/// firmware.  The std PAL emulator uses a fixed pattern so tests are
/// deterministic.  The seed never crosses the trait boundary; callers
/// only see derived masking keys.
const STD_FW_SEED: [u8; 48] = [0x42u8; 48];

/// Hardcoded std PAL `BKS1` seed row used as the first half of the
/// KDF context in [`HsmPartitionManager::derive_masking_key`].
///
/// Real hardware selects this row from a `BKS1` table indexed by SVN;
/// the std PAL emulator has a single row because the simulator models
/// a single SVN.  The bytes are taken from the prior reference
/// firmware so derived masking keys are bit-compatible with persisted
/// `Masked_BK_BOOT` blobs across emulator and real hardware.
const STD_BKS1: [u8; BK_SEED_LEN] = [
    0x9b, 0x4e, 0x4e, 0xb7, 0xad, 0xab, 0xdc, 0xd6, 0xb4, 0xd5, 0x07, 0xeb, 0x68, 0xeb, 0x26, 0x99,
    0x2a, 0xbb, 0xca, 0xb5, 0x5c, 0xfb, 0x77, 0x3b, 0xc4, 0xd0, 0xa8, 0x8c, 0x21, 0x02, 0xb0, 0xac,
];

/// Hardcoded std PAL `BKS2` seed row used as the second half of the
/// KDF context in [`HsmPartitionManager::derive_masking_key`].
///
/// Real hardware selects this row from a `BKS2` table indexed by
/// `bks2_index`; the std PAL emulator has a single row because the
/// simulator models a single partition lineage.  The bytes are taken
/// from the prior reference firmware for bit-compatibility.
const STD_BKS2: [u8; BK_SEED_LEN] = [
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
    pub(crate) establish_cred_key_id: Option<HsmKeyId>,

    /// DER-encoded public key for establish-credential encryption.
    establish_cred_pub_key: [u8; P384_PUB_KEY_LEN],

    /// Vault key ID for the session encryption ECC-384 key.
    /// `None` before enable.
    pub(crate) session_enc_key_id: Option<HsmKeyId>,

    /// Raw public key coordinates (x ∥ y) for session encryption.
    session_enc_pub_key: [u8; P384_PUB_KEY_LEN],

    /// 32-byte random nonce, generated on enable and refreshable.
    pub(crate) nonce: [u8; NONCE_LEN],

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

    /// User credential ID (16 bytes).  Zeroed until set by
    /// `part_set_credential`.
    credential_id: [u8; 16],

    /// User credential PIN (16 bytes).  Zeroed until set by
    /// `part_set_credential`.
    credential_pin: [u8; 16],

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
    ums_key_id: Option<HsmKeyId>,

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
            credential_id: [0u8; 16],
            credential_pin: [0u8; 16],
            credential_set: false,
            bk3_session: [0u8; 48],
            bk3_session_set: false,
            mk_key_id: None,
            unwrapping_key_id: None,
            psk_co: None,
            psk_cu: None,
            pta_key_id: None,
            ums_key_id: None,
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
    /// Returns the current state of the calling partition (`io.pid()`).
    fn part_state(&self, io: &impl HsmIo) -> HsmResult<PartState> {
        // SAFETY: Embassy is single-threaded. This synchronous method
        // completes without yielding, so no concurrent mutation occurs.
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(io.pid()) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        Ok(table.entries[idx].state)
    }

    /// Returns the resource count allocated to the calling partition.
    fn part_res_count(&self, io: &impl HsmIo) -> HsmResult<u8> {
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(io.pid()) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }
        Ok(entry.res_mask.count_ones() as u8)
    }

    /// Returns the 16-byte identity blob for the calling partition.
    fn part_id(&self, io: &impl HsmIo) -> HsmResult<PartId<'_>> {
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(io.pid()) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }
        Ok(&entry.id)
    }

    fn part_id_key_id(&self, io: &impl HsmIo) -> HsmResult<HsmKeyId> {
        self.active_part(io.pid())?
            .id_key_id
            .ok_or(HsmError::InternalError)
    }

    fn part_id_pub_key(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize> {
        copy_out(&self.active_part(io.pid())?.id_pub_key, out)
    }

    fn part_establish_cred_key_id(&self, io: &impl HsmIo) -> HsmResult<Option<HsmKeyId>> {
        Ok(self.enabled_part(u8::from(io.pid()))?.establish_cred_key_id)
    }

    fn part_establish_cred_pub_key(
        &self,
        io: &impl HsmIo,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        // Stored internally as big-endian `x ∥ y` (OpenSSL convention).
        // The wire contract — matching real PKA hardware — is
        // little-endian, and the host-side `post_decode_fn` on
        // `DdiDerPublicKey` reverses each coord back to big-endian
        // before DER-encoding.  Reverse each coord here so the wire
        // bytes are LE.
        let raw = &self
            .enabled_part(u8::from(io.pid()))?
            .establish_cred_pub_key;
        copy_out_pub_key_le(raw, out)
    }

    fn part_session_enc_key_id(&self, io: &impl HsmIo) -> HsmResult<HsmKeyId> {
        self.enabled_part(u8::from(io.pid()))?
            .session_enc_key_id
            .ok_or(HsmError::InternalError)
    }

    fn part_session_enc_pub_key(
        &self,
        io: &impl HsmIo,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        // Stored internally as big-endian `x ∥ y` (OpenSSL convention).
        // The wire contract — matching real PKA hardware — is
        // little-endian, and the host-side `post_decode_fn` on
        // `DdiDerPublicKey` reverses each coord back to big-endian
        // before DER-encoding.  Reverse each coord here so the wire
        // bytes are LE.
        let raw = &self.enabled_part(u8::from(io.pid()))?.session_enc_pub_key;
        copy_out_pub_key_le(raw, out)
    }

    fn part_clear_establish_cred_key(&self, io: &impl HsmIo) -> HsmResult<()> {
        let entry = self.enabled_part_mut(u8::from(io.pid()))?;
        if let Some(kid) = entry.establish_cred_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.establish_cred_pub_key.fill(0);
        Ok(())
    }

    fn part_nonce(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize> {
        copy_out(&self.enabled_part(u8::from(io.pid()))?.nonce, out)
    }

    fn part_nonce_refresh(&self, io: &impl HsmIo) -> HsmResult<()> {
        let entry = self.enabled_part_mut(u8::from(io.pid()))?;
        Rng::rand_bytes(&mut entry.nonce).map_err(|_| HsmError::InternalError)
    }

    fn part_sealed_bk3(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize> {
        let entry = self.active_part(io.pid())?;
        let len = entry.sealed_bk3_len as usize;
        copy_out(&entry.sealed_bk3[..len], out)
    }

    fn part_set_sealed_bk3(&self, io: &impl HsmIo, data: &[u8]) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        if entry.sealed_bk3_len != 0 {
            return Err(HsmError::SealedBk3AlreadySet);
        }
        if data.len() > SEALED_BK3_SIZE {
            return Err(HsmError::SealedBk3TooLarge);
        }
        entry.sealed_bk3[..data.len()].copy_from_slice(data);
        entry.sealed_bk3_len = data.len() as u32;
        Ok(())
    }

    fn part_vm_launch_guid(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize> {
        let entry = self.active_part(io.pid())?;
        copy_out(&entry.vm_launch_guid, out)
    }

    fn part_svn(&self, io: &impl HsmIo) -> HsmResult<u64> {
        // Validate enabled state but discard the borrow; the value is a
        // platform constant on the std PAL.
        let _entry = self.active_part(io.pid())?;
        Ok(STD_SVN)
    }

    fn part_bks2_id(&self, io: &impl HsmIo) -> HsmResult<u16> {
        // No BKS2 selector modelled in the emulator; return slot 0 for
        // wire-format compatibility.
        let _entry = self.active_part(io.pid())?;
        Ok(0)
    }

    fn part_bk_boot(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize> {
        let entry = self.active_part(io.pid())?;
        if let Some(buf) = out {
            if buf.len() < BK_BOOT_LEN {
                return Err(HsmError::InvalidArg);
            }
            buf[..BK_BOOT_LEN].copy_from_slice(&entry.bk_boot);
        }
        Ok(BK_BOOT_LEN)
    }

    fn part_is_bk3_initialized(&self, io: &impl HsmIo) -> HsmResult<bool> {
        let entry = self.enabled_part(u8::from(io.pid()))?;
        Ok(entry.bk3_initialized)
    }

    fn part_mark_bk3_initialized(&self, io: &impl HsmIo) -> HsmResult<()> {
        let entry = self.enabled_part_mut(u8::from(io.pid()))?;
        if entry.bk3_initialized {
            return Err(HsmError::Bk3AlreadyInitialized);
        }
        entry.bk3_initialized = true;
        Ok(())
    }

    fn part_masked_bk_boot(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize> {
        let entry = self.enabled_part(u8::from(io.pid()))?;
        let len = entry.masked_bk_boot_len as usize;
        copy_out(&entry.masked_bk_boot[..len], out)
    }

    fn part_set_masked_bk_boot(&self, io: &impl HsmIo, data: &[u8]) -> HsmResult<()> {
        if data.len() > MASKED_BK_BOOT_LEN {
            return Err(HsmError::InvalidArg);
        }
        let entry = self.enabled_part_mut(u8::from(io.pid()))?;
        entry.masked_bk_boot[..data.len()].copy_from_slice(data);
        entry.masked_bk_boot_len = data.len() as u32;
        Ok(())
    }

    fn fw_seed(&self) -> &[u8] {
        &STD_FW_SEED
    }

    async fn derive_masking_key(
        &self,
        io: &impl HsmIo,
        kdk: &[u8],
        label: &[u8],
        extra_context: &[u8],
        svn: u64,
        bks2_index: u16,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.active_part(io.pid())?;

        // Std PAL models a single SVN + single BKS2 lineage; reject any
        // out-of-range selector.
        if svn != 0 || bks2_index != 0 {
            return Err(HsmError::InvalidArg);
        }

        // Co-locate all KDF inputs (KDK, label, context) in one DMA
        // alloc; pad each region to 4-byte alignment so DMA-driven
        // engines on real hardware see the same layout as
        // per-allocation arrangements.
        let kdk_area_len = kdk.len().next_multiple_of(4);
        let label_area_len = label.len().next_multiple_of(4);
        let ctx_len = STD_BKS1.len() + STD_BKS2.len() + extra_context.len();

        let arena = self.dma_alloc(io, kdk_area_len + label_area_len + ctx_len)?;
        let (kdk_area, rest) = arena.split_at_mut(kdk_area_len);
        let (key_dma, _kdk_pad) = kdk_area.split_at_mut(kdk.len());
        let (label_area, ctx_dma) = rest.split_at_mut(label_area_len);
        let (label_dma, _label_pad) = label_area.split_at_mut(label.len());

        if !kdk.is_empty() {
            key_dma.copy_from_slice(kdk);
        }
        if !label.is_empty() {
            label_dma.copy_from_slice(label);
        }
        {
            let (bks1_slot, ctx_rest) = ctx_dma.split_at_mut(STD_BKS1.len());
            let (bks2_slot, extra_slot) = ctx_rest.split_at_mut(STD_BKS2.len());
            bks1_slot.copy_from_slice(&STD_BKS1);
            bks2_slot.copy_from_slice(&STD_BKS2);
            if !extra_context.is_empty() {
                extra_slot.copy_from_slice(extra_context);
            }
        }

        self.sp800_108_kdf(
            io,
            HsmHashAlgo::Sha384,
            key_dma,
            Some(label_dma),
            Some(ctx_dma),
            output,
        )
        .await
    }

    fn part_verify_nonce(&self, io: &impl HsmIo, nonce: &[u8]) -> HsmResult<()> {
        let part = self.enabled_part(u8::from(io.pid()))?;
        if part.nonce != nonce {
            return Err(HsmError::NonceMismatch);
        }
        Ok(())
    }

    fn part_set_credential(&self, io: &impl HsmIo, id: &[u8], pin: &[u8]) -> HsmResult<()> {
        if id.len() != 16 || pin.len() != 16 {
            return Err(HsmError::InvalidArg);
        }
        let part = self.enabled_part_mut(u8::from(io.pid()))?;
        if part.credential_set {
            return Err(HsmError::VaultAppLimitReached);
        }
        // Reject all-zero ID or PIN — matches the reference firmware's
        // `cred_mgr::change_user_cred` invariant and is also what
        // `verify_user_cred_is_set` uses as the sentinel for "unset".
        if id == [0u8; 16].as_slice() || pin == [0u8; 16].as_slice() {
            return Err(HsmError::InvalidAppCredentials);
        }
        part.credential_id.copy_from_slice(id);
        part.credential_pin.copy_from_slice(pin);
        part.credential_set = true;
        Ok(())
    }

    fn part_is_credential_set(&self, io: &impl HsmIo) -> HsmResult<bool> {
        Ok(self.enabled_part(u8::from(io.pid()))?.credential_set)
    }

    fn part_verify_credential(&self, io: &impl HsmIo, id: &[u8], pin: &[u8]) -> HsmResult<()> {
        if id.len() != 16 || pin.len() != 16 {
            return Err(HsmError::InvalidArg);
        }
        let part = self.enabled_part(u8::from(io.pid()))?;
        if !part.credential_set {
            return Err(HsmError::InvalidAppCredentials);
        }
        // Constant-time compare both fields fully regardless of any
        // mismatch in either, so we don't leak which one was wrong via
        // timing.
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= part.credential_id[i] ^ id[i];
            diff |= part.credential_pin[i] ^ pin[i];
        }
        if diff != 0 {
            return Err(HsmError::InvalidAppCredentials);
        }
        Ok(())
    }

    fn part_is_provisioned(&self, io: &impl HsmIo) -> HsmResult<bool> {
        Ok(self.enabled_part(u8::from(io.pid()))?.mk_key_id.is_some())
    }

    fn part_set_bk3_session(&self, io: &impl HsmIo, data: &[u8]) -> HsmResult<()> {
        if data.len() != 48 {
            return Err(HsmError::InvalidArg);
        }
        let part = self.enabled_part_mut(u8::from(io.pid()))?;
        part.bk3_session.copy_from_slice(data);
        part.bk3_session_set = true;
        Ok(())
    }

    fn part_mk_key_id(&self, io: &impl HsmIo) -> HsmResult<Option<HsmKeyId>> {
        Ok(self.enabled_part(u8::from(io.pid()))?.mk_key_id)
    }

    fn part_set_mk_key_id(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let part = self.enabled_part_mut(u8::from(io.pid()))?;
        part.mk_key_id = Some(key_id);
        Ok(())
    }

    fn part_unwrapping_key_id(&self, io: &impl HsmIo) -> HsmResult<Option<HsmKeyId>> {
        Ok(self.enabled_part(u8::from(io.pid()))?.unwrapping_key_id)
    }

    fn part_set_unwrapping_key_id(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let part = self.enabled_part_mut(u8::from(io.pid()))?;
        part.unwrapping_key_id = Some(key_id);
        Ok(())
    }

    fn part_psk(&self, io: &impl HsmIo, psk_id: u8, out: Option<&mut [u8]>) -> HsmResult<usize> {
        if psk_id > 1 {
            return Err(HsmError::InvalidPskId);
        }
        let part = self.serving_part(io.pid())?;
        let stored: Option<&[u8; PSK_LEN]> = match psk_id {
            0 => part.psk_co.as_ref(),
            _ => part.psk_cu.as_ref(),
        };
        let src: &[u8] = match stored {
            Some(rotated) => rotated.as_slice(),
            None if psk_id == 0 => DEFAULT_PSK_CO.as_slice(),
            None => DEFAULT_PSK_CU.as_slice(),
        };
        match out {
            None => Ok(PSK_LEN),
            Some(buf) => {
                if buf.len() < PSK_LEN {
                    return Err(HsmError::InvalidArg);
                }
                buf[..PSK_LEN].copy_from_slice(src);
                Ok(PSK_LEN)
            }
        }
    }

    fn part_psk_set(&self, io: &impl HsmIo, psk_id: u8, psk: &[u8]) -> HsmResult<()> {
        if psk_id > 1 {
            return Err(HsmError::InvalidPskId);
        }
        if psk.len() != PSK_LEN {
            return Err(HsmError::InvalidArg);
        }
        let part = self.serving_part_mut(io.pid())?;
        let mut buf = [0u8; PSK_LEN];
        buf.copy_from_slice(psk);
        if psk_id == 0 {
            part.psk_co = Some(buf);
        } else {
            part.psk_cu = Some(buf);
        }
        Ok(())
    }

    fn part_uds(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize> {
        copy_out(&self.serving_part(io.pid())?.uds, out)
    }

    fn part_set_pta_key(
        &self,
        io: &impl HsmIo,
        key_id: HsmKeyId,
        pub_sec1: &[u8],
    ) -> HsmResult<()> {
        let part = self.active_part_mut(io.pid())?;
        if pub_sec1.len() != P384_PUB_SEC1_LEN {
            return Err(HsmError::InvalidArg);
        }
        if part.pta_key_id.is_some() {
            return Err(HsmError::PtaKeyAlreadySet);
        }
        if part.state != PartState::Enabled {
            return Err(HsmError::InvalidArg);
        }

        let mut buf = [0u8; P384_PUB_SEC1_LEN];
        buf.copy_from_slice(pub_sec1);
        part.pta_key_id = Some(key_id);
        part.pta_pub_sec1 = Some(buf);
        Ok(())
    }

    fn part_set_policy(&self, io: &impl HsmIo, policy: &[u8]) -> HsmResult<()> {
        let part = self.enabled_part_mut(u8::from(io.pid()))?;
        if policy.len() != PART_POLICY_LEN {
            return Err(HsmError::InvalidArg);
        }
        if part.part_policy_buf.is_some() {
            return Err(HsmError::InvalidArg);
        }

        let mut buf = [0u8; PART_POLICY_LEN];
        buf.copy_from_slice(policy);
        part.part_policy_buf = Some(buf);
        Ok(())
    }

    fn part_set_pota_thumbprint(&self, io: &impl HsmIo, thumb: &[u8]) -> HsmResult<()> {
        let part = self.enabled_part_mut(u8::from(io.pid()))?;
        if thumb.len() != POTA_THUMBPRINT_LEN {
            return Err(HsmError::InvalidArg);
        }
        if part.pota_thumbprint.is_some() {
            return Err(HsmError::InvalidArg);
        }

        let mut buf = [0u8; POTA_THUMBPRINT_LEN];
        buf.copy_from_slice(thumb);
        part.pota_thumbprint = Some(buf);
        Ok(())
    }

    fn part_set_ums_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let part = self.active_part_mut(io.pid())?;
        if part.ums_key_id.is_some() {
            return Err(HsmError::UmsKeyAlreadySet);
        }
        if part.state != PartState::Enabled {
            return Err(HsmError::InvalidArg);
        }
        part.ums_key_id = Some(key_id);
        Ok(())
    }

    fn part_ums_key_id(&self, io: &impl HsmIo) -> HsmResult<HsmKeyId> {
        let part = self.active_part(io.pid())?;
        part.ums_key_id.ok_or(HsmError::UmsKeyNotSet)
    }

    fn part_mark_initializing(&self, io: &impl HsmIo) -> HsmResult<()> {
        let part = self.enabled_part_mut(u8::from(io.pid()))?;
        if part.pta_key_id.is_none()
            || part.ums_key_id.is_none()
            || part.part_policy_buf.is_none()
            || part.pota_thumbprint.is_none()
        {
            return Err(HsmError::InvalidArg);
        }
        part.state = PartState::Initializing;
        Ok(())
    }

    fn part_psk_is_default(&self, io: &impl HsmIo, psk_id: u8) -> HsmResult<bool> {
        if psk_id > 1 {
            return Err(HsmError::InvalidPskId);
        }
        let part = self.active_part(io.pid())?;
        // Authoritative byte-compare against the compiled-in default,
        // not just `Option::is_some()`.  This way the gate cannot be
        // bypassed by a (malformed/malicious) `ChangePsk` that writes
        // the public default bytes back into the slot — the slot then
        // shows up as `Some(default)`, but `is_default` still reports
        // `true` because the effective PSK is still the public one.
        let stored: &[u8] = match psk_id {
            0 => part.psk_co.as_ref().map_or(&DEFAULT_PSK_CO[..], |k| &k[..]),
            _ => part.psk_cu.as_ref().map_or(&DEFAULT_PSK_CU[..], |k| &k[..]),
        };
        let default: &[u8] = match psk_id {
            0 => &DEFAULT_PSK_CO[..],
            _ => &DEFAULT_PSK_CU[..],
        };
        Ok(stored == default)
    }
}

// ---------------------------------------------------------------------------
// Shared partition access helpers (used by vault.rs, session.rs, etc.)
// ---------------------------------------------------------------------------

impl StdHsmPal {
    /// Returns the partition incarnation counter.
    ///
    /// Captured by RAII guards (`StdVaultKeyGuard`, `StdSessionGuard`)
    /// at create time; if the value differs at drop time, the guard
    /// has outlived its partition incarnation and skips rollback to
    /// avoid corrupting a re-allocated partition.
    pub(crate) fn partition_gen(&self, pid: HsmPartId) -> u32 {
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return 0;
        }
        table.entries[idx].gen
    }

    /// Borrow a partition entry that is not Unallocated.
    pub(crate) fn active_part(&self, pid: HsmPartId) -> HsmResult<&PartitionEntry> {
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }
        Ok(&table.entries[idx])
    }

    /// Borrow a partition entry that is not Unallocated (mutable).
    #[allow(clippy::mut_from_ref)]
    pub(crate) fn active_part_mut(&self, pid: HsmPartId) -> HsmResult<&mut PartitionEntry> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }
        Ok(&mut table.entries[idx])
    }

    /// Borrow a partition that is actively serving host traffic.
    ///
    /// "Serving" means [`PartState::Enabled`] or
    /// [`PartState::Initializing`] — i.e. the partition is bound to a
    /// caller's incarnation and may legitimately expose per-incarnation
    /// secrets (PSK, UDS).  Stricter than [`Self::active_part`] (which
    /// permits Allocated and Disabled too) so that PSK/UDS reads cannot
    /// leak across the allocate/enable boundary, and looser than
    /// [`Self::enabled_part`] so that PartInit handlers running in
    /// `Initializing` still observe the rotated PSKs and UDS.
    fn serving_part(&self, pid: HsmPartId) -> HsmResult<&PartitionEntry> {
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if !matches!(
            table.entries[idx].state,
            PartState::Enabled | PartState::Initializing
        ) {
            return Err(HsmError::InvalidArg);
        }
        Ok(&table.entries[idx])
    }

    /// Mutable counterpart to [`Self::serving_part`].
    #[allow(clippy::mut_from_ref)]
    fn serving_part_mut(&self, pid: HsmPartId) -> HsmResult<&mut PartitionEntry> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if !matches!(
            table.entries[idx].state,
            PartState::Enabled | PartState::Initializing
        ) {
            return Err(HsmError::InvalidArg);
        }
        Ok(&mut table.entries[idx])
    }

    /// Borrow a partition that is in Enabled state.
    fn enabled_part(&self, pid: u8) -> HsmResult<&PartitionEntry> {
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state != PartState::Enabled {
            return Err(HsmError::InvalidArg);
        }
        Ok(&table.entries[idx])
    }

    /// Borrow a partition that is in Enabled state (mutable).
    #[allow(clippy::mut_from_ref)]
    fn enabled_part_mut(&self, pid: u8) -> HsmResult<&mut PartitionEntry> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state != PartState::Enabled {
            return Err(HsmError::InvalidArg);
        }
        Ok(&mut table.entries[idx])
    }
}

/// Copy `data` into `out` if provided, return length.
///
/// Returns [`HsmError::InvalidArg`] (per the new partition trait
/// docs) when the caller-supplied buffer is too small.
fn copy_out(data: &[u8], out: Option<&mut [u8]>) -> HsmResult<usize> {
    if let Some(buf) = out {
        if buf.len() < data.len() {
            return Err(HsmError::InvalidArg);
        }
        buf[..data.len()].copy_from_slice(data);
    }
    Ok(data.len())
}

/// Copy a raw P-384 public key (`x ∥ y`, big-endian) into `out`,
/// reversing each coord so the bytes on the wire are little-endian.
///
/// This is the byte-order pivot point between the firmware's internal
/// big-endian representation (matches OpenSSL conventions and is used
/// by cert generation and other crypto consumers) and the wire contract
/// expected by the host-side `post_decode_fn` on
/// [`DdiDerPublicKey`](azihsm_ddi_types::DdiDerPublicKey), which expects
/// little-endian raw coords (matching real PKA hardware) and reverses
/// them back to big-endian before DER-encoding.
///
/// `data` must be exactly `P384_PUB_KEY_LEN` bytes; returns
/// [`HsmError::InvalidArg`] when `out` is too small.
fn copy_out_pub_key_le(data: &[u8; P384_PUB_KEY_LEN], out: Option<&mut [u8]>) -> HsmResult<usize> {
    if let Some(buf) = out {
        if buf.len() < P384_PUB_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        let half = P384_PUB_KEY_LEN / 2;
        let (x_be, y_be) = data.split_at(half);
        let (x_out, y_out) = buf.split_at_mut(half);
        for (dst, src) in x_out.iter_mut().zip(x_be.iter().rev()) {
            *dst = *src;
        }
        for (dst, src) in y_out[..half].iter_mut().zip(y_be.iter().rev()) {
            *dst = *src;
        }
    }
    Ok(P384_PUB_KEY_LEN)
}

// ---------------------------------------------------------------------------
// Internal partition lifecycle (called by part_cmd_task on Embassy thread)
// ---------------------------------------------------------------------------

impl StdHsmPal {
    /// Allocate a partition: generate identity and ECC-384 key pair.
    ///
    /// Transitions `Unallocated → Allocated`.
    pub async fn part_alloc_internal(&self, pid: u8, res_mask: u128) -> HsmResult<()> {
        let table = unsafe { &mut *self.part_table.get() };
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
        let table = unsafe { &mut *self.part_table.get() };
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
        let table = unsafe { &mut *self.part_table.get() };
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
            let table = unsafe { &mut *self.part_table.get() };
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

        let table = unsafe { &mut *self.part_table.get() };
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

        let table = unsafe { &mut *self.part_table.get() };
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
        let table = unsafe { &mut *self.part_table.get() };
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
        let table = unsafe { &mut *self.part_table.get() };
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
        let table = unsafe { &mut *self.part_table.get() };
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
        if let Some(kid) = entry.establish_cred_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.establish_cred_pub_key.fill(0);

        if let Some(kid) = entry.session_enc_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.session_enc_pub_key.fill(0);

        entry.nonce.fill(0);

        // Take id_key_id BEFORE vault.clear() so part_enable_internal
        // knows the identity key was wiped and needs to be regenerated.
        // The cached leaf cert is keyed off the old id_pub_key so it
        // must also be invalidated.
        entry.id_key_id = None;
        entry.leaf_cert[..entry.leaf_cert_len].fill(0);
        entry.leaf_cert_len = 0;

        entry.vault.clear();
        entry.session_table = SessionTable::new();
        entry.sealed_bk3[..entry.sealed_bk3_len as usize].fill(0);
        entry.sealed_bk3_len = 0;

        // Boot-key + BK3-incarnation state — mirrors the prior
        // reference firmware's `clear_partition_info` zeroize
        // grouping.
        entry.bk_boot.fill(0);
        entry.masked_bk_boot[..entry.masked_bk_boot_len as usize].fill(0);
        entry.masked_bk_boot_len = 0;
        entry.vm_launch_guid.fill(0);
        entry.bk3_initialized = false;

        entry.credential_id.fill(0);
        entry.credential_pin.fill(0);
        entry.credential_set = false;
        entry.bk3_session.fill(0);
        entry.bk3_session_set = false;
        if let Some(kid) = entry.mk_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        if let Some(kid) = entry.unwrapping_key_id.take() {
            let _ = entry.vault.delete(kid);
        }

        if let Some(kid) = entry.pta_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        if let Some(kid) = entry.ums_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        if let Some(pub_sec1) = entry.pta_pub_sec1.as_mut() {
            pub_sec1.fill(0);
        }
        entry.pta_pub_sec1 = None;
        if let Some(policy) = entry.part_policy_buf.as_mut() {
            policy.fill(0);
        }
        entry.part_policy_buf = None;
        if let Some(thumb) = entry.pota_thumbprint.as_mut() {
            thumb.fill(0);
        }
        entry.pota_thumbprint = None;

        // Wipe rotated PSK material in place before dropping the
        // `Option`.  Using `as_mut().fill(0)` ensures the bytes that
        // live inside `entry`'s `Option<[u8; PSK_LEN]>` payload are
        // overwritten on the struct itself; the subsequent
        // `= None` write only changes the discriminant and leaves
        // those zeros in place (an `Option<[u8; N]>` has no niche so
        // the payload bytes are stable storage, not a reused
        // tagged-union slot).
        if let Some(psk) = entry.psk_co.as_mut() {
            psk.fill(0);
        }
        entry.psk_co = None;
        if let Some(psk) = entry.psk_cu.as_mut() {
            psk.fill(0);
        }
        entry.psk_cu = None;
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
