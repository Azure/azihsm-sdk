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

/// Length of the per-partition random nonce in bytes.
const NONCE_LEN: usize = 32;

/// Length of a partition's random identity blob in bytes.
const PART_ID_LEN: usize = 16;

/// Size of a single P-384 coordinate (x or y) in bytes.
const P384_COORD_SIZE: usize = 48;

/// Size of the raw public key (x ∥ y) in bytes.
pub(crate) const P384_PUB_KEY_LEN: usize = P384_COORD_SIZE * 2;

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
}

impl Default for PartitionEntry {
    fn default() -> Self {
        Self {
            state: PartState::Unallocated,
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
        if entry.state == PartState::Unallocated {
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
        if entry.state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }
        Ok(&entry.id)
    }

    fn part_id_key_id(&self, pid: u8) -> HsmResult<HsmKeyId> {
        let entry = self.active_part(HsmPartId::from(pid))?;
        entry.id_key_id.ok_or(HsmError::InternalError)
    }

    fn part_id_pub_key(&self, pid: u8, out: Option<&mut [u8]>) -> HsmResult<usize> {
        let entry = self.active_part(HsmPartId::from(pid))?;
        copy_out(&entry.id_pub_key, out)
    }

    fn part_establish_cred_key_id(&self, pid: u8) -> HsmResult<Option<HsmKeyId>> {
        Ok(self.enabled_part(pid)?.establish_cred_key_id)
    }

    fn part_establish_cred_pub_key(&self, pid: u8, out: Option<&mut [u8]>) -> HsmResult<usize> {
        copy_out(&self.enabled_part(pid)?.establish_cred_pub_key, out)
    }

    fn part_session_enc_key_id(&self, pid: u8) -> HsmResult<HsmKeyId> {
        self.enabled_part(pid)?
            .session_enc_key_id
            .ok_or(HsmError::InternalError)
    }

    fn part_session_enc_pub_key(&self, pid: u8, out: Option<&mut [u8]>) -> HsmResult<usize> {
        copy_out(&self.enabled_part(pid)?.session_enc_pub_key, out)
    }

    fn part_clear_establish_cred_key(&self, pid: u8) -> HsmResult<()> {
        let entry = self.enabled_part_mut(pid)?;
        if let Some(kid) = entry.establish_cred_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.establish_cred_pub_key.fill(0);
        Ok(())
    }

    fn part_nonce(&self, pid: u8) -> HsmResult<&[u8]> {
        Ok(&self.enabled_part(pid)?.nonce)
    }

    fn part_nonce_refresh(&self, pid: u8) -> HsmResult<()> {
        let entry = self.enabled_part_mut(pid)?;
        Rng::rand_bytes(&mut entry.nonce).map_err(|_| HsmError::InternalError)
    }
}

// ---------------------------------------------------------------------------
// Shared partition access helpers (used by vault.rs, session.rs, etc.)
// ---------------------------------------------------------------------------

impl StdHsmPal {
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
fn copy_out(data: &[u8], out: Option<&mut [u8]>) -> HsmResult<usize> {
    if let Some(buf) = out {
        if buf.len() < data.len() {
            return Err(HsmError::NotEnoughSpace);
        }
        buf[..data.len()].copy_from_slice(data);
    }
    Ok(data.len())
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
        if let Err(_) = Rng::rand_bytes(&mut entry.nonce) {
            // Rollback both keys.
            Self::clear_enabled_state(entry);
            return Err(HsmError::InternalError);
        }

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
        if table.entries[idx].state != PartState::Enabled {
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

        // If enabled, clear internal keys/nonce/vault/sessions first.
        if entry.state == PartState::Enabled {
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

    /// Generate an ECC P-384 key pair via [`HsmEcc::ecc_gen_keypair`],
    /// store the private key DER in the vault, and write raw public key
    /// coordinates (x ∥ y) into `pub_key_out`.
    ///
    /// Returns the vault key ID.
    async fn create_internal_ecc384_key(
        &self,
        pid: u8,
        kind: HsmVaultKeyKind,
        attrs: HsmVaultKeyAttrs,
        pct: HsmEccPct,
        pub_key_out: &mut [u8; P384_PUB_KEY_LEN],
    ) -> HsmResult<HsmKeyId> {
        let priv_max = HsmEccCurve::P384.priv_key_der_max();
        let mut priv_buf = vec![0u8; priv_max];

        let priv_len = self
            .ecc_gen_keypair(HsmEccCurve::P384, Some(&mut priv_buf), pub_key_out, pct)
            .await?;

        // Store private key DER in vault.
        let table = unsafe { &mut *self.part_table.get() };
        let entry = &mut table.entries[pid as usize];
        entry
            .vault
            .create(&priv_buf[..priv_len], kind, None, attrs, &[])
    }

    /// Clear all state associated with an enabled partition (internal keys,
    /// nonce, vault keys, sessions).  Does NOT change the state field.
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
        entry.vault.clear();
        entry.session_table = SessionTable::new();
    }
}
