// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmPartitionManager`] for the Uno PAL.
//!
//! Partition state lives in the GSRAM-resident partition table
//! (`PART_STORE`, mirroring the reference firmware's
//! `hsm_partition_table`).  One entry per partition records the
//! lifecycle [`PartState`], a monotonic generation counter, and a
//! 128-bit resource mask selecting which of the 65 global key-vault
//! tables the partition owns.
//!
//! The mask defaults to **zero** — a partition has no key storage until
//! Admin assigns tables via the `SetResource` IPC.  Lifecycle state, by
//! contrast, defaults to [`PartState::Enabled`] at boot so the emulated
//! device accepts host DDI traffic (e.g. `GetApiRev`) without an
//! explicit enable step; assigning a zero mask via `SetResource` frees
//! the partition back to [`PartState::Unallocated`].
//!
//! Partition management uses the property-based API: [`PartPropId::STATE`]
//! and [`PartPropId::RES_COUNT`] are backed by the table; the remaining
//! property ids return [`HsmError::UnsupportedCmd`] until the uno
//! partition-crypto handlers are implemented.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEcc;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmPartitionManager;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartPropId;
use azihsm_fw_hsm_pal_traits::PartState;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use azihsm_fw_uno_reg_soc::part_entry_t::EC_KEY_ID_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::EC_PUB_KEY_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::GENERATION_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::ID_KEY_ID_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::ID_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::ID_PUB_KEY_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::PART_ENTRY_T_BASE;
use azihsm_fw_uno_reg_soc::part_entry_t::RES_MASK_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::SE_KEY_ID_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::SE_PUB_KEY_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::STATE_OFFSET;

use crate::UnoHsmPal;
use crate::alloc::UnoScopedAlloc;
use crate::io::UnoHsmIo;
use crate::ipc::PfnEnableDisableAction;

/// Number of partition slots (one per global key-vault table index).
pub const NUM_PARTITIONS: usize = 65;

/// Length of the random partition identity, in bytes.
pub const ID_LEN: usize = 16;

/// Length of the identity ECC P-384 public key (X ‖ Y), in bytes.
pub const ID_PUB_KEY_LEN: usize = 96;

/// Length of an ECC P-384 private scalar (HSM wire format), in bytes.
const P384_PRIV_LEN: usize = 48;

/// Stored length of the enable-time keys (establish-credential and
/// session-encryption): ECC P-384 `pub(96) ‖ priv(48)`, mirroring the
/// reference firmware's 144-byte blob.
const ENABLE_KEY_LEN: usize = ID_PUB_KEY_LEN + P384_PRIV_LEN;

/// Marker bit set in a stored key-handle field to distinguish a
/// provisioned key whose [`HsmKeyId`] is `0` (table 0, slot 0) from an
/// unprovisioned slot (all-zero field). Key handles are 16-bit, so bit 16
/// is free for this flag.
const KEY_PRESENT: u32 = 1 << 16;

/// Encodes an [`HsmKeyId`] into a stored key-handle field.
#[inline]
fn encode_key(key_id: HsmKeyId) -> u32 {
    (u16::from(key_id) as u32) | KEY_PRESENT
}

/// Decodes a stored key-handle field into an [`HsmKeyId`], or `None` if no
/// key is provisioned.
#[inline]
fn decode_key(raw: u32) -> Option<HsmKeyId> {
    (raw & KEY_PRESENT != 0).then(|| HsmKeyId::from(raw as u16))
}

/// Copies `src` into a partition-entry byte field at GSRAM address `dst`.
///
/// `dst` must be 4-byte aligned with capacity `>= src.len()`. Used to write
/// key material straight from a DMA buffer into the partition table,
/// avoiding a stack / task-storage intermediate array. GSRAM is plain
/// shared SRAM, so a plain (non-volatile) copy is used.
#[inline]
fn copy_to_field(dst: usize, src: &[u8]) {
    // SAFETY: `dst` is a partition-entry field in 'static GSRAM with
    // capacity >= `src.len()`; the single-threaded executor guarantees no
    // aliasing during the write.
    let field = unsafe { core::slice::from_raw_parts_mut(dst as *mut u8, src.len()) };
    field.copy_from_slice(src);
}

/// Absolute GSRAM address of the first partition table entry.
const PART_BASE: u32 = IO_GSRAM_BASE + PART_ENTRY_T_BASE;

/// Plain in-memory mirror of one GSRAM partition-table entry.
///
/// The partition table is plain shared GSRAM (not a peripheral), so entries
/// are accessed as an ordinary `#[repr(C)]` struct rather than through the
/// tock-registers overlay — letting the compiler use efficient block
/// loads/stores. The field layout and 0x200 stride are asserted against the
/// generated RDL constants below.
#[repr(C)]
struct PartEntry {
    /// Lifecycle state ([`PartState`] discriminant).
    state: u32,
    /// Monotonic incarnation counter (bumped on free).
    generation: u32,
    /// 128-bit table-ownership mask, little-endian.
    res_mask: [u8; 16],
    /// 16-byte random partition identity.
    id: [u8; ID_LEN],
    /// Identity ECC P-384 key handle (`KEY_PRESENT`-tagged).
    id_key_id: u32,
    /// Identity public key (X ‖ Y).
    id_pub_key: [u8; ID_PUB_KEY_LEN],
    /// Establish-credential key handle.
    ec_key_id: u32,
    /// Establish-credential public key.
    ec_pub_key: [u8; ID_PUB_KEY_LEN],
    /// Session-encryption key handle.
    se_key_id: u32,
    /// Session-encryption public key.
    se_pub_key: [u8; ID_PUB_KEY_LEN],
    /// Reserved padding to the 0x200 entry stride.
    _rsvd: [u8; 172],
}

// Lock the in-memory struct to the generated RDL layout so the plain
// `#[repr(C)]` access stays byte-compatible with the partition table.
const _: () = {
    use core::mem::offset_of;
    assert!(core::mem::size_of::<PartEntry>() == 0x200);
    assert!(offset_of!(PartEntry, state) == STATE_OFFSET as usize);
    assert!(offset_of!(PartEntry, generation) == GENERATION_OFFSET as usize);
    assert!(offset_of!(PartEntry, res_mask) == RES_MASK_OFFSET as usize);
    assert!(offset_of!(PartEntry, id) == ID_OFFSET as usize);
    assert!(offset_of!(PartEntry, id_key_id) == ID_KEY_ID_OFFSET as usize);
    assert!(offset_of!(PartEntry, id_pub_key) == ID_PUB_KEY_OFFSET as usize);
    assert!(offset_of!(PartEntry, ec_key_id) == EC_KEY_ID_OFFSET as usize);
    assert!(offset_of!(PartEntry, ec_pub_key) == EC_PUB_KEY_OFFSET as usize);
    assert!(offset_of!(PartEntry, se_key_id) == SE_KEY_ID_OFFSET as usize);
    assert!(offset_of!(PartEntry, se_pub_key) == SE_PUB_KEY_OFFSET as usize);
};

/// Bytes between consecutive partition entries.
const PART_STRIDE: usize = core::mem::size_of::<PartEntry>();

/// GSRAM-backed partition table.
///
/// Zero-sized: every entry is addressed directly in GSRAM, so this
/// handle carries no state and the accessors are associated functions.
pub(crate) struct PartTable;

impl PartTable {
    /// Raw pointer to partition `pid`'s entry in GSRAM.
    #[inline]
    fn entry_ptr(pid: usize) -> *mut PartEntry {
        debug_assert!(pid < NUM_PARTITIONS);
        (PART_BASE as usize + pid * PART_STRIDE) as *mut PartEntry
    }

    /// Shared reference to partition `pid`'s entry.
    #[inline]
    fn entry(pid: usize) -> &'static PartEntry {
        // SAFETY: `pid < NUM_PARTITIONS` keeps the entry within the reserved
        // PART_STORE GSRAM region; the single-threaded executor guarantees
        // no aliasing for the (non-escaping) borrow.
        unsafe { &*Self::entry_ptr(pid) }
    }

    /// Exclusive reference to partition `pid`'s entry.
    #[inline]
    fn entry_mut(pid: usize) -> &'static mut PartEntry {
        // SAFETY: as `entry`; the returned borrow does not escape the calling
        // accessor, so no two `&mut` to the same entry coexist.
        unsafe { &mut *Self::entry_ptr(pid) }
    }

    /// Resolves an [`HsmPartId`] to a valid table index.
    #[inline(never)]
    pub(crate) fn index(pid: HsmPartId) -> HsmResult<usize> {
        let idx = u8::from(pid) as usize;
        if idx < NUM_PARTITIONS {
            Ok(idx)
        } else {
            Err(HsmError::InvalidArg)
        }
    }

    /// Initializes every partition to the [`PartState::Unallocated`]
    /// posture: empty resource mask, generation zero, no identity.
    ///
    /// Partitions are provisioned and enabled on demand by Admin via the
    /// `SetResource` + `PfnEnable` IPCs. Called once during PAL init; GSRAM
    /// is not guaranteed zeroed, so each field is written explicitly.
    pub(crate) fn init_default() {
        for pid in 0..NUM_PARTITIONS {
            let e = Self::entry_mut(pid);
            e.state = PartState::Unallocated as u32;
            e.generation = 0;
            e.res_mask = [0; 16];
            e.id = [0; ID_LEN];
            e.id_key_id = 0;
            e.id_pub_key = [0; ID_PUB_KEY_LEN];
            e.ec_key_id = 0;
            e.ec_pub_key = [0; ID_PUB_KEY_LEN];
            e.se_key_id = 0;
            e.se_pub_key = [0; ID_PUB_KEY_LEN];
        }
    }

    /// Reads partition `pid`'s lifecycle state.
    #[inline(never)]
    pub(crate) fn state(pid: usize) -> HsmResult<PartState> {
        PartState::from_u8(Self::entry(pid).state as u8).ok_or(HsmError::InvalidArg)
    }

    /// Writes partition `pid`'s lifecycle state.
    #[inline(never)]
    pub(crate) fn set_state(pid: usize, state: PartState) {
        Self::entry_mut(pid).state = state as u32;
    }

    /// Reads partition `pid`'s 128-bit resource mask (little-endian).
    #[inline(never)]
    pub(crate) fn res_mask(pid: usize) -> u128 {
        u128::from_le_bytes(Self::entry(pid).res_mask)
    }

    /// Writes partition `pid`'s 128-bit resource mask (little-endian).
    #[inline(never)]
    pub(crate) fn set_res_mask(pid: usize, mask: u128) {
        Self::entry_mut(pid).res_mask = mask.to_le_bytes();
    }

    /// Bumps the generation counter, invalidating stale key handles.
    #[inline(never)]
    pub(crate) fn bump_gen(pid: usize) {
        let e = Self::entry_mut(pid);
        e.generation = e.generation.wrapping_add(1);
    }

    /// Reads partition `pid`'s generation counter.
    #[inline(never)]
    pub(crate) fn generation(pid: usize) -> u32 {
        Self::entry(pid).generation
    }

    /// OR of every *other* partition's resource mask -- the set of key-vault
    /// tables already owned cluster-wide, excluding `self_idx`. Used to reject
    /// overlapping `SetResource` assignments (one owner per table).
    pub(crate) fn others_res_mask(self_idx: usize) -> u128 {
        let mut owned = 0u128;
        for pid in 0..NUM_PARTITIONS {
            if pid != self_idx {
                owned |= Self::res_mask(pid);
            }
        }
        owned
    }

    /// Absolute GSRAM address of partition `pid`'s 16-byte identity.
    #[inline]
    fn id_addr(pid: usize) -> usize {
        Self::entry_ptr(pid) as usize + ID_OFFSET as usize
    }

    /// Reads partition `pid`'s identity key handle, or `None` if not
    /// provisioned.
    #[inline(never)]
    pub(crate) fn id_key(pid: usize) -> Option<HsmKeyId> {
        decode_key(Self::entry(pid).id_key_id)
    }

    /// Writes partition `pid`'s identity key handle.
    #[inline(never)]
    pub(crate) fn set_id_key(pid: usize, key_id: HsmKeyId) {
        Self::entry_mut(pid).id_key_id = encode_key(key_id);
    }

    /// Absolute GSRAM address of partition `pid`'s 96-byte identity public
    /// key.
    #[inline]
    fn id_pub_key_addr(pid: usize) -> usize {
        Self::entry_ptr(pid) as usize + ID_PUB_KEY_OFFSET as usize
    }

    /// Zeroes partition `pid`'s provisioned identity (ID, key handle, and
    /// public key).
    #[inline]
    pub(crate) fn clear_identity(pid: usize) {
        let e = Self::entry_mut(pid);
        e.id = [0; ID_LEN];
        e.id_key_id = 0;
        e.id_pub_key = [0; ID_PUB_KEY_LEN];
    }

    /// Reads partition `pid`'s establish-credential key handle, or `None`.
    #[inline(never)]
    pub(crate) fn ec_key(pid: usize) -> Option<HsmKeyId> {
        decode_key(Self::entry(pid).ec_key_id)
    }

    /// Writes partition `pid`'s establish-credential key handle.
    #[inline(never)]
    pub(crate) fn set_ec_key(pid: usize, key_id: HsmKeyId) {
        Self::entry_mut(pid).ec_key_id = encode_key(key_id);
    }

    /// Absolute GSRAM address of partition `pid`'s establish-credential
    /// public key (96 bytes).
    #[inline]
    fn ec_pub_key_addr(pid: usize) -> usize {
        Self::entry_ptr(pid) as usize + EC_PUB_KEY_OFFSET as usize
    }

    /// Reads partition `pid`'s session-encryption key handle, or `None`.
    #[inline(never)]
    pub(crate) fn se_key(pid: usize) -> Option<HsmKeyId> {
        decode_key(Self::entry(pid).se_key_id)
    }

    /// Writes partition `pid`'s session-encryption key handle.
    #[inline(never)]
    pub(crate) fn set_se_key(pid: usize, key_id: HsmKeyId) {
        Self::entry_mut(pid).se_key_id = encode_key(key_id);
    }

    /// Absolute GSRAM address of partition `pid`'s session-encryption
    /// public key (96 bytes).
    #[inline]
    fn se_pub_key_addr(pid: usize) -> usize {
        Self::entry_ptr(pid) as usize + SE_PUB_KEY_OFFSET as usize
    }

    /// Zeroes partition `pid`'s enable-time keys (establish-credential and
    /// session-encryption key handles and public keys).
    #[inline]
    pub(crate) fn clear_enabled_keys(pid: usize) {
        let e = Self::entry_mut(pid);
        e.ec_key_id = 0;
        e.ec_pub_key = [0; ID_PUB_KEY_LEN];
        e.se_key_id = 0;
        e.se_pub_key = [0; ID_PUB_KEY_LEN];
    }
}

impl UnoHsmPal {
    /// Applies a `SetResource` assignment from Admin, driving the partition
    /// lifecycle's allocation transitions (mirroring the reference
    /// firmware's `part_alloc` / `part_free`; identity only — no certs).
    ///
    /// A non-zero `mask` (re)allocates the partition: any prior allocation
    /// is freed, the listed key-vault tables are assigned, the random ID
    /// and ECC P-384 identity key are generated, and the partition moves to
    /// [`PartState::Allocated`]. A separate `PfnEnable` IPC is required to
    /// reach [`PartState::Enabled`] before host IO is accepted.
    ///
    /// A zero `mask` deallocates the partition via [`part_free`].
    ///
    /// Returns the resulting owned-table count (`mask.count_ones()`).
    ///
    /// [`part_free`]: Self::part_free
    pub(crate) async fn set_resource(&self, pid: HsmPartId, mask: u128) -> HsmResult<u32> {
        if mask == 0 {
            self.part_free(pid).await?;
            Ok(0)
        } else {
            self.part_alloc(pid, mask).await
        }
    }

    /// Allocates partition `pid` with resource `mask`, transitioning to
    /// [`PartState::Allocated`] (mirrors `part_alloc`).
    ///
    /// Any existing allocation is freed first so `SetResource` is a
    /// declarative "set the resources to this mask" operation.
    async fn part_alloc(&self, pid: HsmPartId, mask: u128) -> HsmResult<u32> {
        let idx = PartTable::index(pid)?;

        // Free any prior allocation so keygen starts from a clean slate.
        self.part_free(pid).await?;

        // Reject masks overlapping tables already owned by another partition --
        // each key-vault table has exactly one owner.
        if mask & PartTable::others_res_mask(idx) != 0 {
            return Err(HsmError::InvalidArg);
        }
        PartTable::set_res_mask(idx, mask);

        match self.provision_identity(pid).await {
            Ok(()) => {
                PartTable::set_state(idx, PartState::Allocated);
                Ok(mask.count_ones())
            }
            Err(e) => {
                // Roll back: release resources, wipe any partial identity.
                PartTable::clear_identity(idx);
                PartTable::set_res_mask(idx, 0);
                PartTable::set_state(idx, PartState::Unallocated);
                Err(e)
            }
        }
    }

    /// Frees partition `pid` (mirrors `part_free`):
    /// `Allocated | Enabled | Disabled → Unallocated`.
    ///
    /// If the partition is `Enabled`, its enable-time state is cleared first
    /// (an implicit disable). The identity key is deleted, all identity and
    /// enable-time material is zeroized, the resource mask is released, and
    /// the generation counter is bumped so previously issued key handles are
    /// rejected. Freeing an already-`Unallocated` partition is a no-op.
    async fn part_free(&self, pid: HsmPartId) -> HsmResult<()> {
        let idx = PartTable::index(pid)?;
        if PartTable::state(idx)? == PartState::Unallocated {
            return Ok(());
        }

        // Disable: clear enable-time keys/state (no-op if not enabled).
        self.clear_enabled_state(pid).await;

        // Dealloc: delete the identity key and zeroize identity material.
        if let Some(key_id) = PartTable::id_key(idx) {
            self.delete_key(pid, key_id).await;
        }
        PartTable::clear_identity(idx);

        // Release resources and reset lifecycle state.
        PartTable::set_res_mask(idx, 0);
        PartTable::bump_gen(idx);
        PartTable::set_state(idx, PartState::Unallocated);
        Ok(())
    }

    /// Generates an internal ECC P-384 key pair, stores the private key in
    /// partition `pid`'s vault, and returns `(key_handle, public_key)`.
    ///
    /// Mirrors the reference firmware's `create_internal_ecc384_key`. The
    /// `pct` argument is accepted for parity with the trait; the uno PKA
    /// path performs no pairwise-consistency self-test.
    async fn create_internal_ecc384(
        &self,
        pid: HsmPartId,
        kind: HsmVaultKeyKind,
        attrs: HsmVaultKeyAttrs,
        pct: HsmEccPct,
        pub_dst: usize,
    ) -> HsmResult<HsmKeyId> {
        let admin_io = UnoHsmIo::admin(pid);
        let alloc = UnoScopedAlloc::for_admin(self);

        // P-384 wire-format lengths: 48-byte scalar, 96-byte X ‖ Y point.
        let priv_buf = alloc.dma_alloc(P384_PRIV_LEN)?;
        let pub_buf = alloc.dma_alloc(ID_PUB_KEY_LEN)?;
        let (_priv_len, pub_len) = self
            .ecc_gen_keypair(
                &admin_io,
                &alloc,
                HsmEccCurve::P384,
                Some((priv_buf, pub_buf)),
                pct,
            )
            .await?;
        if pub_len != ID_PUB_KEY_LEN {
            return Err(HsmError::InternalError);
        }

        // Cache the public key into the partition entry's GSRAM field,
        // copied straight from the DMA buffer (no stack / task-storage
        // intermediate array).
        copy_to_field(pub_dst, &pub_buf[..ID_PUB_KEY_LEN]);

        // Assemble the stored blob to the format the vault expects for
        // `kind`: the identity key stores the bare 48-byte private scalar,
        // while the establish-credential and session-encryption keys store
        // the 144-byte `pub(96) ‖ priv(48)` blob (matching the reference
        // firmware's on-storage layout). All buffers come from the DMA
        // allocator — nothing on the stack.
        let key_buf: &DmaBuf = match kind {
            HsmVaultKeyKind::Ecc384Private => priv_buf,
            HsmVaultKeyKind::EstablishCred | HsmVaultKeyKind::SessionEncryption => {
                let buf = alloc.dma_alloc(ENABLE_KEY_LEN)?;
                buf[..ID_PUB_KEY_LEN].copy_from_slice(&pub_buf[..ID_PUB_KEY_LEN]);
                buf[ID_PUB_KEY_LEN..ENABLE_KEY_LEN].copy_from_slice(&priv_buf[..P384_PRIV_LEN]);
                buf
            }
            _ => return Err(HsmError::InternalError),
        };

        crate::vault::vault(&admin_io)
            .create(self, &admin_io, u8::from(pid), key_buf, kind, None, attrs)
            .await
    }

    /// Generates the partition's random ID and ECC P-384 identity key,
    /// storing the private key in the partition's vault and caching the
    /// ID, key handle, and public key in the partition table.
    async fn provision_identity(&self, pid: HsmPartId) -> HsmResult<()> {
        let idx = PartTable::index(pid)?;

        let attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_sign(true);
        let key_id = self
            .create_internal_ecc384(
                pid,
                HsmVaultKeyKind::Ecc384Private,
                attrs,
                HsmEccPct::SignVerify,
                PartTable::id_pub_key_addr(idx),
            )
            .await?;
        PartTable::set_id_key(idx, key_id);

        // Generate the random partition identity straight into its GSRAM
        // field from the DMA buffer (no stack array).
        let alloc = UnoScopedAlloc::for_admin(self);
        let id_buf = alloc.dma_alloc(ID_LEN)?;
        self.rng.fill_bytes(id_buf)?;
        copy_to_field(PartTable::id_addr(idx), &id_buf[..ID_LEN]);
        Ok(())
    }

    /// Generates the enable-time ECC P-384 key pairs — the
    /// establish-credential and session-encryption keys — mirroring the
    /// reference firmware's `part_enable`. On failure, any partial key is
    /// rolled back. Certificates, nonce, and BK_BOOT are out of scope.
    async fn provision_enabled_keys(&self, pid: HsmPartId) -> HsmResult<()> {
        let idx = PartTable::index(pid)?;
        let attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_derive(true);

        let ec_id = self
            .create_internal_ecc384(
                pid,
                HsmVaultKeyKind::EstablishCred,
                attrs,
                HsmEccPct::KeyAgreement,
                PartTable::ec_pub_key_addr(idx),
            )
            .await?;
        PartTable::set_ec_key(idx, ec_id);

        match self
            .create_internal_ecc384(
                pid,
                HsmVaultKeyKind::SessionEncryption,
                attrs,
                HsmEccPct::KeyAgreement,
                PartTable::se_pub_key_addr(idx),
            )
            .await
        {
            Ok(se_id) => {
                PartTable::set_se_key(idx, se_id);
                Ok(())
            }
            Err(e) => {
                // Roll back the establish-credential key.
                self.delete_key(pid, ec_id).await;
                PartTable::clear_enabled_keys(idx);
                Err(e)
            }
        }
    }

    /// Best-effort deletion of one vault key for partition `pid`.
    async fn delete_key(&self, pid: HsmPartId, key_id: HsmKeyId) {
        let admin_io = UnoHsmIo::admin(pid);
        let _ = crate::vault::vault(&admin_io)
            .delete(self, &admin_io, key_id)
            .await;
    }

    /// Clears partition `pid`'s enable-time state — deletes its
    /// establish-credential and session-encryption keys and zeroes their
    /// handles and public keys (mirrors `clear_enabled_state`).
    ///
    /// Best-effort and idempotent: keys are deleted only if present, so it
    /// is safe to call regardless of the current lifecycle state.
    async fn clear_enabled_state(&self, pid: HsmPartId) {
        let Ok(idx) = PartTable::index(pid) else {
            return;
        };
        if let Some(key_id) = PartTable::ec_key(idx) {
            self.delete_key(pid, key_id).await;
        }
        if let Some(key_id) = PartTable::se_key(idx) {
            self.delete_key(pid, key_id).await;
        }
        PartTable::clear_enabled_keys(idx);
    }

    /// Applies a `PfnEnableDisable` action from Admin, driving the
    /// partition lifecycle:
    ///
    /// * `Enable` — `Allocated` | `Disabled` → `Enabled`: generates the
    ///   establish-credential and session-encryption ECC P-384 key pairs,
    ///   then accepts host IO.
    /// * `Disable` — `Enabled` → `Disabled`: deletes the enable-time keys.
    /// * `Migrate` — not yet supported.
    ///
    /// Returns [`HsmError::InvalidArg`] for an illegal transition and
    /// [`HsmError::UnsupportedCmd`] for unsupported actions.
    pub(crate) async fn set_pfn_action(
        &self,
        pid: HsmPartId,
        action: PfnEnableDisableAction,
    ) -> HsmResult<()> {
        let idx = PartTable::index(pid)?;
        let state = PartTable::state(idx)?;
        match action {
            PfnEnableDisableAction::Enable => match state {
                PartState::Allocated | PartState::Disabled => {
                    self.provision_enabled_keys(pid).await?;
                    PartTable::set_state(idx, PartState::Enabled);
                    Ok(())
                }
                _ => Err(HsmError::InvalidArg),
            },
            PfnEnableDisableAction::Disable => match state {
                PartState::Enabled => {
                    self.clear_enabled_state(pid).await;
                    PartTable::set_state(idx, PartState::Disabled);
                    Ok(())
                }
                _ => Err(HsmError::InvalidArg),
            },
            _ => Err(HsmError::UnsupportedCmd),
        }
    }
}

/// A validated handle to one partition's GSRAM entry -- the Uno analog of the
/// std PAL's `&PartitionEntry`. Carries only the table index; all state lives
/// in GSRAM and is reached through [`PartTable`]. The session-table view will
/// hang off this handle in a later phase, giving the session PAL impl the same
/// `active_part(io.pid()).session_table()` ergonomics as the std PAL.
#[allow(dead_code)] // consumed by the session/vault phases (P3/P4)
pub(crate) struct PartEntryRef {
    idx: usize,
}

#[allow(dead_code)] // accessors consumed by the session/vault phases (P3/P4)
impl PartEntryRef {
    /// Table index this handle resolves to.
    #[inline]
    pub(crate) fn index(&self) -> usize {
        self.idx
    }

    /// Current lifecycle state.
    #[inline]
    pub(crate) fn state(&self) -> HsmResult<PartState> {
        PartTable::state(self.idx)
    }

    /// Monotonic generation counter (for stale-handle rejection).
    #[inline]
    pub(crate) fn generation(&self) -> u32 {
        PartTable::generation(self.idx)
    }

    /// 128-bit resource (table-ownership) mask.
    #[inline]
    pub(crate) fn res_mask(&self) -> u128 {
        PartTable::res_mask(self.idx)
    }
}

impl UnoHsmPal {
    /// Resolves `pid` to a partition handle, bounds-checked against
    /// [`NUM_PARTITIONS`]. The Uno analog of the std PAL's `active_part`; does
    /// not gate on lifecycle state -- callers check [`PartEntryRef::state`] as
    /// needed. Session and vault access will hang off the returned handle.
    #[allow(dead_code)] // consumed by the session/vault phases (P3/P4)
    #[inline]
    pub(crate) fn active_part(&self, pid: HsmPartId) -> HsmResult<PartEntryRef> {
        Ok(PartEntryRef {
            idx: PartTable::index(pid)?,
        })
    }
}

impl HsmPartitionManager for UnoHsmPal {
    fn part_prop_get_u8(&self, io: &impl HsmIo, id: PartPropId, _idx: u16) -> HsmResult<u8> {
        let pid = PartTable::index(io.pid())?;
        match id {
            PartPropId::STATE => Ok(PartTable::state(pid)? as u8),
            PartPropId::RES_COUNT => Ok(PartTable::res_mask(pid).count_ones() as u8),
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_set_u8(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        _idx: u16,
        value: u8,
    ) -> HsmResult<()> {
        let pid = PartTable::index(io.pid())?;
        match id {
            PartPropId::STATE => {
                let state = PartState::from_u8(value).ok_or(HsmError::InvalidArg)?;
                PartTable::set_state(pid, state);
                Ok(())
            }
            // RES_COUNT is read-only; it is derived from the resource mask.
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_get_u16(&self, io: &impl HsmIo, id: PartPropId, _idx: u16) -> HsmResult<u16> {
        let pid = PartTable::index(io.pid())?;
        let key = match id {
            PartPropId::ID_KEY_ID => PartTable::id_key(pid),
            PartPropId::ESTABLISH_CRED_KEY_ID => PartTable::ec_key(pid),
            PartPropId::SESSION_ENC_KEY_ID => PartTable::se_key(pid),
            _ => return Err(HsmError::UnsupportedCmd),
        };
        key.map(u16::from).ok_or(HsmError::KeyNotFound)
    }

    fn part_prop_set_u16(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u16,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_u32(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<u32> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_u32(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u32,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_u64(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<u64> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_u64(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u64,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_bool(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<bool> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_bool(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: bool,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_bytes<'a>(
        &'a self,
        io: &impl HsmIo,
        id: PartPropId,
        _idx: u16,
    ) -> HsmResult<&'a DmaBuf> {
        let pid = PartTable::index(io.pid())?;
        // Each public-key field is only valid once its backing key has
        // been provisioned (identity at SetResource, the others at enable).
        let (addr, len, present) = match id {
            PartPropId::ID => (
                PartTable::id_addr(pid),
                ID_LEN,
                PartTable::id_key(pid).is_some(),
            ),
            PartPropId::ID_PUB_KEY => (
                PartTable::id_pub_key_addr(pid),
                ID_PUB_KEY_LEN,
                PartTable::id_key(pid).is_some(),
            ),
            PartPropId::ESTABLISH_CRED_PUB_KEY => (
                PartTable::ec_pub_key_addr(pid),
                ID_PUB_KEY_LEN,
                PartTable::ec_key(pid).is_some(),
            ),
            PartPropId::SESSION_ENC_PUB_KEY => (
                PartTable::se_pub_key_addr(pid),
                ID_PUB_KEY_LEN,
                PartTable::se_key(pid).is_some(),
            ),
            _ => return Err(HsmError::UnsupportedCmd),
        };
        if !present {
            return Err(HsmError::KeyNotFound);
        }
        // SAFETY: `addr..addr+len` is the partition's field in its 'static
        // GSRAM entry; the single-threaded executor guarantees no aliasing
        // mutation for the borrow's duration.
        Ok(unsafe { DmaBuf::from_raw(core::slice::from_raw_parts(addr as *const u8, len)) })
    }

    fn part_prop_set_bytes(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _data: &DmaBuf,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_clear(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }
}
