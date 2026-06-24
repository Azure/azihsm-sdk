// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GSRAM-backed partition table storage for Uno firmware.

#![no_std]
#![allow(unsafe_code)]


use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
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
use azihsm_fw_uno_reg_soc::part_entry_t::ENABLED_OFFSET;
use azihsm_fw_uno_reg_soc::part_entry_t::STATE_OFFSET;
use azihsm_fw_uno_trace::tracing::info;

/// Number of partition slots (one per global key-vault table index).
pub const NUM_PARTITIONS: usize = 65;

/// Length of the random partition identity, in bytes.
pub const ID_LEN: usize = 16;

/// Length of the identity ECC P-384 public key (X ‖ Y), in bytes.
pub const ID_PUB_KEY_LEN: usize = 96;

/// Marker bit set in a stored key-handle field to distinguish a
/// provisioned key whose [`HsmKeyId`] is `0` (table 0, slot 0) from an
/// unprovisioned slot (all-zero field). Key handles are 16-bit, so bit 16
/// is free for this flag.
pub const KEY_PRESENT: u32 = 1 << 16;

/// Encodes an [`HsmKeyId`] into a stored key-handle field.
#[inline]
pub fn encode_key(key_id: HsmKeyId) -> u32 {
    (u16::from(key_id) as u32) | KEY_PRESENT
}

/// Decodes a stored key-handle field into an [`HsmKeyId`], or `None` if no
/// key is provisioned.
#[inline]
pub fn decode_key(raw: u32) -> Option<HsmKeyId> {
    (raw & KEY_PRESENT != 0).then(|| HsmKeyId::from(raw as u16))
}

/// Absolute GSRAM address of the first partition table entry.
pub const PART_BASE: u32 = IO_GSRAM_BASE + PART_ENTRY_T_BASE;

/// Plain in-memory mirror of one GSRAM partition-table entry.
///
/// The partition table is plain shared GSRAM (not a peripheral), so entries
/// are accessed as an ordinary `#[repr(C)]` struct rather than through the
/// tock-registers overlay — letting the compiler use efficient block
/// loads/stores. The field layout and 0x200 stride are asserted against the
/// generated RDL constants below.
#[repr(C)]
pub struct PartEntry {
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
    /// Enabled flag (1 = enabled), set/cleared by `PfnEnableDisable`,
    /// orthogonal to the allocation `state`. Stored as `u32` so it is written
    /// with a word-aligned store -- GSRAM faults on sub-word (byte) writes.
    enabled: u32,
    /// Reserved padding to the 0x200 entry stride.
    _rsvd: [u8; 168],
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
    assert!(offset_of!(PartEntry, enabled) == ENABLED_OFFSET as usize);
};

/// Bytes between consecutive partition entries.
pub const PART_STRIDE: usize = core::mem::size_of::<PartEntry>();

/// GSRAM-backed partition table.
///
/// Zero-sized: every entry is addressed directly in GSRAM, so this
/// handle carries no state and the accessors are associated functions.
pub struct PartTable;

impl PartTable {
    /// Raw pointer to partition `pid`'s entry in GSRAM.
    #[inline]
    pub fn entry_ptr(pid: usize) -> *mut PartEntry {
        debug_assert!(pid < NUM_PARTITIONS);
        (PART_BASE as usize + pid * PART_STRIDE) as *mut PartEntry
    }

    /// Shared reference to partition `pid`'s entry.
    #[inline]
    pub fn entry(pid: usize) -> &'static PartEntry {
        // SAFETY: `pid < NUM_PARTITIONS` keeps the entry within the reserved
        // PART_STORE GSRAM region; the single-threaded executor guarantees
        // no aliasing for the (non-escaping) borrow.
        unsafe { &*Self::entry_ptr(pid) }
    }

    /// Exclusive reference to partition `pid`'s entry.
    #[inline]
    pub fn entry_mut(pid: usize) -> &'static mut PartEntry {
        // SAFETY: as `entry`; the returned borrow does not escape the calling
        // accessor, so no two `&mut` to the same entry coexist.
        unsafe { &mut *Self::entry_ptr(pid) }
    }

    /// Resolves an [`HsmPartId`] to a valid table index.
    #[inline(never)]
    pub fn index(pid: HsmPartId) -> HsmResult<usize> {
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
    pub fn init_default() {
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
            e.enabled = 0;
        }
    }

    /// Reads partition `pid`'s lifecycle state.
    #[inline(never)]
    pub fn state(pid: usize) -> HsmResult<PartState> {
        PartState::from_u8(Self::entry(pid).state as u8).ok_or(HsmError::InvalidArg)
    }

    /// Writes partition `pid`'s lifecycle state.
    #[inline(never)]
    pub fn set_state(pid: usize, state: PartState) {
        Self::entry_mut(pid).state = state as u32;
    }

    /// Reads partition `pid`'s 128-bit resource mask (little-endian).
    #[inline(never)]
    pub fn res_mask(pid: usize) -> u128 {
        u128::from_le_bytes(Self::entry(pid).res_mask)
    }

    /// Writes partition `pid`'s 128-bit resource mask (little-endian).
    #[inline(never)]
    pub fn set_res_mask(pid: usize, mask: u128) {
        Self::entry_mut(pid).res_mask = mask.to_le_bytes();
    }

    /// Bumps the generation counter, invalidating stale key handles.
    #[inline(never)]
    pub fn bump_gen(pid: usize) {
        let e = Self::entry_mut(pid);
        e.generation = e.generation.wrapping_add(1);
    }

    /// Reads partition `pid`'s generation counter.
    #[inline(never)]
    pub fn generation(pid: usize) -> u32 {
        Self::entry(pid).generation
    }

    /// Reads partition `pid`'s enabled flag.
    #[inline(never)]
    pub fn enabled(pid: usize) -> bool {
        Self::entry(pid).enabled != 0
    }

    /// Sets partition `pid`'s enabled flag (orthogonal to allocation state).
    #[inline(never)]
    pub fn set_enabled(pid: usize, enabled: bool) {
        Self::entry_mut(pid).enabled = enabled as u32;
    }

    /// OR of every *other* partition's resource mask -- the set of key-vault
    /// tables already owned cluster-wide, excluding `self_idx`. Used to reject
    /// overlapping `SetResource` assignments (one owner per table).
    pub fn others_res_mask(self_idx: usize) -> u128 {
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
    pub fn id_addr(pid: usize) -> usize {
        Self::entry_ptr(pid) as usize + ID_OFFSET as usize
    }

    /// Reads partition `pid`'s identity key handle, or `None` if not
    /// provisioned.
    #[inline(never)]
    pub fn id_key(pid: usize) -> Option<HsmKeyId> {
        decode_key(Self::entry(pid).id_key_id)
    }

    /// Writes partition `pid`'s identity key handle.
    #[inline(never)]
    pub fn set_id_key(pid: usize, key_id: HsmKeyId) {
        Self::entry_mut(pid).id_key_id = encode_key(key_id);
    }

    /// Absolute GSRAM address of partition `pid`'s 96-byte identity public
    /// key.
    #[inline]
    pub fn id_pub_key_addr(pid: usize) -> usize {
        Self::entry_ptr(pid) as usize + ID_PUB_KEY_OFFSET as usize
    }

    /// Zeroes partition `pid`'s provisioned identity (ID, key handle, and
    /// public key).
    #[inline]
    pub fn clear_identity(pid: usize) {
        let e = Self::entry_mut(pid);
        e.id = [0; ID_LEN];
        e.id_key_id = 0;
        e.id_pub_key = [0; ID_PUB_KEY_LEN];
    }

    /// Reads partition `pid`'s establish-credential key handle, or `None`.
    #[inline(never)]
    pub fn ec_key(pid: usize) -> Option<HsmKeyId> {
        decode_key(Self::entry(pid).ec_key_id)
    }

    /// Writes partition `pid`'s establish-credential key handle.
    #[inline(never)]
    pub fn set_ec_key(pid: usize, key_id: HsmKeyId) {
        Self::entry_mut(pid).ec_key_id = encode_key(key_id);
    }

    /// Absolute GSRAM address of partition `pid`'s establish-credential
    /// public key (96 bytes).
    #[inline]
    pub fn ec_pub_key_addr(pid: usize) -> usize {
        Self::entry_ptr(pid) as usize + EC_PUB_KEY_OFFSET as usize
    }

    /// Reads partition `pid`'s session-encryption key handle, or `None`.
    #[inline(never)]
    pub fn se_key(pid: usize) -> Option<HsmKeyId> {
        decode_key(Self::entry(pid).se_key_id)
    }

    /// Writes partition `pid`'s session-encryption key handle.
    #[inline(never)]
    pub fn set_se_key(pid: usize, key_id: HsmKeyId) {
        Self::entry_mut(pid).se_key_id = encode_key(key_id);
    }

    /// Absolute GSRAM address of partition `pid`'s session-encryption
    /// public key (96 bytes).
    #[inline]
    pub fn se_pub_key_addr(pid: usize) -> usize {
        Self::entry_ptr(pid) as usize + SE_PUB_KEY_OFFSET as usize
    }

    /// Zeroes partition `pid`'s enable-time keys (establish-credential and
    /// session-encryption key handles and public keys).
    #[inline]
    pub fn clear_enabled_keys(pid: usize) {
        let e = Self::entry_mut(pid);
        e.ec_key_id = 0;
        e.ec_pub_key = [0; ID_PUB_KEY_LEN];
        e.se_key_id = 0;
        e.se_pub_key = [0; ID_PUB_KEY_LEN];
    }

    /// Writes partition `pid`'s random identity bytes.
    #[inline]
    pub fn set_id(pid: usize, id: &[u8]) {
        Self::entry_mut(pid).id.copy_from_slice(id);
    }

    /// Borrows partition `pid`'s random identity bytes.
    #[inline]
    pub fn id(pid: usize) -> &'static [u8] {
        &Self::entry(pid).id
    }

    /// Writes partition `pid`'s identity public key bytes.
    #[inline]
    pub fn set_id_pub_key(pid: usize, key: &[u8]) {
        Self::entry_mut(pid).id_pub_key.copy_from_slice(key);
    }

    /// Borrows partition `pid`'s identity public key bytes.
    #[inline]
    pub fn id_pub_key(pid: usize) -> &'static [u8] {
        &Self::entry(pid).id_pub_key
    }

    /// Writes partition `pid`'s establish-credential public key bytes.
    #[inline]
    pub fn set_ec_pub_key(pid: usize, key: &[u8]) {
        Self::entry_mut(pid).ec_pub_key.copy_from_slice(key);
    }

    /// Borrows partition `pid`'s establish-credential public key bytes.
    #[inline]
    pub fn ec_pub_key(pid: usize) -> &'static [u8] {
        &Self::entry(pid).ec_pub_key
    }

    /// Writes partition `pid`'s session-encryption public key bytes.
    #[inline]
    pub fn set_se_pub_key(pid: usize, key: &[u8]) {
        Self::entry_mut(pid).se_pub_key.copy_from_slice(key);
    }

    /// Borrows partition `pid`'s session-encryption public key bytes.
    #[inline]
    pub fn se_pub_key(pid: usize) -> &'static [u8] {
        &Self::entry(pid).se_pub_key
    }
}

