// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition persistent store: typed GSRAM layout and the [`PartStore`]
//! accessor handle.

use core::mem::size_of;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::PartState;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use azihsm_fw_uno_reg_soc::part_store_t::PART_STORE_T_BASE;

/// Number of partition slots in the persistent store.
pub const NUM_PARTITIONS: usize = 65;

/// Persistent-store schema version stamped by this driver.
pub const STORE_VERSION: u8 = 1;

// ── Field sizes (mirror the reference `HsmPartPersistentStore`) ──────────
const ID_LEN: usize = 16;
const ID_PRIV_LEN: usize = 48;
const ID_PUB_LEN: usize = 97;
const UNWRAPPING_KEY_BK_LEN: usize = 516;
const PART_CERT_DATA_LEN: usize = 800;
const MASKED_BK_BOOT_DATA_LEN: usize = 300;
const SEALED_BK3_DATA_LEN: usize = 512;
const BK3_KEY_LEN: usize = 48;
const NONCE_LEN: usize = 32;
const GUID_LEN: usize = 16;
const SESSION_TABLE_LEN: usize = 18;
const POLICY_HASH_LEN: usize = 48;
const POTA_THUMBPRINT_LEN: usize = 48;
const SATA_THUMBPRINT_LEN: usize = 48;
const SAPOTA_THUMBPRINT_LEN: usize = 48;
const PUB_KEY_LEN: usize = 96;
const PSK_LEN: usize = 32;
const CREDENTIAL_LEN: usize = 32;
const RES_MASK_LEN: usize = 16;
/// Trailing reserved tail = reference `reserved3` (626) minus the appended
/// Uno fields (policy_hash + pota/sata/sapota thumbprints + the flat
/// working-state fields below).
const RESERVED3_LEN: usize = 626
    - POLICY_HASH_LEN
    - POTA_THUMBPRINT_LEN
    - SATA_THUMBPRINT_LEN
    - SAPOTA_THUMBPRINT_LEN
    - 4  // state
    - 4  // generation
    - RES_MASK_LEN
    - 7 * 2  // key handles (u16 + sentinel)
    - PUB_KEY_LEN  // ec_pub_key
    - PUB_KEY_LEN  // se_pub_key
    - PSK_LEN  // psk_co
    - PSK_LEN  // psk_cu
    - CREDENTIAL_LEN
    - 1  // credential_valid
    - 1  // pota_thumbprint_valid
    - 1  // sata_thumbprint_valid
    - 1  // sapota_thumbprint_valid
    - PUB_KEY_LEN  // pta_pub_key
    - 1  // pta_pub_key_valid
    - 1  // policy_hash_valid
    - 1  // bk3_initialized
    - 2; // session_meta (pending_mask + psk_change_mask)

/// Total per-partition slot size (matches the reference layout).
const STORE_SIZE: usize = 3072;

/// Sentinel stored in a key-handle field meaning "no key".
///
/// Vault key ids pack `(table << 8) | slot` with `table < 65`, so
/// `0xFFFF` (table 255) is never a real handle and is safe as the
/// absent marker. (`0` is a *valid* handle — table 0, slot 0 — so it
/// cannot be used.)
const KEY_ABSENT: u16 = u16::MAX;

/// Decodes a stored 2-byte handle field into an optional key id.
#[inline]
fn read_handle(bytes: [u8; 2]) -> Option<HsmKeyId> {
    let raw = u16::from_le_bytes(bytes);
    (raw != KEY_ABSENT).then(|| HsmKeyId::from(raw))
}

/// Encodes an optional key id into a 2-byte handle field.
#[inline]
fn write_handle(key: Option<HsmKeyId>) -> [u8; 2] {
    key.map(u16::from).unwrap_or(KEY_ABSENT).to_le_bytes()
}

/// Absolute GSRAM base address of partition slot 0.
const PART_STORE_BASE: usize = (IO_GSRAM_BASE + PART_STORE_T_BASE) as usize;

/// Bytes between consecutive partition slots.
const STRIDE: usize = size_of::<Storage>();

// ── Lockout policy (reference `PinPolicy`) ───────────────────────────────

/// Pin-policy lockout state.
#[repr(u8)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicyState {
    /// Unrestricted.
    #[default]
    Ready,
    /// Locked out; enforce the delay factor.
    Lockout,
}

/// Partition lockout / pin-policy context (14 bytes, reference layout).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct PinPolicy {
    /// Current lockout state.
    pub state: PinPolicyState,
    /// Back-off delay factor.
    pub delay_factor: u16,
    /// Allowed attempts before lockout.
    pub allowed_attempts: u16,
    /// Lockout timestamp (opaque 8-byte counter).
    pub lockout_time: [u8; 8],
}

// ── On-storage sub-structs (crate-private; mirror reference layout) ───────

/// Partition identity: random id, identity private key (reserved/unused on
/// Uno — the private key lives in the vault), and identity public key.
#[repr(C)]
#[derive(Clone, Copy)]
struct PartitionIdentifier {
    id: [u8; ID_LEN],
    priv_key: [u8; ID_PRIV_LEN],
    pub_key: [u8; ID_PUB_LEN],
}

/// Partition certificate (reserved/unused on Uno for now).
#[repr(C)]
#[derive(Clone, Copy)]
struct PartitionCert {
    length: u32,
    data: [u8; PART_CERT_DATA_LEN],
}

/// Masked boot key (length-prefixed blob).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MaskedBkBoot {
    len: u32,
    data: [u8; MASKED_BK_BOOT_DATA_LEN],
}

/// Sealed backup key 3 (length-prefixed blob).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct SealedBk3 {
    len: u32,
    data: [u8; SEALED_BK3_DATA_LEN],
}

/// BK3 session key (validity flag + key material).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Bk3SessionKey {
    is_valid: bool,
    _reserved: [u8; 3],
    key: [u8; BK3_KEY_LEN],
}

/// Per-partition persistent store slot.
///
/// The region from `version` through `bk3_session_key` is byte-for-byte
/// identical to the reference `HsmPartPersistentStore`; `policy_hash` and
/// `pota_thumbprint` are Uno-specific fields appended into what the
/// reference layout left as `reserved3`.
#[repr(C)]
struct Storage {
    // ===== identical to reference HsmPartPersistentStore =====
    version: u8,
    flags: [u8; 3],
    session_table: [u8; SESSION_TABLE_LEN],
    reserved1: u8,
    unwrapping_key_bk_valid: bool,
    unwrapping_key_bk: [u8; UNWRAPPING_KEY_BK_LEN],
    pin_policy: PinPolicy,
    vm_launch_guid: [u8; GUID_LEN],
    partition_id_valid: bool,
    reserved2: u8,
    partition_identifier: PartitionIdentifier,
    partition_cert_valid: bool,
    partition_cert: PartitionCert,
    masked_bk_boot: MaskedBkBoot,
    sealed_bk3: SealedBk3,
    nonce: [u8; NONCE_LEN],
    bk3_session_key: Bk3SessionKey,
    // ===== Uno-specific fields, appended flat into reserved3 =====
    // Ordered so the DMA-target public-key buffers (`ec_pub_key`,
    // `se_pub_key`, written directly by the ECC keygen engine) land on
    // 4-byte boundaries. The reference region ends 4-aligned, and every
    // field up to and including the buffers has a size that is a multiple
    // of 4, so each stays aligned; the only non-multiple-of-4 fields — the
    // seven `[u8;2]` key handles — are placed last, before `reserved3`,
    // where misalignment is harmless. All fields are byte arrays (align 1)
    // so no implicit padding is introduced; accessors do the LE conversions.
    state: [u8; 4],
    generation: [u8; 4],
    res_mask: [u8; RES_MASK_LEN],
    ec_pub_key: [u8; PUB_KEY_LEN],
    se_pub_key: [u8; PUB_KEY_LEN],
    pta_pub_key: [u8; PUB_KEY_LEN],
    psk_co: [u8; PSK_LEN],
    psk_cu: [u8; PSK_LEN],
    credential: [u8; CREDENTIAL_LEN],
    policy_hash: [u8; POLICY_HASH_LEN],
    pota_thumbprint: [u8; POTA_THUMBPRINT_LEN],
    sata_thumbprint: [u8; SATA_THUMBPRINT_LEN],
    sapota_thumbprint: [u8; SAPOTA_THUMBPRINT_LEN],
    id_key_id: [u8; 2],
    ec_key_id: [u8; 2],
    se_key_id: [u8; 2],
    mk_key_id: [u8; 2],
    ups_key_id: [u8; 2],
    pta_key_id: [u8; 2],
    unwrapping_key_id: [u8; 2],
    // Presence flags for `AbsentUntilSet` byte fields (placed after the
    // key handles, before `reserved3`, where 1-byte alignment is
    // harmless and the DMA-target public keys above stay 4-aligned).
    credential_valid: bool,
    pota_thumbprint_valid: bool,
    sata_thumbprint_valid: bool,
    sapota_thumbprint_valid: bool,
    pta_pub_key_valid: bool,
    policy_hash_valid: bool,
    // One-shot InitBk3 gate. Distinct from `bk3_session_key.is_valid`,
    // which tracks presence of the BK3 *session key*; this flag records
    // that InitBk3 has run and must not run again.
    bk3_initialized: bool,
    // Volatile TBOR session slot metadata: byte 0 = pending_mask
    // (bit N set while slot N's handshake is in flight), byte 1 =
    // psk_change_mask (bit N set once slot N has consumed its one
    // allowed PSK change). Owned by the session_store driver.
    session_meta: [u8; 2],
    reserved3: [u8; RESERVED3_LEN],
}

// Lock the layout to the reference 3072-byte slot. The whole partition-store
// GSRAM region (`PART_STORE_T_BASE`..key vault) is sized for exactly
// `NUM_PARTITIONS` of these.
const _: () = assert!(size_of::<Storage>() == STORE_SIZE);
const _: () = assert!(STRIDE == STORE_SIZE);
// The ECC keygen engine writes the public keys directly into these fields
// via DMA, which requires 4-byte alignment (see `Storage` field ordering).
const _: () = assert!(core::mem::offset_of!(Storage, ec_pub_key) % 4 == 0);
const _: () = assert!(core::mem::offset_of!(Storage, se_pub_key) % 4 == 0);

/// GSRAM-backed partition persistent store.
///
/// Stateless entry point: [`PartStore::partition`] validates a raw
/// partition id and returns a [`Partition`] handle through which the
/// slot's fields are accessed. [`PartStore::init_default`] initializes
/// every slot at PAL boot.
#[derive(Debug)]
pub struct PartStore;

/// A validated partition-store slot.
///
/// Obtained only via [`PartStore::partition`], so holding one is proof
/// that the partition index is in range (`< NUM_PARTITIONS`). Field
/// accessors are therefore infallible with respect to the index; only the
/// byte-buffer setters can fail (on a wrong input length).
#[derive(Debug, Clone, Copy)]
pub struct Partition(usize);

impl PartStore {
    /// Validates a raw partition id and returns a handle to its slot.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `pid >= NUM_PARTITIONS`.
    #[inline]
    pub fn partition(pid: HsmPartId) -> HsmResult<Partition> {
        let idx = u8::from(pid) as usize;
        if idx < NUM_PARTITIONS {
            Ok(Partition(idx))
        } else {
            Err(HsmError::InvalidArg)
        }
    }

    /// Initializes every partition slot to a zeroed posture and stamps the
    /// store version. Called once during PAL init (GSRAM is not guaranteed
    /// zeroed).
    pub fn init_default() {
        for idx in 0..NUM_PARTITIONS {
            Partition(idx).reset();
        }
    }
}

impl Partition {
    /// Raw pointer to this partition's slot in GSRAM.
    #[inline]
    fn slot_ptr(self) -> *mut Storage {
        // `self.0 < NUM_PARTITIONS` by construction (see `PartStore::partition`).
        (PART_STORE_BASE + self.0 * STRIDE) as *mut Storage
    }

    /// Shared reference to this partition's slot.
    #[inline]
    fn slot(self) -> &'static Storage {
        // SAFETY: the index is in range by construction, keeping the slot
        // within the reserved partition-store GSRAM region; plain shared
        // SRAM, single-threaded executor guarantees no aliasing mutation.
        unsafe { &*self.slot_ptr() }
    }

    /// Exclusive reference to this partition's slot, borrowed for the
    /// lifetime of the `&mut self` handle.
    ///
    /// Taking `&mut self` (rather than `self` by value) deliberately ties
    /// the returned `&mut Storage` to an exclusive borrow of the
    /// [`Partition`] handle, so the borrow checker forbids handing out two
    /// overlapping `&mut` into the same slot through one handle (the old
    /// `&'static mut`-from-`Copy` signature did not). Cross-handle aliasing
    /// (two `Partition`s for the same index) is prevented by call
    /// discipline: every accessor borrow is short-lived and the
    /// single-threaded cooperative executor only yields at `.await`, so no
    /// other task observes a slot mid-mutation.
    #[inline]
    fn slot_mut(&mut self) -> &mut Storage {
        // SAFETY: the index is in range by construction (see
        // `PartStore::partition`), keeping the slot within the reserved
        // partition-store GSRAM region. The `&mut self` receiver scopes the
        // returned borrow; on the single-threaded executor no other context
        // accesses the same slot for that borrow's (non-`await`) duration.
        unsafe { &mut *self.slot_ptr() }
    }

    // ── lifecycle ────────────────────────────────────────────────────────

    /// Wipes this partition's slot (zeroizes all fields), re-stamps the
    /// store version, and resets all key handles to the "absent" sentinel
    /// (zeroing alone would otherwise read back as the valid handle 0).
    #[inline(never)]
    pub fn reset(mut self) {
        let slot = self.slot_mut();
        // SAFETY: `slot` is a valid, uniquely-borrowed `Storage` in GSRAM;
        // an all-zero bit pattern is a valid value for every field.
        unsafe {
            core::ptr::write_bytes(slot as *mut Storage as *mut u8, 0, STORE_SIZE);
        }
        slot.version = STORE_VERSION;
        let absent = KEY_ABSENT.to_le_bytes();
        slot.id_key_id = absent;
        slot.ec_key_id = absent;
        slot.se_key_id = absent;
        slot.mk_key_id = absent;
        slot.ups_key_id = absent;
        slot.pta_key_id = absent;
        slot.unwrapping_key_id = absent;
    }

    /// Zeroes the provisioned identity: the 16-byte id, its key handle, and
    /// the cached identity public key.
    #[inline(never)]
    pub fn clear_identity(mut self) {
        self.id_mut().fill(0);
        self.set_id_key_id(None);
        self.id_pub_key_mut().fill(0);
    }

    /// Zeroes the enable-time keys: the establish-credential and
    /// session-encryption key handles and their cached public keys.
    #[inline(never)]
    pub fn clear_enabled_keys(mut self) {
        self.set_ec_key_id(None);
        self.ec_pub_key_mut().fill(0);
        self.set_se_key_id(None);
        self.se_pub_key_mut().fill(0);
    }

    /// Zeroizes all per-tenant state established at enable and `PartInit`.
    ///
    /// Clears the enable-time and provisioning vault-key handles (the
    /// vault deletions themselves are the PAL's responsibility), the
    /// cached public keys, every caller-presented secret and write-once
    /// provisioning field (with their presence flags), the nonce, VM
    /// launch GUID, BK3 incarnation flag, and the per-partition session
    /// table.
    ///
    /// The partition identity and `Masked_BK_BOOT` are deliberately
    /// preserved — they are torn down only on free (see [`reset`]). The
    /// resource mask, generation counter, and lifecycle state are left
    /// for the caller to manage.
    ///
    /// [`reset`]: Self::reset
    #[inline(never)]
    pub fn clear_enabled_state(mut self) {
        // Enable-time keys + cached public keys.
        self.clear_enabled_keys();
        // Provisioning vault-key handles.
        self.set_mk_key_id(None);
        self.set_ups_key_id(None);
        self.set_pta_key_id(None);
        self.set_unwrapping_key_id(None);
        // Write-once provisioning material + presence flags.
        self.clear_pta_pub_key();
        self.clear_policy_hash();
        self.clear_pota_thumbprint();
        self.clear_sata_thumbprint();
        self.clear_sapota_thumbprint();
        self.clear_credential();
        // BK3 session/sealed material + incarnation flag.
        self.clear_bk3_session();
        self.clear_sealed_bk3();
        self.set_bk3_initialized(false);
        // Rotated PSKs, nonce, VM launch GUID, and session table.
        let slot = self.slot_mut();
        slot.psk_co = [0u8; PSK_LEN];
        slot.psk_cu = [0u8; PSK_LEN];
        slot.nonce = [0u8; NONCE_LEN];
        slot.vm_launch_guid = [0u8; GUID_LEN];
        slot.session_table = [0u8; SESSION_TABLE_LEN];
        slot.session_meta = [0u8; 2];
    }

    /// Borrows the partition's 16-byte identity.
    #[inline(never)]
    pub fn id(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().partition_identifier.id) }
    }

    /// Mutably borrows the partition's 16-byte identity.
    #[inline(never)]
    pub fn id_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `id`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().partition_identifier.id) }
    }

    /// Sets the partition's 16-byte identity.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `ID_LEN` bytes.
    #[inline(never)]
    pub fn set_id(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != ID_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.slot_mut().partition_identifier.id.copy_from_slice(src);
        Ok(())
    }

    /// Borrows the partition's identity public key (X ‖ Y, 96 B).
    ///
    /// The backing field is 97 B (reference SEC1 layout); Uno uses the
    /// first 96 B (raw X ‖ Y, no SEC1 prefix).
    #[inline(never)]
    pub fn id_pub_key(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().partition_identifier.pub_key[..PUB_KEY_LEN]) }
    }

    /// Mutably borrows the partition's identity public key (96 B).
    #[inline(never)]
    pub fn id_pub_key_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `id_pub_key`, exclusively borrowed.
        unsafe {
            DmaBuf::from_raw_mut(&mut self.slot_mut().partition_identifier.pub_key[..PUB_KEY_LEN])
        }
    }

    /// Sets the partition's identity public key (96 B, raw X ‖ Y).
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `PUB_KEY_LEN` bytes.
    #[inline(never)]
    pub fn set_id_pub_key(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != PUB_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.slot_mut().partition_identifier.pub_key[..PUB_KEY_LEN].copy_from_slice(src);
        Ok(())
    }

    /// Whether the partition identity has been provisioned.
    #[inline(never)]
    pub fn id_valid(self) -> bool {
        self.slot().partition_id_valid
    }

    /// Sets the partition-identity-valid flag.
    #[inline(never)]
    pub fn set_id_valid(mut self, valid: bool) {
        self.slot_mut().partition_id_valid = valid;
    }

    // ── nonce ────────────────────────────────────────────────────────────

    /// Borrows the partition's 32-byte anti-replay nonce.
    #[inline(never)]
    pub fn nonce(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().nonce) }
    }

    /// Mutably borrows the partition's nonce.
    #[inline(never)]
    pub fn nonce_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `nonce`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().nonce) }
    }

    /// Sets the partition's nonce.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `NONCE_LEN` bytes.
    #[inline(never)]
    pub fn set_nonce(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != NONCE_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.slot_mut().nonce.copy_from_slice(src);
        Ok(())
    }

    // ── vm launch guid ───────────────────────────────────────────────────

    /// Borrows the host-set VM-launch GUID (16 B).
    #[inline(never)]
    pub fn vm_launch_guid(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().vm_launch_guid) }
    }

    /// Mutably borrows the VM-launch GUID.
    #[inline(never)]
    pub fn vm_launch_guid_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `vm_launch_guid`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().vm_launch_guid) }
    }

    /// Sets the VM-launch GUID.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `GUID_LEN` bytes.
    #[inline(never)]
    pub fn set_vm_launch_guid(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != GUID_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.slot_mut().vm_launch_guid.copy_from_slice(src);
        Ok(())
    }

    // ── masked boot key (variable length) ────────────────────────────────

    /// Borrows the masked boot key, trimmed to its stored length.
    #[inline(never)]
    pub fn masked_bk_boot(self) -> &'static DmaBuf {
        let slot = self.slot();
        // Read the packed length field by value (no reference to it).
        let len = (slot.masked_bk_boot.len as usize).min(MASKED_BK_BOOT_DATA_LEN);
        // SAFETY: GSRAM bytes branded as DMA-accessible; `len` is clamped
        // in-bounds; valid for 'static.
        unsafe { DmaBuf::from_raw(&slot.masked_bk_boot.data[..len]) }
    }

    /// Writes the masked boot key (stores length + data).
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` exceeds `MASKED_BK_BOOT_DATA_LEN`.
    #[inline(never)]
    pub fn set_masked_bk_boot(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() > MASKED_BK_BOOT_DATA_LEN {
            return Err(HsmError::InvalidArg);
        }
        let slot = self.slot_mut();
        slot.masked_bk_boot.len = src.len() as u32;
        slot.masked_bk_boot.data[..src.len()].copy_from_slice(src);
        // Zeroize any stale (sensitive) bytes left by a previously longer
        // blob so nothing survives past the new length.
        slot.masked_bk_boot.data[src.len()..].fill(0);
        Ok(())
    }

    // ── sealed BK3 (variable length) ─────────────────────────────────────

    /// Borrows the sealed BK3 blob, trimmed to its stored length.
    #[inline(never)]
    pub fn sealed_bk3(self) -> &'static DmaBuf {
        let slot = self.slot();
        let len = (slot.sealed_bk3.len as usize).min(SEALED_BK3_DATA_LEN);
        // SAFETY: GSRAM bytes branded as DMA-accessible; `len` clamped
        // in-bounds; valid for 'static.
        unsafe { DmaBuf::from_raw(&slot.sealed_bk3.data[..len]) }
    }

    /// Writes the sealed BK3 blob (stores length + data).
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` exceeds `SEALED_BK3_DATA_LEN`.
    #[inline(never)]
    pub fn set_sealed_bk3(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() > SEALED_BK3_DATA_LEN {
            return Err(HsmError::InvalidArg);
        }
        let slot = self.slot_mut();
        slot.sealed_bk3.len = src.len() as u32;
        slot.sealed_bk3.data[..src.len()].copy_from_slice(src);
        // Zeroize any stale (sensitive) bytes left by a previously longer
        // blob so nothing survives past the new length.
        slot.sealed_bk3.data[src.len()..].fill(0);
        Ok(())
    }

    // ── BK3 session key ──────────────────────────────────────────────────

    /// Borrows the 48-byte BK3 session key.
    #[inline(never)]
    pub fn bk3_session(self) -> &'static DmaBuf {
        // SAFETY: `key` is an align-1 packed field; GSRAM bytes branded as
        // DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().bk3_session_key.key) }
    }

    /// Sets the BK3 session key and marks it valid.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `BK3_KEY_LEN` bytes.
    #[inline(never)]
    pub fn set_bk3_session(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != BK3_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        let slot = self.slot_mut();
        slot.bk3_session_key.key.copy_from_slice(src);
        slot.bk3_session_key.is_valid = true;
        Ok(())
    }

    /// Whether a BK3 session key has been provisioned.
    #[inline(never)]
    pub fn bk3_session_valid(self) -> bool {
        self.slot().bk3_session_key.is_valid
    }

    /// Clears the BK3 session key (zeroizes and marks absent).
    #[inline(never)]
    pub fn clear_bk3_session(mut self) {
        let slot = self.slot_mut();
        slot.bk3_session_key.key = [0u8; BK3_KEY_LEN];
        slot.bk3_session_key.is_valid = false;
    }

    /// Clears the sealed BK3 blob (marks absent).
    #[inline(never)]
    pub fn clear_sealed_bk3(mut self) {
        let slot = self.slot_mut();
        slot.sealed_bk3.data = [0u8; SEALED_BK3_DATA_LEN];
        slot.sealed_bk3.len = 0;
    }

    /// Clears the masked boot key (marks absent).
    #[inline(never)]
    pub fn clear_masked_bk_boot(mut self) {
        let slot = self.slot_mut();
        slot.masked_bk_boot.data = [0u8; MASKED_BK_BOOT_DATA_LEN];
        slot.masked_bk_boot.len = 0;
    }

    /// Whether InitBk3 has already run for this partition (one-shot gate).
    #[inline(never)]
    pub fn bk3_initialized(self) -> bool {
        self.slot().bk3_initialized
    }

    /// Sets the one-shot InitBk3 gate.
    #[inline(never)]
    pub fn set_bk3_initialized(mut self, valid: bool) {
        self.slot_mut().bk3_initialized = valid;
    }

    // ── lockout policy ───────────────────────────────────────────────────

    /// Reads the partition lockout / pin policy.
    #[inline(never)]
    pub fn pin_policy(self) -> PinPolicy {
        self.slot().pin_policy
    }

    /// Sets the partition lockout / pin policy.
    #[inline(never)]
    pub fn set_pin_policy(mut self, policy: PinPolicy) {
        self.slot_mut().pin_policy = policy;
    }

    // ── Uno ext fields ───────────────────────────────────────────────────

    /// Borrows the partition policy hash (48 B).
    #[inline(never)]
    pub fn policy_hash(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().policy_hash) }
    }

    /// Mutably borrows the partition policy hash.
    #[inline(never)]
    pub fn policy_hash_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `policy_hash`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().policy_hash) }
    }

    /// Sets the partition policy hash (marks it present).
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `POLICY_HASH_LEN` bytes.
    #[inline(never)]
    pub fn set_policy_hash(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != POLICY_HASH_LEN {
            return Err(HsmError::InvalidArg);
        }
        let slot = self.slot_mut();
        slot.policy_hash.copy_from_slice(src);
        slot.policy_hash_valid = true;
        Ok(())
    }

    /// Whether the partition policy hash has been provisioned.
    #[inline(never)]
    pub fn policy_hash_valid(self) -> bool {
        self.slot().policy_hash_valid
    }

    /// Clears the partition policy hash (zeroizes and marks absent).
    #[inline(never)]
    pub fn clear_policy_hash(mut self) {
        let slot = self.slot_mut();
        slot.policy_hash = [0u8; POLICY_HASH_LEN];
        slot.policy_hash_valid = false;
    }

    /// Borrows the POTA public-key thumbprint (48 B).
    #[inline(never)]
    pub fn pota_thumbprint(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().pota_thumbprint) }
    }

    /// Mutably borrows the POTA thumbprint.
    #[inline(never)]
    pub fn pota_thumbprint_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `pota_thumbprint`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().pota_thumbprint) }
    }

    /// Sets the POTA thumbprint.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `POTA_THUMBPRINT_LEN`
    ///   bytes.
    #[inline(never)]
    pub fn set_pota_thumbprint(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != POTA_THUMBPRINT_LEN {
            return Err(HsmError::InvalidArg);
        }
        let slot = self.slot_mut();
        slot.pota_thumbprint.copy_from_slice(src);
        slot.pota_thumbprint_valid = true;
        Ok(())
    }

    /// Whether a POTA thumbprint has been provisioned.
    #[inline(never)]
    pub fn pota_thumbprint_valid(self) -> bool {
        self.slot().pota_thumbprint_valid
    }

    /// Clears the POTA thumbprint (zeroizes and marks absent).
    #[inline(never)]
    pub fn clear_pota_thumbprint(mut self) {
        let slot = self.slot_mut();
        slot.pota_thumbprint = [0u8; POTA_THUMBPRINT_LEN];
        slot.pota_thumbprint_valid = false;
    }

    /// Borrows the SATA thumbprint (48 B).
    #[inline(never)]
    pub fn sata_thumbprint(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().sata_thumbprint) }
    }

    /// Sets the SATA thumbprint.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `SATA_THUMBPRINT_LEN`
    ///   bytes.
    #[inline(never)]
    pub fn set_sata_thumbprint(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != SATA_THUMBPRINT_LEN {
            return Err(HsmError::InvalidArg);
        }
        let slot = self.slot_mut();
        slot.sata_thumbprint.copy_from_slice(src);
        slot.sata_thumbprint_valid = true;
        Ok(())
    }

    /// Whether a SATA thumbprint has been provisioned.
    #[inline(never)]
    pub fn sata_thumbprint_valid(self) -> bool {
        self.slot().sata_thumbprint_valid
    }

    /// Clears the SATA thumbprint (zeroizes and marks absent).
    #[inline(never)]
    pub fn clear_sata_thumbprint(mut self) {
        let slot = self.slot_mut();
        slot.sata_thumbprint = [0u8; SATA_THUMBPRINT_LEN];
        slot.sata_thumbprint_valid = false;
    }

    /// Borrows the SAPOTA thumbprint (48 B).
    #[inline(never)]
    pub fn sapota_thumbprint(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().sapota_thumbprint) }
    }

    /// Sets the SAPOTA thumbprint.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `SAPOTA_THUMBPRINT_LEN`
    ///   bytes.
    #[inline(never)]
    pub fn set_sapota_thumbprint(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != SAPOTA_THUMBPRINT_LEN {
            return Err(HsmError::InvalidArg);
        }
        let slot = self.slot_mut();
        slot.sapota_thumbprint.copy_from_slice(src);
        slot.sapota_thumbprint_valid = true;
        Ok(())
    }

    /// Whether a SAPOTA thumbprint has been provisioned.
    #[inline(never)]
    pub fn sapota_thumbprint_valid(self) -> bool {
        self.slot().sapota_thumbprint_valid
    }

    /// Clears the SAPOTA thumbprint (zeroizes and marks absent).
    #[inline(never)]
    pub fn clear_sapota_thumbprint(mut self) {
        let slot = self.slot_mut();
        slot.sapota_thumbprint = [0u8; SAPOTA_THUMBPRINT_LEN];
        slot.sapota_thumbprint_valid = false;
    }

    // ── lifecycle state / generation / resource mask ─────────────────────

    /// Reads the partition lifecycle [`PartState`].
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — the stored byte is not a known state.
    #[inline(never)]
    pub fn state(self) -> HsmResult<PartState> {
        PartState::from_u8(self.slot().state[0]).ok_or(HsmError::InvalidArg)
    }

    /// Sets the partition lifecycle [`PartState`].
    #[inline(never)]
    pub fn set_state(mut self, state: PartState) {
        self.slot_mut().state = [state as u8, 0, 0, 0];
    }

    /// Reads the monotonic generation counter.
    #[inline(never)]
    pub fn generation(self) -> u32 {
        u32::from_le_bytes(self.slot().generation)
    }

    /// Sets the generation counter.
    #[inline(never)]
    pub fn set_generation(mut self, generation: u32) {
        self.slot_mut().generation = generation.to_le_bytes();
    }

    /// Increments the generation counter (wrapping).
    #[inline(never)]
    pub fn bump_generation(self) {
        let next = self.generation().wrapping_add(1);
        self.set_generation(next);
    }

    /// Reads the 128-bit table-ownership resource mask.
    #[inline(never)]
    pub fn res_mask(self) -> u128 {
        u128::from_le_bytes(self.slot().res_mask)
    }

    /// Sets the resource mask.
    #[inline(never)]
    pub fn set_res_mask(mut self, mask: u128) {
        self.slot_mut().res_mask = mask.to_le_bytes();
    }

    // ── key handles (`None` = absent; see `KEY_ABSENT`) ──────────────────

    /// Reads the identity key handle.
    #[inline(never)]
    pub fn id_key_id(self) -> Option<HsmKeyId> {
        read_handle(self.slot().id_key_id)
    }

    /// Sets (or clears, with `None`) the identity key handle.
    ///
    /// Keeps `partition_id_valid` in sync with handle presence: the PAL
    /// gates identity-property access on `id_key_id().is_some()`, so the
    /// stored validity flag tracks the same "identity provisioned" state
    /// (set on provisioning, cleared on `clear_identity` / free).
    #[inline(never)]
    pub fn set_id_key_id(mut self, key: Option<HsmKeyId>) {
        let slot = self.slot_mut();
        slot.id_key_id = write_handle(key);
        slot.partition_id_valid = key.is_some();
    }

    /// Reads the establish-credential key handle.
    #[inline(never)]
    pub fn ec_key_id(self) -> Option<HsmKeyId> {
        read_handle(self.slot().ec_key_id)
    }

    /// Sets (or clears) the establish-credential key handle.
    #[inline(never)]
    pub fn set_ec_key_id(mut self, key: Option<HsmKeyId>) {
        self.slot_mut().ec_key_id = write_handle(key);
    }

    /// Reads the session-encryption key handle.
    #[inline(never)]
    pub fn se_key_id(self) -> Option<HsmKeyId> {
        read_handle(self.slot().se_key_id)
    }

    /// Sets (or clears) the session-encryption key handle.
    #[inline(never)]
    pub fn set_se_key_id(mut self, key: Option<HsmKeyId>) {
        self.slot_mut().se_key_id = write_handle(key);
    }

    /// Reads the masking key handle.
    #[inline(never)]
    pub fn mk_key_id(self) -> Option<HsmKeyId> {
        read_handle(self.slot().mk_key_id)
    }

    /// Sets (or clears) the masking key handle.
    #[inline(never)]
    pub fn set_mk_key_id(mut self, key: Option<HsmKeyId>) {
        self.slot_mut().mk_key_id = write_handle(key);
    }

    /// Reads the UMS (unique-machine-secret) key handle.
    #[inline(never)]
    pub fn ups_key_id(self) -> Option<HsmKeyId> {
        read_handle(self.slot().ups_key_id)
    }

    /// Sets (or clears) the UMS key handle.
    #[inline(never)]
    pub fn set_ups_key_id(mut self, key: Option<HsmKeyId>) {
        self.slot_mut().ups_key_id = write_handle(key);
    }

    /// Reads the PTA (partition trust anchor) key handle.
    #[inline(never)]
    pub fn pta_key_id(self) -> Option<HsmKeyId> {
        read_handle(self.slot().pta_key_id)
    }

    /// Sets (or clears) the PTA key handle.
    #[inline(never)]
    pub fn set_pta_key_id(mut self, key: Option<HsmKeyId>) {
        self.slot_mut().pta_key_id = write_handle(key);
    }

    /// Reads the RSA unwrapping key handle.
    #[inline(never)]
    pub fn unwrapping_key_id(self) -> Option<HsmKeyId> {
        read_handle(self.slot().unwrapping_key_id)
    }

    /// Sets (or clears) the RSA unwrapping key handle.
    #[inline(never)]
    pub fn set_unwrapping_key_id(mut self, key: Option<HsmKeyId>) {
        self.slot_mut().unwrapping_key_id = write_handle(key);
    }

    // ── cached public keys (establish-cred / session-enc) ────────────────

    /// Borrows the establish-credential public key (X ‖ Y, 96 B).
    #[inline(never)]
    pub fn ec_pub_key(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().ec_pub_key) }
    }

    /// Mutably borrows the establish-credential public key.
    #[inline(never)]
    pub fn ec_pub_key_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `ec_pub_key`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().ec_pub_key) }
    }

    /// Sets the establish-credential public key.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `PUB_KEY_LEN` bytes.
    #[inline(never)]
    pub fn set_ec_pub_key(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != PUB_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.slot_mut().ec_pub_key.copy_from_slice(src);
        Ok(())
    }

    /// Borrows the session-encryption public key (X ‖ Y, 96 B).
    #[inline(never)]
    pub fn se_pub_key(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().se_pub_key) }
    }

    /// Mutably borrows the session-encryption public key.
    #[inline(never)]
    pub fn se_pub_key_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `se_pub_key`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().se_pub_key) }
    }

    /// Sets the session-encryption public key.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `PUB_KEY_LEN` bytes.
    #[inline(never)]
    pub fn set_se_pub_key(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != PUB_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.slot_mut().se_pub_key.copy_from_slice(src);
        Ok(())
    }

    // ── platform trust-anchor public key ─────────────────────────────────

    /// Borrows the platform trust-anchor public key (X ‖ Y, 96 B).
    #[inline(never)]
    pub fn pta_pub_key(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().pta_pub_key) }
    }

    /// Sets the platform trust-anchor public key (write-once via caller gate).
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `PUB_KEY_LEN` bytes.
    #[inline(never)]
    pub fn set_pta_pub_key(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != PUB_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        let slot = self.slot_mut();
        slot.pta_pub_key.copy_from_slice(src);
        slot.pta_pub_key_valid = true;
        Ok(())
    }

    /// Whether the platform trust-anchor public key has been provisioned.
    #[inline(never)]
    pub fn pta_pub_key_valid(self) -> bool {
        self.slot().pta_pub_key_valid
    }

    /// Clears the platform trust-anchor public key (zeroizes and marks absent).
    #[inline(never)]
    pub fn clear_pta_pub_key(mut self) {
        let slot = self.slot_mut();
        slot.pta_pub_key = [0u8; PUB_KEY_LEN];
        slot.pta_pub_key_valid = false;
    }

    /// Borrows the crypto-officer PSK (32 B).
    #[inline(never)]
    pub fn psk_co(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().psk_co) }
    }

    /// Mutably borrows the crypto-officer PSK.
    #[inline(never)]
    pub fn psk_co_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `psk_co`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().psk_co) }
    }

    /// Sets the crypto-officer PSK.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `PSK_LEN` bytes.
    #[inline(never)]
    pub fn set_psk_co(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != PSK_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.slot_mut().psk_co.copy_from_slice(src);
        Ok(())
    }

    /// Borrows the crypto-user PSK (32 B).
    #[inline(never)]
    pub fn psk_cu(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().psk_cu) }
    }

    /// Mutably borrows the crypto-user PSK.
    #[inline(never)]
    pub fn psk_cu_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `psk_cu`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().psk_cu) }
    }

    /// Sets the crypto-user PSK.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `PSK_LEN` bytes.
    #[inline(never)]
    pub fn set_psk_cu(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != PSK_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.slot_mut().psk_cu.copy_from_slice(src);
        Ok(())
    }

    // ── user credential ──────────────────────────────────────────────────

    /// Borrows the user credential (id ‖ pin, 32 B).
    #[inline(never)]
    pub fn credential(self) -> &'static DmaBuf {
        // SAFETY: GSRAM bytes branded as DMA-accessible; valid for 'static.
        unsafe { DmaBuf::from_raw(&self.slot().credential) }
    }

    /// Mutably borrows the user credential.
    #[inline(never)]
    pub fn credential_mut(&mut self) -> &mut DmaBuf {
        // SAFETY: as `credential`, exclusively borrowed.
        unsafe { DmaBuf::from_raw_mut(&mut self.slot_mut().credential) }
    }

    /// Sets the user credential.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `v` is not exactly `CREDENTIAL_LEN` bytes.
    #[inline(never)]
    pub fn set_credential(mut self, v: &DmaBuf) -> HsmResult<()> {
        let src: &[u8] = v;
        if src.len() != CREDENTIAL_LEN {
            return Err(HsmError::InvalidArg);
        }
        let slot = self.slot_mut();
        slot.credential.copy_from_slice(src);
        slot.credential_valid = true;
        Ok(())
    }

    /// Whether a user credential has been provisioned.
    #[inline(never)]
    pub fn credential_valid(self) -> bool {
        self.slot().credential_valid
    }

    /// Clears the user credential (zeroizes and marks absent).
    #[inline(never)]
    pub fn clear_credential(mut self) {
        let slot = self.slot_mut();
        slot.credential = [0u8; CREDENTIAL_LEN];
        slot.credential_valid = false;
    }

    // ── session table (raw region; typed view in drivers/session_store) ──

    /// Borrows the raw 18-byte session-table region.
    #[inline(never)]
    pub fn session_table(self) -> &'static [u8; SESSION_TABLE_LEN] {
        &self.slot().session_table
    }

    /// Mutably borrows the raw session-table region.
    #[inline(never)]
    pub fn session_table_mut(&mut self) -> &mut [u8; SESSION_TABLE_LEN] {
        &mut self.slot_mut().session_table
    }

    /// Borrows the 2-byte volatile session metadata (`pending_mask`,
    /// `psk_change_mask`) for the TBOR session slots.
    #[inline(never)]
    pub fn session_meta(self) -> &'static [u8; 2] {
        &self.slot().session_meta
    }

    /// Mutably borrows the session metadata region.
    #[inline(never)]
    pub fn session_meta_mut(&mut self) -> &mut [u8; 2] {
        &mut self.slot_mut().session_meta
    }
}

#[cfg(test)]
mod align_probe {
    use core::mem::offset_of;

    use super::*;
    #[test]
    fn pub_key_offsets() {
        std::eprintln!(
            "id_pub  = {}",
            offset_of!(Storage, partition_identifier) + 16 + 48
        );
        std::eprintln!("ec_pub  = {}", offset_of!(Storage, ec_pub_key));
        std::eprintln!("se_pub  = {}", offset_of!(Storage, se_pub_key));
    }
}
