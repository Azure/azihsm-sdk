// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`SessionStore`]: the session indirection table. Its persistent state
//! lives in the raw 18-byte `session_table` region of a partition's
//! persistent store; the volatile Pending and PSK-change bitmasks live in
//! the adjacent 2-byte `session_meta` region (cleared on reset).

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmSessionState;
use azihsm_fw_hsm_pal_traits::SessionRole;
use azihsm_fw_uno_drivers_part_store::PartStore;
use azihsm_fw_uno_drivers_part_store::Partition;

/// Maximum concurrent sessions per partition (one bit per slot in the
/// allocation / renegotiation masks).
pub const MAX_SESSIONS: usize = 8;

/// Size of the persistent session-store region, in bytes:
/// `alloc_mask` (1) + `renego_mask` (1) + `phys_ids` (8 × u16 = 16).
pub const SESSION_STORE_LEN: usize = 2 + MAX_SESSIONS * 2;

// Byte offsets within the region.
const ALLOC_MASK: usize = 0;
const RENEGO_MASK: usize = 1;
const PHYS_IDS: usize = 2;

/// Persistent session indirection table.
///
/// Stateless entry point: [`SessionStore::partition`] validates a raw
/// partition id and returns a [`SessionTable`] handle through which the
/// partition's session slots are managed. Mirrors
/// [`PartStore`](azihsm_fw_uno_drivers_part_store::PartStore).
#[derive(Debug)]
pub struct SessionStore;

impl SessionStore {
    /// Validates a raw partition id and returns a handle to its session
    /// table.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `pid` is out of range.
    #[inline]
    pub fn partition(pid: HsmPartId) -> HsmResult<SessionTable> {
        Ok(SessionTable(PartStore::partition(pid)?))
    }
}

/// A partition's persistent session indirection table.
///
/// Obtained only via [`SessionStore::partition`], so holding one is proof
/// that the partition index is in range. Logical session IDs are slot
/// indices (`0..MAX_SESSIONS`); each occupied slot maps to a physical
/// vault key ID. Only the persistent fields live here — see the crate docs
/// for the volatile state that is managed elsewhere. Mirrors the
/// [`Partition`](azihsm_fw_uno_drivers_part_store::Partition) handle.
#[derive(Debug, Clone, Copy)]
pub struct SessionTable(Partition);

impl SessionTable {
    // ── raw field helpers ────────────────────────────────────────────────

    #[inline]
    fn region(&self) -> &[u8; SESSION_STORE_LEN] {
        self.0.session_table()
    }

    #[inline]
    fn region_mut(&mut self) -> &mut [u8; SESSION_STORE_LEN] {
        self.0.session_table_mut()
    }

    #[inline]
    fn alloc_mask(&self) -> u8 {
        self.region()[ALLOC_MASK]
    }

    #[inline]
    fn renego_mask(&self) -> u8 {
        self.region()[RENEGO_MASK]
    }

    #[inline]
    fn phys_id(&self, slot: usize) -> u16 {
        let off = PHYS_IDS + slot * 2;
        let r = self.region();
        u16::from_le_bytes([r[off], r[off + 1]])
    }

    #[inline]
    fn set_phys_id(&mut self, slot: usize, value: u16) {
        let off = PHYS_IDS + slot * 2;
        self.region_mut()[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    // ── volatile pending / psk-change masks (uno session_meta region) ────

    #[inline]
    fn pending_mask(&self) -> u8 {
        self.0.session_meta()[0]
    }

    #[inline]
    fn set_pending_mask(&mut self, v: u8) {
        self.0.session_meta_mut()[0] = v;
    }

    #[inline]
    fn psk_change_mask(&self) -> u8 {
        self.0.session_meta()[1]
    }

    #[inline]
    fn set_psk_change_mask(&mut self, v: u8) {
        self.0.session_meta_mut()[1] = v;
    }

    /// Slot range eligible for a Pending session of `role`:
    /// CryptoOfficer → slot 0 only; CryptoUser → slots `1..=MAX_SESSIONS-1`.
    #[inline]
    fn role_slot_range(role: SessionRole) -> (usize, usize) {
        match role {
            SessionRole::CryptoOfficer => (0, 0),
            SessionRole::CryptoUser => (1, MAX_SESSIONS - 1),
        }
    }

    /// Validates that `id` refers to an allocated slot, returning its index.
    fn active_slot(&self, id: HsmSessId) -> HsmResult<usize> {
        let slot = u16::from(id) as usize;
        if slot >= MAX_SESSIONS || (self.alloc_mask() & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotFound);
        }
        Ok(slot)
    }

    // ── operations ───────────────────────────────────────────────────────

    /// Allocates a session in the lowest free slot, mapping it to
    /// `physical_id`.
    ///
    /// # Errors
    ///
    /// - [`HsmError::VaultSessionLimitReached`] — all slots are occupied.
    #[inline(never)]
    pub fn create(&mut self, physical_id: HsmKeyId) -> HsmResult<HsmSessId> {
        let slot = self.alloc_mask().trailing_ones() as usize;
        if slot >= MAX_SESSIONS {
            return Err(HsmError::VaultSessionLimitReached);
        }
        self.region_mut()[ALLOC_MASK] |= 1 << slot;
        self.set_phys_id(slot, u16::from(physical_id));
        Ok(HsmSessId::from(slot as u16))
    }

    /// Closes a session, freeing its slot and returning the physical vault
    /// key ID it mapped to (so the caller can clean up the vault entry).
    ///
    /// # Errors
    ///
    /// - [`HsmError::SessionNotFound`] — `id` is not an allocated slot.
    #[inline(never)]
    pub fn delete(&mut self, id: HsmSessId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        let phys = HsmKeyId::from(self.phys_id(slot));
        let clear = !(1u8 << slot);
        self.region_mut()[ALLOC_MASK] &= clear;
        self.region_mut()[RENEGO_MASK] &= clear;
        self.set_pending_mask(self.pending_mask() & clear);
        self.set_psk_change_mask(self.psk_change_mask() & clear);
        self.set_phys_id(slot, 0);
        Ok(phys)
    }

    /// Looks up the physical vault key ID for a logical session.
    ///
    /// # Errors
    ///
    /// - [`HsmError::SessionNotFound`] — `id` is not an allocated slot.
    #[inline(never)]
    pub fn physical_id(&self, id: HsmSessId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        Ok(HsmKeyId::from(self.phys_id(slot)))
    }

    /// Re-keys a session that needs renegotiation with a new physical vault
    /// key ID, clearing its renegotiation flag.
    ///
    /// # Errors
    ///
    /// - [`HsmError::SessionNotFound`] — `id` is not an allocated slot.
    /// - [`HsmError::InvalidArg`] — the session is not in the
    ///   [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation) state.
    #[inline(never)]
    pub fn recreate(&mut self, id: HsmSessId, new_physical: HsmKeyId) -> HsmResult<HsmSessId> {
        let slot = self.active_slot(id)?;
        if (self.renego_mask() & (1 << slot)) == 0 {
            return Err(HsmError::InvalidArg);
        }
        self.region_mut()[RENEGO_MASK] &= !(1u8 << slot);
        self.set_phys_id(slot, u16::from(new_physical));
        Ok(id)
    }

    /// Returns the persistent state of a session slot.
    ///
    /// A slot whose handshake is still in flight reports
    /// [`Pending`](HsmSessionState::Pending); a renegotiation-flagged
    /// slot reports [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation);
    /// otherwise [`Active`](HsmSessionState::Active).
    #[inline(never)]
    pub fn state(&self, id: HsmSessId) -> HsmSessionState {
        let Ok(slot) = self.active_slot(id) else {
            return HsmSessionState::Invalid;
        };
        if (self.pending_mask() & (1 << slot)) != 0 {
            return HsmSessionState::Pending;
        }
        if (self.renego_mask() & (1 << slot)) != 0 {
            return HsmSessionState::NeedsRenegotiation;
        }
        HsmSessionState::Active
    }

    /// Returns `true` when every slot is occupied.
    #[inline(never)]
    pub fn limit_reached(&self) -> bool {
        self.alloc_mask().count_ones() >= MAX_SESSIONS as u32
    }

    /// Marks an allocated session as needing renegotiation. No-op for
    /// unallocated slots.
    #[inline(never)]
    pub fn set_needs_renego(&mut self, id: HsmSessId) {
        let slot = u16::from(id) as usize;
        if slot < MAX_SESSIONS && (self.alloc_mask() & (1 << slot)) != 0 {
            self.region_mut()[RENEGO_MASK] |= 1 << slot;
        }
    }

    /// Returns the physical vault key id of every occupied slot (Active,
    /// NeedsRenegotiation, or Pending), so a caller tearing the partition
    /// down can delete the backing session-blob vault keys before the
    /// table is zeroized — otherwise they would be orphaned in the vault.
    ///
    /// Read-only: the table is left unchanged (the caller clears it
    /// separately, e.g. via the partition store's `clear_enabled_state`).
    #[inline(never)]
    pub fn occupied_physical_ids(&self) -> [Option<HsmKeyId>; MAX_SESSIONS] {
        let mut out = [None; MAX_SESSIONS];
        let mask = self.alloc_mask();
        for (slot, entry) in out.iter_mut().enumerate() {
            if (mask & (1 << slot)) != 0 {
                *entry = Some(HsmKeyId::from(self.phys_id(slot)));
            }
        }
        out
    }

    // ── TBOR in-flight handshake (Pending) slots ─────────────────────────

    /// Reserves a [`Pending`](HsmSessionState::Pending) slot in `role`'s
    /// eligible range, mapping it to the handshake-blob vault key
    /// `physical_id`.
    ///
    /// Prefers the lowest free slot in range; if the range is full, evicts
    /// the lowest-index Pending slot and returns its physical vault key id
    /// so the caller can delete the abandoned handshake key. Active /
    /// renegotiating slots are never evicted.
    ///
    /// # Errors
    ///
    /// - [`HsmError::VaultSessionLimitReached`] — every slot in range is
    ///   Active or NeedsRenegotiation (nothing evictable).
    #[inline(never)]
    pub fn create_pending(
        &mut self,
        role: SessionRole,
        physical_id: HsmKeyId,
    ) -> HsmResult<(HsmSessId, Option<HsmKeyId>)> {
        let (start, end) = Self::role_slot_range(role);

        // 1. Lowest free slot in range.
        for slot in start..=end {
            if (self.alloc_mask() & (1 << slot)) == 0 {
                self.install_pending(slot, physical_id);
                return Ok((HsmSessId::from(slot as u16), None));
            }
        }

        // 2. Evict the lowest-index Pending slot in range.
        for slot in start..=end {
            if (self.pending_mask() & (1 << slot)) != 0 {
                let evicted = HsmKeyId::from(self.phys_id(slot));
                self.install_pending(slot, physical_id);
                return Ok((HsmSessId::from(slot as u16), Some(evicted)));
            }
        }

        // 3. All slots in range are Active or NeedsRenegotiation.
        Err(HsmError::VaultSessionLimitReached)
    }

    /// Occupies `slot` as a fresh Pending session mapped to `physical_id`,
    /// clearing any stale renegotiation / psk-change flags.
    fn install_pending(&mut self, slot: usize, physical_id: HsmKeyId) {
        let bit = 1u8 << slot;
        self.region_mut()[ALLOC_MASK] |= bit;
        self.region_mut()[RENEGO_MASK] &= !bit;
        self.set_pending_mask(self.pending_mask() | bit);
        self.set_psk_change_mask(self.psk_change_mask() & !bit);
        self.set_phys_id(slot, u16::from(physical_id));
    }

    /// Returns the handshake-blob vault key id for a Pending session.
    ///
    /// # Errors
    ///
    /// - [`HsmError::SessionNotFound`] — `id` is not an allocated slot.
    /// - [`HsmError::SessionNotPending`] — the slot exists but is not
    ///   Pending.
    #[inline(never)]
    pub fn pending_phys(&self, id: HsmSessId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        if (self.pending_mask() & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotPending);
        }
        Ok(HsmKeyId::from(self.phys_id(slot)))
    }

    /// Promotes a [`Pending`](HsmSessionState::Pending) slot to
    /// [`Active`](HsmSessionState::Active), rebinding it to the committed
    /// session vault key `new_physical`. Returns the old handshake vault
    /// key id so the caller can delete it.
    ///
    /// # Errors
    ///
    /// - [`HsmError::SessionNotFound`] — `id` is not an allocated slot.
    /// - [`HsmError::SessionNotPending`] — the slot exists but is not
    ///   Pending.
    #[inline(never)]
    pub fn promote(&mut self, id: HsmSessId, new_physical: HsmKeyId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        let bit = 1u8 << slot;
        if (self.pending_mask() & bit) == 0 {
            return Err(HsmError::SessionNotPending);
        }
        let old = HsmKeyId::from(self.phys_id(slot));
        self.set_pending_mask(self.pending_mask() & !bit);
        self.set_psk_change_mask(self.psk_change_mask() & !bit);
        self.set_phys_id(slot, u16::from(new_physical));
        Ok(old)
    }

    /// Consumes the one PSK change permitted for an Active session.
    ///
    /// # Errors
    ///
    /// - [`HsmError::SessionNotFound`] — `id` is not an allocated slot, or
    ///   is still Pending.
    /// - [`HsmError::InvalidPermissions`] — the session has already
    ///   consumed its PSK change (the flag remains set).
    #[inline(never)]
    pub fn try_consume_psk_change(&mut self, id: HsmSessId) -> HsmResult<()> {
        let slot = self.active_slot(id)?;
        let bit = 1u8 << slot;
        if (self.pending_mask() & bit) != 0 {
            return Err(HsmError::SessionNotFound);
        }
        if (self.psk_change_mask() & bit) != 0 {
            return Err(HsmError::InvalidPermissions);
        }
        self.set_psk_change_mask(self.psk_change_mask() | bit);
        Ok(())
    }
}
