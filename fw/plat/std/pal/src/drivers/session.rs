// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-partition session table with logical → physical ID remapping.
//!
//! This module implements the session slot allocator for the standard
//! PAL, mirroring the hardware session table layout.
//! reference firmware.  Each partition has its own independent
//! [`SessionTable`] with up to [`MAX_SESSIONS`] (8) concurrent sessions.
//!
//! ## Logical vs physical session IDs
//!
//! - **Logical ID** ([`HsmSessId`], 0–7): slot index returned to callers.
//! - **Physical ID** ([`HsmKeyId`]): vault key ID where the session blob
//!   (8-byte API revision + 80-byte masking key) is stored.
//!
//! The `phys_ids` array maps each logical slot to its physical vault
//! key ID.  Session-scoped vault keys reference the **physical** ID so
//! that `delete_by_session_key` can match without knowing the logical
//! slot.
//!
//! ## Allocation strategy
//!
//! Sessions are tracked with two `u8` bitmasks plus the mapping array:
//!
//! - **`alloc_mask`** — bit *N* is set when slot *N* is in use.
//! - **`renego_mask`** — bit *N* is set when slot *N* requires
//!   renegotiation (e.g., after a VM live-migration event).
//! - **`phys_ids`** — `phys_ids[N]` holds the vault key ID for slot *N*.
//!
//! A new session is allocated by finding the lowest zero bit in
//! `alloc_mask` via [`u8::trailing_ones`].
//!
//! ## Session states
//!
//! | `alloc_mask[N]` | `renego_mask[N]` | State |
//! |:---:|:---:|:---|
//! | 0 | — | [`Invalid`](HsmSessionState::Invalid) — slot is free |
//! | 1 | 0 | [`Active`](HsmSessionState::Active) — session is usable |
//! | 1 | 1 | [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation) |

use azihsm_fw_hsm_pal_traits::*;

/// Maximum number of concurrent sessions per partition.
const MAX_SESSIONS: usize = 8;

/// Per-partition session table with logical → physical ID remapping.
///
/// Each logical session slot (0–7) maps to a physical vault key ID
/// ([`HsmKeyId`]) where the session blob is stored.
pub struct SessionTable {
    /// Allocation bitmask — bit N is set when session slot N is in use.
    alloc_mask: u8,
    /// Renegotiation bitmask — bit N is set when session N needs renegotiation.
    renego_mask: u8,
    /// Logical → physical mapping: `phys_ids[slot]` is the vault key ID
    /// for session slot `slot`.  Only valid when the corresponding
    /// `alloc_mask` bit is set.
    phys_ids: [u16; MAX_SESSIONS],
}

impl SessionTable {
    /// Create an empty session table with no allocated sessions.
    pub fn new() -> Self {
        Self {
            alloc_mask: 0,
            renego_mask: 0,
            phys_ids: [0; MAX_SESSIONS],
        }
    }

    /// Validate that a logical session ID refers to an allocated slot.
    /// Returns the slot index on success.
    fn active_slot(&self, id: HsmSessId) -> HsmResult<usize> {
        let slot = u16::from(id) as usize;
        if slot >= MAX_SESSIONS || (self.alloc_mask & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotFound);
        }
        Ok(slot)
    }

    /// Allocate a new session in the first available slot.
    ///
    /// Finds the lowest-numbered free slot via [`u8::trailing_ones`] on
    /// the allocation mask and stores the logical → physical mapping.
    ///
    /// # Parameters
    ///
    /// - `physical_id` — vault key ID where the session blob is stored.
    ///
    /// # Returns
    ///
    /// The logical [`HsmSessId`] (slot index 0–7).
    pub fn create(&mut self, physical_id: HsmKeyId) -> HsmResult<HsmSessId> {
        let slot = self.alloc_mask.trailing_ones() as usize;
        if slot >= MAX_SESSIONS {
            return Err(HsmError::VaultSessionLimitReached);
        }
        self.alloc_mask |= 1 << slot;
        self.phys_ids[slot] = u16::from(physical_id);
        Ok(HsmSessId::from(slot as u16))
    }

    /// Delete (close) an existing session, freeing its slot.
    ///
    /// Clears both the allocation and renegotiation bits and returns
    /// the physical vault key ID so the caller can clean up the vault.
    pub fn delete(&mut self, id: HsmSessId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        let phys = HsmKeyId::from(self.phys_ids[slot]);
        let mask = !(1u8 << slot);
        self.alloc_mask &= mask;
        self.renego_mask &= mask;
        self.phys_ids[slot] = 0;
        Ok(phys)
    }

    /// Look up the physical vault key ID for a logical session.
    pub fn physical_id(&self, id: HsmSessId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        Ok(HsmKeyId::from(self.phys_ids[slot]))
    }

    /// Re-key an existing session with a new physical vault key ID.
    ///
    /// The session must be in [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation)
    /// state.  On success, clears the renegotiation bit and updates the
    /// physical mapping.
    pub fn recreate(&mut self, id: HsmSessId, new_physical: HsmKeyId) -> HsmResult<HsmSessId> {
        let slot = self.active_slot(id)?;
        if (self.renego_mask & (1 << slot)) == 0 {
            return Err(HsmError::InvalidArg);
        }
        self.renego_mask &= !(1u8 << slot);
        self.phys_ids[slot] = u16::from(new_physical);
        Ok(id)
    }

    /// Query the current state of a session slot.
    pub fn state(&self, id: HsmSessId) -> HsmSessionState {
        let Ok(slot) = self.active_slot(id) else {
            return HsmSessionState::Invalid;
        };
        if (self.renego_mask & (1 << slot)) != 0 {
            return HsmSessionState::NeedsRenegotiation;
        }
        HsmSessionState::Active
    }

    /// Check whether all session slots are occupied.
    pub fn limit_reached(&self) -> bool {
        self.alloc_mask.count_ones() >= MAX_SESSIONS as u32
    }

    /// Set the renegotiation bit for a session (test helper).
    #[cfg(test)]
    pub fn set_needs_renego(&mut self, id: HsmSessId) {
        let slot = u16::from(id) as usize;
        if slot < MAX_SESSIONS && (self.alloc_mask & (1 << slot)) != 0 {
            self.renego_mask |= 1 << slot;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_session() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(0x0100)).unwrap();
        assert_eq!(u16::from(id), 0);
    }

    #[test]
    fn create_multiple_sessions() {
        let mut table = SessionTable::new();
        for expected in 0u16..8 {
            let phys = HsmKeyId::from(0x0100 + expected);
            let id = table.create(phys).unwrap();
            assert_eq!(u16::from(id), expected);
        }
    }

    #[test]
    fn create_beyond_limit() {
        let mut table = SessionTable::new();
        for i in 0..8u16 {
            table.create(HsmKeyId::from(i)).unwrap();
        }
        let err = table.create(HsmKeyId::from(99)).unwrap_err();
        assert_eq!(err, HsmError::VaultSessionLimitReached);
    }

    #[test]
    fn delete_and_reuse() {
        let mut table = SessionTable::new();
        let phys = HsmKeyId::from(42);
        let id = table.create(phys).unwrap();
        let returned_phys = table.delete(id).unwrap();
        assert_eq!(u16::from(returned_phys), 42);
        // Slot reused.
        let id2 = table.create(HsmKeyId::from(99)).unwrap();
        assert_eq!(u16::from(id2), 0);
    }

    #[test]
    fn session_state_active() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(0)).unwrap();
        assert!(matches!(table.state(id), HsmSessionState::Active));
    }

    #[test]
    fn session_state_invalid_never_created() {
        let table = SessionTable::new();
        let id = HsmSessId::from(0);
        assert!(matches!(table.state(id), HsmSessionState::Invalid));
    }

    #[test]
    fn session_state_invalid_after_delete() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(0)).unwrap();
        table.delete(id).unwrap();
        assert!(matches!(table.state(id), HsmSessionState::Invalid));
    }

    #[test]
    fn limit_reached_true() {
        let mut table = SessionTable::new();
        for i in 0..8u16 {
            table.create(HsmKeyId::from(i)).unwrap();
        }
        assert!(table.limit_reached());
    }

    #[test]
    fn limit_reached_false_after_delete() {
        let mut table = SessionTable::new();
        for i in 0..8u16 {
            table.create(HsmKeyId::from(i)).unwrap();
        }
        assert!(table.limit_reached());
        table.delete(HsmSessId::from(3)).unwrap();
        assert!(!table.limit_reached());
    }

    // --- New tests ---

    #[test]
    fn physical_id_lookup() {
        let mut table = SessionTable::new();
        let phys = HsmKeyId::from(0x0102);
        let id = table.create(phys).unwrap();
        assert_eq!(u16::from(table.physical_id(id).unwrap()), 0x0102);
    }

    #[test]
    fn physical_id_invalid() {
        let table = SessionTable::new();
        let err = table.physical_id(HsmSessId::from(0)).unwrap_err();
        assert_eq!(err, HsmError::SessionNotFound);
    }

    #[test]
    fn recreate_session() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(10)).unwrap();
        // Mark as needing renegotiation.
        table.set_needs_renego(id);
        assert!(matches!(
            table.state(id),
            HsmSessionState::NeedsRenegotiation
        ));
        // Recreate with new physical ID.
        let same_id = table.recreate(id, HsmKeyId::from(20)).unwrap();
        assert_eq!(u16::from(same_id), u16::from(id));
        assert!(matches!(table.state(id), HsmSessionState::Active));
        assert_eq!(u16::from(table.physical_id(id).unwrap()), 20);
    }

    #[test]
    fn recreate_not_renegotiating_fails() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(10)).unwrap();
        // Active, not NeedsRenegotiation — should fail.
        let err = table.recreate(id, HsmKeyId::from(20)).unwrap_err();
        assert_eq!(err, HsmError::InvalidArg);
    }

    #[test]
    fn delete_returns_physical_id() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(42)).unwrap();
        let phys = table.delete(id).unwrap();
        assert_eq!(u16::from(phys), 42);
    }
}
