// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-partition session table using bitmask allocation.
//!
//! This module implements the session slot allocator for the standard
//! PAL, mirroring the hardware session table layout from the mcr-hsm
//! reference firmware.  Each partition has its own independent
//! [`SessionTable`] with up to [`MAX_SESSIONS`] (8) concurrent sessions.
//!
//! ## Allocation strategy
//!
//! Sessions are tracked with two `u8` bitmasks:
//!
//! - **`alloc_mask`** — bit *N* is set when slot *N* is in use.
//! - **`renego_mask`** — bit *N* is set when slot *N* requires
//!   renegotiation (e.g., after a VM live-migration event).
//!
//! A new session is allocated by finding the lowest zero bit in
//! `alloc_mask` via [`u8::trailing_ones`].  Deletion clears both
//! bitmask bits for the slot.
//!
//! ## Session states
//!
//! | `alloc_mask[N]` | `renego_mask[N]` | State |
//! |:---:|:---:|:---|
//! | 0 | — | [`Invalid`](HsmSessionState::Invalid) — slot is free |
//! | 1 | 0 | [`Active`](HsmSessionState::Active) — session is usable |
//! | 1 | 1 | [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation) |
//!
//! ## Integration
//!
//! A `SessionTable` instance is embedded in each
//! [`PartitionEntry`](crate::part::PartitionEntry).  The PAL's
//! [`HsmSessionManager`] implementation (in `session.rs`) delegates to
//! these per-partition tables after validating the partition index.

use azihsm_fw_hsm_pal_traits::*;

/// Maximum number of concurrent sessions per partition.
const MAX_SESSIONS: usize = 8;

/// Per-partition session table using bitmask allocation.
///
/// Matches the mcr-hsm hardware session table layout:
/// - `alloc_mask: u8` — bit N = 1 means session N is allocated.
/// - `renego_mask: u8` — bit N = 1 means session N needs renegotiation.
///
/// Session IDs are slot indices 0–7, found via [`u8::trailing_ones`].
pub struct SessionTable {
    /// Allocation bitmask — bit N is set when session slot N is in use.
    alloc_mask: u8,
    /// Renegotiation bitmask — bit N is set when session N needs renegotiation.
    renego_mask: u8,
}

impl SessionTable {
    /// Create an empty session table with no allocated sessions.
    pub fn new() -> Self {
        Self {
            alloc_mask: 0,
            renego_mask: 0,
        }
    }

    /// Allocate a new session in the first available slot.
    ///
    /// Finds the lowest-numbered free slot via [`u8::trailing_ones`] on
    /// the allocation mask. If all [`MAX_SESSIONS`] slots are occupied,
    /// returns [`HsmError::VaultSessionLimitReached`].
    ///
    /// # Returns
    ///
    /// The [`HsmSessId`] of the newly allocated session (slot index 0–7).
    pub fn create(&mut self) -> HsmResult<HsmSessId> {
        let slot = self.alloc_mask.trailing_ones() as usize;
        if slot >= MAX_SESSIONS {
            return Err(HsmError::VaultSessionLimitReached);
        }
        self.alloc_mask |= 1 << slot;
        Ok(HsmSessId::from(slot as u16))
    }

    /// Delete (close) an existing session, freeing its slot.
    ///
    /// Validates that the session ID is within bounds and currently
    /// allocated. Clears both the allocation and renegotiation bits.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::SessionNotFound`] if `id` is out of range or
    /// the slot is not currently allocated.
    pub fn delete(&mut self, id: HsmSessId) -> HsmResult<()> {
        let slot = u16::from(id) as usize;
        if slot >= MAX_SESSIONS || (self.alloc_mask & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotFound);
        }
        let mask = !(1u8 << slot);
        self.alloc_mask &= mask;
        self.renego_mask &= mask;
        Ok(())
    }

    /// Query the current state of a session slot.
    ///
    /// - [`HsmSessionState::Active`] — allocated and not pending renegotiation.
    /// - [`HsmSessionState::NeedsRenegotiation`] — allocated but flagged for
    ///   renegotiation (e.g., after VM migration).
    /// - [`HsmSessionState::Invalid`] — not allocated (never created or deleted).
    pub fn state(&self, id: HsmSessId) -> HsmSessionState {
        let slot = u16::from(id) as usize;
        if slot >= MAX_SESSIONS || (self.alloc_mask & (1 << slot)) == 0 {
            return HsmSessionState::Invalid;
        }
        if (self.renego_mask & (1 << slot)) != 0 {
            return HsmSessionState::NeedsRenegotiation;
        }
        HsmSessionState::Active
    }

    /// Check whether all session slots are occupied.
    ///
    /// Returns `true` when [`MAX_SESSIONS`] sessions are allocated,
    /// meaning no new sessions can be created.
    pub fn limit_reached(&self) -> bool {
        self.alloc_mask.count_ones() >= MAX_SESSIONS as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_session() {
        let mut table = SessionTable::new();
        let id = table.create().unwrap();
        assert_eq!(u16::from(id), 0);
    }

    #[test]
    fn create_multiple_sessions() {
        let mut table = SessionTable::new();
        for expected in 0u16..8 {
            let id = table.create().unwrap();
            assert_eq!(u16::from(id), expected);
        }
    }

    #[test]
    fn create_beyond_limit() {
        let mut table = SessionTable::new();
        for _ in 0..8 {
            table.create().unwrap();
        }
        let err = table.create().unwrap_err();
        assert_eq!(err, HsmError::VaultSessionLimitReached);
    }

    #[test]
    fn delete_and_reuse() {
        let mut table = SessionTable::new();
        let id = table.create().unwrap();
        assert_eq!(u16::from(id), 0);
        table.delete(id).unwrap();
        let id2 = table.create().unwrap();
        assert_eq!(u16::from(id2), 0);
    }

    #[test]
    fn session_state_active() {
        let mut table = SessionTable::new();
        let id = table.create().unwrap();
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
        let id = table.create().unwrap();
        table.delete(id).unwrap();
        assert!(matches!(table.state(id), HsmSessionState::Invalid));
    }

    #[test]
    fn limit_reached_true() {
        let mut table = SessionTable::new();
        for _ in 0..8 {
            table.create().unwrap();
        }
        assert!(table.limit_reached());
    }

    #[test]
    fn limit_reached_false_after_delete() {
        let mut table = SessionTable::new();
        for _ in 0..8 {
            table.create().unwrap();
        }
        assert!(table.limit_reached());
        table.delete(HsmSessId::from(3)).unwrap();
        assert!(!table.limit_reached());
    }
}
