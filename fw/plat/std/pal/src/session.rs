// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmSessionManager`] implementation for the standard PAL.
//!
//! This module bridges the platform-agnostic
//! [`HsmSessionManager`] trait to the per-partition
//! [`SessionTable`] driver.  Each partition stores its own
//! `SessionTable` inside [`PartitionEntry`]; the methods here
//! validate the partition index, borrow the correct table through
//! the [`UnsafeCell`]-wrapped partition table, and delegate to the
//! driver.
//!
//! # Safety
//!
//! Access to the partition table uses the same [`UnsafeCell`] pattern
//! as [`HsmPartitionManager`].  This is sound because:
//!
//! 1. The Embassy executor is **single-threaded** — no concurrent
//!    access from other tasks.
//! 2. All methods in this impl are **synchronous** (no `.await`
//!    points), so no interleaving can occur between borrow and use.
//! 3. Mutable methods (`session_create`, `session_delete`) are only
//!    called by the DDI handler task, which holds the I/O object and
//!    therefore has exclusive logical ownership.
//!
//! [`SessionTable`]: crate::drivers::session::SessionTable
//! [`PartitionEntry`]: crate::part::PartitionEntry

use super::*;

impl HsmSessionManager for StdHsmPal {
    /// Check whether the partition's session table is full.
    ///
    /// Returns `true` when all 8 session slots are allocated, meaning
    /// [`session_create`](Self::session_create) would fail with
    /// [`HsmError::VaultSessionLimitReached`].
    ///
    /// If `pid` is out of range or partition is disabled, conservatively
    /// returns `true` (no sessions available).
    fn session_limit_reached(&self, pid: HsmPartId) -> bool {
        let Ok(entry) = self.active_part(pid) else {
            return true;
        };
        entry.session_table.limit_reached()
    }

    /// Allocate a new session in the partition's session table.
    ///
    /// Finds the lowest free slot via [`SessionTable::create`] and
    /// returns the corresponding [`HsmSessId`].
    ///
    /// # Parameters
    ///
    /// - `pid` — Target partition (must be < [`NUM_PARTITIONS`](crate::part::NUM_PARTITIONS)).
    /// - `_id` — Reserved for session re-keying (currently unused).
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] if `pid` is out of range.
    /// - [`HsmError::VaultSessionLimitReached`] if all 8 slots are in use.
    ///
    /// [`SessionTable::create`]: crate::drivers::session::SessionTable::create
    fn session_create(&self, pid: HsmPartId, _id: Option<HsmSessId>) -> HsmResult<HsmSessId> {
        // TODO: handle recreate (re-key of existing session via _id parameter)
        let entry = self.active_part_mut(pid)?;
        entry.session_table.create()
    }

    /// Delete (close) a session, freeing its slot for reuse.
    ///
    /// Clears both the allocation and renegotiation bits for the
    /// session via [`SessionTable::delete`].
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] if `pid` is out of range.
    /// - [`HsmError::SessionNotFound`] if the slot is not currently
    ///   allocated.
    ///
    /// [`SessionTable::delete`]: crate::drivers::session::SessionTable::delete
    fn session_delete(&self, pid: HsmPartId, id: HsmSessId) -> HsmResult<()> {
        let entry = self.active_part_mut(pid)?;
        entry.session_table.delete(id)
    }

    /// Query the lifecycle state of a session.
    ///
    /// Returns [`HsmSessionState::Active`],
    /// [`HsmSessionState::NeedsRenegotiation`], or
    /// [`HsmSessionState::Invalid`] depending on the allocation and
    /// renegotiation bitmask bits.
    ///
    /// Out-of-range `pid` values return [`HsmSessionState::Invalid`].
    fn session_state(&self, pid: HsmPartId, id: HsmSessId) -> HsmSessionState {
        let Ok(entry) = self.active_part(pid) else {
            return HsmSessionState::Invalid;
        };
        entry.session_table.state(id)
    }
}
