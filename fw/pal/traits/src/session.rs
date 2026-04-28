// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session management trait for the HSM PAL.
//!
//! Defines the [`HsmSessionStore`] trait that PAL implementations use to
//! manage authenticated user sessions within a partition. Each session
//! is identified by an [`HsmSessId`] and is scoped to a partition
//! ([`HsmPartId`]).
//!
//! ## Session lifecycle
//!
//! ```text
//! session_create(pid, key_id) → session_id
//!   ↓
//! session_valid(pid, id)       — verify session is active
//! session_key_id(pid, id)      — get the session's masking key
//! session_needs_renego(pid, id) — check if re-negotiation required
//!   ↓
//! session_recreate(pid, id, new_key_id)  — re-key after migration
//!   ↓
//! session_delete(pid, id)      — close and destroy
//! ```
//!
//! ## Session–key binding
//!
//! Each session is bound to an [`HsmKeyId`] at creation time. This key
//! (typically a session masking key derived during the `OpenSession` DDI
//! command) is used to protect session-scoped vault keys. The key ID can
//! be retrieved via [`session_key_id`](HsmSessionStore::session_key_id) and
//! updated via [`session_recreate`](HsmSessionStore::session_recreate)
//! after a VM migration triggers session re-negotiation.

use super::*;

pub enum HsmSessionState {
    /// The session exists and is active.
    Active,

    /// The session exists but requires re-negotiation (e.g., after VM migration).
    NeedsRenegotiation,

    /// The session has been deleted or is otherwise invalid.
    Invalid,
}

/// Session management interface.
///
/// All methods are synchronous — session operations are fast table
/// lookups, not hardware-offloaded crypto. Sessions are partitioned:
/// each partition has its own session table with an independent capacity.
pub trait HsmSessionManager {
    /// Check whether the partition has at least one free session slot.
    ///
    /// Default implementation: `session_free_count(pid) > 0`.
    fn session_limit_reached(&self, pid: HsmPartId) -> bool;

    /// Create a new session for the partition.
    ///
    /// # Parameters
    /// - `pid` — Partition to create the session in.
    /// - `id` — The existing session to re-key.
    ///
    /// # Returns
    /// A new [`HsmSessId`] that uniquely identifies the session
    /// within the partition.
    ///
    /// # Errors
    /// Returns [`HsmError`] if no free session slots remain.
    fn session_create(&self, pid: HsmPartId, id: Option<HsmSessId>) -> HsmResult<HsmSessId>;

    /// Delete (close) a session.
    ///
    /// Frees the session slot and allows the core to clean up
    /// session-scoped vault keys via
    /// [`vault_key_delete_by_session`](super::HsmVault::vault_key_delete_by_session).
    ///
    /// # Errors
    /// Returns [`HsmError`] if the session ID is invalid.
    fn session_delete(&self, pid: HsmPartId, id: HsmSessId) -> HsmResult<()>;

    /// Query the current state of a session.
    ///
    /// Returns one of the [`HsmSessionState`] variants indicating whether
    /// the session is active, requires re-negotiation, or has been deleted/invalidated.
    fn session_state(&self, pid: HsmPartId, id: HsmSessId) -> HsmSessionState;
}
