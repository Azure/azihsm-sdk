// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session management trait for the HSM PAL.
//!
//! Defines the [`HsmSessionManager`] trait that PAL implementations use
//! to manage authenticated user sessions within a partition.  Each
//! session is identified by a logical [`HsmSessId`] (slot index 0–7)
//! and is scoped to a partition ([`HsmPartId`]).
//!
//! ## Session storage
//!
//! Sessions are stored as vault keys (`HsmVaultKeyKind::Session`)
//! containing an 88-byte blob: `[api_revision(8) || masking_key(80)]`.
//! The session table maps logical session IDs to physical vault key
//! IDs ([`HsmKeyId`]).
//!
//! ## Session lifecycle
//!
//! ```text
//! session_create(io, api_rev, masking_key, None) → logical HsmSessId
//!   ↓
//! session_state(io, id)   — verify session is active
//!   ↓
//! session_create(io, api_rev, masking_key, Some(id)) — re-key after migration
//!   ↓
//! session_destroy(io, id) — close: delete scoped keys + session key + free slot
//! ```
//!
//! ## Session–key binding
//!
//! Session-scoped vault keys are bound to the session's **physical**
//! vault key ID (not the logical slot index).  When a session is
//! deleted, all keys matching that physical ID are removed first.

use super::*;

/// Lifecycle state of a session.
///
/// Returned by [`HsmSessionManager::session_state`].  The state is
/// derived from the underlying vault entry plus session-table
/// metadata; there is no separate persistent state field.
pub enum HsmSessionState {
    /// The session slot is allocated and the masking key is valid for
    /// the current API revision.  The session may be used.
    Active,

    /// The session slot is allocated, but the API revision recorded in
    /// the masking blob does not match the live one (e.g. after a VM
    /// migration).  The host must call
    /// [`HsmSessionManager::session_create`] with `id =
    /// Some(existing)` to re-key before any further operations.
    NeedsRenegotiation,

    /// The slot is free, the partition does not own such a session, or
    /// the session was destroyed.  Any operation referencing this ID
    /// must fail.
    Invalid,
}

/// RAII guard for a newly created session.
///
/// Returned by [`HsmSessionManager::session_create`].  The guard
/// implements an explicit commit/rollback discipline: the session is
/// *provisional* until [`dismiss`](Self::dismiss) is called.  If the
/// guard is dropped without dismissing — for example because a
/// downstream encode step or DDI handler returned an error — the
/// destructor tears the session down (frees the slot, deletes the
/// session vault key, removes any session-scoped keys), leaving no
/// half-created session behind.
///
/// Typical usage:
///
/// ```ignore
/// let guard = pal.session_create(io, api_rev, masking_key, None)?;
/// // ... fallible work that uses `guard.sess_id()` ...
/// let id = guard.dismiss(); // commit; session now permanent
/// ```
pub trait SessionGuard {
    /// Returns the session ID assigned to the provisional session.
    ///
    /// Safe to call multiple times; does **not** commit the session.
    ///
    /// # Returns
    ///
    /// The [`HsmSessId`] under which the session is currently
    /// registered in the partition's session table.
    fn sess_id(&self) -> HsmSessId;

    /// Commits the session.  The session table entry persists past
    /// the guard's lifetime and the destructor becomes a no-op.
    ///
    /// # Returns
    ///
    /// The committed [`HsmSessId`].
    fn dismiss(self) -> HsmSessId;
}

/// Session management interface.
///
/// All methods take an [`HsmIo`] handle, which scopes the operation to
/// the calling partition: a session created by partition A is
/// invisible to partition B.  The trait is `&self`; PAL
/// implementations are expected to use interior mutability for the
/// session table (the firmware is single-core, cooperatively
/// scheduled, so a plain `Cell`/`RefCell` suffices).
pub trait HsmSessionManager {
    /// RAII guard returned by
    /// [`session_create`](Self::session_create).
    ///
    /// The lifetime parameter ties the guard to the session manager
    /// so an uncommitted session cannot outlive the manager that
    /// owns it.
    type Guard<'a>: SessionGuard
    where
        Self: 'a;

    /// Returns `true` if the calling partition has no free session
    /// slots.
    ///
    /// Used by DDI handlers to short-circuit `OpenSession` requests
    /// with [`HsmError::VaultSessionLimitReached`] before allocating
    /// any crypto state.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    ///
    /// # Returns
    ///
    /// - `true` — every session slot for this partition is in use.
    /// - `false` — at least one slot is free; a subsequent
    ///   [`session_create`](Self::session_create) with `id == None`
    ///   may succeed.
    fn session_limit_reached(&self, io: &impl HsmIo) -> bool;

    /// Creates a new session, or re-keys an existing one in place.
    ///
    /// On success, returns a [`Self::Guard`] that holds the session
    /// in a *provisional* state.  The caller must invoke
    /// [`SessionGuard::dismiss`] to commit; dropping the guard
    /// otherwise rolls the session back.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `api_rev` — 8-byte API-revision tag stored alongside the
    ///   masking key; later compared by
    ///   [`session_state`](Self::session_state) to detect post-
    ///   migration drift.
    /// - `masking_key` — 80-byte masking-key blob to seal into the
    ///   session vault entry.
    /// - `id` — `None` to allocate a new slot; `Some(existing)` to
    ///   re-key an already-open session in place (post-migration
    ///   renegotiation).  The existing session must currently be in
    ///   either [`HsmSessionState::Active`] or
    ///   [`HsmSessionState::NeedsRenegotiation`].
    ///
    /// # Returns
    ///
    /// - `Ok(guard)` — provisional session; commit with
    ///   [`SessionGuard::dismiss`].
    /// - `Err(HsmError::VaultSessionLimitReached)` — `id == None` and
    ///   no slots are free (see
    ///   [`session_limit_reached`](Self::session_limit_reached)).
    /// - `Err(HsmError::InvalidArg)` — `id == Some(_)` and the slot
    ///   is free, or `api_rev`/`masking_key` is the wrong length.
    /// - `Err(HsmError::NotEnoughSpace)` — vault is full and cannot
    ///   store the masking blob.
    fn session_create(
        &self,
        io: &impl HsmIo,
        api_rev: &[u8],
        masking_key: &[u8],
        id: Option<HsmSessId>,
    ) -> HsmResult<Self::Guard<'_>>;

    /// Closes a session.
    ///
    /// Tears down the session in this order:
    ///
    /// 1. Removes every vault key bound to the session's physical
    ///    vault key ID (see module-level docs for the
    ///    session→physical-ID binding).
    /// 2. Deletes the session vault entry itself.
    /// 3. Frees the session table slot.
    ///
    /// Idempotent only in the sense that a freed slot is safe to
    /// reuse; calling `session_destroy` on an already-free slot is
    /// reported as [`HsmError::InvalidArg`].
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — session to close.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::InvalidArg)` — `id` does not refer to a live
    ///   session in the caller's partition.
    fn session_destroy(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()>;

    /// Queries the lifecycle state of a session slot.
    ///
    /// This is an infallible probe: an unknown or freed slot is
    /// reported as [`HsmSessionState::Invalid`] rather than an
    /// `HsmError`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — session slot to probe.
    ///
    /// # Returns
    ///
    /// One of [`HsmSessionState::Active`],
    /// [`HsmSessionState::NeedsRenegotiation`], or
    /// [`HsmSessionState::Invalid`].
    fn session_state(&self, io: &impl HsmIo, id: HsmSessId) -> HsmSessionState;
}
