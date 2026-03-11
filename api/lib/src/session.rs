// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM session management.
//!
//! This module provides structures and operations for managing HSM sessions.
//! Sessions represent authenticated connections to an HSM partition, providing
//! a context for performing cryptographic operations.

use std::sync::Arc;

use parking_lot::RwLock;
use tracing::*;

use super::*;

#[derive(Debug, Clone)]
pub struct HsmSession {
    inner: Arc<RwLock<HsmSessionInner>>,
}

/// Marker trait for HSM sessions.
impl Session for HsmSession {}

impl HsmSession {
    #[instrument(skip_all, fields(session_id = id))]
    pub(crate) fn new(
        id: u16,
        app_id: u8,
        rev: HsmApiRev,
        partition: HsmPartition,
        seed: [u8; 48],
        bmk_session: Vec<u8>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HsmSessionInner::new(
                id,
                app_id,
                rev,
                partition,
                seed,
                bmk_session,
            ))),
        }
    }

    delegate::delegate! {
        to self.inner.read() {
            pub fn id(&self) -> u16;
            pub(crate) fn _app_id(&self) -> u8;
            pub fn api_rev(&self) -> HsmApiRev;

            pub(crate) fn with_dev<F, R>(&self, f: F) -> HsmResult<R>
            where
                F: FnOnce(&ddi::HsmDev) -> HsmResult<R>;
        }
    }

    /// Returns the partition restore epoch at which this session
    /// was last reopened.
    pub(crate) fn last_restore_epoch(&self) -> u64 {
        self.inner.read().last_restore_epoch()
    }

    /// Serializes session-reopen attempts for a given epoch.
    ///
    /// Acquires the session write lock and checks whether the session
    /// has already been reopened to `part_restore_epoch`.  If so, returns
    /// `Ok(None)` without calling `f`.  Otherwise, executes `f` under
    /// the lock and, on success, advances the session epoch to
    /// `part_restore_epoch` before releasing the lock.
    ///
    /// This ensures that only one thread performs the DDI `reopen_session`
    /// call for a given a resiliency event; racing threads block on the write lock
    /// and then observe the updated epoch.
    pub(crate) fn with_reopen_guard<F, R>(
        &self,
        part_restore_epoch: u64,
        f: F,
    ) -> HsmResult<Option<R>>
    where
        F: FnOnce() -> HsmResult<R>,
    {
        let mut inner = self.inner.write();
        if inner.last_restore_epoch == part_restore_epoch {
            return Ok(None);
        } else if inner.last_restore_epoch > part_restore_epoch {
            // This should never happen — session cannot be newer than the partition's epoch.
            return Err(HsmError::InternalError);
        }

        // Session is stale, execute the reopen under the lock.
        // If it succeeds, update the session's last_restore_epoch.
        let result = f()?;
        inner.last_restore_epoch = part_restore_epoch;
        Ok(Some(result))
    }

    /// Returns the partition handle associated with this session.
    pub(crate) fn partition(&self) -> HsmPartition {
        self.inner.read().partition().clone()
    }

    /// Returns the 48-byte session seed needed for `reopen_session`.
    pub(crate) fn seed(&self) -> [u8; 48] {
        self.inner.read().seed
    }

    /// Returns a clone of the backed-up session masking key.
    pub(crate) fn bmk_session(&self) -> Vec<u8> {
        self.inner.read().bmk_session.clone()
    }

    /// Updates the backed-up session masking key after a successful reopen.
    pub(crate) fn set_bmk_session(&self, bmk_session: Vec<u8>) {
        self.inner.write().bmk_session = bmk_session;
    }
}

/// HSM session handle.
///
/// Represents an active authenticated session with an HSM partition. Each session
/// is associated with a specific application ID and provides the context for
/// cryptographic operations within the partition.
///
/// The `last_restore_epoch` field tracks the most recent partition restore
/// epoch that this session has been reopened for, enabling per-session
/// staleness detection during key operations.
#[derive(Debug)]
struct HsmSessionInner {
    id: u16,
    _app_id: u8,
    rev: HsmApiRev,
    partition: HsmPartition,
    /// The partition restore epoch at which this session was last reopened.
    /// Compared against `ResiliencyState::restore_epoch` to decide whether
    /// a `reopen_session` call is needed before retrying a key operation.
    last_restore_epoch: u64,
    /// The 48-byte random seed used for credential encryption during
    /// `open_session`. Needed by `reopen_session` after a resiliency event.
    seed: [u8; 48],
    /// Backed-up session masking key returned by the device.
    /// Updated after each successful `reopen_session` call.
    bmk_session: Vec<u8>,
}

impl Drop for HsmSessionInner {
    /// Automatically closes the session when the handle is dropped.
    ///
    /// Ensures that HSM resources are properly released by closing the
    /// session connection when the `HsmSession` goes out of scope.
    #[instrument(skip_all, fields(session_id = self.id))]
    fn drop(&mut self) {
        let _ = self.with_dev(|dev| ddi::close_session(dev, self.id, self.rev));
    }
}

impl HsmSessionInner {
    /// Creates a new HSM session handle.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique session identifier
    /// * `app_id` - Application identifier for this session
    /// * `rev` - API revision used for this session
    /// * `partition` - The HSM partition this session is associated with
    ///
    /// # Returns
    ///
    /// A new `HsmSession` instance.
    #[instrument(skip_all, fields(session_id = id))]
    pub(crate) fn new(
        id: u16,
        app_id: u8,
        rev: HsmApiRev,
        partition: HsmPartition,
        seed: [u8; 48],
        bmk_session: Vec<u8>,
    ) -> Self {
        let epoch = partition.restore_epoch();
        Self {
            id,
            _app_id: app_id,
            rev,
            partition,
            last_restore_epoch: epoch,
            seed,
            bmk_session,
        }
    }

    /// Returns the session identifier.
    ///
    /// # Returns
    ///
    /// The unique 16-bit session ID assigned by the HSM.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Returns a reference to the associated partition.
    ///
    /// # Returns
    ///
    /// A reference to the `HsmPartition` handle that this session is bound to.
    pub(crate) fn partition(&self) -> &HsmPartition {
        &self.partition
    }

    /// Returns the application identifier.
    ///
    /// # Returns
    ///
    /// The 8-bit application ID associated with this session.
    pub(crate) fn _app_id(&self) -> u8 {
        self._app_id
    }

    /// Returns the API revision used by this session.
    ///
    /// # Returns
    ///
    /// The `HsmApiRev` that was specified when the session was opened.
    pub(crate) fn api_rev(&self) -> HsmApiRev {
        self.rev
    }

    /// Executes a closure with access to the underlying device handle.
    ///
    /// Provides thread-safe access to the HSM device through the session's
    /// associated partition. Acquires a read lock on the partition and passes
    /// the device handle to the provided closure.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that receives the device handle and returns a result
    ///
    /// # Returns
    ///
    /// Returns the result produced by the closure.
    ///
    /// # Errors
    ///
    /// Returns any error produced by the closure.
    pub(crate) fn with_dev<F, R>(&self, f: F) -> HsmResult<R>
    where
        F: FnOnce(&ddi::HsmDev) -> HsmResult<R>,
    {
        let part = self.partition().inner().read();
        let dev = part.dev();
        f(dev)
    }

    /// Returns the partition restore epoch at which this session was last
    /// reopened.
    pub(crate) fn last_restore_epoch(&self) -> u64 {
        self.last_restore_epoch
    }
}
