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
    pub(crate) fn new(id: u16, app_id: u8, rev: HsmApiRev, partition: HsmPartition) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HsmSessionInner::new(
                id, app_id, rev, partition,
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
}

/// HSM session handle.
///
/// Represents an active authenticated session with an HSM partition. Each session
/// is associated with a specific application ID and provides the context for
/// cryptographic operations within the partition.
#[derive(Debug)]
struct HsmSessionInner {
    id: u16,
    _app_id: u8,
    rev: HsmApiRev,
    partition: HsmPartition,
}

impl Drop for HsmSessionInner {
    /// Automatically closes the session when the handle is dropped.
    ///
    /// Ensures that HSM resources are properly released by closing the
    /// session connection when the `HsmSession` goes out of scope.
    #[instrument(skip_all, fields(session_id = self.id))]
    fn drop(&mut self) {
        // Session cleanup logic can be added here if needed.
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
    pub(crate) fn new(id: u16, app_id: u8, rev: HsmApiRev, partition: HsmPartition) -> Self {
        Self {
            id,
            _app_id: app_id,
            rev,
            partition,
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
}
