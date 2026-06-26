// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM session management.
//!
//! This module provides structures and operations for managing HSM sessions.
//! Sessions represent authenticated connections to an HSM partition, providing
//! a context for performing cryptographic operations.

use std::fmt;
use std::sync::Arc;

use azihsm_crypto::AesKey;
use azihsm_ddi_tbor_types::SessionType;
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

    /// Wraps a successful `open_session_ex` (TBOR) result in a session
    /// handle.
    pub(crate) fn new_ex(
        rev: HsmApiRev,
        partition: HsmPartition,
        result: ddi::OpenSessionExResult,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HsmSessionInner::new_ex(rev, partition, result))),
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
        self.inner.read().seed()
    }

    /// Returns a clone of the backed-up session masking key.
    pub(crate) fn bmk_session(&self) -> Vec<u8> {
        self.inner.read().bmk_session()
    }

    /// Updates the backed-up session masking key after a successful reopen.
    pub(crate) fn set_bmk_session(&self, bmk_session: Vec<u8>) {
        self.inner.write().set_bmk_session(bmk_session);
    }

    /// Issues TBOR `PartInit` (opcode `0x30`) on this CO session.
    ///
    /// Seals `mach_seed` under the session `param_key` and ships it
    /// alongside `part_policy` + `pota_thumbprint`. Only valid on a
    /// TBOR session; an MBOR session returns
    /// [`HsmError::InvalidSession`].
    pub fn part_init(
        &self,
        mach_seed: &[u8],
        part_policy: &[u8],
        pota_thumbprint: &[u8],
    ) -> HsmResult<PartInitResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Tbor { param_key, .. } => ddi::init_part_ex(
                &inner.partition,
                inner.id,
                param_key,
                mach_seed,
                part_policy,
                pota_thumbprint,
            ),
            SessionKind::Mbor { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `FinalizePart` (opcode `0x31`) on this CO session.
    ///
    /// Only valid on a TBOR session; an MBOR session returns
    /// [`HsmError::InvalidSession`].
    pub fn finalize_part(
        &self,
        pta_cert_chain: &[u8],
        prev_part_local_bmk: Option<&[u8]>,
    ) -> HsmResult<FinalizePartResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Tbor { .. } => ddi::finalize_part_ex(
                &inner.partition,
                inner.id,
                pta_cert_chain,
                prev_part_local_bmk,
            ),
            SessionKind::Mbor { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `GetPartId` (opcode `0x32`) on this CO session.
    ///
    /// Only valid on a TBOR session; an MBOR session returns
    /// [`HsmError::InvalidSession`].
    pub fn get_part_id(&self) -> HsmResult<GetPartIdResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Tbor { .. } => ddi::get_part_id_ex(&inner.partition, inner.id),
            SessionKind::Mbor { .. } => Err(HsmError::InvalidSession),
        }
    }
}

/// Transport-specific session state.
///
/// The fields that differ between the MBOR `open_session` path and the
/// TBOR `open_session_ex` handshake live here; the shared
/// identity/rev/partition/epoch fields stay on [`HsmSessionInner`].
enum SessionKind {
    /// Session established over the MBOR `OpenSession` command.
    Mbor {
        /// 8-bit application id assigned by the device.
        app_id: u8,
        /// 48-byte random seed used for credential encryption during
        /// `open_session`. Needed by `reopen_session` after a
        /// resiliency event.
        seed: [u8; 48],
        /// Backed-up session masking key returned by the device.
        /// Updated after each successful `reopen_session` call.
        bmk_session: Vec<u8>,
    },
    /// Session established over the two-phase TBOR `OpenSessionEx`
    /// handshake.
    ///
    Tbor {
        /// PSK id selecting the role (0 = CO, 1 = CU).
        psk_id: u8,
        /// Channel integrity profile pinned at handshake time.
        session_type: SessionType,
        /// HPKE exported secret (`Nh = 48`).
        exported: Vec<u8>,
        /// Per-session AES-256 wrap key derived from the HPKE export.
        /// Sensitive — never logged (redacted in the manual `Debug`
        /// impl, since `AesKey` is not `Debug`).
        param_key: AesKey,
        /// FW-emitted wrapped masking-key blob.
        bmk_session: Vec<u8>,
    },
}

impl fmt::Debug for SessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionKind::Mbor {
                app_id,
                seed,
                bmk_session,
            } => f
                .debug_struct("Mbor")
                .field("app_id", app_id)
                .field("seed", seed)
                .field("bmk_session", bmk_session)
                .finish(),
            SessionKind::Tbor {
                psk_id,
                session_type,
                exported,
                bmk_session,
                ..
            } => f
                .debug_struct("Tbor")
                .field("psk_id", psk_id)
                .field("session_type", session_type)
                .field("exported", exported)
                .field("param_key", &"<redacted>")
                .field("bmk_session", bmk_session)
                .finish(),
        }
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
    rev: HsmApiRev,
    partition: HsmPartition,
    /// The partition restore epoch at which this session was last reopened.
    /// Compared against `ResiliencyState::restore_epoch` to decide whether
    /// a `reopen_session` call is needed before retrying a key operation.
    last_restore_epoch: u64,
    /// Transport-specific session material (MBOR vs TBOR).
    kind: SessionKind,
}

impl Drop for HsmSessionInner {
    /// Automatically closes the session when the handle is dropped.
    ///
    /// Ensures that HSM resources are properly released by closing the
    /// session connection when the `HsmSession` goes out of scope.
    #[instrument(skip_all, fields(session_id = self.id))]
    fn drop(&mut self) {
        let _ = match &self.kind {
            SessionKind::Mbor { .. } => {
                self.with_dev(|dev| ddi::close_session(dev, self.id, self.rev))
            }
            SessionKind::Tbor { .. } => ddi::close_session_ex(&self.partition, self.id),
        };
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
            rev,
            partition,
            last_restore_epoch: epoch,
            kind: SessionKind::Mbor {
                app_id,
                seed,
                bmk_session,
            },
        }
    }

    /// Creates a new TBOR session handle from an `open_session_ex`
    /// result.
    #[instrument(skip_all, fields(session_id = result.session_id))]
    pub(crate) fn new_ex(
        rev: HsmApiRev,
        partition: HsmPartition,
        result: ddi::OpenSessionExResult,
    ) -> Self {
        let epoch = partition.restore_epoch();
        Self {
            id: result.session_id,
            rev,
            partition,
            last_restore_epoch: epoch,
            kind: SessionKind::Tbor {
                psk_id: result.psk_id,
                session_type: result.session_type,
                exported: result.exported,
                param_key: result.param_key,
                bmk_session: result.bmk_session,
            },
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
    /// The 8-bit application ID associated with this session (MBOR
    /// only; `0` for a TBOR session).
    pub(crate) fn _app_id(&self) -> u8 {
        match &self.kind {
            SessionKind::Mbor { app_id, .. } => *app_id,
            SessionKind::Tbor { .. } => 0,
        }
    }

    /// Returns the 48-byte MBOR session seed, or zeros for a TBOR
    /// session (whose reopen path is not yet wired).
    pub(crate) fn seed(&self) -> [u8; 48] {
        match &self.kind {
            SessionKind::Mbor { seed, .. } => *seed,
            SessionKind::Tbor { .. } => [0u8; 48],
        }
    }

    /// Returns a clone of the backed-up session masking key.
    pub(crate) fn bmk_session(&self) -> Vec<u8> {
        match &self.kind {
            SessionKind::Mbor { bmk_session, .. } | SessionKind::Tbor { bmk_session, .. } => {
                bmk_session.clone()
            }
        }
    }

    /// Replaces the backed-up session masking key after a successful
    /// reopen.
    pub(crate) fn set_bmk_session(&mut self, bmk_session: Vec<u8>) {
        match &mut self.kind {
            SessionKind::Mbor { bmk_session: b, .. } | SessionKind::Tbor { bmk_session: b, .. } => {
                *b = bmk_session;
            }
        }
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
