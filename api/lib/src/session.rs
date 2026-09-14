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
use zeroize::Zeroize;

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

    /// Wraps a successful `open_session_ex` (V2) result in a session
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

    /// Returns the 48-byte V1 session seed needed for
    /// `reopen_session`, or `None` for a V2 session (whose stale
    /// state must be re-established via a fresh handshake, not the
    /// V1 reopen path).
    pub(crate) fn seed(&self) -> Option<[u8; 48]> {
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

    /// Returns the active TBOR (V2, security-domain) session id.
    ///
    /// Yields the session id for a V2 session, or
    /// [`HsmError::InvalidSession`] for a V1 session. Used by the DDI
    /// layer to bind security-domain commands to the session.
    pub(crate) fn ex_session_id(&self) -> HsmResult<u16> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => Ok(inner.id),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Returns `true` for a V2 (security-domain / TBOR) session.
    ///
    /// Used by the DDI layer to route key operations to the TBOR
    /// (masked, non-resident) path vs. the MBOR (device-resident) path.
    pub(crate) fn is_ex(&self) -> bool {
        matches!(self.inner.read().kind, SessionKind::Ver2 { .. })
    }

    /// Issues TBOR `PskChange` (opcode `0x06`) on this session.
    ///
    /// Rotates this session's own partition PSK to `new_psk`, sealed
    /// under the session `param_key`. The slot is implied by the session
    /// role (CO session → CO, CU session → CU). Required once on a fresh
    /// partition to move past the default-PSK gate before provisioning.
    /// Only valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn change_psk(&self, new_psk: &[u8; PSK_LEN]) -> HsmResult<()> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { param_key, .. } => {
                ddi::psk_change(&inner.partition, inner.id, param_key, new_psk)
            }
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `PartInit` (opcode `0x07`) on this CO session.
    ///
    /// Seals `mach_seed` under the session `param_key` and ships it
    /// alongside the unified `part_policy` and the POTA / SATA /
    /// optional SAPOTA thumbprints. Only valid on a V2 session; a V1
    /// session returns [`HsmError::InvalidSession`].
    pub fn part_init_ex(
        &self,
        mach_seed: &[u8],
        part_policy: &[u8],
        pota_thumbprint: &[u8],
        sata_thumbprint: &[u8],
        sapota_thumbprint: Option<&[u8]>,
    ) -> HsmResult<HsmPartInitExResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { param_key, .. } => ddi::part_init_ex(
                &inner.partition,
                inner.id,
                param_key,
                mach_seed,
                part_policy,
                pota_thumbprint,
                sata_thumbprint,
                sapota_thumbprint,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `PartFinal` (opcode `0x08`) on this CO session.
    ///
    /// Re-supplies the unified `part_policy` (for `POTAPubKey` recovery)
    /// and the PTA certificate chain (as a list of [`HsmCert`]s),
    /// optionally restoring a prior `local_mk` backup. Only valid on a V2
    /// session; a V1 session returns [`HsmError::InvalidSession`].
    pub fn part_final_ex(
        &self,
        part_policy: &[u8],
        pta_cert_chain: &[HsmCert<'_>],
        prev_local_mk_backup: Option<&[u8]>,
    ) -> HsmResult<HsmPartFinalExResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::part_final_ex(
                &inner.partition,
                inner.id,
                part_policy,
                pta_cert_chain,
                prev_local_mk_backup,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdCreateRemoteBackup` (opcode `0x0A`) on this CO
    /// session.
    ///
    /// Creates a new security domain from the caller-supplied unified
    /// `policy`, using the sender's `masked_sealing_key` (from
    /// `SdSealingKeyGen`) and the receiver's attestation `evidence`.
    /// Returns the remote backup together with the device-local backups.
    /// Only valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn sd_create_remote_backup(
        &self,
        masked_sealing_key: &[u8],
        receiver_evidence: &HsmSdEvidence<'_>,
        policy: &[u8],
    ) -> HsmResult<HsmSdRemoteBackupResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_create_remote_backup_ex(
                &inner.partition,
                inner.id,
                masked_sealing_key,
                receiver_evidence,
                policy,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdResealRemoteBackup` (opcode `0x0B`) on this CO
    /// session.
    ///
    /// HPKE-opens `src_remote_backup` with the receiver's
    /// `masked_sealing_key` (authenticated by the source sender in
    /// `src_evidence`) and reseals the recovered backup to the destination
    /// receiver (`dest_evidence`), returning the resealed remote backup.
    /// Only valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn sd_reseal_remote_backup(
        &self,
        masked_sealing_key: &[u8],
        src_evidence: &HsmSdEvidence<'_>,
        dest_evidence: &HsmSdEvidence<'_>,
        policy: &[u8],
        src_remote_backup: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_reseal_remote_backup_ex(
                &inner.partition,
                inner.id,
                masked_sealing_key,
                src_evidence,
                dest_evidence,
                policy,
                src_remote_backup,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdRestoreRemoteBackup` (opcode `0x0C`) on this CO
    /// session.
    ///
    /// HPKE-opens `src_remote_backup` with the receiver's
    /// `masked_sealing_key` (authenticated by the sender in
    /// `sender_evidence`), recovers the security-domain masking key from
    /// `prev_sd_mk_backup`, and returns the refreshed device-local backups.
    /// Only valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn sd_restore_remote_backup(
        &self,
        masked_sealing_key: &[u8],
        sender_evidence: &HsmSdEvidence<'_>,
        policy: &[u8],
        src_remote_backup: &[u8],
        prev_sd_mk_backup: &[u8],
    ) -> HsmResult<HsmSdRestoreResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_restore_remote_backup_ex(
                &inner.partition,
                inner.id,
                masked_sealing_key,
                sender_evidence,
                policy,
                src_remote_backup,
                prev_sd_mk_backup,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdCreatePeerBackup` (opcode `0x0E`) on this CO session.
    ///
    /// Recovers BKS3 from `pok_local_backup` and HPKE-Auth-seals it to the
    /// destination peer in `dst_evidence` (authenticated by the sender's
    /// `masked_sealing_key`), returning the peer backup. Gated by the
    /// security domain's `allow_peer_cloning` policy flag. Only valid on a
    /// V2 session; a V1 session returns [`HsmError::InvalidSession`].
    pub fn sd_create_peer_backup(
        &self,
        masked_sealing_key: &[u8],
        dst_evidence: &HsmSdEvidence<'_>,
        policy: &[u8],
        pok_local_backup: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_create_peer_backup_ex(
                &inner.partition,
                inner.id,
                masked_sealing_key,
                dst_evidence,
                policy,
                pok_local_backup,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdRestorePeerBackup` (opcode `0x0F`) on this CO
    /// session.
    ///
    /// HPKE-opens `pok_peer_backup` with the receiver's `masked_sealing_key`
    /// (authenticated by the source peer in `src_evidence`), recovers the
    /// security-domain masking key from `prev_sd_mk_backup`, and returns the
    /// refreshed device-local backups. Gated by the security domain's
    /// `allow_peer_cloning` policy flag. Only valid on a V2 session; a V1
    /// session returns [`HsmError::InvalidSession`].
    pub fn sd_restore_peer_backup(
        &self,
        masked_sealing_key: &[u8],
        src_evidence: &HsmSdEvidence<'_>,
        policy: &[u8],
        pok_peer_backup: &[u8],
        prev_sd_mk_backup: &[u8],
    ) -> HsmResult<HsmSdRestoreResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_restore_peer_backup_ex(
                &inner.partition,
                inner.id,
                masked_sealing_key,
                src_evidence,
                policy,
                pok_peer_backup,
                prev_sd_mk_backup,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdRestoreLocalBackup` (opcode `0x0D`) on this CO
    /// session.
    ///
    /// Restores the security domain from the device-local `pok_local_backup`
    /// and `sd_mk_backup` (no attestation evidence is involved), returning
    /// the refreshed device-local backups. Only valid on a V2 session; a V1
    /// session returns [`HsmError::InvalidSession`].
    pub fn sd_restore_local_backup(
        &self,
        pok_local_backup: &[u8],
        sd_mk_backup: &[u8],
    ) -> HsmResult<HsmSdRestoreResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_restore_local_backup_ex(
                &inner.partition,
                inner.id,
                pok_local_backup,
                sd_mk_backup,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }
}

/// Transport-specific session state.
///
/// The fields that differ between the V1 `open_session` path and the
/// V2 `open_session_ex` handshake live here; the shared
/// identity/rev/partition/epoch fields stay on [`HsmSessionInner`].
enum SessionKind {
    /// Version 1 session, established over the single-round-trip
    /// `OpenSession` command.
    Ver1 {
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
    /// Version 2 session, established over the two-phase
    /// `OpenSessionEx` HPKE handshake.
    Ver2 {
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
            SessionKind::Ver1 {
                app_id,
                seed,
                bmk_session,
            } => f
                .debug_struct("Ver1")
                .field("app_id", app_id)
                .field("seed", &format_args!("<redacted; {} bytes>", seed.len()))
                .field(
                    "bmk_session",
                    &format_args!("<redacted; {} bytes>", bmk_session.len()),
                )
                .finish(),
            SessionKind::Ver2 {
                psk_id,
                session_type,
                exported,
                bmk_session,
                ..
            } => f
                .debug_struct("Ver2")
                .field("psk_id", psk_id)
                .field("session_type", session_type)
                .field(
                    "exported",
                    &format_args!("<redacted; {} bytes>", exported.len()),
                )
                .field("param_key", &"<redacted>")
                .field(
                    "bmk_session",
                    &format_args!("<redacted; {} bytes>", bmk_session.len()),
                )
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
    /// Version-specific session material (V1 vs V2).
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
            SessionKind::Ver1 { .. } => {
                self.with_dev(|dev| ddi::close_session(dev, self.id, self.rev))
            }
            SessionKind::Ver2 { .. } => ddi::close_session_ex(&self.partition, self.id),
        };

        // Wipe sensitive session material from process memory once the
        // session is closed: `seed` for V1, the HPKE `exported` secret
        // for V2, and the device-wrapped `bmk_session` blob for both.
        match &mut self.kind {
            SessionKind::Ver1 {
                seed, bmk_session, ..
            } => {
                seed.zeroize();
                bmk_session.zeroize();
            }
            SessionKind::Ver2 {
                exported,
                bmk_session,
                ..
            } => {
                exported.zeroize();
                bmk_session.zeroize();
            }
        }
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
            kind: SessionKind::Ver1 {
                app_id,
                seed,
                bmk_session,
            },
        }
    }

    /// Creates a new V2 session handle from an `open_session_ex`
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
            kind: SessionKind::Ver2 {
                psk_id: result.psk_id,
                session_type: result.session_type,
                exported: result.exported.to_vec(),
                param_key: result.param_key,
                bmk_session: result.bmk_session.to_vec(),
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
    /// The 8-bit application ID associated with this session (V1
    /// only; `0` for a V2 session).
    pub(crate) fn _app_id(&self) -> u8 {
        match &self.kind {
            SessionKind::Ver1 { app_id, .. } => *app_id,
            SessionKind::Ver2 { .. } => 0,
        }
    }

    /// Returns the 48-byte V1 session seed, or `None` for a V2
    /// session (which is re-established via a fresh handshake rather
    /// than the V1 reopen path).
    pub(crate) fn seed(&self) -> Option<[u8; 48]> {
        match &self.kind {
            SessionKind::Ver1 { seed, .. } => Some(*seed),
            SessionKind::Ver2 { .. } => None,
        }
    }

    /// Returns a clone of the backed-up session masking key.
    pub(crate) fn bmk_session(&self) -> Vec<u8> {
        match &self.kind {
            SessionKind::Ver1 { bmk_session, .. } | SessionKind::Ver2 { bmk_session, .. } => {
                bmk_session.clone()
            }
        }
    }

    /// Replaces the backed-up session masking key after a successful
    /// reopen.
    pub(crate) fn set_bmk_session(&mut self, bmk_session: Vec<u8>) {
        match &mut self.kind {
            SessionKind::Ver1 { bmk_session: b, .. } | SessionKind::Ver2 { bmk_session: b, .. } => {
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
