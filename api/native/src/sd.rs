// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain (SD) backup command FFI for the native C API.
//!
//! FFI bindings for the SD backup command family (create / reseal / restore
//! remote, peer, and local), exposed to C callers through the
//! ABI-compatible interface.

use super::*;

/// One certificate chain in an SD attestation-evidence party: an array of
/// `len` `azihsm_buffer`s, each a DER-encoded certificate (root to leaf).
#[repr(C)]
pub struct AzihsmSdCertChain {
    /// Pointer to an array of `len` DER certificate `azihsm_buffer`s.
    pub certs: *const AzihsmBuffer,
    /// Number of certificates in `certs`.
    pub len: u32,
}

/// Attestation evidence for one SD-backup party: three certificate chains
/// (manufacturer, owner, partition-owner) and a COSE_Sign1 report. The DER
/// bytes are borrowed, not copied.
#[repr(C)]
pub struct AzihsmSdEvidence {
    /// Manufacturer certificate chain.
    pub mfgr_cert_chain: AzihsmSdCertChain,
    /// Owner certificate chain.
    pub owner_cert_chain: AzihsmSdCertChain,
    /// Partition-owner certificate chain.
    pub part_owner_cert_chain: AzihsmSdCertChain,
    /// COSE_Sign1 attestation-report buffer.
    pub report: *const AzihsmBuffer,
}

/// Input buffers for [`azihsm_sd_create_remote_backup`].
#[repr(C)]
pub struct AzihsmSdCreateRemoteBackupParams {
    /// Sender's masked SD-sealing key (from `azihsm_key_gen`), exactly
    /// `MASKED_SEALING_KEY_LEN` (180 B).
    pub masked_sealing_key: *const AzihsmBuffer,
    /// Receiver attestation evidence.
    pub receiver_evidence: *const AzihsmSdEvidence,
    /// Unified partition-policy image (484 B) describing the domain.
    pub policy: *const AzihsmBuffer,
}

/// Borrows one C [`AzihsmSdCertChain`] into a `Vec<HsmCert>`, rejecting an
/// empty or oversized chain up front so a bogus `len` cannot trigger an
/// unbounded allocation ahead of the host validation.
#[allow(unsafe_code)]
fn unpack_cert_chain(chain: &AzihsmSdCertChain) -> Result<Vec<api::HsmCert<'_>>, AzihsmStatus> {
    let len = chain.len as usize;
    if len == 0 || len > api::EVIDENCE_CHAIN_MAX_CERTS {
        Err(AzihsmStatus::InvalidArgument)?;
    }
    validate_ptr(chain.certs)?;
    // SAFETY: `certs` is non-null and aligned for `AzihsmBuffer` (checked
    // by `validate_ptr`), the caller guarantees it points to `len` valid
    // `azihsm_buffer`s, and `len` is bounded by `EVIDENCE_CHAIN_MAX_CERTS`.
    let raw = unsafe { std::slice::from_raw_parts(chain.certs, len) };
    let mut certs = Vec::with_capacity(len);
    for buf in raw {
        let der: &[u8] = buf.try_into()?;
        certs.push(api::HsmCert { cert: der });
    }
    Ok(certs)
}

/// Owned, validated decode of one C [`AzihsmSdEvidence`]: the three cert
/// chains materialized as `HsmCert` vectors plus the report slice (the DER
/// bytes stay borrowed from the caller's buffers). Convert a reference
/// with `api::HsmSdEvidence::from` for the borrowing
/// [`api::HsmSdEvidence`] view the session API expects; that view
/// borrows these owned vectors, so it cannot be produced from the C
/// struct in a single step.
struct SdEvidence<'a> {
    mfgr: Vec<api::HsmCert<'a>>,
    owner: Vec<api::HsmCert<'a>>,
    part_owner: Vec<api::HsmCert<'a>>,
    report: &'a [u8],
}

impl<'a> TryFrom<&'a AzihsmSdEvidence> for SdEvidence<'a> {
    type Error = AzihsmStatus;

    fn try_from(ev: &'a AzihsmSdEvidence) -> Result<Self, Self::Error> {
        Ok(Self {
            mfgr: unpack_cert_chain(&ev.mfgr_cert_chain)?,
            owner: unpack_cert_chain(&ev.owner_cert_chain)?,
            part_owner: unpack_cert_chain(&ev.part_owner_cert_chain)?,
            report: deref_ptr(ev.report)?.try_into()?,
        })
    }
}

impl<'a: 'b, 'b> From<&'b SdEvidence<'a>> for api::HsmSdEvidence<'b> {
    fn from(ev: &'b SdEvidence<'a>) -> Self {
        api::HsmSdEvidence {
            mfgr_cert_chain: &ev.mfgr,
            owner_cert_chain: &ev.owner,
            part_owner_cert_chain: &ev.part_owner,
            report: ev.report,
        }
    }
}

/// @brief Create a new security domain and its remote backup
///
/// Creates a security domain under the calling session's partition from
/// `params.policy`, using the sender's masked sealing key and the
/// receiver's attestation evidence, and returns the three backups the
/// firmware produces.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Create-backup input buffers
/// @param[in,out] pok_remote_backup Output buffer for the remote
///                partition-owner-key backup (161 B).
/// @param[in,out] pok_local_backup Output buffer for the local
///                partition-owner-key backup (180 B).
/// @param[in,out] sd_mk_backup Output buffer for the security-domain
///                masking-key backup (164 B).
///
/// All three output buffers follow the probe/fill convention and are
/// validated **before** the domain is created, so the one-shot command is
/// not consumed when a buffer is too small.
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` and each of its buffer/evidence pointers must be valid; each
///   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
/// - Each output buffer must be a valid `azihsm_buffer` with writable
///   backing storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sd_create_remote_backup(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSdCreateRemoteBackupParams,
    pok_remote_backup: *mut AzihsmBuffer,
    pok_local_backup: *mut AzihsmBuffer,
    sd_mk_backup: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_sealing_key: &[u8] = deref_ptr(params.masked_sealing_key)?.try_into()?;
        let policy: &[u8] = deref_ptr(params.policy)?.try_into()?;

        let receiver = deref_ptr(params.receiver_evidence)?;
        let receiver = SdEvidence::try_from(receiver)?;
        let receiver = api::HsmSdEvidence::from(&receiver);

        // Validate all outputs up-front (aliasing on raw pointers, then
        // sizes) so one probe advertises every length before the backup runs.
        validate_distinct_output_buffers(&[pok_remote_backup, pok_local_backup, sd_mk_backup])?;
        let pok_remote_backup = deref_mut_ptr(pok_remote_backup)?;
        let pok_local_backup = deref_mut_ptr(pok_local_backup)?;
        let sd_mk_backup = deref_mut_ptr(sd_mk_backup)?;
        validate_output_sizes(&mut [
            (&mut *pok_remote_backup, api::POK_REMOTE_BACKUP_LEN),
            (&mut *pok_local_backup, api::MASKED_SD_LEN),
            (&mut *sd_mk_backup, api::SD_MK_BACKUP_LEN),
        ])?;

        let result = session.sd_create_remote_backup(masked_sealing_key, &receiver, policy)?;

        copy_to_buffer(pok_remote_backup, &result.pok_remote_backup)?;
        copy_to_buffer(pok_local_backup, &result.pok_local_backup)?;
        copy_to_buffer(sd_mk_backup, &result.sd_mk_backup)?;

        Ok(())
    })
}

/// Input buffers for [`azihsm_sd_reseal_remote_backup`].
#[repr(C)]
pub struct AzihsmSdResealRemoteBackupParams {
    /// Receiver's masked SD-sealing key (from `azihsm_key_gen`) that
    /// unseals the source backup, exactly `MASKED_SEALING_KEY_LEN` (180 B).
    pub masked_sealing_key: *const AzihsmBuffer,
    /// Source (sender) attestation evidence.
    pub src_evidence: *const AzihsmSdEvidence,
    /// Destination (receiver) attestation evidence.
    pub dest_evidence: *const AzihsmSdEvidence,
    /// Unified partition-policy image (484 B) describing the domain.
    pub policy: *const AzihsmBuffer,
    /// Source remote backup to reseal, exactly `POK_REMOTE_BACKUP_LEN`
    /// (161 B).
    pub src_remote_backup: *const AzihsmBuffer,
}

/// @brief Reseal an existing remote backup to a new recipient
///
/// HPKE-opens `params.src_remote_backup` with the receiver's masked
/// sealing key (authenticated by the source sender in `params.src_evidence`)
/// and reseals the recovered backup to the destination receiver
/// (`params.dest_evidence`), returning the resealed remote backup.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Reseal-backup input buffers
/// @param[in,out] dst_remote_backup Output buffer for the resealed remote
///                partition-owner-key backup (161 B).
///
/// The output buffer follows the probe/fill convention and is validated
/// **before** the reseal is performed.
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` and each of its buffer/evidence pointers must be valid; each
///   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
/// - `dst_remote_backup` must be a valid `azihsm_buffer` with writable
///   backing storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sd_reseal_remote_backup(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSdResealRemoteBackupParams,
    dst_remote_backup: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_sealing_key: &[u8] = deref_ptr(params.masked_sealing_key)?.try_into()?;
        let policy: &[u8] = deref_ptr(params.policy)?.try_into()?;
        let src_remote_backup: &[u8] = deref_ptr(params.src_remote_backup)?.try_into()?;

        let src_evidence = deref_ptr(params.src_evidence)?;
        let dest_evidence = deref_ptr(params.dest_evidence)?;
        let src_evidence = SdEvidence::try_from(src_evidence)?;
        let dest_evidence = SdEvidence::try_from(dest_evidence)?;
        let src_evidence = api::HsmSdEvidence::from(&src_evidence);
        let dest_evidence = api::HsmSdEvidence::from(&dest_evidence);

        // Validate the output buffer before resealing.
        validate_ptr(dst_remote_backup)?;
        let dst_remote_backup = deref_mut_ptr(dst_remote_backup)?;
        validate_output_buffer(dst_remote_backup, api::POK_REMOTE_BACKUP_LEN)?;

        let result = session.sd_reseal_remote_backup(
            masked_sealing_key,
            &src_evidence,
            &dest_evidence,
            policy,
            src_remote_backup,
        )?;

        copy_to_buffer(dst_remote_backup, &result)?;

        Ok(())
    })
}

/// Input buffers for [`azihsm_sd_restore_remote_backup`].
#[repr(C)]
pub struct AzihsmSdRestoreRemoteBackupParams {
    /// Receiver's masked SD-sealing key (from `azihsm_key_gen`) that
    /// unseals the backup, exactly `MASKED_SEALING_KEY_LEN` (180 B).
    pub masked_sealing_key: *const AzihsmBuffer,
    /// Sender attestation evidence.
    pub sender_evidence: *const AzihsmSdEvidence,
    /// Unified partition-policy image (484 B) describing the domain.
    pub policy: *const AzihsmBuffer,
    /// Remote backup to restore, exactly `POK_REMOTE_BACKUP_LEN` (161 B).
    pub src_remote_backup: *const AzihsmBuffer,
    /// Previous security-domain masking-key backup, exactly
    /// `SD_MK_BACKUP_LEN` (164 B).
    pub prev_sd_mk_backup: *const AzihsmBuffer,
}

/// @brief Restore a security domain from a remote backup
///
/// HPKE-opens `params.src_remote_backup` with the receiver's masked sealing
/// key (authenticated by the sender in `params.sender_evidence`), recovers
/// the security-domain masking key from `params.prev_sd_mk_backup`, and
/// returns the refreshed device-local backups.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Restore-backup input buffers
/// @param[in,out] pok_local_backup Output buffer for the local
///                partition-owner-key backup (180 B).
/// @param[in,out] sd_mk_backup Output buffer for the security-domain
///                masking-key backup (164 B).
///
/// Both output buffers follow the probe/fill convention and are validated
/// **before** the restore is performed.
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` and each of its buffer/evidence pointers must be valid; each
///   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
/// - Each output buffer must be a valid `azihsm_buffer` with writable
///   backing storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sd_restore_remote_backup(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSdRestoreRemoteBackupParams,
    pok_local_backup: *mut AzihsmBuffer,
    sd_mk_backup: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_sealing_key: &[u8] = deref_ptr(params.masked_sealing_key)?.try_into()?;
        let policy: &[u8] = deref_ptr(params.policy)?.try_into()?;
        let src_remote_backup: &[u8] = deref_ptr(params.src_remote_backup)?.try_into()?;
        let prev_sd_mk_backup: &[u8] = deref_ptr(params.prev_sd_mk_backup)?.try_into()?;

        let sender = deref_ptr(params.sender_evidence)?;
        let sender = SdEvidence::try_from(sender)?;
        let sender = api::HsmSdEvidence::from(&sender);

        // Validate all outputs up-front (aliasing on raw pointers, then
        // sizes) so one probe advertises every length before the restore runs.
        validate_distinct_output_buffers(&[pok_local_backup, sd_mk_backup])?;
        let pok_local_backup = deref_mut_ptr(pok_local_backup)?;
        let sd_mk_backup = deref_mut_ptr(sd_mk_backup)?;
        validate_output_sizes(&mut [
            (&mut *pok_local_backup, api::MASKED_SD_LEN),
            (&mut *sd_mk_backup, api::SD_MK_BACKUP_LEN),
        ])?;

        let result = session.sd_restore_remote_backup(
            masked_sealing_key,
            &sender,
            policy,
            src_remote_backup,
            prev_sd_mk_backup,
        )?;

        copy_to_buffer(pok_local_backup, &result.pok_local_backup)?;
        copy_to_buffer(sd_mk_backup, &result.sd_mk_backup)?;

        Ok(())
    })
}

/// Input buffers for [`azihsm_sd_create_peer_backup`].
#[repr(C)]
pub struct AzihsmSdCreatePeerBackupParams {
    /// Sender's masked SD-sealing key (from `azihsm_key_gen`), exactly
    /// `MASKED_SEALING_KEY_LEN` (180 B).
    pub masked_sealing_key: *const AzihsmBuffer,
    /// Destination (peer) attestation evidence.
    pub dst_evidence: *const AzihsmSdEvidence,
    /// Unified partition-policy image (484 B) describing the domain.
    pub policy: *const AzihsmBuffer,
    /// Device-local partition-owner-key backup (180 B) from which BKS3 is
    /// recovered.
    pub pok_local_backup: *const AzihsmBuffer,
}

/// @brief Create a peer-transferable backup of a security domain
///
/// Recovers BKS3 from `params.pok_local_backup` and HPKE-Auth-seals it to
/// the destination peer named by `params.dst_evidence` (authenticated by
/// the sender's masked sealing key), returning the peer backup. Gated by
/// the security domain's `allow_peer_cloning` policy flag.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Create-peer-backup input buffers
/// @param[in,out] pok_peer_backup Output buffer for the peer
///                partition-owner-key backup (161 B).
///
/// The output buffer follows the probe/fill convention and is validated
/// **before** the peer backup is created.
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` and each of its buffer/evidence pointers must be valid; each
///   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
/// - `pok_peer_backup` must be a valid `azihsm_buffer` with writable
///   backing storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sd_create_peer_backup(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSdCreatePeerBackupParams,
    pok_peer_backup: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_sealing_key: &[u8] = deref_ptr(params.masked_sealing_key)?.try_into()?;
        let policy: &[u8] = deref_ptr(params.policy)?.try_into()?;
        let pok_local_backup: &[u8] = deref_ptr(params.pok_local_backup)?.try_into()?;

        let dst = deref_ptr(params.dst_evidence)?;
        let dst = SdEvidence::try_from(dst)?;
        let dst = api::HsmSdEvidence::from(&dst);

        // Validate the output buffer before creating the peer backup.
        validate_ptr(pok_peer_backup)?;
        let pok_peer_backup = deref_mut_ptr(pok_peer_backup)?;
        validate_output_buffer(pok_peer_backup, api::POK_REMOTE_BACKUP_LEN)?;

        let result =
            session.sd_create_peer_backup(masked_sealing_key, &dst, policy, pok_local_backup)?;

        copy_to_buffer(pok_peer_backup, &result)?;

        Ok(())
    })
}

/// Input buffers for [`azihsm_sd_restore_peer_backup`].
#[repr(C)]
pub struct AzihsmSdRestorePeerBackupParams {
    /// Receiver's masked SD-sealing key (from `azihsm_key_gen`) that
    /// unseals the backup, exactly `MASKED_SEALING_KEY_LEN` (180 B).
    pub masked_sealing_key: *const AzihsmBuffer,
    /// Source (peer) attestation evidence.
    pub src_evidence: *const AzihsmSdEvidence,
    /// Unified partition-policy image (484 B) describing the domain.
    pub policy: *const AzihsmBuffer,
    /// Peer backup to restore, exactly `POK_REMOTE_BACKUP_LEN` (161 B).
    pub pok_peer_backup: *const AzihsmBuffer,
    /// Previous security-domain masking-key backup, exactly
    /// `SD_MK_BACKUP_LEN` (164 B).
    pub prev_sd_mk_backup: *const AzihsmBuffer,
}

/// @brief Restore a security domain from a peer backup
///
/// HPKE-opens `params.pok_peer_backup` with the receiver's masked sealing
/// key (authenticated by the source peer in `params.src_evidence`), recovers
/// the security-domain masking key from `params.prev_sd_mk_backup`, and
/// returns the refreshed device-local backups.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Restore-backup input buffers
/// @param[in,out] pok_local_backup Output buffer for the local
///                partition-owner-key backup (180 B).
/// @param[in,out] sd_mk_backup Output buffer for the security-domain
///                masking-key backup (164 B).
///
/// Both output buffers follow the probe/fill convention and are validated
/// **before** the restore is performed.
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` and each of its buffer/evidence pointers must be valid; each
///   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
/// - Each output buffer must be a valid `azihsm_buffer` with writable
///   backing storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sd_restore_peer_backup(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSdRestorePeerBackupParams,
    pok_local_backup: *mut AzihsmBuffer,
    sd_mk_backup: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_sealing_key: &[u8] = deref_ptr(params.masked_sealing_key)?.try_into()?;
        let policy: &[u8] = deref_ptr(params.policy)?.try_into()?;
        let pok_peer_backup: &[u8] = deref_ptr(params.pok_peer_backup)?.try_into()?;
        let prev_sd_mk_backup: &[u8] = deref_ptr(params.prev_sd_mk_backup)?.try_into()?;

        let src = deref_ptr(params.src_evidence)?;
        let src = SdEvidence::try_from(src)?;
        let src = api::HsmSdEvidence::from(&src);

        // Validate all outputs up-front (aliasing on raw pointers, then
        // sizes) so one probe advertises every length before the restore runs.
        validate_distinct_output_buffers(&[pok_local_backup, sd_mk_backup])?;
        let pok_local_backup = deref_mut_ptr(pok_local_backup)?;
        let sd_mk_backup = deref_mut_ptr(sd_mk_backup)?;
        validate_output_sizes(&mut [
            (&mut *pok_local_backup, api::MASKED_SD_LEN),
            (&mut *sd_mk_backup, api::SD_MK_BACKUP_LEN),
        ])?;

        let result = session.sd_restore_peer_backup(
            masked_sealing_key,
            &src,
            policy,
            pok_peer_backup,
            prev_sd_mk_backup,
        )?;

        copy_to_buffer(pok_local_backup, &result.pok_local_backup)?;
        copy_to_buffer(sd_mk_backup, &result.sd_mk_backup)?;

        Ok(())
    })
}

/// Input buffers for [`azihsm_sd_restore_local_backup`].
#[repr(C)]
pub struct AzihsmSdRestoreLocalBackupParams {
    /// Device-local partition-owner-key backup to restore, exactly
    /// `MASKED_SD_LEN` (180 B).
    pub pok_local_backup: *const AzihsmBuffer,
    /// Security-domain masking-key backup, exactly `SD_MK_BACKUP_LEN`
    /// (164 B).
    pub sd_mk_backup: *const AzihsmBuffer,
}

/// @brief Restore a security domain from its device-local backups
///
/// Restores the security domain from the device-local
/// `params.pok_local_backup` and `params.sd_mk_backup`, returning the
/// refreshed device-local backups. No attestation evidence is involved.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Restore-backup input buffers
/// @param[in,out] pok_local_backup Output buffer for the refreshed local
///                partition-owner-key backup (180 B).
/// @param[in,out] sd_mk_backup Output buffer for the refreshed
///                security-domain masking-key backup (164 B).
///
/// Both output buffers follow the probe/fill convention and are validated
/// **before** the restore is performed.
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` and each of its buffer pointers must be valid.
/// - Each output buffer must be a valid `azihsm_buffer` with writable
///   backing storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sd_restore_local_backup(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSdRestoreLocalBackupParams,
    pok_local_backup: *mut AzihsmBuffer,
    sd_mk_backup: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let pok_local_backup_in: &[u8] = deref_ptr(params.pok_local_backup)?.try_into()?;
        let sd_mk_backup_in: &[u8] = deref_ptr(params.sd_mk_backup)?.try_into()?;

        // Validate all outputs up-front (aliasing on raw pointers, then
        // sizes) so one probe advertises every length before the restore runs.
        validate_distinct_output_buffers(&[pok_local_backup, sd_mk_backup])?;
        let pok_local_backup = deref_mut_ptr(pok_local_backup)?;
        let sd_mk_backup = deref_mut_ptr(sd_mk_backup)?;
        validate_output_sizes(&mut [
            (&mut *pok_local_backup, api::MASKED_SD_LEN),
            (&mut *sd_mk_backup, api::SD_MK_BACKUP_LEN),
        ])?;

        let result = session.sd_restore_local_backup(pok_local_backup_in, sd_mk_backup_in)?;

        copy_to_buffer(pok_local_backup, &result.pok_local_backup)?;
        copy_to_buffer(sd_mk_backup, &result.sd_mk_backup)?;

        Ok(())
    })
}
