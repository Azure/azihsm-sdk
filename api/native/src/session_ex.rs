// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM session operations for the native C API.
//!
//! This module provides the FFI (Foreign Function Interface) bindings for
//! HSM session management operations, exposing them to C callers through
//! the ABI-compatible interface.

use super::*;

/// PSK credential for opening a security-domain session.
///
/// Pairs the PSK slot (`psk_id`) with an optional caller-supplied PSK.
/// When the `psk` **field** (below) is NULL, the partition **default** PSK
/// for the slot is used — required for the first session, before the
/// default is rotated via `azihsm_sess_ex_psk_change`. After rotation,
/// point the `psk` field at the rotated secret.
#[repr(C)]
pub struct AzihsmSessionPsk {
    /// PSK slot: 0 = Crypto Officer, 1 = Crypto User.
    pub psk_id: u8,
    /// Optional PSK buffer (exactly `PSK_LEN` bytes); NULL selects the
    /// partition default PSK for the slot.
    pub psk: *const AzihsmBuffer,
}

/// @brief Open a security-domain session to the device
///
/// Opens a security-domain session using the API revision negotiated when
/// the partition was opened, and returns a handle to the resulting
/// session. `psk` selects the role slot and (optionally) the PSK, and
/// `session_type` selects the channel integrity profile pinned for the
/// session.
///
/// @param[in] dev_handle Handle to the HSM partition
/// @param[in] psk PSK credential — slot plus optional PSK
///            (see `azihsm_session_psk`)
/// @param[in] session_type Channel integrity profile to pin for the session
/// @param[out] sess_handle Pointer to the session handle to be allocated
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `dev_handle` must be a valid partition handle.
/// - `psk` must be a valid pointer to an `azihsm_session_psk` whose `psk`
///   field is NULL or a valid `azihsm_buffer` holding exactly `PSK_LEN`
///   bytes.
/// - `sess_handle` must be a valid pointer to memory where the session handle
///   will be written.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_ex_open(
    dev_handle: AzihsmHandle,
    psk: *const AzihsmSessionPsk,
    session_type: AzihsmSessionExType,
    sess_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(sess_handle)?;

        let psk = deref_ptr(psk)?;
        let psk_id = match psk.psk_id {
            0 => api::HsmPskId::CO,
            1 => api::HsmPskId::CU,
            _ => Err(AzihsmStatus::InvalidArgument)?,
        };
        // NULL `psk` buffer selects the partition default PSK; otherwise
        // the caller-supplied PSK must be exactly `PSK_LEN` bytes.
        let session_psk = match buffer_to_optional_slice(psk.psk)? {
            Some(bytes) => {
                let key: &[u8; api::PSK_LEN] = bytes
                    .try_into()
                    .map_err(|_| AzihsmStatus::InvalidArgument)?;
                api::HsmSessionPsk::with_psk(psk_id, key)
            }
            None => api::HsmSessionPsk::new(psk_id),
        };

        // Get the partition from the handle
        let partition = &api::HsmPartition::try_from(dev_handle)?;
        let session = Box::new(partition.open_session_ex(
            partition.api_rev(),
            session_psk,
            api::HsmSessionExType::from(session_type),
        )?);

        let handle = HANDLE_TABLE.alloc_handle(HandleType::Session, session);

        // Return the generated session handle
        assign_ptr(sess_handle, handle)?;

        Ok(())
    })
}

/// Input buffers for [`azihsm_sess_ex_part_init`].
///
/// Groups the security-domain provisioning inputs into a single struct so
/// the call site does not pass them as separate arguments. Each field
/// points to an `azihsm_buffer`; `sapota_thumbprint` is optional and may
/// be NULL to omit it.
#[repr(C)]
pub struct AzihsmSessExPartInitParams {
    /// Machine seed plaintext buffer.
    pub mach_seed: *const AzihsmBuffer,
    /// Unified partition policy image buffer.
    pub part_policy: *const AzihsmBuffer,
    /// POTA public-key thumbprint buffer.
    pub pota_thumbprint: *const AzihsmBuffer,
    /// SATA public-key thumbprint buffer.
    pub sata_thumbprint: *const AzihsmBuffer,
    /// Optional SAPOTA thumbprint buffer; NULL to omit.
    pub sapota_thumbprint: *const AzihsmBuffer,
}

/// @brief Provision a partition's security domain
///
/// Initializes the partition from the machine seed and unified partition
/// policy, together with the partition-owner (POTA), security-administrator
/// (SATA), and optional secondary-owner (SAPOTA) trust-anchor thumbprints,
/// returning the partition's certificate-signing request and attestation
/// report.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Provisioning input buffers
///            (see `azihsm_sess_ex_part_init_params`)
/// @param[in,out] pta_csr Output buffer for the DER PKCS#10 CSR. On input
///                `len` is the capacity; on success it is set to the number
///                of bytes written. If the buffer is too small (or `ptr` is
///                NULL with `len == 0`), `len` is set to the maximum possible
///                output size (the buffer is validated up-front against a
///                fixed wire-schema bound, so the probe reports that bound
///                rather than the exact byte count for this device) and
///                `AZIHSM_STATUS_BUFFER_TOO_SMALL` is returned **before** the
///                partition is provisioned — so the standard two-call probe
///                (call once with a zero-length buffer to learn the required
///                capacity, then retry) is safe for this one-shot command.
///                When either output buffer is too small, **both** `pta_csr`
///                and `pta_report` have their `len` set to their maximum
///                bound, so a single probe reports both required sizes. A
///                buffer sized to that bound is always large enough; the
///                `len` written on success is the exact number of bytes. A
///                NULL `ptr` with a non-zero `len` is rejected with
///                `AZIHSM_STATUS_INVALID_ARGUMENT`.
/// @param[in,out] pta_report Output buffer for the attestation report, with
///                the same capacity/length contract as `pta_csr`.
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` must be a valid pointer to an `azihsm_sess_ex_part_init_params`
///   whose `mach_seed`, `part_policy`, `pota_thumbprint`, and
///   `sata_thumbprint` are valid `azihsm_buffer` pointers, and whose
///   `sapota_thumbprint` is NULL or a valid `azihsm_buffer` pointer.
/// - `pta_csr` and `pta_report` must be valid pointers to distinct
///   `azihsm_buffer` structures with writable backing storage of the
///   advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_ex_part_init(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSessExPartInitParams,
    pta_csr: *mut AzihsmBuffer,
    pta_report: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let mach_seed: &[u8] = deref_ptr(params.mach_seed)?.try_into()?;
        let part_policy: &[u8] = deref_ptr(params.part_policy)?.try_into()?;
        let pota_thumbprint: &[u8] = deref_ptr(params.pota_thumbprint)?.try_into()?;
        let sata_thumbprint: &[u8] = deref_ptr(params.sata_thumbprint)?.try_into()?;
        let sapota_thumbprint = buffer_to_optional_slice(params.sapota_thumbprint)?;

        // Validate the output buffers before calling into the session
        validate_ptr(pta_csr)?;
        validate_ptr(pta_report)?;

        if std::ptr::eq(pta_csr, pta_report) {
            Err(AzihsmStatus::InvalidArgument)?;
        }

        let pta_csr = deref_mut_ptr(pta_csr)?;
        let pta_report = deref_mut_ptr(pta_report)?;

        // Reject two distinct `azihsm_buffer` structs that alias the same
        // non-NULL backing storage; writing both outputs would overlap.
        // The size-probe case (`ptr == NULL`, `len == 0`) is still allowed.
        if !pta_csr.ptr.is_null() && pta_csr.ptr == pta_report.ptr {
            Err(AzihsmStatus::InvalidArgument)?;
        }

        // Validate both output buffers up-front against the fixed
        // wire-schema bounds so the partition is not provisioned when a buffer is too small.
        let csr_check = validate_output_buffer(pta_csr, api::PTA_CSR_MAX_LEN).map(|_| ());
        let report_check = validate_output_buffer(pta_report, api::PTA_REPORT_MAX_LEN).map(|_| ());

        // A malformed buffer (`INVALID_ARGUMENT`) is the hardest error and
        // must not be masked by a `BUFFER_TOO_SMALL` from the other buffer.
        if matches!(csr_check, Err(AzihsmStatus::InvalidArgument))
            || matches!(report_check, Err(AzihsmStatus::InvalidArgument))
        {
            return Err(AzihsmStatus::InvalidArgument);
        }

        // If either buffer is too small, advertise BOTH required
        // capacities in a single probe (`validate_output_buffer` fills in
        // `len` only for the buffer that is itself too small).
        if matches!(csr_check, Err(AzihsmStatus::BufferTooSmall))
            || matches!(report_check, Err(AzihsmStatus::BufferTooSmall))
        {
            pta_csr.len = api::PTA_CSR_MAX_LEN as u32;
            pta_report.len = api::PTA_REPORT_MAX_LEN as u32;
            return Err(AzihsmStatus::BufferTooSmall);
        }

        // Propagate any other status verbatim, then continue on success.
        csr_check?;
        report_check?;

        let result = session.part_init_ex(
            mach_seed,
            part_policy,
            pota_thumbprint,
            sata_thumbprint,
            sapota_thumbprint,
        )?;

        copy_to_buffer(pta_csr, &result.pta_csr)?;
        copy_to_buffer(pta_report, &result.pta_report)?;

        Ok(())
    })
}

/// Input buffers for [`azihsm_sess_ex_part_final`].
///
/// Groups the security-domain finalization inputs into a single struct so
/// the call site does not pass them as separate arguments. `pta_cert_chain`
/// points to an array of `pta_cert_chain_len` `azihsm_buffer`s, each holding
/// one DER-encoded PTA certificate (root to leaf). `prev_local_mk_backup` is
/// optional and may be NULL to omit it.
#[repr(C)]
pub struct AzihsmSessExPartFinalParams {
    /// Unified partition policy image buffer, re-supplied for `POTAPubKey`
    /// recovery; must match the policy given to `part_init`.
    pub part_policy: *const AzihsmBuffer,
    /// Pointer to an array of `pta_cert_chain_len` `azihsm_buffer`s, each a
    /// DER-encoded PTA certificate (root to leaf).
    pub pta_cert_chain: *const AzihsmBuffer,
    /// Number of certificates in `pta_cert_chain`.
    pub pta_cert_chain_len: u32,
    /// Optional previous `local_mk` backup envelope to restore; NULL to omit.
    pub prev_local_mk_backup: *const AzihsmBuffer,
}

/// @brief Finalize a partition's security domain
///
/// Completes provisioning started by `azihsm_sess_ex_part_init`: re-supplies
/// the unified partition policy and the PTA certificate chain (root to leaf),
/// optionally restoring a prior `local_mk` backup, and returns the current
/// `local_mk` backup envelope the firmware produced.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Finalization input buffers
///            (see `azihsm_sess_ex_part_final_params`)
/// @param[in,out] local_mk_backup Output buffer for the `local_mk` backup
///                envelope. On input `len` is the capacity; on success it is
///                set to the number of bytes written. If the buffer is too
///                small (or `ptr` is NULL with `len == 0`), `len` is set to
///                the maximum possible output size and
///                `AZIHSM_STATUS_BUFFER_TOO_SMALL` is returned **before** the
///                partition is finalized, so the standard two-call probe
///                (call once with a zero-length buffer to learn the required
///                capacity, then retry) is safe for this one-shot command. A
///                NULL `ptr` with a non-zero `len` is rejected with
///                `AZIHSM_STATUS_INVALID_ARGUMENT`.
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` must be a valid pointer to an `azihsm_sess_ex_part_final_params`
///   whose `part_policy` is a valid `azihsm_buffer` pointer, whose
///   `pta_cert_chain` points to `pta_cert_chain_len` valid `azihsm_buffer`s,
///   and whose `prev_local_mk_backup` is NULL or a valid `azihsm_buffer`
///   pointer.
/// - `local_mk_backup` must be a valid pointer to an `azihsm_buffer` with
///   writable backing storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_ex_part_final(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSessExPartFinalParams,
    local_mk_backup: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let part_policy: &[u8] = deref_ptr(params.part_policy)?.try_into()?;
        let prev_local_mk_backup = buffer_to_optional_slice(params.prev_local_mk_backup)?;

        // Build the PTA cert chain (borrowing, not copying) from the C
        // array of `azihsm_buffer`s. Reject an empty or oversized chain
        // up front so a bogus `pta_cert_chain_len` cannot trigger an
        // unbounded allocation ahead of the `part_final_ex` validation;
        // the firmware accepts at most `MAX_CERTS` certificates.
        let chain_len = params.pta_cert_chain_len as usize;
        if chain_len == 0 || chain_len > api::MAX_CERTS {
            Err(AzihsmStatus::InvalidArgument)?;
        }
        validate_array_ptr(params.pta_cert_chain)?;
        // SAFETY: `pta_cert_chain` is non-null and aligned for
        // `AzihsmBuffer` (checked by `validate_array_ptr`), the caller
        // guarantees it points to `chain_len` valid `azihsm_buffer`s
        // (documented above), and `chain_len` is bounded by `MAX_CERTS`.
        let raw = unsafe { std::slice::from_raw_parts(params.pta_cert_chain, chain_len) };
        let mut certs: Vec<api::HsmCert<'_>> = Vec::with_capacity(chain_len);
        for buf in raw {
            let der: &[u8] = buf.try_into()?;
            certs.push(api::HsmCert { cert: der });
        }

        // Validate the output buffer up-front against the fixed
        // wire-schema bound so the partition is not finalized when the
        // buffer is too small.
        validate_ptr(local_mk_backup)?;
        let local_mk_backup = deref_mut_ptr(local_mk_backup)?;
        validate_output_buffer(local_mk_backup, api::LOCAL_MK_BACKUP_LEN)?;

        let result = session.part_final_ex(part_policy, &certs, prev_local_mk_backup)?;

        copy_to_buffer(local_mk_backup, &result.local_mk_backup)?;

        Ok(())
    })
}

/// @brief Rotate the calling session's partition PSK
///
/// Replaces the PSK of the slot implied by the session role (CO session
/// → CO, CU session → CU) with `new_psk`, sealed under the session key.
/// Required once on a fresh partition to move past the default-PSK gate
/// before provisioning.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] new_psk New PSK buffer; must be exactly `PSK_LEN` (32 B)
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `new_psk` must be a valid pointer to an `azihsm_buffer` whose
///   backing storage holds exactly `PSK_LEN` bytes.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_ex_psk_change(
    sess_handle: AzihsmHandle,
    new_psk: *const AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let new_psk: &[u8] = deref_ptr(new_psk)?.try_into()?;
        let new_psk: &[u8; api::PSK_LEN] = new_psk
            .try_into()
            .map_err(|_| AzihsmStatus::InvalidArgument)?;

        session.change_psk(new_psk)?;

        Ok(())
    })
}

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

/// Input buffers for [`azihsm_sess_ex_sd_create_remote_backup`].
#[repr(C)]
pub struct AzihsmSessExSdCreateRemoteBackupParams {
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
    validate_array_ptr(chain.certs)?;
    // SAFETY: `certs` is non-null and aligned for `AzihsmBuffer` (checked
    // by `validate_array_ptr`), the caller guarantees it points to `len`
    // valid `azihsm_buffer`s, and `len` is bounded by
    // `EVIDENCE_CHAIN_MAX_CERTS`.
    let raw = unsafe { std::slice::from_raw_parts(chain.certs, len) };
    let mut certs = Vec::with_capacity(len);
    for buf in raw {
        let der: &[u8] = buf.try_into()?;
        certs.push(api::HsmCert { cert: der });
    }
    Ok(certs)
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
pub unsafe extern "C" fn azihsm_sess_ex_sd_create_remote_backup(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSessExSdCreateRemoteBackupParams,
    pok_remote_backup: *mut AzihsmBuffer,
    pok_local_backup: *mut AzihsmBuffer,
    sd_mk_backup: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_sealing_key: &[u8] = deref_ptr(params.masked_sealing_key)?.try_into()?;
        let policy: &[u8] = deref_ptr(params.policy)?.try_into()?;

        let ev = deref_ptr(params.receiver_evidence)?;
        let mfgr = unpack_cert_chain(&ev.mfgr_cert_chain)?;
        let owner = unpack_cert_chain(&ev.owner_cert_chain)?;
        let part_owner = unpack_cert_chain(&ev.part_owner_cert_chain)?;
        let report: &[u8] = deref_ptr(ev.report)?.try_into()?;
        let receiver = api::HsmSdEvidence {
            mfgr_cert_chain: &mfgr,
            owner_cert_chain: &owner,
            part_owner_cert_chain: &part_owner,
            report,
        };

        // Validate all three output buffers before creating the domain so
        // the one-shot command is not consumed on a too-small buffer.
        validate_ptr(pok_remote_backup)?;
        let pok_remote_backup = deref_mut_ptr(pok_remote_backup)?;
        validate_output_buffer(pok_remote_backup, api::POK_REMOTE_BACKUP_LEN)?;
        validate_ptr(pok_local_backup)?;
        let pok_local_backup = deref_mut_ptr(pok_local_backup)?;
        validate_output_buffer(pok_local_backup, api::MASKED_SD_LEN)?;
        validate_ptr(sd_mk_backup)?;
        let sd_mk_backup = deref_mut_ptr(sd_mk_backup)?;
        validate_output_buffer(sd_mk_backup, api::SD_MK_BACKUP_LEN)?;

        let result = session.sd_create_remote_backup(masked_sealing_key, &receiver, policy)?;

        copy_to_buffer(pok_remote_backup, &result.pok_remote_backup)?;
        copy_to_buffer(pok_local_backup, &result.pok_local_backup)?;
        copy_to_buffer(sd_mk_backup, &result.sd_mk_backup)?;

        Ok(())
    })
}

/// Input buffers for [`azihsm_sess_ex_sd_reseal_remote_backup`].
#[repr(C)]
pub struct AzihsmSessExSdResealRemoteBackupParams {
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
pub unsafe extern "C" fn azihsm_sess_ex_sd_reseal_remote_backup(
    sess_handle: AzihsmHandle,
    params: *const AzihsmSessExSdResealRemoteBackupParams,
    dst_remote_backup: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_sealing_key: &[u8] = deref_ptr(params.masked_sealing_key)?.try_into()?;
        let policy: &[u8] = deref_ptr(params.policy)?.try_into()?;
        let src_remote_backup: &[u8] = deref_ptr(params.src_remote_backup)?.try_into()?;

        let src_ev = deref_ptr(params.src_evidence)?;
        let src_mfgr = unpack_cert_chain(&src_ev.mfgr_cert_chain)?;
        let src_owner = unpack_cert_chain(&src_ev.owner_cert_chain)?;
        let src_part_owner = unpack_cert_chain(&src_ev.part_owner_cert_chain)?;
        let src_report: &[u8] = deref_ptr(src_ev.report)?.try_into()?;
        let src_evidence = api::HsmSdEvidence {
            mfgr_cert_chain: &src_mfgr,
            owner_cert_chain: &src_owner,
            part_owner_cert_chain: &src_part_owner,
            report: src_report,
        };

        let dest_ev = deref_ptr(params.dest_evidence)?;
        let dest_mfgr = unpack_cert_chain(&dest_ev.mfgr_cert_chain)?;
        let dest_owner = unpack_cert_chain(&dest_ev.owner_cert_chain)?;
        let dest_part_owner = unpack_cert_chain(&dest_ev.part_owner_cert_chain)?;
        let dest_report: &[u8] = deref_ptr(dest_ev.report)?.try_into()?;
        let dest_evidence = api::HsmSdEvidence {
            mfgr_cert_chain: &dest_mfgr,
            owner_cert_chain: &dest_owner,
            part_owner_cert_chain: &dest_part_owner,
            report: dest_report,
        };

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
