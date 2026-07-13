// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM session operations for the native C API.
//!
//! This module provides the FFI (Foreign Function Interface) bindings for
//! HSM session management operations, exposing them to C callers through
//! the ABI-compatible interface.

use super::*;

/// @brief Open a security-domain session to the device
///
/// Opens a security-domain session using the API revision negotiated when
/// the partition was opened, and returns a handle to the resulting
/// session. `session_type` selects the channel integrity profile pinned
/// for the session.
///
/// @param[in] dev_handle Handle to the HSM partition
/// @param[in] session_type Channel integrity profile to pin for the session
/// @param[out] sess_handle Pointer to the session handle to be allocated
///
/// @return `AzihsmStatus` indicating the result of the operation
///
/// # Safety
///
/// - `dev_handle` must be a valid partition handle.
/// - `sess_handle` must be a valid pointer to memory where the session handle
///   will be written.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_ex_open(
    dev_handle: AzihsmHandle,
    session_type: AzihsmSessionExType,
    sess_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(sess_handle)?;

        // Get the partition from the handle
        let partition = &api::HsmPartition::try_from(dev_handle)?;
        // PSK id selecting the role (0 = CO, 1 = CU). Hardcoded to CO for
        // now; role selection is not yet exposed on this entry point.
        let psk_id = 0;
        let session = Box::new(partition.open_session_ex(
            partition.api_rev(),
            psk_id,
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
