// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM session operations for the native C API.
//!
//! This module provides the FFI (Foreign Function Interface) bindings for
//! HSM session management operations, exposing them to C callers through
//! the ABI-compatible interface.

use super::*;

/// @brief Open an HSM session over the TBOR transport (security-domain)
///
/// Runs the two-phase `open_session_ex` HPKE handshake using the API
/// revision negotiated when the partition was opened, and returns a
/// handle to the resulting session.
///
/// @param[in] dev_handle Handle to the HSM partition
/// @param[in] session_type Channel integrity profile to pin for the session
/// @param[out] sess_handle Pointer to the session handle to be allocated
///
/// @return `AzihsmError` indicating the result of the operation
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
            session_type.into(),
        )?);

        let handle = HANDLE_TABLE.alloc_handle(HandleType::Session, session);

        // Return the generated session handle
        assign_ptr(sess_handle, handle)?;

        Ok(())
    })
}

/// @brief Provision a partition over a security-domain session (TBOR `PartInit`)
///
/// Issues the TBOR `PartInit` command on the given V2 session: it seals
/// `mach_seed` under the session key and ships it alongside the unified
/// `part_policy` and the POTA / SATA / optional SAPOTA thumbprints,
/// returning the PTA certificate-signing request and the PTA attestation
/// report.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] mach_seed Machine seed plaintext buffer
/// @param[in] part_policy Unified partition policy image buffer
/// @param[in] pota_thumbprint POTA public-key thumbprint buffer
/// @param[in] sata_thumbprint SATA public-key thumbprint buffer
/// @param[in] sapota_thumbprint Optional SAPOTA thumbprint buffer (may be null)
/// @param[in,out] pta_csr Output buffer for the DER PKCS#10 CSR. On input
///                `len` is the capacity; on success it is set to the number
///                of bytes written. On `BufferTooSmall` it is set to the
///                required size.
/// @param[in,out] pta_report Output buffer for the COSE_Sign1 attestation
///                report, with the same capacity/length contract as
///                `pta_csr`.
///
/// @return `AzihsmError` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `mach_seed`, `part_policy`, `pota_thumbprint`, and `sata_thumbprint`
///   must be valid pointers to `azihsm_buffer` structures.
/// - `sapota_thumbprint` must be null or a valid `azihsm_buffer` pointer.
/// - `pta_csr` and `pta_report` must be valid pointers to distinct
///   `azihsm_buffer` structures with writable backing storage of the
///   advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_ex_part_init(
    sess_handle: AzihsmHandle,
    mach_seed: *const AzihsmBuffer,
    part_policy: *const AzihsmBuffer,
    pota_thumbprint: *const AzihsmBuffer,
    sata_thumbprint: *const AzihsmBuffer,
    sapota_thumbprint: *const AzihsmBuffer,
    pta_csr: *mut AzihsmBuffer,
    pta_report: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;

        let mach_seed: &[u8] = deref_ptr(mach_seed)?.try_into()?;
        let part_policy: &[u8] = deref_ptr(part_policy)?.try_into()?;
        let pota_thumbprint: &[u8] = deref_ptr(pota_thumbprint)?.try_into()?;
        let sata_thumbprint: &[u8] = deref_ptr(sata_thumbprint)?.try_into()?;
        let sapota_thumbprint = buffer_to_optional_slice(sapota_thumbprint)?;

        // Validate the output buffers before the one-shot provisioning op
        // so a null pointer is rejected up front rather than after the
        // partition has already been provisioned.
        let pta_csr = deref_mut_ptr(pta_csr)?;
        let pta_report = deref_mut_ptr(pta_report)?;

        let result = session.part_init(
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
