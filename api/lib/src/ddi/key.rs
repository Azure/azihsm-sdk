// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// RAII guard for a newly-created HSM key handle.
///
/// Many DDI operations return a `key_id` plus some additional metadata (for example,
/// masked key material that must be parsed into [`HsmKeyProps`]). If parsing/validation
/// fails after the key has already been created in the device, the key would otherwise
/// be leaked.
///
/// `HsmKeyIdGuard` deletes the key on drop unless it is explicitly disarmed.
///
/// # Behavior
///
/// - **Default:** on drop, calls [`delete_key`] for `key_id`.
/// - **Disarmed:** does nothing on drop.
/// - **Best effort:** any error from [`delete_key`] is ignored in `Drop`.
///
/// # Typical usage
///
/// Create the guard immediately after the DDI call returns a key id, then call
/// [`HsmKeyIdGuard::disarm`] only after all fallible parsing/validation has succeeded.
pub(crate) struct HsmKeyIdGuard<'a> {
    session: &'a HsmSession,
    key_id: u16,
    released: bool,
}

impl<'a> Drop for HsmKeyIdGuard<'a> {
    /// Attempts to delete the guarded key on drop.
    ///
    /// This is intentionally best-effort: `Drop` cannot return an error, and callers
    /// typically cannot recover meaningfully from a cleanup failure during unwinding.
    fn drop(&mut self) {
        if !self.released {
            let _ = delete_key(self.session, self.key_id);
        }
    }
}

impl<'a> HsmKeyIdGuard<'a> {
    /// Creates a new guard for `key_id` in `session`.
    pub(crate) fn new(session: &'a HsmSession, key_id: u16) -> Self {
        Self {
            session,
            key_id,
            released: false,
        }
    }

    /// Returns the guarded key id.
    pub(crate) fn key_id(&self) -> u16 {
        self.key_id
    }

    /// Releases ownership of the key id without deleting the key on drop.
    ///
    /// Call this once all fallible parsing/validation has succeeded and the
    /// caller is transferring the key id to a higher-level wrapper that will
    /// manage its lifecycle.
    pub(crate) fn release(mut self) -> u16 {
        self.released = true;
        self.key_id
    }
}

/// Deletes a key from the HSM.
///
/// Removes the specified key from the HSM partition, making it no longer usable
/// for cryptographic operations. This is a permanent operation that cannot be undone.
///
/// # Arguments
///
/// * `session` - The HSM session context
/// * `key_id` - The HSM key handle identifying the key to delete
///
/// # Returns
///
/// Returns `Ok(())` on successful deletion.
///
pub(crate) fn delete_key(session: &HsmSession, key_id: u16) -> HsmResult<()> {
    let req = DdiDeleteKeyCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::DeleteKey, session),
        data: DdiDeleteKeyReq { key_id },
        ext: None,
    };

    session.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    Ok(())
}

/// Executes the unmask key operation.
///
/// # Arguments
///
/// * `session` - The HSM session context
/// * `masked_key` - The masked key data to be unmasked
///
/// # Returns
///
/// Returns the DDI unmask key command response.
fn unmask_key_exec(session: &HsmSession, masked_key: &[u8]) -> HsmResult<DdiUnmaskKeyCmdResp> {
    let req = DdiUnmaskKeyCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::UnmaskKey, session),
        data: DdiUnmaskKeyReq {
            masked_key: MborByteArray::from_slice(masked_key)
                .map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };

    session.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })
}

/// Unmasks a masked key within the HSM.
///
/// # Arguments
///
/// * `session` - The HSM session context
/// * `masked_key` - The masked key data to be unmasked
///
/// # Returns
///
/// Returns a tuple containing the key handle and key properties.
pub(crate) fn unmask_key(session: &HsmSession, masked_key: &[u8]) -> HsmResult<(u16, HsmKeyProps)> {
    let resp = unmask_key_exec(session, masked_key)?;

    //create key guard to delete key if error occurs before disarming
    let key_id = HsmKeyIdGuard::new(session, resp.data.key_id);

    let masked_key = resp.data.masked_key.as_slice();

    let key_props = HsmMaskedKey::to_key_props(masked_key)?;

    Ok((key_id.release(), key_props))
}

/// Unmasks a masked key pair within the HSM.
///
/// # Arguments
///
/// * `session` - The HSM session context
/// * `masked_key` - The masked key pair data to be unmasked
/// * `priv_key_props` - Properties for the private key
/// * `pub_key_props` - Properties for the public key
///
/// # Returns
///
/// Returns a tuple containing the key handle, private key properties, and public key properties.
pub(crate) fn unmask_key_pair(
    session: &HsmSession,
    masked_key: &[u8],
) -> HsmResult<(u16, HsmKeyProps, HsmKeyProps)> {
    let resp = unmask_key_exec(session, masked_key)?;

    let key_id = HsmKeyIdGuard::new(session, resp.data.key_id);

    let Some(pub_key) = resp.data.pub_key else {
        return Err(HsmError::InternalError);
    };

    let der = pub_key.der.as_slice();

    let masked_key_data = resp.data.masked_key.as_slice();
    let (priv_key_props, pub_key_props) = HsmMaskedKey::to_key_pair_props(masked_key_data, der)?;

    Ok((key_id.release(), priv_key_props, pub_key_props))
}

/// Generates a key report (attestation) for the specified key.
///
/// # Arguments
///
/// * `session` - The HSM session context
/// * `key_handle` - The HSM key handle identifying the key to attest
/// * `report_data` - Custom data to include in the attestation report
/// * `report` - Optional mutable buffer to receive the attestation report
///
/// # Returns
///
/// Returns the size of the attestation report on success.
pub(crate) fn generate_key_report(
    session: &HsmSession,
    key_handle: HsmKeyHandle,
    report_data: &[u8],
    report: Option<&mut [u8]>,
) -> HsmResult<usize> {
    if report_data.len() > DdiAttestKeyReq::MAX_REPORT_DATA_SIZE {
        return Err(HsmError::InvalidArgument);
    }

    let Some(report) = report else {
        return Ok(DdiAttestKeyResp::MAX_REPORT_SIZE);
    };

    if report.len() < DdiAttestKeyResp::MAX_REPORT_SIZE {
        return Err(HsmError::BufferTooSmall);
    }

    let req = DdiAttestKeyCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::AttestKey, session),
        data: DdiAttestKeyReq {
            key_id: key_handle,
            report_data: MborByteArray::from_slice(report_data)
                .map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };

    let resp = session.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    let dev_report = resp.data.report.as_slice();
    report[..dev_report.len()].copy_from_slice(dev_report);
    Ok(dev_report.len())
}
