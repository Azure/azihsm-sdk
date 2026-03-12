// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use resiliency_macro::resiliency_key_gen;

use super::*;

/// RAII guard for a newly-created HSM key handle.
///
/// Many DDI operations return a `key_id` plus some additional metadata (for example,
/// masked key material that must be parsed into [`HsmKeyProps`]). If parsing/validation
/// fails after the key has already been created in the device, the key would otherwise
/// be leaked.
///
/// `HsmKeyIdGuard` deletes the key on drop unless it is explicitly released.
///
/// # Behavior
///
/// - **Default:** on drop, checks the epoch and calls [`delete_key_raw_no_res`]
///   without acquiring the barrier lock.  This makes the guard safe to use
///   inside code that already holds the barrier (read or write).
///   - If the epoch has advanced since the guard was created, the device
///     was reset and all session keys are already destroyed — the delete
///     is skipped.
///   - If the epoch matches, the handle is still valid and the DDI delete
///     is executed.  A race where a restore starts between the epoch check
///     and the DDI call is benign: `delete_key_raw_no_res` treats device-reset
///     errors as success.
/// - **Released:** does nothing on drop.
/// - **Best effort:** any error from [`delete_key_raw_no_res`] is ignored in `Drop`.
///
/// # Typical usage
///
/// Create the guard immediately after the DDI call returns a key id, then call
/// [`HsmKeyIdGuard::release`] only after all fallible parsing/validation has succeeded.
pub(crate) struct HsmKeyIdGuard<'a> {
    session: &'a HsmSession,
    key_id: HsmKeyHandle,
    released: bool,
    /// Partition restore epoch at the time the guard was created.
    creation_epoch: u64,
}

impl<'a> Drop for HsmKeyIdGuard<'a> {
    fn drop(&mut self) {
        if !self.released {
            let partition = self.session.partition();
            // If a restore happened since this guard was created,
            // the device already wiped all session keys — skip delete.
            if partition.resiliency_enabled() && self.creation_epoch < partition.restore_epoch() {
                return;
            }
            let _ = delete_key_raw_no_res(self.session, self.key_id);
        }
    }
}

impl<'a> HsmKeyIdGuard<'a> {
    /// Creates a new guard for `key_id` in `session`.
    pub(crate) fn new(session: &'a HsmSession, key_id: HsmKeyHandle) -> Self {
        Self {
            session,
            key_id,
            released: false,
            creation_epoch: session.partition().restore_epoch(),
        }
    }

    /// Returns the guarded key id.
    pub(crate) fn key_id(&self) -> HsmKeyHandle {
        self.key_id
    }

    /// Releases ownership of the key id without deleting the key on drop.
    ///
    /// Call this once all fallible parsing/validation has succeeded and the
    /// caller is transferring the key id to a higher-level wrapper that will
    /// manage its lifecycle.
    pub(crate) fn release(mut self) -> HsmKeyHandle {
        self.released = true;
        self.key_id
    }
}

/// Raw DDI delete — no resiliency retry, no barrier lock.
/// Caller must hold the key-ops barrier lock (read or write) or accept
/// the risk of racing with a concurrent restore.
///
/// Treats device-reset errors ([`key_needs_restoration`]) as success,
/// because a device reset already destroyed all session keys.
///
/// All other errors are propagated to the caller.
fn delete_key_raw_no_res(session: &HsmSession, key_id: HsmKeyHandle) -> HsmResult<()> {
    let req = DdiDeleteKeyCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::DeleteKey, session),
        data: DdiDeleteKeyReq {
            key_id: ddi::get_key_id(key_id),
        },
        ext: None,
    };

    let result = session.with_dev(|dev| dev.exec_op(&req, &mut None).map_err(HsmError::from));

    match result {
        Ok(_) => Ok(()),
        // If the delete failed because the device was reset after the key was created,
        // then the key is already gone and we can treat this as success.
        Err(ref err) if crate::resiliency::key_needs_restoration(err) => Ok(()),
        Err(err) => Err(err),
    }
}

/// Epoch-aware key deletion with barrier lock.
///
/// Acquires the restore barrier read lock and compares `key_epoch` against
/// the partition's current restore epoch:
///
/// - If `key_epoch < restore_epoch`, the device was reset after the key was
///   created — the key is already destroyed. Returns `Ok(())`.
/// - If `key_epoch == restore_epoch`, the key handle is current — calls
///   [`delete_key_raw_no_res`] under the read lock to prevent any concurrent
///   restore from reassigning handles mid-delete.
/// - If `key_epoch > restore_epoch`, this is a logic bug — caught by
///   `debug_assert!`.
///
/// When resiliency is not enabled, delegates directly to [`delete_key_raw_no_res`].
pub(crate) fn delete_key(
    session: &HsmSession,
    key_id: HsmKeyHandle,
    key_epoch: u64,
) -> HsmResult<()> {
    let partition = session.partition();
    if partition.resiliency_enabled() {
        let _barrier = partition.key_barrier_read();
        let restore_epoch = partition.restore_epoch();
        if key_epoch < restore_epoch {
            // The device was reset after this key was created, so the key is already destroyed.
            return Ok(());
        } else if key_epoch > restore_epoch {
            // The key epoch is ahead of the restore epoch — this indicates a logic bug.
            return Err(HsmError::InternalError);
        }
        return delete_key_raw_no_res(session, key_id);
    }
    delete_key_raw_no_res(session, key_id)
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

    session.with_dev(|dev| dev.exec_op(&req, &mut None).map_err(HsmError::from))
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
#[resiliency_key_gen(session = "session")]
pub(crate) fn unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    unmask_key_raw_no_res(session, masked_key)
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
#[resiliency_key_gen(session = "session")]
pub(crate) fn unmask_key_pair(
    session: &HsmSession,
    masked_key: &[u8],
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    unmask_key_pair_raw_no_res(session, masked_key)
}

/// Raw unmask — no resiliency retry.
///
/// For use under the barrier write lock (Phase 3 key restoration) or
/// anywhere the caller manages locking externally. On parse failure
/// after a successful DDI call, the newly created key is cleaned up
/// via [`HsmKeyIdGuard`].
pub(crate) fn unmask_key_raw_no_res(
    session: &HsmSession,
    masked_key: &[u8],
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    let resp = unmask_key_exec(session, masked_key)?;
    let key_id = to_key_handle(resp.data.key_id, resp.data.bulk_key_id);
    let guard = HsmKeyIdGuard::new(session, key_id);
    let key_props = HsmMaskedKey::to_key_props(resp.data.masked_key.as_slice())?;
    Ok((guard.release(), key_props))
}

/// Raw unmask for key pairs — no resiliency retry.
///
/// For use under the barrier write lock (Phase 3 key restoration) or
/// anywhere the caller manages locking externally.
/// On failure after a successful DDI call, the newly created key is
/// cleaned up via [`HsmKeyIdGuard`].
pub(crate) fn unmask_key_pair_raw_no_res(
    session: &HsmSession,
    masked_key: &[u8],
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    let resp = unmask_key_exec(session, masked_key)?;
    let key_id = to_key_handle(resp.data.key_id, resp.data.bulk_key_id);
    let guard = HsmKeyIdGuard::new(session, key_id);

    let pub_key = resp.data.pub_key.ok_or(HsmError::InternalError)?;

    let der = pub_key.der.as_slice();
    let masked_key_data = resp.data.masked_key.as_slice();
    let (priv_key_props, pub_key_props) = HsmMaskedKey::to_key_pair_props(masked_key_data, der)?;
    Ok((guard.release(), priv_key_props, pub_key_props))
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
            key_id: ddi::get_key_id(key_handle),
            report_data: MborByteArray::from_slice(report_data)
                .map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };

    let resp = session.with_dev(|dev| dev.exec_op(&req, &mut None).map_err(HsmError::from))?;

    let dev_report = resp.data.report.as_slice();
    report[..dev_report.len()].copy_from_slice(dev_report);
    Ok(dev_report.len())
}

/// Raw key-pair refresh — no resiliency retry.
///
/// For use under the barrier write lock (Phase 3 key restoration).
/// Calls [`unmask_key_pair_raw_no_res`] instead of the macro-wrapped variant.
pub(crate) fn refresh_key_pair_raw_no_res(
    session: &HsmSession,
    old_props: &HsmKeyProps,
    masked_key: &[u8],
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    if old_props.kind() == HsmKeyKind::Rsa && old_props.can_unwrap() {
        let priv_key_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Private)
            .key_kind(old_props.kind())
            .bits(old_props.bits())
            .can_unwrap(true)
            .build()?;

        let pub_key_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Public)
            .key_kind(old_props.kind())
            .bits(old_props.bits())
            .can_wrap(true)
            .build()?;

        let (handle, priv_props, pub_props) =
            get_rsa_unwrapping_key_raw_no_res(session, priv_key_props, pub_key_props)?;

        if let Some(muk) = priv_props.masked_key() {
            session
                .partition()
                .write_resiliency_storage(crate::resiliency::AZIHSM_STORAGE_MUK, muk)?;
        }

        return Ok((handle, priv_props, pub_props));
    }

    unmask_key_pair_raw_no_res(session, masked_key)
}
