// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain vault operations over the TBOR transport at the DDI
//! layer.
//!
//! This module hosts the host-side dispatch for in-session
//! security-domain commands, mirroring the firmware handlers. Currently:
//!
//! * **`SdSealingKeyGen`** (opcode `0x09`) — generate a new
//!   security-domain sealing key in the partition's vault and return its
//!   packed [`HsmKeyHandle`](super::HsmKeyHandle).
//!
//! It runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`]: the request carries the
//! active session id alongside the partition handle.
//!
//! The wire schema lives in [`azihsm_ddi_tbor_types`].

use azihsm_ddi_tbor_types::*;

use super::*;

/// Issue `SdSealingKeyGen` (opcode `0x09`) on the active session.
///
/// Generates a new security-domain sealing key in the partition's
/// vault under the caller-supplied `scope` and returns its vault key id
/// packed into an [`HsmKeyHandle`] (no bulk key id — TBOR vault keys are
/// single-handle).
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `scope` - Requested key scope (lifecycle / visibility domain) as
///   the raw 1-byte `KeyScope` discriminant (mirror of the firmware
///   `HsmKeyScope`).
///
/// # Errors
///
/// Surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_sealing_key_gen(
    partition: &HsmPartition,
    session_id: u16,
    scope: u8,
) -> HsmResult<HsmKeyHandle> {
    let req = TborSdSealingKeyGenReq { session_id, scope };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    let key_id = dev
        .exec_op_tbor(&req, &mut cookie)
        .map(|resp| resp.key_handle)
        .map_err(HsmError::from)?;
    Ok(to_key_handle(key_id, None))
}
