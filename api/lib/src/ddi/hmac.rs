// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC operations through the Device Driver Interface (DDI).
//!
//! This module provides low-level helpers for executing the DDI `Hmac` operation.
//! It bridges the N-API key wrapper layer to the underlying DDI protocol by:
//! - Encoding request payloads into MBOR
//! - Executing the command on the device
//! - Copying the returned tag into caller-provided buffers
//!
//! # Message size
//!
//! The DDI request for HMAC uses a fixed-size MBOR byte array for the message.
//! The maximum supported message size is 1024 bytes (see `DdiHmacReq.msg`).
//! Requests larger than this will fail when building the MBOR payload.

use super::*;

/// Computes an HMAC tag for the provided message using an HSM-managed key.
///
/// This is a low-level DDI wrapper. It constructs a `DdiHmacCmdReq`, executes it on
/// the device, and copies the returned tag into `signature`.
///
/// # Arguments
///
/// * `key` - HMAC key handle stored in the HSM.
/// * `data` - Message bytes. Must be at most 1024 bytes due to the DDI message buffer.
/// * `signature` - Output buffer that receives the computed tag.
///
/// # Returns
///
/// Returns the number of bytes written to `signature`.
///
/// The returned tag length is determined by the HSM/DDI response. The DDI response
/// type supports up to 64 bytes of tag data (e.g., HMAC-SHA-512).
///
/// # Errors
///
/// Returns an error if:
/// - `data` exceeds the DDI message limit and cannot be encoded to MBOR.
/// - The device command execution fails.
/// - The provided `signature` buffer is too small.
pub(crate) fn hmac_sign(key: &HsmHmacKey, data: &[u8], signature: &mut [u8]) -> HsmResult<usize> {
    // build hmac sign ddi request
    let req = DdiHmacCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::Hmac, &key.session()),
        data: DdiHmacReq {
            key_id: key.handle(),
            msg: MborByteArray::from_slice(data).map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };
    let resp = key.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    // check if signature buffer is large enough
    if signature.len() < resp.data.tag.len() {
        Err(HsmError::BufferTooSmall)?;
    }
    // Copy output signature
    signature[..resp.data.tag.len()].copy_from_slice(resp.data.tag.as_slice());

    Ok(resp.data.tag.len())
}
