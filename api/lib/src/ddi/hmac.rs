// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC operations through the Device Driver Interface (DDI).
//!
//! This module provides low-level helpers for executing the DDI `Hmac` operation.
//! It bridges the N-API key wrapper layer to the underlying DDI protocol by:
//! - Encoding request payloads into MBOR (device-resident key) or TBOR
//!   (caller-held masked key, unmask-on-use)
//! - Executing the command on the device
//! - Copying the returned tag into caller-provided buffers
//!
//! # Message size
//!
//! The DDI request for HMAC uses a fixed-size MBOR byte array for the message.
//! The maximum supported message size is 1024 bytes (see `DdiHmacReq.msg`).
//! Requests larger than this will fail when building the MBOR payload.

use azihsm_ddi_tbor_types::HMAC_HASH_SHA256;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA384;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA512;
use azihsm_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;
use azihsm_ddi_tbor_types::TborHmacGenerateKeyReq;
use azihsm_ddi_tbor_types::TborHmacReq;
use resiliency_macro::resiliency_key_gen;
use resiliency_macro::resiliency_key_op;

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
#[resiliency_key_op(key = "key")]
pub(crate) fn hmac_sign(key: &HsmHmacKey, data: &[u8], signature: &mut [u8]) -> HsmResult<usize> {
    // A V2 (TBOR) session holds the key as a caller-held masked blob
    // (unmask-on-use); a V1 (MBOR) session uses the device-resident key.
    if key.session().is_ex() {
        hmac_sign_tbor(key, data, signature)
    } else {
        hmac_sign_mbor(key, data, signature)
    }
}

/// Computes an HMAC tag over MBOR `Hmac` using the device-resident key.
fn hmac_sign_mbor(key: &HsmHmacKey, data: &[u8], signature: &mut [u8]) -> HsmResult<usize> {
    // build hmac sign ddi request
    let req = DdiHmacCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::Hmac, &key.session()),
        data: DdiHmacReq {
            key_id: ddi::get_key_id(key.handle())?,
            msg: MborByteArray::from_slice(data).map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };
    let resp = key.with_dev(|dev| dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from))?;

    // check if signature buffer is large enough
    if signature.len() < resp.data.tag.len() {
        Err(HsmError::BufferTooSmall)?;
    }
    // Copy output signature
    signature[..resp.data.tag.len()].copy_from_slice(resp.data.tag.as_slice());

    Ok(resp.data.tag.len())
}

/// Computes an HMAC tag over TBOR `Hmac` using the caller-held masked key
/// (unmask-on-use); nothing is stored on-device.
fn hmac_sign_tbor(key: &HsmHmacKey, data: &[u8], signature: &mut [u8]) -> HsmResult<usize> {
    let props = key.props();
    let masked = props.masked_key().ok_or(HsmError::InternalError)?;

    let req = TborHmacReq {
        session_id: key.session().ex_session_id()?,
        masked_key: masked.to_vec(),
        msg: data.to_vec(),
    };
    let mut cookie = None;
    let resp = key.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    // check if signature buffer is large enough
    if signature.len() < resp.tag.len() {
        Err(HsmError::BufferTooSmall)?;
    }
    // Copy output signature
    signature[..resp.tag.len()].copy_from_slice(&resp.tag);

    Ok(resp.tag.len())
}

/// Generates a random HMAC key via TBOR `HmacGenerateKey`.
///
/// HMAC key generation is a TBOR-only (V2) capability — MBOR has no
/// `HmacGenerateKey` command — so a V1 (MBOR) session is rejected. The key
/// is non-resident: firmware returns it as a masked blob (unmasked on-use
/// by [`hmac_sign`]); nothing is stored on-device.
#[resiliency_key_gen(session = "session")]
pub(crate) fn hmac_generate_key(
    session: &HsmSession,
    props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    // HMAC key generation is TBOR-only; MBOR has no `HmacGenerateKey`.
    if !session.is_ex() {
        return Err(HsmError::UnsupportedKeyOperation);
    }

    let key_label = props.label();
    if key_label.len() > TBOR_KEY_LABEL_MAX_LEN {
        return Err(HsmError::InvalidKeyProps);
    }
    // Fixed canonical key length for the SHA variant (validated by
    // `HsmHmacKey::validate_props`: 256/384/512 bits -> 32/48/64 B).
    let key_length = u8::try_from(props.bits() / 8).map_err(|_| HsmError::InvalidKeyProps)?;
    let req = TborHmacGenerateKeyReq {
        session_id: session.ex_session_id()?,
        scope: props.tbor_scope(),
        hash_algo: hmac_hash_for_kind(props.kind())?,
        key_length,
        key_label: key_label.to_vec(),
    };
    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    let key_props = HsmMaskedKey::to_key_props(&resp.masked_key)?;
    if !props.validate_dev_props(&key_props) {
        return Err(HsmError::InvalidKeyProps);
    }
    Ok((ddi::HsmKeyHandle::Unpinned, key_props))
}

/// Maps the HMAC key kind to its TBOR `HashAlgo` discriminant (the SHA
/// variant / PRF).
fn hmac_hash_for_kind(kind: HsmKeyKind) -> HsmResult<u8> {
    match kind {
        HsmKeyKind::HmacSha256 => Ok(HMAC_HASH_SHA256),
        HsmKeyKind::HmacSha384 => Ok(HMAC_HASH_SHA384),
        HsmKeyKind::HmacSha512 => Ok(HMAC_HASH_SHA512),
        _ => Err(HsmError::InvalidKeyProps),
    }
}
