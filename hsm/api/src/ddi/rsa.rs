#![warn(missing_docs)]
// Copyright (C) Microsoft Corporation. All rights reserved.

//! RSA cryptographic DDI operations
//!
//! This module provides functions for generating RSA key pairs, encrypting and decrypting data,
//! and signing and verifying messages using RSA keys.

use super::*;

pub(crate) fn rsa_get_unwrapping_key(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetUnwrappingKeyCmdResp, DdiError> {
    let req = DdiGetUnwrappingKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetUnwrappingKey,
            sess_id,
            rev,
        },
        data: DdiGetUnwrappingKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub(crate) struct DdiRsaUnwrapParams {
    // key ID
    pub key_id: u16,
    // wrapped blob key class
    pub key_class: DdiKeyClass,
    // wrapped blob padding
    pub padding: DdiRsaCryptoPadding,
    //Hash algorithm
    pub hash_algo: DdiHashAlgorithm,
    // key tag
    pub key_tag: Option<u16>,
    // optional label
    pub label: Option<Vec<u8>>,
    // key usage
    pub key_usage: DdiKeyUsage,
    /// Key Availability
    pub key_availability: DdiKeyAvailability,
}

pub(crate) fn rsa_unwrap_key(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    params: DdiRsaUnwrapParams,
    wrapped_blob: &[u8],
) -> Result<DdiRsaUnwrapCmdResp, DdiError> {
    // check if wrapped blob is empty or > MBOR size
    const MAX_WRAPPED_BLOB_SIZE: usize = 3072;
    if wrapped_blob.is_empty() || wrapped_blob.len() > MAX_WRAPPED_BLOB_SIZE {
        Err(DdiError::InvalidParameter)?;
    }
    let key_props = DdiKeyProperties {
        key_usage: params.key_usage,
        key_availability: params.key_availability,
        key_label: MborByteArray::from_slice(params.label.as_deref().unwrap_or(&[]))
            .expect("Failed to create empty byte array for key label"),
    };

    let req = DdiRsaUnwrapCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RsaUnwrap,
            sess_id,
            rev,
        },
        data: DdiRsaUnwrapReq {
            key_id: params.key_id,
            wrapped_blob: MborByteArray::from_slice(wrapped_blob)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
            wrapped_blob_key_class: params.key_class,
            wrapped_blob_padding: params.padding,
            wrapped_blob_hash_algorithm: params.hash_algo,
            key_tag: params.key_tag,
            key_properties: key_props
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

fn rsa_mod_exp_sign(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    op_type: DdiRsaOpType,
    y: &[u8],
) -> Result<DdiRsaModExpCmdResp, DdiError> {
    // check if y is empty or > MBOR size
    const MAX_Y_SIZE: usize = 512;
    if y.is_empty() || y.len() > MAX_Y_SIZE {
        Err(DdiError::InvalidParameter)?;
    }
    let y_array =
        MborByteArray::from_slice(y).map_err(|_| DdiError::MborError(MborError::EncodeError))?;
    let req = DdiRsaModExpCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RsaModExp,
            sess_id,
            rev,
        },
        data: DdiRsaModExpReq {
            key_id,
            y: y_array,
            op_type,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
pub(crate) fn rsa_sign(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    digest: &[u8],
) -> Result<DdiRsaModExpCmdResp, DdiError> {
    rsa_mod_exp_sign(dev, sess_id, rev, key_id, DdiRsaOpType::Sign, digest)
}
pub(crate) fn rsa_decrypt(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    ciphertext: &[u8],
) -> Result<DdiRsaModExpCmdResp, DdiError> {
    rsa_mod_exp_sign(dev, sess_id, rev, key_id, DdiRsaOpType::Decrypt, ciphertext)
}
