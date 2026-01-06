// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_rsa_unwrap(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    wrapped_blob: MborByteArray<3072>,
    wrapped_blob_key_class: DdiKeyClass,
    wrapped_blob_padding: DdiRsaCryptoPadding,
    wrapped_blob_hash_algorithm: DdiHashAlgorithm,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> Result<DdiRsaUnwrapCmdResp, DdiError> {
    let req = DdiRsaUnwrapCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RsaUnwrap,
            sess_id,
            rev,
        },
        data: DdiRsaUnwrapReq {
            key_id,
            wrapped_blob,
            wrapped_blob_key_class,
            wrapped_blob_padding,
            wrapped_blob_hash_algorithm,
            key_tag,
            key_properties: key_properties
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_rsa_mod_exp(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    y: MborByteArray<512>,
    op_type: DdiRsaOpType,
) -> Result<DdiRsaModExpCmdResp, DdiError> {
    let req = DdiRsaModExpCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RsaModExp,
            sess_id,
            rev,
        },
        data: DdiRsaModExpReq { key_id, y, op_type },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_rsa_mod_exp_op(
    dev: &<AzihsmDdi as Ddi>::Dev,
    op: DdiOp,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    y: MborByteArray<512>,
    op_type: DdiRsaOpType,
) -> Result<DdiRsaModExpCmdResp, DdiError> {
    let req = DdiRsaModExpCmdReq {
        hdr: DdiReqHdr { op, sess_id, rev },
        data: DdiRsaModExpReq { key_id, y, op_type },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
