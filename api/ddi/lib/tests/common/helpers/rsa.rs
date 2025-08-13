// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_rsa_unwrap(
    dev: &<DdiTest as Ddi>::Dev,
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
            key_properties,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
