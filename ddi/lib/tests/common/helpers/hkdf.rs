// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[allow(unused, clippy::too_many_arguments)]
pub fn helper_hkdf_derive(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    hash_algorithm: DdiHashAlgorithm,
    salt: Option<MborByteArray<256>>,
    info: Option<MborByteArray<256>>,
    // info: Option<mcr_ddi_mbor::MborByteArray<256>>,
    key_type: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> Result<DdiHkdfDeriveCmdResp, DdiError> {
    let req = DdiHkdfDeriveCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::HkdfDerive,
            sess_id,
            rev,
        },
        data: DdiHkdfDeriveReq {
            key_id,
            hash_algorithm,
            salt,
            info,
            key_type,
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
