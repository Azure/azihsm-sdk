// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_ecdh_key_exchange(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    priv_key_id: u16,
    pub_key_der: MborByteArray<192>,
    key_tag: Option<u16>,
    key_type: DdiKeyType,
    key_properties: DdiKeyProperties,
) -> Result<DdiEcdhKeyExchangeCmdResp, DdiError> {
    // Perform Ecdh exchange for each pair
    let req = DdiEcdhKeyExchangeCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EcdhKeyExchange,
            sess_id,
            rev,
        },
        data: DdiEcdhKeyExchangeReq {
            priv_key_id,
            pub_key_der,
            key_tag,
            key_type,
            key_properties,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
