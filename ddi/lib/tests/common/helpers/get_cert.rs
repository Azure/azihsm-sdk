// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

// HSM calculates the cert hashes for Alias and Partition ID certs
// The rest are calculated by HSP
pub const NUM_HSM_CALCULATED_CERT_HASHES: usize = 2;

pub fn helper_get_cert_chain_info(
    dev: &<DdiTest as Ddi>::Dev,
) -> Result<DdiGetCertChainInfoCmdResp, DdiError> {
    let req = DdiGetCertChainInfoCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetCertChainInfo,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetCertChainInfoReq { slot_id: 0 },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_certificate(
    dev: &<DdiTest as Ddi>::Dev,
    cert_id: u8,
) -> Result<DdiGetCertificateCmdResp, DdiError> {
    let req = DdiGetCertificateCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetCertificate,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetCertificateReq {
            slot_id: 0,
            cert_id,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
