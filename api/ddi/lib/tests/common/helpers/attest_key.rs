// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_sim::report::REPORT_DATA_SIZE;

use super::*;

pub fn helper_attest_key_cmd(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    report_data: [u8; REPORT_DATA_SIZE],
    key_id: u16,
) -> Result<DdiAttestKeyCmdResp, DdiError> {
    let req = DdiAttestKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::AttestKey,
            sess_id,
            rev,
        },
        data: DdiAttestKeyReq {
            key_id,
            report_data: MborByteArray::new(report_data, report_data.len())
                .expect("failed to create byte array"),
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
