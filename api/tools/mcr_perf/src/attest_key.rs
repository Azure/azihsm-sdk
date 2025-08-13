// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_attest_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    report_data: &[u8; 128],
) -> DdiResult<()> {
    let req = DdiAttestKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::AttestKey,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiAttestKeyReq {
            key_id,
            report_data: MborByteArray::new(*report_data, 128)
                .expect("failed to create byte array"),
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|_| ())
}
