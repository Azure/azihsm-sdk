// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto::*;

use super::*;

pub fn helper_init_bk3(
    dev: &<AzihsmDdi as Ddi>::Dev,
    bk3: Vec<u8>,
) -> Result<DdiInitBk3CmdResp, DdiError> {
    let req = DdiInitBk3CmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::InitBk3,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiInitBk3Req {
            bk3: MborByteArray::from_slice(&bk3).expect("failed to create byte array"),
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_or_init_bk3(dev: &<AzihsmDdi as Ddi>::Dev) -> MborByteArray<1024> {
    let mut bk3 = vec![0u8; 48];
    Rng::rand_bytes(&mut bk3).unwrap();

    // first check if sealed bk3 is already set. Assuming sealed bk3 = masked bk3
    let resp = helper_get_sealed_bk3(dev);
    if let Ok(result) = resp {
        return result.data.sealed_bk3;
    }

    // if set bk3 is not set, then set it
    let result = helper_init_bk3(dev, bk3);
    assert!(result.is_ok(), "result {:?}", result);
    let masked_bk3 = result.unwrap().data.masked_bk3;

    let result = helper_set_sealed_bk3(dev, masked_bk3.as_slice().to_vec());
    assert!(result.is_ok(), "result {:?}", result);

    masked_bk3
}
