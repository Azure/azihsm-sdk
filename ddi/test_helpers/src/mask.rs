// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub fn helper_unmask_key(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    masked_key: MborByteArray<3072>,
) -> Result<DdiUnmaskKeyCmdResp, DdiError> {
    let req = DdiUnmaskKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::UnmaskKey,
            sess_id,
            rev,
        },
        data: DdiUnmaskKeyReq { masked_key },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_new_key_id_from_unmask(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    try_to_unmask_first: bool,
    masked_key: MborByteArray<3072>,
) -> Result<(u16, Option<u16>, Option<DdiDerPublicKey>), DdiError> {
    if try_to_unmask_first {
        // Try to unmask this key, it should fail because the key tag already exists
        let resp = helper_unmask_key(dev, sess_id, rev, masked_key);

        assert!(resp.is_err(), "resp {:?}", resp);
    }

    // Delete that key
    let resp = helper_delete_key(dev, sess_id, rev, key_id);

    assert!(resp.is_ok(), "resp {:?}", resp);

    // Import that key with masked key (Unmask this key)
    let resp = helper_unmask_key(dev, sess_id, rev, masked_key);

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();

    Ok((resp.data.key_id, resp.data.bulk_key_id, resp.data.pub_key))
}
