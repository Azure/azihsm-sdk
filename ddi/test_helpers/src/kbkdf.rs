// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[allow(unused, clippy::too_many_arguments)]
pub fn helper_kbkdf_derive(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    hash_algorithm: DdiHashAlgorithm,
    label: Option<MborByteArray<256>>,
    context: Option<MborByteArray<256>>,
    // info: Option<azihsm_ddi_mbor::MborByteArray<256>>,
    key_type: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
    key_length: Option<u8>,
) -> Result<DdiKbkdfCounterHmacDeriveCmdResp, DdiError> {
    let req = DdiKbkdfCounterHmacDeriveCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::KbkdfCounterHmacDerive,
            sess_id,
            rev,
        },
        data: DdiKbkdfCounterHmacDeriveReq {
            key_id,
            hash_algorithm,
            label,
            context,
            key_type,
            key_tag,
            key_properties: key_properties
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
            key_length,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
