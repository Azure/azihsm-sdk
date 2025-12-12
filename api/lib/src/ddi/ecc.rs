// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn ecc_generate_key_pair(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    curve: DdiEccCurve,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> Result<DdiEccGenerateKeyPairCmdResp, DdiError> {
    let req = DdiEccGenerateKeyPairCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EccGenerateKeyPair,
            sess_id,
            rev,
        },
        data: DdiEccGenerateKeyPairReq {
            curve,
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

pub(crate) fn ecc_sign(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    digest: &[u8],
) -> Result<DdiEccSignCmdResp, DdiError> {
    let digest_algo = match digest.len() {
        20 => DdiHashAlgorithm::Sha1,
        32 => DdiHashAlgorithm::Sha256,
        48 => DdiHashAlgorithm::Sha384,
        64 => DdiHashAlgorithm::Sha512,
        _ => Err(DdiError::InvalidParameter)?,
    };

    let req = DdiEccSignCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EccSign,
            sess_id,
            rev,
        },
        data: DdiEccSignReq {
            key_id,
            digest: MborByteArray::from_slice(digest)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
            digest_algo,
        },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
