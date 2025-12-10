// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) struct HkdfKeyDeriveParams {
    pub hash_algo: DdiHashAlgorithm,
    pub target_key_type: DdiKeyType,
    pub key_usage: DdiKeyUsage,
    pub key_availability: DdiKeyAvailability,
    pub key_label: Option<Vec<u8>>,
}

/// HKDF Key derive operation
pub(crate) fn hkdf_key_derive(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    secret_key_id: u16,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    key_params: HkdfKeyDeriveParams,
) -> Result<DdiHkdfDeriveCmdResp, DdiError> {
    // prepare key properties
    let key_properties = DdiKeyProperties {
        key_usage: key_params.key_usage,
        key_availability: key_params.key_availability,
        key_label: match &key_params.key_label {
            Some(label) => MborByteArray::from_slice(label)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
            None => MborByteArray::from_slice(&[])
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
        },
    };
    let salt = match salt {
        Some(s) => Some(
            MborByteArray::from_slice(s)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
        ),
        None => None,
    };

    let info = match info {
        Some(i) => Some(
            MborByteArray::from_slice(i)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
        ),
        None => None,
    };

    let req = DdiHkdfDeriveCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::HkdfDerive,
            sess_id,
            rev,
        },
        data: DdiHkdfDeriveReq {
            key_id: secret_key_id,
            hash_algorithm: key_params.hash_algo,
            salt,
            info,
            key_type: key_params.target_key_type,
            key_tag: None,
            key_properties: key_properties
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
