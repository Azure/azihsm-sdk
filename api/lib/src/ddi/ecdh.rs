// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

/// ECDH Key derive operation
pub(crate) fn ecdh_key_derive(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    priv_key_id: u16,
    pub_key_der: &[u8],
    key_tag: Option<u16>,
    key_type: DdiKeyType,
    key_usage: DdiKeyUsage,
    key_availability: DdiKeyAvailability,
    key_label: Option<&[u8]>,
) -> Result<DdiEcdhKeyExchangeCmdResp, DdiError> {
    // Perform Ecdh exchange for each pair
    //prepare key properties
    let key_props = DdiKeyProperties {
        key_usage,
        key_availability,
        key_label: match key_label {
            Some(label) => MborByteArray::from_slice(label)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,

            None => MborByteArray::from_slice(&[])
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
        },
    };

    let req = DdiEcdhKeyExchangeCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EcdhKeyExchange,
            sess_id,
            rev,
        },
        data: DdiEcdhKeyExchangeReq {
            priv_key_id,
            pub_key_der: MborByteArray::from_slice(pub_key_der)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
            key_tag,
            key_type,
            key_properties: key_props
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
