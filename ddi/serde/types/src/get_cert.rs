// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Get Cert Chain Info Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCertChainInfoReq {
    /// Slot Id
    #[ddi(id = 1)]
    pub slot_id: u8,
}

/// DDI Get Cert Chain Info Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCertChainInfoResp {
    /// Number of certificates in the chain
    #[ddi(id = 1)]
    pub num_certs: u8,

    /// Hash of the certificate chain
    #[ddi(id = 2)]
    pub thumbprint: MborByteArray<32>,
}

ddi_op_req_resp!(DdiGetCertChainInfo);

/// DDI Get Certificate Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCertificateReq {
    /// Slot Id
    #[ddi(id = 1)]
    pub slot_id: u8,

    /// Cert Id
    #[ddi(id = 2)]
    pub cert_id: u8,
}

/// DDI Get Certificate Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCertificateResp {
    /// Output data (certificate)
    #[ddi(id = 1)]
    pub certificate: MborByteArray<2048>,
}

ddi_op_req_resp!(DdiGetCertificate);
