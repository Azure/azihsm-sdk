// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// DDI Get Collateral Type
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiGetCollateralType {
    /// Attestation key certificate (virtual and physical manticore)
    AKCert = 1,

    /// Intermediate certificate (physical manticore only)
    CertChainLen = 2,

    /// cert_num field in the request should be set to the cert ID. (physical manticore only)
    CertId = 3,

    /// TEE report (virtual manticore only)
    TeeReport = 4,
}

/// DDI Get Collateral Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCollateralReq {
    /// Input data (Type)
    #[ddi(id = 1)]
    pub collateral_type: DdiGetCollateralType,

    /// Cert Id (for CertId collateral type)
    #[ddi(id = 2)]
    pub cert_id: Option<u8>,
}

/// DDI Get Collateral Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCollateralResp {
    /// Number of certificates in the chain
    #[ddi(id = 1)]
    pub num_certs: Option<u8>,

    /// Output data (Collateral)
    #[ddi(id = 2)]
    pub collateral: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiGetCollateral);
