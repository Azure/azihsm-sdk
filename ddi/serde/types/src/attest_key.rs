// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Generate Attestation Report Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiAttestKeyReq {
    /// Key ID to generate attestation report for
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Report data to be included in the report
    #[ddi(id = 2)]
    pub report_data: MborByteArray<128>,
}

/// DDI Generate Attestation Report Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiAttestKeyResp {
    /// Output data (attestation report)
    #[ddi(id = 1)]
    pub report: MborByteArray<834>,
}

ddi_op_req_resp!(DdiAttestKey);
