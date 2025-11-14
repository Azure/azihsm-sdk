#![warn(missing_docs)]
// Copyright (C) Microsoft Corporation. All rights reserved.

//! RSA cryptographic DDI operations
//!
//! This module provides functions for generating RSA key pairs, encrypting and decrypting data,
//! and signing and verifying messages using RSA keys.

use super::*;

pub(crate) fn rsa_get_unwrapping_key(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetUnwrappingKeyCmdResp, DdiError> {
    let req = DdiGetUnwrappingKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetUnwrappingKey,
            sess_id,
            rev,
        },
        data: DdiGetUnwrappingKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
