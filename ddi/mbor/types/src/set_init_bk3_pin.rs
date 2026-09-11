// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_mbor_derive::Ddi;

use crate::*;

/// DDI Set Init BK3 PIN Request Structure (FIPS BK3 secure provisioning, Phase 2)
///
/// Carries the encrypted (id, pin) credential and the host ephemeral public key.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSetInitBk3PinReq {
    /// Encrypted credential (encrypted id, encrypted pin, iv, nonce, tag)
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedEstablishCredential,

    /// Host ephemeral Public Key (ECC 384)
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,
}

/// DDI Set Init BK3 PIN Response Structure
///
/// Empty acknowledgement; the operation is one-shot per partition.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSetInitBk3PinResp {}

ddi_op_req_resp!(DdiSetInitBk3Pin);
