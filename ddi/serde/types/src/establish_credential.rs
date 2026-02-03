// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Get Param Encryption Key Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEstablishCredentialReq {
    /// Encrypted credential
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedEstablishCredential,

    /// Public Key (ECC 384)
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,

    /// Masked BK3
    #[ddi(id = 3)]
    pub masked_bk3: MborByteArray<1024>,

    /// Backed up Masked Key, if available
    #[ddi(id = 4)]
    pub bmk: MborByteArray<1024>,

    /// Masked unwrapping key, if available
    #[ddi(id = 5)]
    pub masked_unwrapping_key: MborByteArray<1024>,

    /// Partition ID signed by the TPM
    #[ddi(id = 6)]
    pub signed_pid: MborByteArray<1024>,

    /// TPM Public Key
    #[ddi(id = 7)]
    pub tpm_pub_key: DdiDerPublicKey,
}

/// DDI Get Param Encryption Key Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEstablishCredentialResp {
    /// Backed up Masked Key
    #[ddi(id = 1)]
    pub bmk: MborByteArray<1024>,
}

ddi_op_req_resp!(DdiEstablishCredential);
