// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlDsaKeyGen` command.
//!
//! `MlDsaKeyGen` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that generates an ML-DSA (FIPS 204) keypair **on the
//! device**, seeded from hardware entropy, and returns both halves in their
//! wire encodings.
//!
//! This is strictly better than importing a key with
//! [`TborMlDsaSignReq`](crate::TborMlDsaSignReq): the private half is never
//! chosen by, nor transmitted to, the device. It is still a
//! proof-of-concept path — a production design would return the signing key
//! **masked**, as `EccGenerateKey` does — but the key never crosses the
//! wire inbound.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `MlDsaKeyGen`.
pub const TBOR_OP_ML_DSA_KEY_GEN: u8 = 0x22;

/// Host-facing TBOR `MlDsaKeyGen` request.
#[tbor(opcode = TBOR_OP_ML_DSA_KEY_GEN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaKeyGenReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,
}

/// Host-facing TBOR `MlDsaKeyGen` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaKeyGenResp {
    /// The FIPS 204 encoded signing key: 2560 B at ML-DSA-44, 4032 B at
    /// ML-DSA-65.
    #[tbor(min_len = 2560, max_len = 4032)]
    pub signing_key: Vec<u8>,

    /// The FIPS 204 encoded verifying key: 1312 B at ML-DSA-44, 1952 B at
    /// ML-DSA-65.
    #[tbor(min_len = 1312, max_len = 1952)]
    pub verifying_key: Vec<u8>,
}
