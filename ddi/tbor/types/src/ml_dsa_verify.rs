// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlDsaVerify` command.
//!
//! `MlDsaVerify` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that verifies an ML-DSA (FIPS 204) signature over a
//! host-supplied message under a host-supplied **encoded verifying key**.
//! Every input is a public value, so the command carries no secret.
//!
//! A signature that does not verify comes back as the
//! [`TborStatus::MlDsaVerifyFailed`](crate::TborStatus) status rather than
//! as a boolean inside a successful response — a caller that checks only
//! for transport success cannot mistake a bad signature for a good one.
//! The response is a bare acknowledgement.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `MlDsaVerify`.
pub const TBOR_OP_ML_DSA_VERIFY: u8 = 0x21;

/// Host-facing TBOR `MlDsaVerify` request.
#[tbor(opcode = TBOR_OP_ML_DSA_VERIFY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaVerifyReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The FIPS 204 encoded verifying key (`pk`).  Its length selects the
    /// parameter set: 1312 B → ML-DSA-44, 1952 B → ML-DSA-65.
    #[tbor(min_len = 1312, max_len = 2592)]
    pub verifying_key: Vec<u8>,

    /// Length in bytes of the signature passed as OOB SGL item 0.
    pub signature_len: u32,

    /// The message that was signed.
    ///
    /// The signature is **not** carried here — pass it as OOB SGL item 0
    /// (`TestCtx::tbor_oob`). Inline it would not fit the device's 4 KiB
    /// inbound limit at ML-DSA-65.
    #[tbor(max_len = 1024)]
    pub msg: Vec<u8>,
}

/// Host-facing TBOR `MlDsaVerify` response — a bare acknowledgement.
///
/// There is no payload by design: a signature that fails to verify is
/// reported as an error status, so a successful response *is* the
/// affirmative result.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaVerifyResp;
