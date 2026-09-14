// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaVerify` wire schema.
//!
//! `MlDsaVerify` is an in-session command that verifies an ML-DSA
//! (FIPS 204) signature over a host-supplied message under a
//! host-supplied **encoded verifying key**.  It persists nothing and
//! touches no partition state.
//!
//! All three inputs are public values, so — unlike
//! [`MlDsaSign`](crate::ml_dsa_sign) — this command carries no secret.
//!
//! A signature that does not verify is reported as the
//! `MlDsaVerifyFailed` status rather than as a boolean in a successful
//! response, mirroring `EccVerifyFailed`.  A caller that checks only for
//! transport success therefore cannot mistake a bad signature for a good
//! one.  The response is a bare acknowledgement.
//!
//! The parameter set is inferred from the verifying-key length, exactly as
//! [`MlDsaSign`](crate::ml_dsa_sign) infers it from the signing-key length.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `verifying_key` — the FIPS 204 encoded verifying key (`pk`).
//! * `msg` — the message that was signed.
//! * `signature` — the encoded signature to check.
//!
//! Outputs: none — success *is* the verification result.

use azihsm_fw_ddi_tbor_api::tbor;

pub use crate::ml_dsa_sign::ML_DSA_44_SIGNATURE_LEN;
pub use crate::ml_dsa_sign::ML_DSA_44_VERIFYING_KEY_LEN;
pub use crate::ml_dsa_sign::ML_DSA_65_SIGNATURE_LEN;
pub use crate::ml_dsa_sign::ML_DSA_65_VERIFYING_KEY_LEN;
pub use crate::ml_dsa_sign::ML_DSA_MSG_MAX_LEN;

/// TBOR opcode for `MlDsaVerify`.
pub const TBOR_OP_ML_DSA_VERIFY: u8 = 0x21;

/// `MlDsaVerify` request schema.
#[tbor(opcode = 0x21)]
pub struct TborMlDsaVerifyReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The FIPS 204 encoded verifying key (`pk`).  Its length selects the
    /// parameter set: 1312 B → ML-DSA-44, 1952 B → ML-DSA-65.
    #[tbor(buffer, min_len = 1312, max_len = 1952)]
    pub verifying_key: &'a [u8],

    /// The message that was signed, up to [`ML_DSA_MSG_MAX_LEN`] bytes.
    #[tbor(buffer, max_len = 256)]
    pub msg: &'a [u8],

    /// The FIPS 204 encoded signature to check.
    #[tbor(buffer, min_len = 2420, max_len = 3309)]
    pub signature: &'a [u8],
}

/// `MlDsaVerify` response schema — a bare acknowledgement.
///
/// There is no payload by design: a signature that fails to verify is
/// reported as an error status, so a successful response *is* the
/// affirmative result.
#[tbor(response)]
pub struct TborMlDsaVerifyResp;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 8192];
        let pk = [0x11u8; ML_DSA_44_VERIFYING_KEY_LEN];
        let msg = [0x22u8; 64];
        let sig = [0x33u8; ML_DSA_44_SIGNATURE_LEN];
        let frame = TborMlDsaVerifyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .verifying_key(&pk)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .signature(&sig)
            .unwrap()
            .finish();
        assert_eq!(frame.verifying_key().len(), ML_DSA_44_VERIFYING_KEY_LEN);
        assert_eq!(frame.msg(), &msg[..]);
        assert_eq!(frame.signature().len(), ML_DSA_44_SIGNATURE_LEN);
    }
}
