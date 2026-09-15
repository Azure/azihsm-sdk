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
//!
//! The signature rides **out of band** as OOB SGL descriptor 0. Inline it
//! does not fit: at ML-DSA-65 the verifying key and signature together are
//! 1952 + 3309 = 5261 B, over the firmware's 4 KiB `MAX_SRC_LEN`. Its length
//! is implied by the parameter set, so no descriptor table is needed.
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

    /// Length in bytes of the signature carried in OOB descriptor 0.
    ///
    /// Declared inline so a signature sized for another parameter set is
    /// rejected with `InvalidArg` before the transfer starts; the GDMA
    /// length-checks the descriptor independently.
    #[tbor(U32)]
    pub signature_len: u32,

    /// The message that was signed, up to [`ML_DSA_MSG_MAX_LEN`] bytes.
    #[tbor(buffer, max_len = 1024)]
    pub msg: &'a [u8],
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
        let frame = TborMlDsaVerifyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .verifying_key(&pk)
            .unwrap()
            .signature_len(ML_DSA_44_SIGNATURE_LEN as u32)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .finish();
        assert_eq!(frame.verifying_key().len(), ML_DSA_44_VERIFYING_KEY_LEN);
        assert_eq!(frame.msg(), &msg[..]);
        // The signature itself rides out of band; only its declared length
        // is on the wire.
        assert_eq!(frame.signature_len(), ML_DSA_44_SIGNATURE_LEN as u32);
    }
}
