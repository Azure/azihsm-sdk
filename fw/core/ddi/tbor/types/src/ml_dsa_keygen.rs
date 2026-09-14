// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaKeyGen` wire schema.
//!
//! `MlDsaKeyGen` is an in-session command that generates an ML-DSA
//! (FIPS 204) keypair **on the device**, seeded from hardware entropy, and
//! returns both halves in their wire encodings. It persists nothing and
//! touches no partition state.
//!
//! # Why this fits
//!
//! On-device keygen was originally ruled out as too large. That was wrong,
//! and for two reasons:
//!
//! * Keygen is the *cheaper* operation. It performs one matrix-vector
//!   product; signing expands the same matrix and then performs one per
//!   rejection round. Any build whose signing path fits has already paid
//!   for the larger of the two.
//! * The original figure was measured before large values stopped being
//!   returned through `Result` across call boundaries, which had been
//!   inflating every ML-DSA frame by roughly 3x.
//!
//! It is also the *easiest* command for the transport: the request carries
//! no payload at all, and the reply — 4032 + 1952 B at ML-DSA-65 — fits the
//! 8 KiB outbound limit, unlike `MlDsaVerify`, whose inbound payload
//! exceeds the 4 KiB `MAX_SRC_LEN`.
//!
//! # Proof-of-concept key handling
//!
//! The signing key is returned in the clear rather than masked, matching
//! [`MlDsaSign`](crate::ml_dsa_sign). Generating on-device is strictly
//! better than importing — the private half is never chosen by, or
//! transmitted to, the device — but a production design would mask it here
//! the way [`EccGenerateKey`](crate::ecc_generate_key) does, which needs an
//! ML-DSA key kind in the masking layer.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//!
//! Outputs:
//!
//! * `signing_key` — the FIPS 204 encoded signing key (`sk`).
//! * `verifying_key` — the FIPS 204 encoded verifying key (`pk`).

use azihsm_fw_ddi_tbor_api::tbor;

pub use crate::ml_dsa_sign::ML_DSA_44_SIGNING_KEY_LEN;
pub use crate::ml_dsa_sign::ML_DSA_44_VERIFYING_KEY_LEN;
pub use crate::ml_dsa_sign::ML_DSA_65_SIGNING_KEY_LEN;
pub use crate::ml_dsa_sign::ML_DSA_65_VERIFYING_KEY_LEN;

/// TBOR opcode for `MlDsaKeyGen`.
pub const TBOR_OP_ML_DSA_KEY_GEN: u8 = 0x22;

/// `MlDsaKeyGen` request schema.
#[tbor(opcode = 0x22)]
pub struct TborMlDsaKeyGenReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,
}

/// `MlDsaKeyGen` response schema.
///
/// Both buffers are `#[tbor(mutable)]` so the handler can reserve the slots
/// and have keygen write straight into them — the response buffer is the
/// only copy of the private half.
#[tbor(response)]
pub struct TborMlDsaKeyGenResp<'a> {
    /// The FIPS 204 encoded signing key: 2560 B at ML-DSA-44, 4032 B at
    /// ML-DSA-65.
    #[tbor(buffer, min_len = 2560, max_len = 4032, mutable)]
    pub signing_key: &'a [u8],

    /// The FIPS 204 encoded verifying key: 1312 B at ML-DSA-44, 1952 B at
    /// ML-DSA-65.
    #[tbor(buffer, min_len = 1312, max_len = 1952, mutable)]
    pub verifying_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn response_round_trips_both_halves() {
        let mut buf = [0u8; 8192];
        let sk = [0x11u8; ML_DSA_65_SIGNING_KEY_LEN];
        let pk = [0x22u8; ML_DSA_65_VERIFYING_KEY_LEN];
        let frame = TborMlDsaKeyGenResp::encode(&mut buf, 0, false)
            .unwrap()
            .signing_key(&sk)
            .unwrap()
            .verifying_key(&pk)
            .unwrap()
            .finish();
        assert_eq!(frame.signing_key().len(), ML_DSA_65_SIGNING_KEY_LEN);
        assert_eq!(frame.verifying_key().len(), ML_DSA_65_VERIFYING_KEY_LEN);
    }

    /// The largest reply must clear the firmware's 8 KiB outbound cap.
    #[test]
    fn worst_case_response_fits_max_dst_len() {
        const MAX_DST_LEN: usize = 2 * 4096;
        let mut buf = [0u8; MAX_DST_LEN];
        let sk = [0u8; ML_DSA_65_SIGNING_KEY_LEN];
        let pk = [0u8; ML_DSA_65_VERIFYING_KEY_LEN];
        TborMlDsaKeyGenResp::encode(&mut buf, 0, false)
            .unwrap()
            .signing_key(&sk)
            .unwrap()
            .verifying_key(&pk)
            .unwrap();
    }
}
