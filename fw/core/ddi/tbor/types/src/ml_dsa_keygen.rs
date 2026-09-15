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
//! # Why the seed, not the expanded key
//!
//! The reply carries the 32-byte **seed**, not the 4032-byte expanded
//! signing key. The response path is capped at one 4 KiB page — measured: a
//! 4032 + 1952 B reply comes back with the trailing 1904 bytes of the
//! verifying key zeroed — so the expanded form does not fit at ML-DSA-65.
//! The seed is the private key in FIPS 204's own seed form and a host can
//! expand it cheaply, so nothing is lost by sending the smaller of the two
//! representations.
//!
//! Outputs:
//!
//! * `seed` — the 32-byte FIPS 204 key-generation seed.
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
    /// The 32-byte FIPS 204 key-generation seed. Expanding it yields the
    /// signing key; this is private key material.
    #[tbor(buffer, min_len = 32, max_len = 32, mutable)]
    pub seed: &'a [u8],

    /// The FIPS 204 encoded verifying key: 1312 B at ML-DSA-44, 1952 B at
    /// ML-DSA-65.
    #[tbor(buffer, min_len = 1312, max_len = 1952, mutable)]
    pub verifying_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The largest reply must clear the response path's 4 KiB cap.
    ///
    /// Pinned because exceeding it does not fail cleanly: the reply is
    /// silently truncated, which showed up as a keypair whose verifying key
    /// was mostly zeros.
    #[test]
    fn worst_case_response_fits_one_page() {
        const MAX_RESPONSE: usize = 4096;
        let mut buf = [0u8; MAX_RESPONSE];
        let seed = [0u8; 32];
        let pk = [0u8; ML_DSA_65_VERIFYING_KEY_LEN];
        TborMlDsaKeyGenResp::encode(&mut buf, 0, false)
            .unwrap()
            .seed(&seed)
            .unwrap()
            .verifying_key(&pk)
            .unwrap();
    }
}
