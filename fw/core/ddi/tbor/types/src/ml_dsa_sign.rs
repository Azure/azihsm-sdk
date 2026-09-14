// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaSign` wire schema.
//!
//! `MlDsaSign` is an in-session command that produces an ML-DSA (FIPS 204)
//! signature over a host-supplied message using a host-supplied **encoded
//! signing key**.  It persists nothing and touches no partition state.
//!
//! # Proof-of-concept key handling
//!
//! Unlike [`EccSign`](crate::ecc_sign), which consumes a **masked** key
//! blob, this command takes the signing key in the clear.  ML-DSA key
//! generation does not fit in this part's RAM, so the key is generated on
//! the host and imported per call; there is as yet no ML-DSA key kind in
//! the masking layer to wrap it with.  The key is therefore protected only
//! by the session transport, and is zeroized from the request buffer
//! before the handler returns.  **This is a proof-of-concept path and not
//! a production key-management design.**
//!
//! # Parameter set
//!
//! The parameter set is inferred from the signing-key length rather than
//! carried as a separate selector, mirroring the way
//! [`EccSign`](crate::ecc_sign) infers its hash from the digest length.
//! The schema admits both ML-DSA-44 and ML-DSA-65 so the wire format does
//! not change when the second parameter set is enabled; firmware accepts
//! only the length matching the parameter set it was built with and
//! answers `InvalidArg` otherwise.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `signing_key` — the FIPS 204 encoded signing key (`sk`).
//! * `msg` — the message to sign, up to [`ML_DSA_MSG_MAX_LEN`] bytes.
//!
//! Outputs:
//!
//! * `signature` — the encoded signature, whose length is fixed by the
//!   parameter set.

use azihsm_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `MlDsaSign`.
pub const TBOR_OP_ML_DSA_SIGN: u8 = 0x20;

/// Encoded ML-DSA-44 signing key length (bytes), per FIPS 204.
pub const ML_DSA_44_SIGNING_KEY_LEN: usize = 2560;
/// Encoded ML-DSA-65 signing key length (bytes), per FIPS 204.
pub const ML_DSA_65_SIGNING_KEY_LEN: usize = 4032;

/// Encoded ML-DSA-44 verifying key length (bytes), per FIPS 204.
pub const ML_DSA_44_VERIFYING_KEY_LEN: usize = 1312;
/// Encoded ML-DSA-65 verifying key length (bytes), per FIPS 204.
pub const ML_DSA_65_VERIFYING_KEY_LEN: usize = 1952;

/// Encoded ML-DSA-44 signature length (bytes), per FIPS 204.
pub const ML_DSA_44_SIGNATURE_LEN: usize = 2420;
/// Encoded ML-DSA-65 signature length (bytes), per FIPS 204.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// Maximum message length (bytes) accepted by `MlDsaSign` / `MlDsaVerify`.
///
/// Bounded by the 4 KiB TBOR request buffer rather than by the algorithm.
/// `MlDsaVerify` is the binding case: at ML-DSA-44 its verifying key and
/// signature alone occupy 1312 + 2420 = 3732 B, leaving roughly 300 B for
/// the message and the TOC. A larger message must ride out of band, or be
/// pre-hashed by the caller (HashML-DSA, FIPS 204 5.4).
pub const ML_DSA_MSG_MAX_LEN: usize = 256;

/// `MlDsaSign` request schema.
///
/// `signing_key` is `#[tbor(mutable)]` so the handler can zeroize the
/// imported key in place in the request buffer before returning — the
/// cleartext private key must not outlive the call.
#[tbor(opcode = 0x20)]
pub struct TborMlDsaSignReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The FIPS 204 encoded signing key (`sk`).  Its length selects the
    /// parameter set: 2560 B → ML-DSA-44, 4032 B → ML-DSA-65.
    #[tbor(buffer, min_len = 2560, max_len = 4032, mutable)]
    pub signing_key: &'a [u8],

    /// The message to sign, up to [`ML_DSA_MSG_MAX_LEN`] bytes.
    #[tbor(buffer, max_len = 256)]
    pub msg: &'a [u8],
}

/// `MlDsaSign` response schema.
///
/// `signature` is `#[tbor(mutable)]` so the handler can reserve the slot
/// and write the encoded signature straight into it — no scratch copy.
#[tbor(response)]
pub struct TborMlDsaSignResp<'a> {
    /// The FIPS 204 encoded signature: 2420 B for ML-DSA-44, 3309 B for
    /// ML-DSA-65.
    #[tbor(buffer, max_len = 3309, mutable)]
    pub signature: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 8192];
        let sk = [0x11u8; ML_DSA_44_SIGNING_KEY_LEN];
        let msg = [0x22u8; 64];
        let frame = TborMlDsaSignReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .signing_key(&sk)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .finish();
        assert_eq!(frame.signing_key().len(), ML_DSA_44_SIGNING_KEY_LEN);
        assert_eq!(frame.msg(), &msg[..]);
    }

    #[test]
    fn response_round_trips_signature() {
        let mut buf = [0u8; 8192];
        let sig = [0x33u8; ML_DSA_44_SIGNATURE_LEN];
        let frame = TborMlDsaSignResp::encode(&mut buf, 0, false)
            .unwrap()
            .signature(&sig)
            .unwrap()
            .finish();
        assert_eq!(frame.signature(), &sig[..]);
    }

    #[test]
    fn lengths_match_fips_204() {
        assert_eq!(ML_DSA_44_SIGNING_KEY_LEN, 2560);
        assert_eq!(ML_DSA_44_VERIFYING_KEY_LEN, 1312);
        assert_eq!(ML_DSA_44_SIGNATURE_LEN, 2420);
        assert_eq!(ML_DSA_65_SIGNING_KEY_LEN, 4032);
        assert_eq!(ML_DSA_65_VERIFYING_KEY_LEN, 1952);
        assert_eq!(ML_DSA_65_SIGNATURE_LEN, 3309);
    }
}
