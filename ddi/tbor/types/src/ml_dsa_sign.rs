// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlDsaSign` command.
//!
//! `MlDsaSign` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that produces an ML-DSA (FIPS 204) signature over a
//! host-supplied message using a host-supplied **encoded signing key**.
//!
//! # Proof-of-concept key handling
//!
//! Unlike [`TborEccSignReq`](crate::TborEccSignReq), which carries a
//! **masked** key blob, this command carries the signing key in the
//! clear: ML-DSA key generation does not fit in the device's RAM, so the
//! key is generated on the host and imported per call, and the masking
//! layer has no ML-DSA key kind yet.  The key is protected only by the
//! session transport and is zeroized on-device before the handler
//! returns.  **This is a proof-of-concept path, not a production
//! key-management design.**
//!
//! The parameter set is inferred from the signing-key length, so no
//! separate selector is carried on the wire.  Firmware accepts only the
//! length matching the parameter set it was built with.

use alloc::vec::Vec;

use crate::tbor;

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

/// Host-facing TBOR `MlDsaSign` request.
#[tbor(opcode = TBOR_OP_ML_DSA_SIGN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaSignReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The FIPS 204 encoded signing key (`sk`).  Its length selects the
    /// parameter set: 2560 B → ML-DSA-44, 4032 B → ML-DSA-65.
    #[tbor(min_len = 2560, max_len = 4032)]
    pub signing_key: Vec<u8>,

    /// The message to sign, up to [`ML_DSA_MSG_MAX_LEN`] bytes.
    #[tbor(max_len = 256)]
    pub msg: Vec<u8>,
}

/// Host-facing TBOR `MlDsaSign` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaSignResp {
    /// The FIPS 204 encoded signature: 2420 B for ML-DSA-44, 3309 B for
    /// ML-DSA-65.
    #[tbor(max_len = 3309)]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_message() {
        let req = TborMlDsaSignReq {
            session_id: 7,
            signing_key: alloc::vec![0x11u8; ML_DSA_44_SIGNING_KEY_LEN],
            msg: alloc::vec![0x22u8; 32],
        };
        let mut buf = [0u8; 8192];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x22u8; 4]),
            "encoded frame must carry the message bytes",
        );
    }

    /// Both parameter sets must fit the transport's request buffer.
    ///
    /// The backends encode into an 8 KiB buffer (`REQ_BUF_LEN`), and the
    /// firmware DMA slot is 16 KiB, so the binding limit is this 8 KiB
    /// encode buffer. Pinned as a test because the ML-DSA-65 payloads are
    /// the largest this schema admits and it is not obvious by inspection
    /// that the worst case clears it: a maximal `MlDsaVerify` request
    /// carries 1952 + 3309 B of key and signature before any message.
    #[test]
    fn worst_case_requests_fit_the_transport_buffer() {
        const REQ_BUF_LEN: usize = 8192;

        let sign = TborMlDsaSignReq {
            session_id: 1,
            signing_key: alloc::vec![0xAAu8; ML_DSA_65_SIGNING_KEY_LEN],
            msg: alloc::vec![0xBBu8; ML_DSA_MSG_MAX_LEN],
        };
        let mut buf = [0u8; REQ_BUF_LEN];
        sign.encode_request(&mut buf)
            .expect("a maximal ML-DSA-65 MlDsaSign request must fit REQ_BUF_LEN");

        let verify = crate::TborMlDsaVerifyReq {
            session_id: 1,
            verifying_key: alloc::vec![0xCCu8; ML_DSA_65_VERIFYING_KEY_LEN],
            msg: alloc::vec![0xDDu8; ML_DSA_MSG_MAX_LEN],
            signature: alloc::vec![0xEEu8; ML_DSA_65_SIGNATURE_LEN],
        };
        let mut buf = [0u8; REQ_BUF_LEN];
        verify
            .encode_request(&mut buf)
            .expect("a maximal ML-DSA-65 MlDsaVerify request must fit REQ_BUF_LEN");
    }
}
