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
pub const ML_DSA_MSG_MAX_LEN: usize = 1024;

/// Host-facing TBOR `MlDsaSign` request.
#[tbor(opcode = TBOR_OP_ML_DSA_SIGN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaSignReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Length in bytes of the signing key passed as OOB SGL item 0.
    pub signing_key_len: u32,

    /// The message to sign, up to [`ML_DSA_MSG_MAX_LEN`] bytes.
    ///
    /// The signing key is **not** carried here — pass it as OOB SGL item 0
    /// (`TestCtx::tbor_oob`). Inline it would not fit the device's 4 KiB
    /// inbound limit.
    #[tbor(max_len = 1024)]
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
            signing_key_len: ML_DSA_44_SIGNING_KEY_LEN as u32,
            msg: alloc::vec![0x22u8; 32],
        };
        let mut buf = [0u8; 8192];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x22u8; 4]),
            "encoded frame must carry the message bytes",
        );
    }

    /// The worst-case **inline** request must fit the firmware's inbound
    /// limit of one 4 KiB page (`MAX_SRC_LEN`), which is stricter than the
    /// backends' 8 KiB encode buffer and is what actually rejects an
    /// oversized request on hardware.
    ///
    /// This is why the signing key and signature ride out of band: with
    /// them inline, ML-DSA-65 `MlDsaVerify` alone is 1952 + 3309 B and
    /// cannot pass. Pinned so that moving a payload back inline fails here
    /// rather than on silicon.
    #[test]
    fn worst_case_inline_requests_fit_max_src_len() {
        const REQ_BUF_LEN: usize = 4096;

        let sign = TborMlDsaSignReq {
            session_id: 1,
            signing_key_len: ML_DSA_65_SIGNING_KEY_LEN as u32,
            msg: alloc::vec![0xBBu8; ML_DSA_MSG_MAX_LEN],
        };
        let mut buf = [0u8; REQ_BUF_LEN];
        sign.encode_request(&mut buf)
            .expect("a maximal ML-DSA-65 MlDsaSign request must fit REQ_BUF_LEN");

        let verify = crate::TborMlDsaVerifyReq {
            session_id: 1,
            signature_len: ML_DSA_65_SIGNATURE_LEN as u32,
            verifying_key: alloc::vec![0xCCu8; ML_DSA_65_VERIFYING_KEY_LEN],
            msg: alloc::vec![0xDDu8; ML_DSA_MSG_MAX_LEN],
        };
        let mut buf = [0u8; REQ_BUF_LEN];
        verify
            .encode_request(&mut buf)
            .expect("a maximal ML-DSA-65 MlDsaVerify request must fit REQ_BUF_LEN");
    }
}
