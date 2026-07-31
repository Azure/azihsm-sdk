// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `KeyReport` command.
//!
//! `KeyReport` is an **in-session** command that takes a **masked key**
//! (e.g. the `masked_key` returned by `SdSealingKeyGen`), unmasks it,
//! derives the attested key's public component on-device, and returns a
//! signed COSE_Sign1 key-attestation report over it. The report is signed
//! by the partition-identity (PID) key.
//!
//! The request carries the masked-key envelope to attest plus a
//! caller-supplied 128-byte `report_data` bound into the report payload.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `KeyReport`.
///
/// `0x0A..=0x0F` are reserved by the Security-Domain backup schema family
/// (`SdCreateRemoteBackup` .. `SdRestorePeerBackup`), so `KeyReport`
/// takes the next free opcode, `0x10`.
pub const TBOR_OP_KEY_REPORT: u8 = 0x10;

/// Maximum wire length of the `masked_key` request buffer (a masked-key
/// AEAD envelope; the plaintext size depends on the key kind).
pub const KEY_REPORT_MASKED_KEY_MAX_LEN: usize = 512;

/// Length of the caller-supplied `report_data` bound into the report.
pub const KEY_REPORT_DATA_LEN: usize = 128;

/// Maximum wire length of the returned COSE_Sign1 `report`.
pub const KEY_REPORT_MAX_LEN: usize = 1024;

/// Host-facing TBOR `KeyReport` request.
#[tbor(opcode = TBOR_OP_KEY_REPORT, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborKeyReportReq {
    /// Session id this request is bound to. Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked-key envelope to attest. Variable length up to
    /// [`KEY_REPORT_MASKED_KEY_MAX_LEN`].
    #[tbor(max_len = 512)]
    pub masked_key: Vec<u8>,

    /// Caller-supplied [`KEY_REPORT_DATA_LEN`] (128 B) report data.
    pub report_data: [u8; KEY_REPORT_DATA_LEN],
}

/// Host-facing TBOR `KeyReport` response.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborKeyReportResp {
    /// The tagged COSE_Sign1 key-attestation report, signed by the PID
    /// key. Variable length up to [`KEY_REPORT_MAX_LEN`].
    #[tbor(max_len = 1024)]
    pub report: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_and_masked_key() {
        let req = TborKeyReportReq {
            session_id: 9,
            masked_key: alloc::vec![0xCD; 180],
            report_data: [0xAB; KEY_REPORT_DATA_LEN],
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The masked-key bytes must appear in the encoded frame.
        assert!(
            frame.windows(4).any(|w| w == [0xCD; 4]),
            "encoded frame must carry the masked key",
        );
    }
}
