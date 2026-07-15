// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `KeyReport` wire schema.
//!
//! `KeyReport` is an in-session command that takes a **masked key**
//! (e.g. the `masked_key` returned by
//! [`SdSealingKeyGen`](crate::sd_sealing_key_gen)), unmasks it, derives
//! the attested key's public component on-device, and returns a signed
//! COSE_Sign1 key-attestation report over it. The report is signed by the
//! partition-identity (PID) key — the same signer as the `PartInit` PTA
//! report.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `masked_key` — the masked-key envelope to attest, as produced by a
//!   masking command. Variable length (the plaintext size depends on the
//!   key kind) up to [`KEY_REPORT_MASKED_KEY_MAX_LEN`].
//! * `report_data` — caller-supplied [`KEY_REPORT_DATA_LEN`] (128 B) data
//!   bound into the report payload (typically a freshness nonce or a
//!   challenge digest).
//!
//! Outputs:
//!
//! * `report` — the tagged COSE_Sign1 key-attestation report. Variable
//!   length up to [`KEY_REPORT_MAX_LEN`].

use azihsm_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `KeyReport`.
///
/// `0x0A..=0x0F` are reserved by the Security-Domain backup schema family
/// (`SdCreateRemoteBackup` .. `SdRestorePeerBackup`), so `KeyReport`
/// takes the next free opcode, `0x10`.
pub const TBOR_OP_KEY_REPORT: u8 = 0x10;

/// Maximum wire length of the `masked_key` request buffer.
///
/// A masked-key envelope is `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(N) ‖
/// tag(16)` = `132 + N`, where `N` is the raw key plaintext (48 B for a
/// P-384 sealing scalar). The command currently attests only ECC-private
/// kinds; this bound is sized generously to leave headroom for larger
/// key kinds (e.g. symmetric or larger curves) without a wire change.
/// Pinned into the `#[tbor(buffer, max_len = 512)]` literal on
/// [`TborKeyReportReq::masked_key`].
pub const KEY_REPORT_MASKED_KEY_MAX_LEN: usize = 512;

/// Length of the caller-supplied `report_data` field bound into the
/// report payload. Pinned into the `#[tbor(buffer, len = 128)]` literal
/// on [`TborKeyReportReq::report_data`].
pub const KEY_REPORT_DATA_LEN: usize = 128;

/// Maximum wire length of the returned COSE_Sign1 `report`. The command
/// currently attests ECC-private keys (P-256/384/521 COSE_Key); this
/// bound carries headroom for a future largest case (a 4096-bit RSA
/// COSE_Key) so the wire size need not change if RSA attestation is
/// later added. Pinned into the `#[tbor(buffer, max_len = 1024)]`
/// literal on [`TborKeyReportResp::report`].
pub const KEY_REPORT_MAX_LEN: usize = 1024;

/// `KeyReport` request schema.
///
/// Attests the key carried by `masked_key`, binding `report_data` into
/// the signed report payload.
#[tbor(opcode = 0x10)]
pub struct TborKeyReportReq<'a> {
    /// CO/CU session id this request is bound to. The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked-key envelope to attest. Variable length up to
    /// [`KEY_REPORT_MASKED_KEY_MAX_LEN`].
    #[tbor(buffer, max_len = 512)]
    pub masked_key: &'a [u8],

    /// Caller-supplied [`KEY_REPORT_DATA_LEN`] (128 B) report data bound
    /// into the report payload.
    #[tbor(buffer, len = 128)]
    pub report_data: &'a [u8],
}

/// `KeyReport` response schema.
#[tbor(response)]
pub struct TborKeyReportResp<'a> {
    /// The tagged COSE_Sign1 key-attestation report, signed by the PID
    /// key. Variable length up to [`KEY_REPORT_MAX_LEN`].
    #[tbor(buffer, max_len = 1024)]
    pub report: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_masked_key_and_report_data() {
        let mut buf = [0u8; 1024];
        let masked = [0xCDu8; 180];
        let report_data = [0xABu8; KEY_REPORT_DATA_LEN];
        let frame = TborKeyReportReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .report_data(&report_data)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.report_data(), &report_data[..]);
    }

    #[test]
    fn response_round_trips_report() {
        let mut buf = [0u8; 1024];
        let report = [0x5Au8; 300];
        let frame = TborKeyReportResp::encode(&mut buf, 0, false)
            .unwrap()
            .report(&report)
            .unwrap()
            .finish();
        assert_eq!(frame.report(), &report[..]);
    }

    #[test]
    fn schema_lengths_match_pinned_values() {
        // The `#[tbor(... len)]` attributes must remain numeric literals;
        // pin them against the exported consts.
        const _: () = assert!(512 == KEY_REPORT_MASKED_KEY_MAX_LEN);
        const _: () = assert!(128 == KEY_REPORT_DATA_LEN);
        const _: () = assert!(1024 == KEY_REPORT_MAX_LEN);
        assert_eq!(TBOR_OP_KEY_REPORT, 0x10);
    }
}
