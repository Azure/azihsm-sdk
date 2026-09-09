// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetCertificate` wire schema.
//!
//! `GetCertificate` is an **out-of-session** command — the TBOR analogue
//! of MBOR `GetCertificate`.  The host sends a `(slot_id, cert_id)` pair;
//! the firmware responds with the DER-encoded X.509 certificate at that
//! index of the partition slot's chain.  By convention index `0` is the
//! leaf and the last index is the root
//! (see [`GetCertChainInfo`](crate::get_cert_chain_info) for the chain
//! length).  No session is required.
//!
//! Inputs:
//!
//! * `slot_id` — the certificate chain slot within the caller's
//!   partition.
//! * `cert_id` — zero-based certificate index; must satisfy
//!   `cert_id < num_certs` from `GetCertChainInfo` for the same slot.
//!
//! Outputs:
//!
//! * `certificate` — the DER-encoded X.509 certificate, up to
//!   [`CERT_MAX_LEN`] (2048) bytes.

use azihsm_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `GetCertificate`.
pub const TBOR_OP_GET_CERTIFICATE: u8 = 0x1F;

/// Maximum DER-encoded certificate length in bytes.  Pinned into the
/// `#[tbor(buffer, max_len = 2048)]` literal on
/// [`TborGetCertResp::certificate`]; mirrors the MBOR
/// `DdiGetCertificateResp` bound.
pub const CERT_MAX_LEN: usize = 2048;

/// `GetCertificate` request schema.
#[tbor(opcode = 0x1F)]
pub struct TborGetCertReq {
    /// Certificate chain slot within the caller's partition.
    #[tbor(U8)]
    pub slot_id: u8,

    /// Zero-based certificate index; `0` is the leaf, the last index is
    /// the root.
    #[tbor(U8)]
    pub cert_id: u8,
}

/// `GetCertificate` response schema.
///
/// `certificate` is `#[tbor(mutable)]` so the handler can reserve the
/// slot (via `certificate_reserve`) and have the PAL copy the DER bytes
/// straight into it (`decode_mut`) — no scratch buffer and no copy.
#[tbor(response)]
pub struct TborGetCertResp<'a> {
    /// The DER-encoded X.509 certificate, up to [`CERT_MAX_LEN`] (2048)
    /// bytes.
    #[tbor(buffer, max_len = 2048, mutable)]
    pub certificate: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 64];
        let frame = TborGetCertReq::encode(&mut buf)
            .unwrap()
            .slot_id(1)
            .unwrap()
            .cert_id(2)
            .unwrap()
            .finish();
        assert_eq!(frame.slot_id(), 1);
        assert_eq!(frame.cert_id(), 2);
    }

    #[test]
    fn response_round_trips_certificate() {
        let mut buf = [0u8; 512];
        let cert = [0xC7u8; 300];
        let frame = TborGetCertResp::encode(&mut buf, 0, false)
            .unwrap()
            .certificate(&cert)
            .unwrap()
            .finish();
        assert_eq!(frame.certificate(), &cert[..]);
    }

    #[test]
    fn cert_max_len_matches_pinned_value() {
        const _: () = assert!(2048 == CERT_MAX_LEN);
        assert_eq!(CERT_MAX_LEN, 2048);
    }
}
