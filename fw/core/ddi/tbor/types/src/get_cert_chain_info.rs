// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetCertChainInfo` wire schema.
//!
//! `GetCertChainInfo` is an **out-of-session** info command — the TBOR
//! analogue of MBOR `GetCertChainInfo`.  The host sends a `slot_id`; the
//! firmware responds with the number of certificates in that partition
//! slot's chain and the SHA-256 thumbprint of the leaf certificate.  The
//! thumbprint lets the host detect chain rotation without downloading
//! every certificate.  No session is required.
//!
//! Inputs:
//!
//! * `slot_id` — the certificate chain slot within the caller's
//!   partition (e.g. slot 0 = identity chain).
//!
//! Outputs:
//!
//! * `num_certs` — number of certificates in the chain; valid indices for
//!   [`GetCertificate`](crate::get_cert) are `0..num_certs`.
//! * `thumbprint` — SHA-256 thumbprint of the leaf certificate, exactly
//!   [`CERT_THUMBPRINT_LEN`] (32) bytes.

use azihsm_fw_ddi_tbor_api::tbor;

use crate::tbor_int::U8;

/// TBOR opcode for `GetCertChainInfo`.
pub const TBOR_OP_GET_CERT_CHAIN_INFO: u8 = 0x1E;

/// Length of the leaf-certificate SHA-256 thumbprint in bytes.  Pinned
/// into the `#[tbor(buffer, len = 32)]` literal on
/// [`TborGetCertChainInfoResp::thumbprint`].
pub const CERT_THUMBPRINT_LEN: usize = 32;

/// `GetCertChainInfo` request schema.
#[tbor(opcode = 0x1E)]
pub struct TborGetCertChainInfoReq {
    /// Certificate chain slot within the caller's partition.
    #[tbor(U8)]
    pub slot_id: u8,
}

/// `GetCertChainInfo` response schema.
#[tbor(response)]
pub struct TborGetCertChainInfoResp<'a> {
    /// Number of certificates in the chain.  Valid `GetCertificate`
    /// indices are `0..num_certs`.
    pub num_certs: U8,

    /// SHA-256 thumbprint of the leaf certificate, exactly
    /// [`CERT_THUMBPRINT_LEN`] (32) bytes.
    #[tbor(buffer, len = 32)]
    pub thumbprint: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn request_round_trips_slot_id() {
        let mut buf = [0u8; 64];
        let frame = TborGetCertChainInfoReq::encode(&mut buf)
            .unwrap()
            .slot_id(3)
            .unwrap()
            .finish();
        assert_eq!(frame.slot_id(), 3);
    }

    #[test]
    fn response_round_trips_fields() {
        let mut buf = [0u8; 128];
        let thumbprint = [0x5Au8; CERT_THUMBPRINT_LEN];
        let frame = TborGetCertChainInfoResp::encode(&mut buf, 0, false)
            .unwrap()
            .num_certs(4)
            .unwrap()
            .thumbprint(&thumbprint)
            .unwrap()
            .finish();
        assert_eq!(frame.num_certs(), 4);
        assert_eq!(frame.thumbprint(), &thumbprint[..]);
    }

    #[test]
    fn thumbprint_len_matches_pinned_value() {
        const _: () = assert!(32 == CERT_THUMBPRINT_LEN);
        assert_eq!(CERT_THUMBPRINT_LEN, 32);
    }
}
