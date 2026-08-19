// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `GetCertificate` command.
//!
//! `GetCertificate` is an **out-of-session** command — the TBOR analogue
//! of MBOR `GetCertificate`. The host sends a `(slot_id, cert_id)` pair;
//! the firmware responds with the DER-encoded X.509 certificate at that
//! index of the partition slot's chain. By convention index `0` is the
//! leaf and the last index is the root (see
//! [`GetCertChainInfo`](crate::get_cert_chain_info) for the chain length).
//! No session is required.
//!
//! Both the request and response wire schemas are shared with the
//! firmware handler via `azihsm_fw_ddi_tbor_types::get_cert`
//! (`fw/core/ddi/tbor/types/src/get_cert.rs`); this module adds the
//! host-facing value types so [`exec_op_tbor`] returns owned response
//! values rather than borrowing `View<'a>` accessors.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `GetCertificate`.
pub const TBOR_OP_GET_CERTIFICATE: u8 = 0x1F;

/// Maximum DER-encoded certificate length in bytes.
pub const CERT_MAX_LEN: usize = 2048;

/// Host-facing TBOR `GetCertificate` request.
#[tbor(opcode = TBOR_OP_GET_CERTIFICATE, session_ctrl = no_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborGetCertReq {
    /// Certificate chain slot within the caller's partition.
    pub slot_id: u8,

    /// Zero-based certificate index; `0` is the leaf, the last index is
    /// the root.
    pub cert_id: u8,
}

impl TborGetCertReq {
    /// Construct a `GetCertificate` request for `(slot_id, cert_id)`.
    #[inline]
    pub const fn new(slot_id: u8, cert_id: u8) -> Self {
        Self { slot_id, cert_id }
    }
}

/// Host-facing TBOR `GetCertificate` response.
///
/// Field order mirrors the firmware schema in
/// `azihsm_fw_ddi_tbor_types::get_cert`; the two MUST stay in sync
/// so the TOC layouts match.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborGetCertResp {
    /// The DER-encoded X.509 certificate, up to `CERT_MAX_LEN` (2048) B.
    #[tbor(max_len = 2048)]
    pub certificate: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborGetCertReq::new(1, 2);
        let mut buf = [0u8; 64];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&1u8) && frame.contains(&2u8),
            "encoded frame must carry the slot and cert ids",
        );
    }
}
