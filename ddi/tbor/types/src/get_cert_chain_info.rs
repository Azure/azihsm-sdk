// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `GetCertChainInfo` command.
//!
//! `GetCertChainInfo` is an **out-of-session** info command — the TBOR
//! analogue of MBOR `GetCertChainInfo`. The host sends a `slot_id`; the
//! firmware responds with the number of certificates in that partition
//! slot's chain and the SHA-256 thumbprint of the leaf certificate,
//! without first establishing a session.
//!
//! Both the request and response wire schemas are shared with the
//! firmware handler via `azihsm_fw_ddi_tbor_types::get_cert_chain_info`
//! (`fw/core/ddi/tbor/types/src/get_cert_chain_info.rs`); this module adds
//! the host-facing value types so [`exec_op_tbor`] returns owned response
//! values rather than borrowing `View<'a>` accessors.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use crate::tbor;
use crate::tbor_int::U8;

/// TBOR opcode for `GetCertChainInfo`.
pub const TBOR_OP_GET_CERT_CHAIN_INFO: u8 = 0x1E;

/// Length of the leaf-certificate SHA-256 thumbprint in bytes.
pub const CERT_THUMBPRINT_LEN: usize = 32;

/// Host-facing TBOR `GetCertChainInfo` request.
#[tbor(opcode = TBOR_OP_GET_CERT_CHAIN_INFO, session_ctrl = no_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborGetCertChainInfoReq {
    /// Certificate chain slot within the caller's partition.
    pub slot_id: u8,
}

impl TborGetCertChainInfoReq {
    /// Construct a `GetCertChainInfo` request for `slot_id`.
    #[inline]
    pub const fn new(slot_id: u8) -> Self {
        Self { slot_id }
    }
}

/// Host-facing TBOR `GetCertChainInfo` response.
///
/// Field order mirrors the firmware schema in
/// `azihsm_fw_ddi_tbor_types::get_cert_chain_info`; the two MUST stay in
/// sync so the TOC layouts match.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborGetCertChainInfoResp {
    /// Number of certificates in the chain. Valid `GetCertificate`
    /// indices are `0..num_certs`.
    pub num_certs: U8,

    /// SHA-256 thumbprint of the leaf certificate (32 B).
    pub thumbprint: [u8; CERT_THUMBPRINT_LEN],
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_slot_id() {
        let req = TborGetCertChainInfoReq::new(3);
        let mut buf = [0u8; 64];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(frame.contains(&3u8), "encoded frame must carry the slot id",);
    }
}
