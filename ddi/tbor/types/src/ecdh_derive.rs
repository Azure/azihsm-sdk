// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `EcdhDerive` command.
//!
//! `EcdhDerive` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that derives an ECDH shared secret from a caller-held
//! **masked** local ECC private key and a host-supplied peer public key,
//! and returns the derived secret as a **masked** blob under the requested
//! scope's masking key.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `EcdhDerive`.
pub const TBOR_OP_ECDH_DERIVE: u8 = 0x19;

/// Maximum peer public-key length (`x ‖ y`, P-521 padded).
pub const ECDH_PEER_PUB_MAX_LEN: usize = 136;
/// Minimum masked derived-secret envelope length (P-256).
pub const MASKED_SECRET_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;
/// Maximum masked derived-secret envelope length (P-521).
pub const MASKED_SECRET_MAX_LEN: usize = 8 + 12 + 96 + 66 + 16;

/// Host-facing TBOR `EcdhDerive` request.
#[tbor(opcode = TBOR_OP_ECDH_DERIVE, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEcdhDeriveReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope (masks the derived secret), 1-byte `KeyScope`.
    pub scope: u8,

    /// The masked local ECC private key (from `EccGenerateKey` /
    /// `UnwrapKey`).
    #[tbor(min_len = 164, max_len = 200)]
    pub masked_key: Vec<u8>,

    /// The peer's wire public key `x ‖ y` (little-endian, P-521 padded).
    #[tbor(max_len = 136)]
    pub peer_pub_key: Vec<u8>,
}

/// Host-facing TBOR `EcdhDerive` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEcdhDeriveResp {
    /// The derived ECDH shared secret, masked under the scope's masking
    /// key.
    #[tbor(max_len = 198)]
    pub masked_secret: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_peer_pub() {
        let req = TborEcdhDeriveReq {
            session_id: 7,
            scope: 0b011,
            masked_key: alloc::vec![0x11u8; 164],
            peer_pub_key: alloc::vec![0x22u8; 64],
        };
        let mut buf = [0u8; 512];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x22u8; 4]),
            "encoded frame must carry the peer public-key bytes",
        );
    }
}
