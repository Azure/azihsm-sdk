// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `EccSign` command.
//!
//! `EccSign` is an **in-session** command (Crypto-Officer or Crypto-User)
//! that produces a raw ECDSA `r ‖ s` signature over a host-supplied
//! **pre-computed digest** using a caller-held **masked** ECC private key.
//! Firmware does no hashing — the caller supplies the digest in wire
//! little-endian order.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `EccSign`.
pub const TBOR_OP_ECC_SIGN: u8 = 0x18;

/// Maximum digest length (bytes): the SHA-512 digest.
pub const ECC_DIGEST_MAX_LEN: usize = 64;
/// Maximum wire ECDSA signature length (`r ‖ s`, P-521 padded).
pub const ECC_SIG_MAX_LEN: usize = 136;

/// Host-facing TBOR `EccSign` request.
#[tbor(opcode = TBOR_OP_ECC_SIGN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEccSignReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked ECC private key (from `EccGenerateKey` / `UnwrapKey`).
    #[tbor(min_len = 164, max_len = 200)]
    pub masked_key: Vec<u8>,

    /// The pre-computed message digest in wire little-endian order. Its
    /// length must be one of the supported SHA-2 digest lengths
    /// (32 / 48 / 64 B); the hash algorithm is inferred from that length,
    /// so no separate algorithm selector is carried on the wire.
    #[tbor(max_len = 64)]
    pub digest: Vec<u8>,
}

/// Host-facing TBOR `EccSign` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEccSignResp {
    /// Raw ECDSA `r ‖ s`, each component little-endian and padded to the
    /// curve wire coordinate length (64 / 96 / 136 B).
    #[tbor(max_len = 136)]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_digest() {
        let req = TborEccSignReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; 164],
            digest: alloc::vec![0x22u8; 32],
        };
        let mut buf = [0u8; 512];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x22u8; 4]),
            "encoded frame must carry the digest bytes",
        );
    }
}
