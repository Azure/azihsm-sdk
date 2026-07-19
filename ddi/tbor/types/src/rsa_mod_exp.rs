// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `RsaModExp` command.
//!
//! `RsaModExp` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that performs the RSA private-key primitive
//! `x = y^d mod n` using a caller-held **masked** RSA private key
//! (imported via [`UnwrapKey`](crate::unwrap_key) with the RSA / RSA-CRT
//! key class).  It is the raw modular exponentiation underlying RSA
//! decrypt / sign — the host applies and removes any padding.  There is no
//! TBOR RSA key generation; RSA keys enter the device only through
//! `UnwrapKey`.
//!
//! `op_type` is a raw 1-byte discriminant (the firmware types it as the
//! `RsaOp` open-enum; this host crate is firewalled from the firmware PAL
//! types).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `RsaModExp`.
pub const TBOR_OP_RSA_MOD_EXP: u8 = 0x1A;

/// Max masked RSA private-key envelope length (RSA-4096-CRT).
pub const RSA_MASKED_KEY_MAX_LEN: usize = 3072;
/// Max RSA modulus length (bytes) — RSA-4096.
pub const RSA_MOD_EXP_MAX_LEN: usize = 512;

/// `RsaOp` discriminant for the RSA decrypt primitive (requires the
/// masked key's `decrypt` usage attribute).
pub const RSA_OP_DECRYPT: u8 = 1;
/// `RsaOp` discriminant for the RSA sign primitive (requires the masked
/// key's `sign` usage attribute).
pub const RSA_OP_SIGN: u8 = 2;

/// Host-facing TBOR `RsaModExp` request.
#[tbor(opcode = TBOR_OP_RSA_MOD_EXP, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborRsaModExpReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked RSA private key (from `UnwrapKey`); its kind recovers the
    /// modulus size and CRT form.
    #[tbor(max_len = 3072)]
    pub masked_key: Vec<u8>,

    /// The private-key operation, 1-byte `RsaOp` (see `RSA_OP_*`): gates on
    /// the masked key's `decrypt` / `sign` usage.
    pub op_type: u8,

    /// The input integer `y` in wire little-endian order, exactly the key's
    /// modulus length (256 / 384 / 512 B).
    #[tbor(max_len = 512)]
    pub y: Vec<u8>,
}

/// Host-facing TBOR `RsaModExp` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborRsaModExpResp {
    /// The result `x = y^d mod n` in wire little-endian order, exactly the
    /// key's modulus length (256 / 384 / 512 B).
    #[tbor(max_len = 512)]
    pub x: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborRsaModExpReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; 400],
            op_type: RSA_OP_SIGN,
            y: alloc::vec![0x22u8; 256],
        };
        let mut buf = [0u8; 4096];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&RSA_OP_SIGN),
            "encoded frame must carry the op-type discriminant",
        );
    }
}
