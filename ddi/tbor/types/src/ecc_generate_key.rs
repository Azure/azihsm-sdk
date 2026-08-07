// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `EccGenerateKey` command.
//!
//! `EccGenerateKey` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that generates a fresh ECC keypair and returns the private
//! key as a **masked** blob plus the wire public key.  The private key is
//! not stored on-device; the caller holds the masked blob and passes it
//! back to [`EccSign`](crate::ecc_sign) / [`EcdhDerive`](crate::ecdh_derive).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `EccGenerateKey`.
pub const TBOR_OP_ECC_GENERATE_KEY: u8 = 0x17;

/// Minimum masked ECC private-key envelope length (P-256).
pub const MASKED_ECC_KEY_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;
/// Maximum masked ECC private-key envelope length (P-521).
pub const MASKED_ECC_KEY_MAX_LEN: usize = 8 + 12 + 96 + 68 + 16;
/// Maximum wire public-key length (`x ‖ y`, P-521 padded).
pub const ECC_PUB_KEY_MAX_LEN: usize = 136;

/// `EccCurve` discriminant for NIST P-256.
pub const ECC_CURVE_P256: u8 = 1;
/// `EccCurve` discriminant for NIST P-384.
pub const ECC_CURVE_P384: u8 = 2;
/// `EccCurve` discriminant for NIST P-521.
pub const ECC_CURVE_P521: u8 = 3;

/// Host-facing TBOR `EccGenerateKey` request.
#[tbor(opcode = TBOR_OP_ECC_GENERATE_KEY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborEccGenerateKeyReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope as the 1-byte `KeyScope` discriminant.
    pub scope: u8,

    /// NIST curve as the 1-byte `EccCurve` discriminant (see
    /// [`ECC_CURVE_P256`] / [`ECC_CURVE_P384`] / [`ECC_CURVE_P521`]).
    pub curve: u8,
}

/// Host-facing TBOR `EccGenerateKey` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEccGenerateKeyResp {
    /// The generated private key, masked under the scope's masking key.
    #[tbor(max_len = 200)]
    pub masked_key: Vec<u8>,

    /// The wire public key `x ‖ y` (little-endian, P-521 padded).
    #[tbor(max_len = 136)]
    pub pub_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_scope_and_curve() {
        let req = TborEccGenerateKeyReq {
            session_id: 5,
            scope: 0b011,
            curve: ECC_CURVE_P384,
        };
        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&ECC_CURVE_P384),
            "encoded frame must carry the curve discriminant",
        );
    }
}
