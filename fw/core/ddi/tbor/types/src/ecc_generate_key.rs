// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EccGenerateKey` wire schema.
//!
//! `EccGenerateKey` is an in-session command that generates a fresh ECC
//! keypair on the requested NIST curve (P-256 / P-384 / P-521) and returns
//! the private key as a **masked** blob plus the wire public key.  The
//! private key is **not** stored on the device: the caller holds the
//! masked blob and passes it back to [`EccSign`](crate::ecc_sign) /
//! [`EcdhDerive`](crate::ecdh_derive) (unmask-on-use).  This is the TBOR
//! analogue of MBOR `EccGenerateKeyPair`, but without a vault `key_id`.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `scope` — the [`KeyScope`] whose masking key wraps the private key.
//! * `curve` — the [`EccCurve`] selecting the NIST curve.
//!
//! Outputs:
//!
//! * `masked_key` — the private key, masked (AEAD-GCM-256) under the
//!   scope's masking key.
//! * `pub_key` — the wire public key `x ‖ y` (little-endian, P-521 padded).

use azihsm_fw_ddi_tbor_api::tbor;
use open_enum::open_enum;

use crate::key_props::KeyScope;

/// TBOR opcode for `EccGenerateKey`.
pub const TBOR_OP_ECC_GENERATE_KEY: u8 = 0x17;

/// Minimum masked ECC private-key envelope length (P-256, 32-byte scalar):
/// `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(32) ‖ tag(16)`.
pub const MASKED_ECC_KEY_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;

/// Maximum masked ECC private-key envelope length (P-521, 68-byte
/// wire scalar).  Pinned into the `#[tbor(buffer, max_len = 200)]` literal
/// on [`TborEccGenerateKeyResp::masked_key`].
pub const MASKED_ECC_KEY_MAX_LEN: usize = 8 + 12 + 96 + 68 + 16;

/// Maximum wire public-key length (`x ‖ y`, P-521 padded coordinates).
/// Pinned into the `#[tbor(buffer, max_len = 136)]` literal on
/// [`TborEccGenerateKeyResp::pub_key`].
pub const ECC_PUB_KEY_MAX_LEN: usize = 136;

/// ECC curve selector on the TBOR wire.
///
/// The 1-byte discriminants mirror the MBOR `DdiEccCurve` values
/// (`P256 = 1`, `P384 = 2`, `P521 = 3`).  Kept as an [`open_enum`] so an
/// unrecognized discriminant round-trips as `EccCurve(x)` and is rejected
/// on-device rather than failing to decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    /// NIST P-256 (secp256r1).
    P256 = 1,

    /// NIST P-384 (secp384r1).
    P384 = 2,

    /// NIST P-521 (secp521r1).
    P521 = 3,
}

/// `EccGenerateKey` request schema.
#[tbor(opcode = 0x17)]
pub struct TborEccGenerateKeyReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the private key), 1-byte [`KeyScope`].
    #[tbor(U8)]
    pub scope: KeyScope,

    /// NIST curve, 1-byte [`EccCurve`].
    #[tbor(U8)]
    pub curve: EccCurve,
}

/// `EccGenerateKey` response schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can reserve the slot
/// and mask the private key straight into it (`decode_mut`) — no scratch
/// copy of the masked blob.
#[tbor(response)]
pub struct TborEccGenerateKeyResp<'a> {
    /// The generated private key, masked (AEAD-GCM-256) under the scope's
    /// masking key.  164 / 180 / 200 B for P-256 / P-384 / P-521.
    #[tbor(buffer, max_len = 200, mutable)]
    pub masked_key: &'a [u8],

    /// The wire public key `x ‖ y` (little-endian, P-521 padded):
    /// 64 / 96 / 136 B for P-256 / P-384 / P-521.
    #[tbor(buffer, max_len = 136)]
    pub pub_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_scope_and_curve() {
        let mut buf = [0u8; 256];
        let frame = TborEccGenerateKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(5))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .curve(EccCurve::P384)
            .unwrap()
            .finish();

        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.curve(), EccCurve::P384);
    }

    #[test]
    fn response_round_trips_masked_and_pub() {
        let mut buf = [0u8; 512];
        let masked = [0xABu8; MASKED_ECC_KEY_MAX_LEN];
        let pub_key = [0xCDu8; ECC_PUB_KEY_MAX_LEN];
        let frame = TborEccGenerateKeyResp::encode(&mut buf, 0, true)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.pub_key(), &pub_key[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(200 == MASKED_ECC_KEY_MAX_LEN);
        const _: () = assert!(136 == ECC_PUB_KEY_MAX_LEN);
        assert_eq!(MASKED_ECC_KEY_MIN_LEN, 164);
        assert_eq!(MASKED_ECC_KEY_MAX_LEN, 200);
    }
}
