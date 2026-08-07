// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EcdhDerive` wire schema.
//!
//! `EcdhDerive` is an in-session command that derives an ECDH shared
//! secret from a caller-held **masked** local ECC private key (from
//! [`EccGenerateKey`](crate::ecc_generate_key) or imported via
//! [`UnwrapKey`](crate::unwrap_key)) and a host-supplied peer public key,
//! and returns the derived secret as a **masked** blob under the requested
//! scope's masking key.  This is the TBOR analogue of MBOR
//! `EcdhKeyExchange`, but re-masking the secret instead of vaulting it.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `scope` — the [`KeyScope`] whose masking key wraps the derived secret.
//! * `masked_key` — the masked local ECC private key (unmasked in place;
//!   its kind recovers the curve).
//! * `peer_pub_key` — the peer's wire public key `x ‖ y` (little-endian,
//!   P-521 padded), exactly the curve's wire public-key length.
//!
//! Outputs:
//!
//! * `masked_secret` — the derived ECDH shared secret, masked
//!   (AEAD-GCM-256) under the scope's masking key.

use azihsm_fw_ddi_tbor_api::tbor;

pub use crate::ecc_generate_key::MASKED_ECC_KEY_MAX_LEN;
pub use crate::ecc_generate_key::MASKED_ECC_KEY_MIN_LEN;
use crate::key_props::KeyScope;

/// TBOR opcode for `EcdhDerive`.
pub const TBOR_OP_ECDH_DERIVE: u8 = 0x19;

/// Maximum peer public-key length (`x ‖ y`, P-521 padded).  Pinned into the
/// `#[tbor(buffer, max_len = 136)]` literal on
/// [`TborEcdhDeriveReq::peer_pub_key`].
pub const ECDH_PEER_PUB_MAX_LEN: usize = 136;

/// Minimum masked derived-secret envelope length (P-256, 32-byte secret):
/// `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(32) ‖ tag(16)`.
pub const MASKED_SECRET_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;

/// Maximum masked derived-secret envelope length (P-521, 66-byte secret).
/// Pinned into the `#[tbor(buffer, max_len = 198)]` literal on
/// [`TborEcdhDeriveResp::masked_secret`].
pub const MASKED_SECRET_MAX_LEN: usize = 8 + 12 + 96 + 66 + 16;

/// `EcdhDerive` request schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can `unmask` the local
/// key **in place** in the request buffer (via `decode_mut`) — no scratch
/// copy — and derive directly from the recovered key.
#[tbor(opcode = 0x19)]
pub struct TborEcdhDeriveReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the derived secret), 1-byte [`KeyScope`].
    #[tbor(U8)]
    pub scope: KeyScope,

    /// The masked local ECC private key (from `EccGenerateKey` /
    /// `UnwrapKey`), an AEAD-GCM-256 envelope of 164..=200 B.  Its kind
    /// recovers the curve.
    #[tbor(buffer, min_len = 164, max_len = 200, mutable)]
    pub masked_key: &'a [u8],

    /// The peer's wire public key `x ‖ y` (little-endian, P-521 padded),
    /// exactly the curve's wire public-key length (64 / 96 / 136 B).
    #[tbor(buffer, max_len = 136)]
    pub peer_pub_key: &'a [u8],
}

/// `EcdhDerive` response schema.
///
/// `masked_secret` is `#[tbor(mutable)]` so the handler can reserve the
/// slot and mask the derived secret straight into it (`decode_mut`).
#[tbor(response)]
pub struct TborEcdhDeriveResp<'a> {
    /// The derived ECDH shared secret, masked (AEAD-GCM-256) under the
    /// scope's masking key.  164 / 180 / 198 B for P-256 / P-384 / P-521.
    #[tbor(buffer, max_len = 198, mutable)]
    pub masked_secret: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 512];
        let masked = [0x11u8; MASKED_ECC_KEY_MIN_LEN];
        let peer = [0x22u8; 64];
        let frame = TborEcdhDeriveReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .peer_pub_key(&peer)
            .unwrap()
            .finish();
        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.peer_pub_key(), &peer[..]);
    }

    #[test]
    fn response_round_trips_masked_secret() {
        let mut buf = [0u8; 256];
        let masked = [0x33u8; MASKED_SECRET_MAX_LEN];
        let frame = TborEcdhDeriveResp::encode(&mut buf, 0, true)
            .unwrap()
            .masked_secret(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_secret(), &masked[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(136 == ECDH_PEER_PUB_MAX_LEN);
        const _: () = assert!(198 == MASKED_SECRET_MAX_LEN);
        assert_eq!(MASKED_SECRET_MIN_LEN, 164);
        assert_eq!(MASKED_SECRET_MAX_LEN, 198);
    }
}
