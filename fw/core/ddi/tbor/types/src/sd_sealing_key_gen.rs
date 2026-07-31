// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdSealingKeyGen` wire schema.
//!
//! `SdSealingKeyGen` is an in-session command that generates a new
//! security-domain sealing key and returns it as a masked private-key
//! blob plus the public key.  The private key is not stored on the
//! device (see Outputs below).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `scope` — the requested key [`KeyScope`] (lifecycle / visibility
//!   domain), carried as its 1-byte [`open_enum`](open_enum::open_enum)
//!   discriminant.  Mirrors the firmware
//!   [`HsmKeyScope`](azihsm_fw_hsm_pal_traits::HsmKeyScope).
//!
//! Outputs:
//!
//! * `masked_key` — the new sealing key's ECC-P384 **private** half,
//!   masked (AEAD-GCM-256) under the requested scope's masking key, as a
//!   fixed [`MASKED_SEALING_KEY_LEN`] (180 B) envelope.  The private key
//!   is **not** stored on the device: the caller holds the masked blob
//!   and re-imports it (unmask-on-use) when the key is later needed.
//! * `pub_key` — the raw P-384 public key of the new sealing key: the
//!   `x ‖ y` affine coordinates (96 bytes, little-endian per coordinate)
//!   as emitted by the PAL.  This is the bare coordinate pair, **not** a
//!   SEC1 point encoding (no `0x04` prefix).  The caller uses it as the
//!   ECDH peer for ECIES-style seal / unseal.

use azihsm_fw_ddi_tbor_api::tbor;

use crate::key_props::KeyScope;

/// TBOR opcode for `SdSealingKeyGen`.
pub const TBOR_OP_SD_SEALING_KEY_GEN: u8 = 0x09;

/// Wire length of the returned sealing public key: a raw P-384 point
/// (`x ‖ y`, 48 + 48 bytes).  Pinned into the `#[tbor(buffer, len =
/// 96)]` literal on [`TborSdSealingKeyGenResp::pub_key`] (see the
/// `pub_key_len_matches_pinned_value` test).
pub const SD_SEALING_PUB_KEY_LEN: usize = 96;

/// Wire length of the masked sealing private key: an AEAD-GCM-256
/// masked-key envelope (`header(8) ‖ iv(12) ‖ aad(96) ‖ pt(48) ‖
/// tag(16)`) whose plaintext is the 48-byte raw P-384 private scalar and
/// whose AAD is the 96-byte `MaskedKeyMetadata`.  Pinned into the
/// `#[tbor(buffer, len = 180)]` literal on
/// [`TborSdSealingKeyGenResp::masked_key`].
pub const MASKED_SEALING_KEY_LEN: usize = 8 + 12 + 96 + 48 + 16;

/// `SdSealingKeyGen` request schema.
///
/// Generates a security-domain sealing key under the active session's
/// partition with the caller-supplied [`KeyScope`].
#[tbor(opcode = 0x09)]
pub struct TborSdSealingKeyGenReq {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (lifecycle / visibility domain). Carried as
    /// the 1-byte [`KeyScope`] discriminant.
    #[tbor(U8)]
    pub scope: KeyScope,
}

/// `SdSealingKeyGen` response schema.
#[tbor(response)]
pub struct TborSdSealingKeyGenResp<'a> {
    /// The new sealing key's ECC-P384 private half, masked (AEAD-GCM-256)
    /// under the requested scope's masking key.  Always exactly
    /// [`MASKED_SEALING_KEY_LEN`] (180 B).  The private key is not stored
    /// on the device; the caller re-imports this blob when needed.
    #[tbor(buffer, len = 180)]
    pub masked_key: &'a [u8],

    /// Raw P-384 public key (`x ‖ y` affine coordinates, 96 bytes,
    /// little-endian per coordinate) of the new sealing key, as emitted
    /// by the PAL.  Not a SEC1 point encoding (no `0x04` prefix).
    #[tbor(buffer, len = 96)]
    pub pub_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_scope() {
        let mut buf = [0u8; 256];
        let frame = TborSdSealingKeyGenReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .scope(KeyScope::SecurityDomain)
            .unwrap()
            .finish();

        // The wire carries the 1-byte scope discriminant.
        assert_eq!(frame.scope(), KeyScope::SecurityDomain);
    }

    #[test]
    fn response_round_trips_masked_key_and_pub_key() {
        let mut buf = [0u8; 512];
        let masked = [0xCDu8; MASKED_SEALING_KEY_LEN];
        let pub_key = [0xABu8; SD_SEALING_PUB_KEY_LEN];
        let frame = TborSdSealingKeyGenResp::encode(&mut buf, 0, true)
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
    fn response_lengths_match_pinned_values() {
        // The `#[tbor(buffer, len = N)]` attributes must remain numeric
        // literals; pin them against the exported consts.
        const _: () = assert!(96 == SD_SEALING_PUB_KEY_LEN);
        const _: () = assert!(180 == MASKED_SEALING_KEY_LEN);
        assert_eq!(SD_SEALING_PUB_KEY_LEN, 96);
        assert_eq!(MASKED_SEALING_KEY_LEN, 180);
    }
}
