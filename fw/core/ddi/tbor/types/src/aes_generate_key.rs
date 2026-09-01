// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesGenerateKey` wire schema.
//!
//! `AesGenerateKey` is an in-session command that generates a fresh random
//! AES key (128 / 192 / 256 bits) and returns it as a **masked** blob.
//! The key is **not** stored on the device: the caller holds the masked
//! blob and passes it back to
//! [`AesEncryptDecrypt`](crate::aes_encrypt_decrypt) to transform data
//! (unmask-on-use), exactly like the masked HMAC key.  This is the TBOR
//! analogue of MBOR `AesGenerateKey`, but without a vault `key_id` /
//! `key_tag`: nothing is persisted on-device.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `scope` — the requested key [`KeyScope`] (lifecycle / visibility
//!   domain), carried as its 1-byte discriminant.  Selects which masking
//!   key wraps the returned blob.
//! * `key_size` — the [`AesKeySize`] selecting the AES key length
//!   (128 / 192 / 256 → 16 / 24 / 32 B).
//!
//! Outputs:
//!
//! * `masked_key` — the freshly generated AES key, masked (AEAD-GCM-256)
//!   under the requested scope's masking key.  Its length depends on the
//!   key size: [`MASKED_AES_KEY_MIN_LEN`] (148 B, AES-128) …
//!   [`MASKED_AES_KEY_MAX_LEN`] (164 B, AES-256).

use azihsm_fw_ddi_tbor_api::tbor;
use open_enum::open_enum;

use crate::key_props::KeyScope;

/// TBOR opcode for `AesGenerateKey`.
pub const TBOR_OP_AES_GENERATE_KEY: u8 = 0x15;

/// Minimum masked AES-key envelope length (AES-128, 16-byte key): an
/// AEAD-GCM-256 masked-key envelope `header(8) ‖ iv(12) ‖ aad(96) ‖
/// pt(16) ‖ tag(16)`.  Lower bound of the masked-key output.
pub const MASKED_AES_KEY_MIN_LEN: usize = 8 + 12 + 96 + 16 + 16;

/// Maximum masked AES-key envelope length (AES-256, 32-byte key): the same
/// envelope with a 32-byte plaintext.  Pinned into the `#[tbor(buffer,
/// max_len = 164)]` literal on [`TborAesGenerateKeyResp::masked_key`].
pub const MASKED_AES_KEY_MAX_LEN: usize = 8 + 12 + 96 + 32 + 16;

/// AES key-size selector on the TBOR wire.
///
/// The 1-byte discriminants mirror the non-bulk MBOR `DdiAesKeySize`
/// values (`Aes128 = 1`, `Aes192 = 2`, `Aes256 = 3`).  Kept as an
/// [`open_enum`] so an unrecognized discriminant round-trips as
/// `AesKeySize(x)` and is rejected on-device rather than failing to
/// decode.  The XTS / GCM bulk variants are intentionally absent — like
/// MBOR `AesGenerateKey`, only non-bulk keys are generated here.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeySize {
    /// AES-128: 16-byte key.
    Aes128 = 1,

    /// AES-192: 24-byte key.
    Aes192 = 2,

    /// AES-256: 32-byte key.
    Aes256 = 3,
}

/// `AesGenerateKey` request schema.
///
/// Generates a random AES key of the requested [`AesKeySize`] under the
/// active session's partition, masked with the requested [`KeyScope`]'s
/// masking key.
#[tbor(opcode = 0x15)]
pub struct TborAesGenerateKeyReq<'a> {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (lifecycle / visibility domain), carried as
    /// the 1-byte [`KeyScope`] discriminant.
    #[tbor(U8)]
    pub scope: KeyScope,

    /// AES key size (and thus key length), carried as the 1-byte
    /// [`AesKeySize`] discriminant.
    #[tbor(U8)]
    pub key_size: AesKeySize,

    /// Caller-supplied key label recorded in the masked blob's
    /// `MaskedKeyMetadata.key_label`, up to [`KEY_LABEL_MAX`] bytes.
    /// Empty for an unlabeled key.
    #[tbor(buffer, max_len = 32)]
    pub key_label: &'a [u8],
}

/// `AesGenerateKey` response schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can reserve the slot
/// (via `masked_key_reserve`) and mask the generated key straight into it
/// (`decode_mut`) — no scratch buffer and no copy.
#[tbor(response)]
pub struct TborAesGenerateKeyResp<'a> {
    /// The freshly generated AES key, masked (AEAD-GCM-256) under the
    /// requested scope's masking key.  148 / 156 / 164 B for
    /// AES-128 / 192 / 256.  The key is not stored on the device; the
    /// caller passes this blob back to `AesEncryptDecrypt`.
    #[tbor(buffer, max_len = 164, mutable)]
    pub masked_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_scope_and_size() {
        let mut buf = [0u8; 256];
        let label = b"my-aes-key";
        let frame = TborAesGenerateKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(5))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .key_size(AesKeySize::Aes256)
            .unwrap()
            .key_label(label)
            .unwrap()
            .finish();

        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.key_size(), AesKeySize::Aes256);
        assert_eq!(frame.key_label(), label);
    }

    #[test]
    fn response_round_trips_masked_key() {
        let mut buf = [0u8; 512];
        let masked = [0xABu8; MASKED_AES_KEY_MAX_LEN];
        let frame = TborAesGenerateKeyResp::encode(&mut buf, 0, true)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
    }

    #[test]
    fn masked_key_lengths_match_pinned_values() {
        // The `#[tbor(buffer, max_len = N)]` attribute must remain a
        // numeric literal; pin it against the exported const.
        const _: () = assert!(164 == MASKED_AES_KEY_MAX_LEN);
        assert_eq!(MASKED_AES_KEY_MIN_LEN, 148);
        assert_eq!(MASKED_AES_KEY_MAX_LEN, 164);
    }
}
