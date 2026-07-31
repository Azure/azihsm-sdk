// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `HmacGenerateKey` wire schema.
//!
//! `HmacGenerateKey` is an in-session command that generates a fresh
//! random HMAC key of the caller-selected SHA variant and returns it as a
//! masked-key blob.  The key is **not** stored on the device: the caller
//! holds the masked blob and passes it back to [`Hmac`](crate::hmac) to
//! compute a MAC (unmask-on-use), exactly like the security-domain
//! sealing key.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `scope` — the requested key [`KeyScope`] (lifecycle / visibility
//!   domain), carried as its 1-byte discriminant.  Selects which masking
//!   key wraps the returned blob.
//! * `hash_algo` — the [`HashAlgo`] selecting the HMAC SHA variant, which
//!   selects the HMAC PRF and the per-variant valid key-length range.
//! * `key_length` — the requested key length in bytes.  HMAC keys are
//!   variable-length ([`HsmVaultKeyKind::VarLenHmacSha256`] etc.); the
//!   value must fall in the SHA variant's `[min, max]` range
//!   (SHA-256: 32–64, SHA-384: 48–128, SHA-512: 64–128 — matching the
//!   reference firmware's `VarLenHmacSha*` bounds), else the handler
//!   rejects it with `InvalidKeyLength`.
//!
//! Outputs:
//!
//! * `masked_key` — the freshly generated HMAC key, masked (AEAD-GCM-256)
//!   under the requested scope's masking key.  Its length depends on the
//!   requested `key_length`: [`MASKED_HMAC_KEY_MIN_LEN`] (164 B, 32-byte
//!   key) … [`MASKED_HMAC_KEY_MAX_LEN`] (260 B, 128-byte key).

use azihsm_fw_ddi_tbor_api::tbor;

use crate::key_props::HashAlgo;
use crate::key_props::KeyScope;

/// TBOR opcode for `HmacGenerateKey`.
pub const TBOR_OP_HMAC_GENERATE_KEY: u8 = 0x11;

/// Minimum masked HMAC-key envelope length (32-byte key, the SHA-256
/// minimum): an AEAD-GCM-256 masked-key envelope `header(8) ‖ iv(12) ‖
/// aad(96) ‖ pt(32) ‖ tag(16)`.  Lower bound of the `#[tbor(buffer,
/// max_len = 260)]` masked-key output.
pub const MASKED_HMAC_KEY_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;

/// Maximum masked HMAC-key envelope length (128-byte key, the SHA-384 /
/// SHA-512 maximum): the same envelope with a 128-byte plaintext.  Pinned
/// into the `#[tbor(buffer, max_len = 260)]` literal on
/// [`TborHmacGenerateKeyResp::masked_key`].
pub const MASKED_HMAC_KEY_MAX_LEN: usize = 8 + 12 + 96 + 128 + 16;

/// `HmacGenerateKey` request schema.
///
/// Generates a random variable-length HMAC key of the requested
/// [`HashAlgo`] and `key_length` under the active session's partition,
/// masked with the requested [`KeyScope`]'s masking key.
#[tbor(opcode = 0x11)]
pub struct TborHmacGenerateKeyReq {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (lifecycle / visibility domain), carried as
    /// the 1-byte [`KeyScope`] discriminant.
    #[tbor(U8)]
    pub scope: KeyScope,

    /// Hash algorithm selecting the HMAC SHA variant (the PRF and the
    /// valid `key_length` range), carried as the 1-byte [`HashAlgo`]
    /// discriminant.
    #[tbor(U8)]
    pub hash_algo: HashAlgo,

    /// Requested key length in bytes.  HMAC keys are variable-length; the
    /// value must be in the SHA variant's range (SHA-256: 32–64,
    /// SHA-384: 48–128, SHA-512: 64–128), else the handler returns
    /// `InvalidKeyLength`.
    #[tbor(U8)]
    pub key_length: u8,
}

/// `HmacGenerateKey` response schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can reserve the slot
/// (via `masked_key_reserve`) and mask the generated key straight into it
/// (`decode_mut`) — no scratch buffer and no copy.
#[tbor(response)]
pub struct TborHmacGenerateKeyResp<'a> {
    /// The freshly generated HMAC key, masked (AEAD-GCM-256) under the
    /// requested scope's masking key.  `132 + key_length` B (164 … 260 B
    /// for a 32 … 128-byte key).  The key is not stored on the device;
    /// the caller passes this blob back to `Hmac`.
    #[tbor(buffer, max_len = 260, mutable)]
    pub masked_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_scope_and_hash() {
        let mut buf = [0u8; 256];
        let frame = TborHmacGenerateKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(5))
            .unwrap()
            .scope(KeyScope::Session)
            .unwrap()
            .hash_algo(HashAlgo::Sha384)
            .unwrap()
            .key_length(96)
            .unwrap()
            .finish();

        assert_eq!(frame.scope(), KeyScope::Session);
        assert_eq!(frame.hash_algo(), HashAlgo::Sha384);
        assert_eq!(frame.key_length(), 96);
    }

    #[test]
    fn response_round_trips_masked_key() {
        let mut buf = [0u8; 512];
        let masked = [0xABu8; MASKED_HMAC_KEY_MAX_LEN];
        let frame = TborHmacGenerateKeyResp::encode(&mut buf, 0, true)
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
        const _: () = assert!(260 == MASKED_HMAC_KEY_MAX_LEN);
        assert_eq!(MASKED_HMAC_KEY_MIN_LEN, 164);
        assert_eq!(MASKED_HMAC_KEY_MAX_LEN, 260);
    }
}
