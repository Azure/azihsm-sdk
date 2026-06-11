// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `ChangePsk` wire schema.
//!
//! Changes the active session's own partition PSK to a new value
//! supplied encrypted inside an AEAD-GCM envelope under the session's
//! `param_key`.
//!
//! ## Authorization — implicit, "self-only"
//!
//! The target slot is **always** derived from the session role; the
//! request carries no slot-selection field:
//!
//! * Crypto Officer session (slot 0, Authenticated) → changes the CO
//!   PSK.
//! * Crypto User session (slot 1..=7, PlainText) → changes the CU
//!   PSK.
//!
//! This removes any cross-role rotation matrix: each role is the only
//! principal that can alter its own credentials.  Recovery of a lost
//! credential is out of scope for this command and is delegated to an
//! admin-side reset path (or factory reset).
//!
//! ## Replay model
//!
//! Cross-session replay is structurally impossible: `param_key` is
//! HPKE-derived per session, so a captured envelope cannot decrypt
//! under a different session's key (the AEAD tag fails before any
//! plaintext is produced).
//!
//! Intra-session replay is bounded to **one successful change per
//! session**: a second `ChangePsk` on the same session is rejected
//! with [`HsmError::InvalidPermissions`].
//!
//! ## AEAD envelope contents
//!
//! Wrapped by [`azihsm_fw_core_crypto_aead_envelope`] (AES-256-GCM)
//! under the active session's `param_key`:
//!
//! * **AAD** (wire-embedded, **32 bytes**, authenticated plaintext —
//!   length pinned to satisfy the AEAD crate's 32-byte AAD
//!   granularity):
//!     * `"psk-change-v1"` (13 B) — domain/version label.
//!     * `session_id` (2 B little-endian) — defense-in-depth binding
//!       to the active session (replay protection comes from the
//!       per-session `param_key`).
//!     * reserved-zero (17 B) — padding to 32 B.
//! * **Plaintext**: exactly 32 bytes (`PSK_LEN`); HSM rejects with
//!   `InvalidArgument` if length differs after decrypt.

use azihsm_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `ChangePsk`.
pub const TBOR_OP_CHANGE_PSK: u8 = 0x20;

/// Domain/version label embedded in the AEAD envelope's AAD.
pub const PSK_CHANGE_AAD_LABEL: &[u8; 13] = b"psk-change-v1";

/// Length of the AAD bound into the AEAD envelope.
///
/// Pinned to 32 B to satisfy
/// [`azihsm_fw_core_crypto_aead_envelope`]'s AAD-granularity
/// invariant.  Layout: `label(13) ‖ session_id(2 LE) ‖ rsv0(17)`.
pub const PSK_CHANGE_AAD_LEN: usize = 32;

/// Maximum bytes the wrapped `psk_envelope` may occupy on the wire.
///
/// AEAD-GCM envelope around a 32-byte plaintext with a 32-byte AAD:
/// `header(8) + iv(12) + aad(32) + ct(32) + tag(16)` = 100 B.
/// Rounded up to 160 to leave headroom.
pub const PSK_CHANGE_ENVELOPE_MAX_LEN: usize = 160;

/// `ChangePsk` request schema.
///
/// The new PSK value is delivered encrypted inside `psk_envelope`; the
/// HSM authenticates and decrypts under the active session's
/// `param_key`.  The target PSK slot is derived from the session role
/// (CO session → CO slot, CU session → CU slot); there is no
/// slot-selection field on the wire.
#[tbor(opcode = 0x20)]
pub struct TborChangePskReq<'a> {
    /// Logical session id the request is bound to.  Pulled out as a
    /// TOC field (`#[tbor(session_id)]`) for parity with MBOR and
    /// `CloseSession`; the FW handler must also see this value as
    /// part of the AEAD AAD.
    #[tbor(session_id)]
    pub session_id: u16,

    /// AEAD envelope wrapping the 32-byte new PSK under the active
    /// session's `param_key`.  See module docs for AAD layout.
    ///
    /// Marked `#[tbor(mutable)]` so the FW handler can AEAD-open the
    /// envelope in place — the field is exposed as the
    /// `psk_envelope` member of the generated
    /// `TborChangePskReqViewMut` destructured view.
    #[tbor(max_len = 160, mutable)]
    pub psk_envelope: &'a [u8],
}

/// `ChangePsk` response schema (empty acknowledgement; status
/// lives in the TBOR response header).
#[tbor(response)]
pub struct TborChangePskResp;

/// Builds the 32-byte AEAD AAD bound into a `ChangePsk` envelope.
///
/// Layout: [`PSK_CHANGE_AAD_LABEL`] (13 B) `‖ session_id` (2 B LE)
/// `‖ rsv0` (17 B).
///
/// This is the **single source of truth** for the AAD layout — both
/// the firmware handler and the host wrapper construct envelopes via
/// this helper to guarantee they stay byte-for-byte identical.
#[must_use]
pub fn build_psk_change_aad(session_id: u16) -> [u8; PSK_CHANGE_AAD_LEN] {
    let mut aad = [0u8; PSK_CHANGE_AAD_LEN];
    aad[..PSK_CHANGE_AAD_LABEL.len()].copy_from_slice(PSK_CHANGE_AAD_LABEL);
    aad[PSK_CHANGE_AAD_LABEL.len()..PSK_CHANGE_AAD_LABEL.len() + 2]
        .copy_from_slice(&session_id.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_layout_label_then_session_id_le_then_zero_padding() {
        let aad = build_psk_change_aad(0x1234);
        assert_eq!(&aad[..13], PSK_CHANGE_AAD_LABEL);
        assert_eq!(&aad[13..15], &0x1234u16.to_le_bytes());
        assert!(aad[15..].iter().all(|&b| b == 0));
    }

    #[test]
    fn aad_const_len_matches_array() {
        assert_eq!(build_psk_change_aad(0).len(), PSK_CHANGE_AAD_LEN);
        assert_eq!(PSK_CHANGE_AAD_LEN, 32);
    }
}
