// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `PskChange` command.
//!
//! Construction of the inner AEAD-GCM envelope is the caller's
//! responsibility: pass the wire-ready envelope bytes (already wrapped
//! under the active session's `param_key`, with the
//! `"psk-change-v1" ‖ session_id` AAD) in `psk_envelope`.  See the FW
//! schema docs at `azihsm_fw_ddi_tbor_types::psk_change` for the
//! AAD layout and the implicit (session-role-driven) target selection.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `PskChange`.
pub const TBOR_OP_PSK_CHANGE: u8 = 0x06;

/// Length in bytes of a partition pre-shared key (PSK).
///
/// Both the CO and CU PSKs are exactly this length.  Mirror of the
/// FW-side `azihsm_fw_hsm_pal_traits::PSK_LEN`.
pub const PSK_LEN: usize = 32;

/// Well-known default Crypto Officer (CO) PSK.
///
/// Mirror of `azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO`.  Returned by
/// the FW for `psk_id = 0` until rotated via `PskChange`.  Public by
/// design so partitions are usable immediately at bring-up.
pub const DEFAULT_PSK_CO: [u8; PSK_LEN] = [
    0x41, 0x5a, 0x49, 0x48, 0x53, 0x4d, 0x2d, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x2d, 0x43,
    0x4f, 0x2d, 0x50, 0x53, 0x4b, 0x2d, 0x76, 0x31, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
];

/// Well-known default Crypto User (CU) PSK.
///
/// Mirror of `azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CU`.
pub const DEFAULT_PSK_CU: [u8; PSK_LEN] = [
    0x41, 0x5a, 0x49, 0x48, 0x53, 0x4d, 0x2d, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x2d, 0x43,
    0x55, 0x2d, 0x50, 0x53, 0x4b, 0x2d, 0x76, 0x31, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
];

/// AAD label prefix bound into the `psk_envelope` AAD.
pub const PSK_CHANGE_AAD_LABEL: &[u8; 13] = b"psk-change-v1";

/// Total AAD length bound into the `psk_envelope` (label + session_id LE + zero-padding).
pub const PSK_CHANGE_AAD_LEN: usize = 32;

/// Maximum on-the-wire length of the `psk_envelope`.
pub const PSK_CHANGE_ENVELOPE_MAX_LEN: usize = 160;

/// Builds the 32-byte AEAD AAD bound into a `PskChange` envelope.
///
/// Layout: [`PSK_CHANGE_AAD_LABEL`] (13 B) `‖ session_id` (2 B LE)
/// `‖ rsv0` (17 B).
///
/// This is the **single source of truth** for the host-side AAD
/// layout; the FW handler builds the identical layout via its own
/// helper of the same name, and a host test cross-validates the two.
#[must_use]
pub fn build_psk_change_aad(session_id: u16) -> [u8; PSK_CHANGE_AAD_LEN] {
    let mut aad = [0u8; PSK_CHANGE_AAD_LEN];
    aad[..PSK_CHANGE_AAD_LABEL.len()].copy_from_slice(PSK_CHANGE_AAD_LABEL);
    aad[PSK_CHANGE_AAD_LABEL.len()..PSK_CHANGE_AAD_LABEL.len() + 2]
        .copy_from_slice(&session_id.to_le_bytes());
    aad
}

/// Host-facing TBOR `PskChange` request.
///
/// The target PSK slot is derived HSM-side from the session role
/// (CO session → CO slot, CU session → CU slot); the request does
/// not carry a slot-selection field.
#[tbor(opcode = TBOR_OP_PSK_CHANGE, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborPskChangeReq {
    /// Logical session id the request is bound to.  Same value must
    /// appear in the AEAD-GCM envelope's AAD; see
    /// [`build_psk_change_aad`].
    #[tbor(session_id)]
    pub session_id: u16,

    /// AEAD-GCM envelope wrapping the 32-byte new PSK under the active
    /// session's `param_key`.
    #[tbor(max_len = 160)]
    pub psk_envelope: Vec<u8>,
}

/// Host-facing TBOR `PskChange` response (empty ack).
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborPskChangeResp;
