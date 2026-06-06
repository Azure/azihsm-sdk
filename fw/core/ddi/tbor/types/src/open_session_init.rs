// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `OpenSessionInit` wire schema (session-establishment Phase 1).
//!
//! Carries the VM's per-handshake ephemeral public key plus the
//! `psk_id` identifying the caller role (`0` = Crypto Officer,
//! `1` = Crypto User).  The response advertises the slot the HSM
//! reserved for the in-flight handshake, the HSM's HPKE-encap
//! response ephemeral, and the Phase-1 confirmation MAC.
//!
//! All byte fields are declared as `&[u8]` slices with `max_len`
//! constraints rather than fixed-size arrays so that handler code
//! can pass and receive slices end-to-end without materializing
//! stack-allocated arrays at any layer.

use azihsm_fw_ddi_tbor_api::tbor;

/// Length of the VM's per-handshake ephemeral public key
/// (HPKE `Npk` for the P-384 KEM: SEC1 uncompressed
/// `0x04 ‖ X ‖ Y` per RFC 9180 §7.1.1, big-endian coordinates).
pub const PK_INIT_LEN: usize = 97;

/// Length of the HSM's HPKE response ephemeral (same `Npk` layout).
pub const PK_RESP_LEN: usize = 97;

/// Length of the Phase-1 confirmation MAC (HMAC-SHA-384).
pub const MAC_RESP_LEN: usize = 48;

/// `OpenSessionInit` request schema.
///
/// Always starts a fresh HPKE handshake bound to the partition
/// identity key and the caller-asserted PSK.  Resume (recovery of
/// a prior session's `masking_key`) is handled separately by the
/// MBOR `ReopenSession` command and is no longer multiplexed onto
/// this opcode.
///
/// The `suite_id` field selects the cryptographic suite used for
/// every subsequent step of the handshake (KEM, KDF, AEAD, MAC).  It
/// is also mixed into the HPKE `info` for transcript binding, so any
/// suite-downgrade attempt by an attacker would produce a different
/// `exported` secret on the HSM and fail the Phase-1 confirm MAC.
/// See [`azihsm_fw_hsm_pal_traits::SessionSuite`] for the wire
/// registry.
#[tbor(opcode = 0x10)]
pub struct TborOpenSessionInitReq<'a> {
    /// PSK identifier asserting the caller role.
    pub psk_id: u8,

    /// Channel-level integrity profile selected by the caller.
    ///
    /// * `0` = `PlainText`  — required for CU (`psk_id = 1`).
    /// * `1` = `Authenticated` — required for CO (`psk_id = 0`).
    ///
    /// Any other value, or a role/type pair other than the two above,
    /// is rejected with `InvalidSessionType`.  See
    /// [`azihsm_fw_hsm_pal_traits::SessionType`] for the full
    /// validation matrix.
    pub session_type: u8,

    /// Cryptographic suite identifier.  See
    /// [`azihsm_fw_hsm_pal_traits::SessionSuite`] for the registered
    /// values.  Today only `0x01`
    /// (`P384HkdfSha384AesGcm256`) is implemented; any other value is
    /// rejected with `UnsupportedSessionSuite`.
    pub suite_id: u8,

    /// Per-handshake ephemeral public key supplied by the requesting
    /// VM.  The encoding and length are dictated by the negotiated
    /// suite — for `suite_id = 0x01` this is the HPKE `Npk` SEC1
    /// uncompressed `0x04 ‖ X ‖ Y` for the P-384 KEM (97 B).
    #[tbor(len = 97)]
    pub pk_init: &'a [u8],
}

/// `OpenSessionInit` response schema.
///
/// The `session_id` field is marked `#[tbor(session_id)]` so the
/// codec emits it as a 16-bit `SessionId` TOC entry (matching MBOR's
/// session-id encoding); the field type is a `u16` placeholder — the
/// generated view accessor and encoder builder both use
/// [`azihsm_fw_ddi_tbor_api::SessionId`] via full paths.
#[tbor(response)]
pub struct TborOpenSessionInitResp<'a> {
    /// Reserved session identifier (slot index).
    #[tbor(session_id)]
    pub session_id: u16,

    /// HSM's HPKE response ephemeral public key (HPKE `Npk` SEC1
    /// uncompressed `0x04 ‖ X ‖ Y` for the P-384 KEM, 97 B).
    #[tbor(len = 97)]
    pub pk_resp: &'a [u8],

    /// Phase-1 confirmation MAC binding `(pk_init, pk_hsm, pk_resp,
    /// session_id)` under the HPKE-exported handshake secret.
    #[tbor(len = 48)]
    pub mac_resp: &'a [u8],
}
