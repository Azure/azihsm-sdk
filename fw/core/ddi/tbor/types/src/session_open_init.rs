// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionOpenInit` wire schema (session-establishment Phase 1).
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
use open_enum::open_enum;

/// Typed wire wrapper for the `SessionOpenInit` `psk_id` byte.
///
/// An [`open_enum`] newtype over the raw `u8` carried on the wire,
/// identifying the caller role asserted for the handshake. Being **open**
/// keeps it forward-compatible: an unrecognized byte surfaces as
/// `PskId(x)` rather than failing to decode. The value is **not**
/// validated at decode (any byte round-trips); the handler maps it to a
/// [`SessionRole`](azihsm_fw_hsm_pal_traits::SessionRole), rejecting any
/// value outside the two below with
/// [`InvalidPskId`](azihsm_fw_hsm_pal_traits::HsmError::InvalidPskId).
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskId {
    /// Crypto Officer role (authenticated sessions).
    CryptoOfficer = 0,

    /// Crypto User role (plaintext sessions).
    CryptoUser = 1,
}

/// Typed wire wrapper for the `SessionOpenInit` `session_type` byte.
///
/// An [`open_enum`] newtype over the raw `u8` carried on the wire, so the
/// schema field and its accessor are self-documenting (`SessionKind` with
/// named variants rather than a bare `u8`) without coupling the wire type
/// to the firmware-internal
/// [`SessionType`](azihsm_fw_hsm_pal_traits::SessionType) enum. Being
/// **open** keeps it forward-compatible: an unrecognized byte surfaces as
/// `SessionKind(x)` rather than failing to decode. The value is **not**
/// validated at decode (any byte round-trips); the handler maps it to a
/// [`SessionType`] via `SessionType::from_u8(kind.0)` and cross-checks it
/// against the caller role, which is where an invalid value or role
/// pairing is rejected with [`InvalidSessionType`].
///
/// [`SessionType`]: azihsm_fw_hsm_pal_traits::SessionType
/// [`InvalidSessionType`]: azihsm_fw_hsm_pal_traits::HsmError::InvalidSessionType
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// Channel transports bodies without a per-message MAC. Required for
    /// CU (`psk_id = 1`).
    PlainText = 0,

    /// Channel transports bodies under a per-message MAC envelope.
    /// Required for CO (`psk_id = 0`).
    Authenticated = 1,
}

/// Typed wire wrapper for the `SessionOpenInit` `suite_id` byte.
///
/// An [`open_enum`] newtype over the raw `u8` carried on the wire, so the
/// schema field and its accessor are self-documenting (`SuiteId` with
/// named variants rather than a bare `u8`) without coupling the wire type
/// to the firmware-internal
/// [`SessionSuite`](azihsm_fw_hsm_pal_traits::SessionSuite) enum. Being
/// **open** keeps it forward-compatible: an unrecognized byte surfaces as
/// `SuiteId(x)` rather than failing to decode. The value is **not**
/// validated at decode (any byte round-trips); the handler maps it to a
/// [`SessionSuite`] via `SessionSuite::from_u8(id.0)`, which is where an
/// unsupported suite is rejected with [`UnsupportedSessionSuite`].
///
/// [`SessionSuite`]: azihsm_fw_hsm_pal_traits::SessionSuite
/// [`UnsupportedSessionSuite`]: azihsm_fw_hsm_pal_traits::HsmError::UnsupportedSessionSuite
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteId {
    /// HPKE `DHKEM(P-384, HKDF-SHA-384) + HKDF-SHA-384 + AES-256-GCM`.
    /// The only registered suite today.
    P384HkdfSha384AesGcm256 = 0x01,
}

/// Length of the VM's per-handshake ephemeral public key
/// (HPKE `Npk` for the P-384 KEM: SEC1 uncompressed
/// `0x04 ‖ X ‖ Y` per RFC 9180 §7.1.1, big-endian coordinates).
pub const PK_INIT_LEN: usize = 97;

/// Length of the HSM's HPKE response ephemeral (same `Npk` layout).
pub const PK_RESP_LEN: usize = 97;

/// Length of the Phase-1 confirmation MAC (HMAC-SHA-384).
pub const MAC_RESP_LEN: usize = 48;

/// `SessionOpenInit` request schema.
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
#[tbor(opcode = 0x03)]
pub struct TborSessionOpenInitReq<'a> {
    /// PSK identifier asserting the caller role (`CryptoOfficer` = `0`,
    /// `CryptoUser` = `1`). Any other value is rejected with
    /// `InvalidPskId` by the handler.
    #[tbor(U8)]
    pub psk_id: PskId,

    /// Channel-level integrity profile selected by the caller.
    ///
    /// * `PlainText` (`0`) — required for CU (`psk_id = 1`).
    /// * `Authenticated` (`1`) — required for CO (`psk_id = 0`).
    ///
    /// Any other value, or a role/type pair other than the two above,
    /// is rejected with `InvalidSessionType` by the handler.  See
    /// [`azihsm_fw_hsm_pal_traits::SessionType`] for the full
    /// validation matrix.
    #[tbor(U8)]
    pub session_type: SessionKind,

    /// Cryptographic suite identifier.  See
    /// [`azihsm_fw_hsm_pal_traits::SessionSuite`] for the registered
    /// values.  Today only `0x01`
    /// (`P384HkdfSha384AesGcm256`) is implemented; any other value is
    /// rejected with `UnsupportedSessionSuite` by the handler.
    #[tbor(U8)]
    pub suite_id: SuiteId,

    /// Per-handshake ephemeral public key supplied by the requesting
    /// VM.  The encoding and length are dictated by the negotiated
    /// suite — for `suite_id = 0x01` this is the HPKE `Npk` SEC1
    /// uncompressed `0x04 ‖ X ‖ Y` for the P-384 KEM (97 B).
    #[tbor(buffer, len = 97)]
    pub pk_init: &'a [u8],
}

/// `SessionOpenInit` response schema.
///
/// The `session_id` field is typed
/// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId) and marked
/// `#[tbor(session_id)]` so the codec emits it as a 16-bit `SessionId`
/// TOC entry (matching MBOR's session-id encoding).
#[tbor(response)]
pub struct TborSessionOpenInitResp<'a> {
    /// Reserved session identifier (slot index).
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// HSM's HPKE response ephemeral public key (HPKE `Npk` SEC1
    /// uncompressed `0x04 ‖ X ‖ Y` for the P-384 KEM, 97 B).
    #[tbor(buffer, len = 97)]
    pub pk_resp: &'a [u8],

    /// Phase-1 confirmation MAC binding `(pk_init, pk_hsm, pk_resp,
    /// session_id)` under the HPKE-exported handshake secret.
    #[tbor(buffer, len = 48)]
    pub mac_resp: &'a [u8],
}
