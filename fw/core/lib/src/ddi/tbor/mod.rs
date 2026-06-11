// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR DDI command dispatch.
//!
//! TBOR commands are addressed by a single `u8` opcode carried in the
//! TBOR request header. Each handler decodes its typed request via
//! [`azihsm_fw_ddi_tbor::TborRequest::decode`] (or the generated
//! `XxxReq::decode` shortcut) and encodes its response via the matching
//! `XxxResp::encode` typestate builder.
//!
//! ## Async, PAL-aware shape
//!
//! The dispatcher signature mirrors
//! [`crate::ddi::mbor::dispatch`]: it is `async fn dispatch<P:
//! HsmPal>(pal, io, view, opcode) -> HsmResult<&'p DmaBuf>` so handlers
//! can perform vault, crypto, and session-manager work.  Each handler
//! allocates its output buffer via
//! [`HsmAlloc::dma_alloc_var`](azihsm_fw_hsm_pal_traits::HsmAlloc::dma_alloc_var)
//! and returns the resulting `&DmaBuf` slice (lifetime tied to the
//! per-IO allocator scope).

pub(crate) mod change_psk;
pub(crate) mod close_session;
pub(crate) mod get_api_rev;
pub(crate) mod open_session_finish;
pub(crate) mod open_session_init;
pub mod part_init;
pub mod policy;

use azihsm_fw_ddi_tbor::RequestView;
use azihsm_fw_ddi_tbor::ResponseEncoder;
use azihsm_fw_ddi_tbor::TocEntry;
use azihsm_fw_ddi_tbor::PROTOCOL_VERSION;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::SessionRole;

use super::*;

/// TBOR opcodes recognised by the firmware dispatcher.
///
/// The wire opcode is a single byte. Constants kept here (rather than in
/// the host-side `azihsm_ddi_tbor_types` crate) so that firmware can be
/// built `no_std` without host-side feature flags.
pub(crate) mod opcode {
    /// `GetApiRev` — bootstrap TBOR command. Reports the firmware's
    /// supported TBOR wire-protocol version range.
    pub(crate) const GET_API_REV: u8 = 0x01;

    /// `OpenSessionInit` — Phase 1 of the session-establishment
    /// handshake.  Client sends `(psk_id, pk_init, seed,
    /// bmk_session?)`; HSM responds with `(session_id, pk_resp,
    /// mac_resp)`.  The optional `bmk_session` selects the resume
    /// variant (preserves `masking_key` continuity from a prior
    /// session); fresh keys are always derived from the HPKE
    /// handshake, so every promoted session has forward secrecy.
    pub(crate) const OPEN_SESSION_INIT: u8 = 0x10;

    /// `OpenSessionFinish` — Phase 2 of the session-establishment
    /// handshake.  Client sends `(session_id, mac_fin)`; on success
    /// the slot transitions Pending → Active and the response carries
    /// a fresh `bmk_session` envelope the host may persist for a
    /// future resume.
    pub(crate) const OPEN_SESSION_FINISH: u8 = 0x11;

    /// `CloseSession` — destroys an Active or Pending session slot.
    pub(crate) const CLOSE_SESSION: u8 = 0x12;

    /// `ChangePsk` — rotate the CO or CU partition PSK to a
    /// new value supplied encrypted inside an AEAD-GCM envelope wrapped
    /// under the active session's `param_key`.  See
    /// [`super::change_psk`] for the authorization matrix and
    /// AAD layout.
    pub(crate) const CHANGE_PSK: u8 = 0x20;

    /// `PartInit` — bind PTA, policy, and POTA thumbprint.
    pub(crate) const PART_INIT: u8 = 0x30;
}

/// Dispatch a parsed TBOR request to its handler.
///
/// On success returns a `&DmaBuf` view of the encoded response (lifetime
/// bound to the per-IO allocator).  On dispatch-level failure (unknown
/// opcode, default-PSK gate, etc.) returns the typed [`HsmError`];
/// per-handler decoding errors are also reported as `Err(...)`.  The
/// caller is responsible for translating a returned error into a TBOR
/// error response via [`encode_tbor_err`].
///
/// ## Default-PSK gate
///
/// Before invoking an in-session handler, the dispatcher checks
/// whether the calling role's partition PSK is still the well-known
/// public default (see
/// [`DEFAULT_PSK_CO`](azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO) /
/// [`DEFAULT_PSK_CU`](azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CU)).  If
/// so, only commands listed in [`allowed_with_default_psk`] are
/// permitted; anything else returns
/// [`HsmError::DefaultPskMustRotate`].  Out-of-session commands
/// (`GetApiRev`, `OpenSessionInit`, `OpenSessionFinish`) are never
/// gated — the client must always be able to bring up a session in
/// order to issue [`change_psk`] in the first place.
pub(crate) async fn dispatch<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
    opcode: u8,
    sqe_session_id: u16,
) -> HsmResult<&'p DmaBuf> {
    // Reject unknown opcodes with the canonical error *before*
    // applying any gating logic so the gate cannot leak existence of
    // unsupported opcodes through a different error code.
    if !is_known_opcode(opcode) {
        return Err(HsmError::UnsupportedCmd);
    }

    // Pre-dispatch gating work (session-id cross-check, default-PSK
    // gate) runs against a short-lived shared reborrow of the parent
    // mutable buffer. The reborrow drops at the end of this block,
    // freeing `req_buf` for handlers that need `&mut DmaBuf`.
    {
        let view = RequestView::parse(&*req_buf)?;

        // SQE/body session-id cross-check: for every opcode whose
        // `SessionCtrl` requires `id_valid = true` (close + in-session),
        // the SQE-carried `session_id` MUST match the inline body
        // `session_id` TOC entry.  Out-of-session opcodes do not carry a
        // body session id, and `validate_tbor_session_flags` has already
        // rejected the `id_valid = true` case for them upstream.
        //
        // This matches MBOR's `validate_session` (Rule 3): the audit
        // trail / CQE always reflects the same slot the handler mutates.
        if needs_session_id_cross_check(opcode) {
            let body_sess_id = extract_session_id(&view)?;
            if u16::from(body_sess_id) != sqe_session_id {
                return Err(HsmError::InvalidArg);
            }
        }

        // Default-PSK gate: applies only to in-session commands that are
        // not on the allow-list.  Skipped for out-of-session opcodes.
        //
        // The role used for the gate is derived from the request's
        // `session_id` TOC field (via [`HsmSessId::role`]).  This is the
        // same source of truth each handler ultimately uses to fetch the
        // session's `param_key`, so a client that forges a `session_id`
        // they do not own gains nothing — the handler's crypto-layer
        // authentication still rejects them.  When an outer
        // authenticated-framing layer lands, the role source should
        // switch to it; the gate's invariant ("the requested role's PSK
        // must be rotated") remains the same.
        if is_in_session(opcode) && !allowed_with_default_psk(opcode) {
            let sess_id = extract_session_id(&view)?;
            let psk_id = psk_id_for_role(sess_id.role());
            if pal.part_psk_is_default(io, psk_id)? {
                return Err(HsmError::DefaultPskMustRotate);
            }
        }
    }

    match opcode {
        opcode::GET_API_REV => get_api_rev::handle(pal, io, req_buf),
        opcode::OPEN_SESSION_INIT => open_session_init::handle(pal, io, req_buf).await,
        opcode::OPEN_SESSION_FINISH => open_session_finish::handle(pal, io, req_buf).await,
        opcode::CLOSE_SESSION => close_session::handle(pal, io, req_buf).await,
        opcode::CHANGE_PSK => change_psk::handle(pal, io, req_buf).await,
        opcode::PART_INIT => part_init::handle(pal, io, req_buf).await,
        _ => Err(HsmError::UnsupportedCmd),
    }
}

/// Returns `true` iff `opcode` is one of the opcodes wired into
/// [`dispatch`].  Kept in sync with the `match` arm by construction —
/// add a new opcode to the dispatcher AND this classifier in the same
/// change.
fn is_known_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        opcode::GET_API_REV
            | opcode::OPEN_SESSION_INIT
            | opcode::OPEN_SESSION_FINISH
            | opcode::CLOSE_SESSION
            | opcode::CHANGE_PSK
            | opcode::PART_INIT
    )
}

/// Returns `true` iff `opcode` is an in-session command (i.e. requires
/// an Active session slot to operate on, identified by an inline
/// `session_id` TOC field).
///
/// Out-of-session opcodes (`GetApiRev`) and session-establishment
/// opcodes (`OpenSessionInit`, `OpenSessionFinish`) return `false` —
/// they either need no session at all or they bring a Pending slot to
/// life, and the default-PSK gate would have nothing meaningful to
/// check for them.
///
/// New opcodes are in-session by default: anyone adding an opcode
/// must explicitly add it here and choose whether it bypasses the
/// default-PSK gate via [`allowed_with_default_psk`].
fn is_in_session(opcode: u8) -> bool {
    match opcode {
        opcode::GET_API_REV | opcode::OPEN_SESSION_INIT | opcode::OPEN_SESSION_FINISH => false,
        opcode::CLOSE_SESSION | opcode::CHANGE_PSK | opcode::PART_INIT => true,
        // Default-deny: any future opcode is treated as in-session
        // until classified, so the default-PSK gate applies to it.
        _ => true,
    }
}

/// Returns `true` iff `opcode` carries an inline body `session_id`
/// TOC entry that the dispatcher should cross-check against the SQE
/// `session_id` field.
///
/// Equivalent to "the opcode's [`SessionCtrl`] requires
/// `id_valid = true`" (see
/// [`SessionCtrl::from_tbor_opcode`](crate::op::SessionCtrl::from_tbor_opcode)):
/// `OpenSessionFinish`, `CloseSession`, and `ChangePsk` all carry
/// the targeted slot id both in the SQE header and in the body's
/// `SessionId` TOC entry, and the two MUST agree.
///
/// Out-of-session opcodes (`GetApiRev`, `OpenSessionInit`) carry no
/// body `session_id` and are not cross-checked here;
/// `validate_tbor_session_flags` already rejects them if the SQE
/// `id_valid` bit is set.
///
/// Default-deny for unknown opcodes: a new TBOR opcode is assumed to
/// be session-bearing until explicitly classified, so any future
/// addition that is *not* session-bearing must opt out here in the
/// same change that wires it into `dispatch`.
fn needs_session_id_cross_check(opcode: u8) -> bool {
    match opcode {
        opcode::GET_API_REV | opcode::OPEN_SESSION_INIT => false,
        opcode::OPEN_SESSION_FINISH
        | opcode::CLOSE_SESSION
        | opcode::CHANGE_PSK
        | opcode::PART_INIT => true,
        _ => true,
    }
}

/// Returns `true` iff `opcode` is permitted while the calling role's
/// partition PSK is still the public default.
///
/// **Allow-list, not block-list:** any opcode not explicitly listed
/// here is rejected with [`HsmError::DefaultPskMustRotate`] on a
/// default-PSK partition.  This keeps the gate safe-by-default —
/// adding a new in-session command does NOT silently expose it via
/// the public default PSK.
///
/// The two members are the minimum needed for the bootstrap flow:
/// `ChangePsk` rotates the PSK; `CloseSession` lets the client tear
/// the bootstrap session down cleanly.
fn allowed_with_default_psk(opcode: u8) -> bool {
    matches!(opcode, opcode::CHANGE_PSK | opcode::CLOSE_SESSION)
}

/// Maps a session role to the partition PSK slot id it authenticates
/// against: CO sessions → slot 0, CU sessions → slot 1.  Matches the
/// convention used by [`change_psk`] and the session-establishment
/// handlers.
fn psk_id_for_role(role: SessionRole) -> u8 {
    match role {
        SessionRole::CryptoOfficer => 0,
        SessionRole::CryptoUser => 1,
    }
}

/// Extracts the inline `session_id` TOC entry from an in-session
/// request.  Every in-session schema declares exactly one
/// `#[tbor(session_id)]` field, so the request is required to carry
/// **exactly one** `TocEntry::SessionId`.  A missing or duplicate
/// `SessionId` entry is a protocol-malformed request and returns
/// [`HsmError::DdiDecodeFailed`].
fn extract_session_id(view: &RequestView<'_>) -> HsmResult<HsmSessId> {
    let mut found: Option<u16> = None;
    for entry in view.toc_iter() {
        if let TocEntry::SessionId(id) = entry {
            if found.is_some() {
                return Err(HsmError::DdiDecodeFailed);
            }
            found = Some(id);
        }
    }
    found.map(HsmSessId::from).ok_or(HsmError::DdiDecodeFailed)
}

/// Encode a TBOR error response: header with `status = err.0` and a
/// single `none` placeholder TOC entry (the wire format requires
/// `toc_count >= 1`).
///
/// `opcode` is included only in trace context — TBOR responses do not
/// carry the opcode (it's implicit from the request/response pairing).
pub(crate) fn encode_tbor_err(_opcode: u8, err: HsmError, out: &mut [u8]) -> HsmResult<usize> {
    let bytes = ResponseEncoder::new(out, PROTOCOL_VERSION, err.0, false)
        .none()?
        .finish()?;
    Ok(bytes.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Synthetic opcode used to exercise the "future in-session
    /// command that is NOT on the allow-list" branch of the gate.
    /// Picked from the unallocated opcode space so it cannot collide
    /// with a real handler.
    const SYNTHETIC_FUTURE_OPCODE: u8 = 0xFE;

    #[test]
    fn known_opcodes_match_dispatch_arms() {
        for op in [
            opcode::GET_API_REV,
            opcode::OPEN_SESSION_INIT,
            opcode::OPEN_SESSION_FINISH,
            opcode::CLOSE_SESSION,
            opcode::CHANGE_PSK,
        ] {
            assert!(is_known_opcode(op), "{op:#04x} should be known");
        }
        assert!(!is_known_opcode(0x00));
        assert!(!is_known_opcode(0xFF));
    }

    #[test]
    fn out_of_session_opcodes_are_not_in_session() {
        for op in [
            opcode::GET_API_REV,
            opcode::OPEN_SESSION_INIT,
            opcode::OPEN_SESSION_FINISH,
        ] {
            assert!(!is_in_session(op), "{op:#04x} must be out-of-session");
        }
    }

    #[test]
    fn close_and_change_psk_are_in_session() {
        assert!(is_in_session(opcode::CLOSE_SESSION));
        assert!(is_in_session(opcode::CHANGE_PSK));
    }

    #[test]
    fn unknown_opcode_defaults_to_in_session() {
        // Default-deny: an unknown future opcode is treated as
        // in-session so the default-PSK gate applies to it until it
        // is explicitly classified.
        assert!(is_in_session(SYNTHETIC_FUTURE_OPCODE));
    }

    #[test]
    fn allow_list_is_exactly_change_psk_and_close_session() {
        assert!(allowed_with_default_psk(opcode::CHANGE_PSK));
        assert!(allowed_with_default_psk(opcode::CLOSE_SESSION));
        // Everything else — known or unknown — is NOT allowed.
        for op in [
            opcode::GET_API_REV,
            opcode::OPEN_SESSION_INIT,
            opcode::OPEN_SESSION_FINISH,
            SYNTHETIC_FUTURE_OPCODE,
            0x00,
            0xFF,
        ] {
            assert!(
                !allowed_with_default_psk(op),
                "{op:#04x} must NOT bypass the default-PSK gate",
            );
        }
    }

    #[test]
    fn psk_id_maps_role_to_slot() {
        assert_eq!(psk_id_for_role(SessionRole::CryptoOfficer), 0);
        assert_eq!(psk_id_for_role(SessionRole::CryptoUser), 1);
    }

    #[test]
    fn future_in_session_opcode_is_gated() {
        // Composite property the dispatcher relies on: a future
        // unknown-but-classified-as-in-session opcode is NOT on the
        // allow-list, so the gate would apply.  This is the
        // safe-by-default contract of `is_in_session` +
        // `allowed_with_default_psk`.
        assert!(is_in_session(SYNTHETIC_FUTURE_OPCODE));
        assert!(!allowed_with_default_psk(SYNTHETIC_FUTURE_OPCODE));
    }
}
