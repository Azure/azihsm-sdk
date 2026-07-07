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

pub(crate) mod api_rev;
pub mod part_info;
pub mod part_init;
pub mod policy;
pub(crate) mod psk_change;
pub(crate) mod session_close;
pub(crate) mod session_open_finish;
pub(crate) mod session_open_init;

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
    /// `ApiRev` — bootstrap TBOR command. Reports the firmware's
    /// supported TBOR wire-protocol version range.
    pub(crate) const API_REV: u8 = 0x01;

    /// `SessionOpenInit` — Phase 1 of the session-establishment
    /// handshake.  Client sends `(psk_id, pk_init, seed,
    /// bmk_session?)`; HSM responds with `(session_id, pk_resp,
    /// mac_resp)`.  The optional `bmk_session` selects the resume
    /// variant (preserves `masking_key` continuity from a prior
    /// session); fresh keys are always derived from the HPKE
    /// handshake, so every promoted session has forward secrecy.
    pub(crate) const SESSION_OPEN_INIT: u8 = 0x03;

    /// `SessionOpenFinish` — Phase 2 of the session-establishment
    /// handshake.  Client sends `(session_id, mac_fin)`; on success
    /// the slot transitions Pending → Active and the response carries
    /// a fresh `bmk_session` envelope the host may persist for a
    /// future resume.
    pub(crate) const SESSION_OPEN_FINISH: u8 = 0x04;

    /// `SessionClose` — destroys an Active or Pending session slot.
    pub(crate) const SESSION_CLOSE: u8 = 0x05;

    /// `PskChange` — rotate the CO or CU partition PSK to a
    /// new value supplied encrypted inside an AEAD-GCM envelope wrapped
    /// under the active session's `param_key`.  See
    /// [`super::psk_change`] for the authorization matrix and
    /// AAD layout.
    pub(crate) const PSK_CHANGE: u8 = 0x06;

    /// `PartInit` — bind PTA, policy, and POTA thumbprint.
    pub(crate) const PART_INIT: u8 = 0x07;

    /// `PartInfo` — out-of-session info command reporting device kind /
    /// FIPS status plus the bound partition's lifecycle and identity
    /// (state, generation, owner/manufacturer SVN, PID, identity public
    /// key).  TBOR analogue of MBOR `GetDeviceInfo` + the Manticore
    /// `GetPartID` primitive.
    pub(crate) const PART_INFO: u8 = 0x02;
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
/// (`ApiRev`, `SessionOpenInit`, `SessionOpenFinish`) are never
/// gated — the client must always be able to bring up a session in
/// order to issue [`psk_change`] in the first place.
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
    // gate).  Only out-of-session opcodes that need neither check skip
    // the re-parse entirely — the caller's `RequestView::parse` in
    // `handle_tbor_op` already validated the header and TOC structure.
    {
        let needs_cross_check = needs_session_id_cross_check(opcode);
        let needs_psk_gate = is_in_session(opcode) && !allowed_with_default_psk(opcode);

        if needs_cross_check || needs_psk_gate {
            let view = RequestView::parse(&*req_buf)?;

            // SQE/body session-id cross-check: for every opcode whose
            // `SessionCtrl` requires `id_valid = true` (close +
            // in-session), the SQE-carried `session_id` MUST match the
            // inline body `session_id` TOC entry.
            if needs_cross_check {
                let body_sess_id = extract_session_id(&view)?;
                if u16::from(body_sess_id) != sqe_session_id {
                    return Err(HsmError::InvalidArg);
                }
            }

            // Default-PSK gate: applies only to in-session commands
            // that are not on the allow-list.
            if needs_psk_gate {
                let sess_id = extract_session_id(&view)?;
                let psk_id = psk_id_for_role(sess_id.role());
                if crate::part_state::part_psk_is_default(pal, io, psk_id)? {
                    return Err(HsmError::DefaultPskMustRotate);
                }
            }
        }
    }

    match opcode {
        opcode::API_REV => api_rev::handle(pal, io, req_buf),
        opcode::SESSION_OPEN_INIT => session_open_init::handle(pal, io, req_buf).await,
        opcode::SESSION_OPEN_FINISH => session_open_finish::handle(pal, io, req_buf).await,
        opcode::SESSION_CLOSE => session_close::handle(pal, io, req_buf).await,
        opcode::PSK_CHANGE => psk_change::handle(pal, io, req_buf).await,
        opcode::PART_INIT => part_init::handle(pal, io, req_buf).await,
        opcode::PART_INFO => part_info::handle(pal, io, req_buf),
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
        opcode::API_REV
            | opcode::SESSION_OPEN_INIT
            | opcode::SESSION_OPEN_FINISH
            | opcode::SESSION_CLOSE
            | opcode::PSK_CHANGE
            | opcode::PART_INIT
            | opcode::PART_INFO
    )
}

/// Returns `true` iff `opcode` is an in-session command (i.e. requires
/// an Active session slot to operate on, identified by an inline
/// `session_id` TOC field).
///
/// Out-of-session opcodes (`ApiRev`) and session-establishment
/// opcodes (`SessionOpenInit`, `SessionOpenFinish`) return `false` —
/// they either need no session at all or they bring a Pending slot to
/// life, and the default-PSK gate would have nothing meaningful to
/// check for them.
///
/// New opcodes are in-session by default: anyone adding an opcode
/// must explicitly add it here and choose whether it bypasses the
/// default-PSK gate via [`allowed_with_default_psk`].
fn is_in_session(opcode: u8) -> bool {
    match opcode {
        opcode::API_REV
        | opcode::SESSION_OPEN_INIT
        | opcode::SESSION_OPEN_FINISH
        | opcode::PART_INFO => false,
        opcode::SESSION_CLOSE | opcode::PSK_CHANGE | opcode::PART_INIT => true,
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
/// `SessionOpenFinish`, `SessionClose`, and `PskChange` all carry
/// the targeted slot id both in the SQE header and in the body's
/// `SessionId` TOC entry, and the two MUST agree.
///
/// Out-of-session opcodes (`ApiRev`, `SessionOpenInit`) carry no
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
        opcode::API_REV | opcode::SESSION_OPEN_INIT | opcode::PART_INFO => false,
        opcode::SESSION_OPEN_FINISH
        | opcode::SESSION_CLOSE
        | opcode::PSK_CHANGE
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
/// `PskChange` rotates the PSK; `SessionClose` lets the client tear
/// the bootstrap session down cleanly.
fn allowed_with_default_psk(opcode: u8) -> bool {
    matches!(opcode, opcode::PSK_CHANGE | opcode::SESSION_CLOSE)
}

/// Maps a session role to the partition PSK slot id it authenticates
/// against: CO sessions → slot 0, CU sessions → slot 1.  Matches the
/// convention used by [`psk_change`] and the session-establishment
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
            opcode::API_REV,
            opcode::SESSION_OPEN_INIT,
            opcode::SESSION_OPEN_FINISH,
            opcode::SESSION_CLOSE,
            opcode::PSK_CHANGE,
        ] {
            assert!(is_known_opcode(op), "{op:#04x} should be known");
        }
        assert!(!is_known_opcode(0x00));
        assert!(!is_known_opcode(0xFF));
    }

    #[test]
    fn out_of_session_opcodes_are_not_in_session() {
        for op in [
            opcode::API_REV,
            opcode::SESSION_OPEN_INIT,
            opcode::SESSION_OPEN_FINISH,
        ] {
            assert!(!is_in_session(op), "{op:#04x} must be out-of-session");
        }
    }

    #[test]
    fn close_and_psk_change_are_in_session() {
        assert!(is_in_session(opcode::SESSION_CLOSE));
        assert!(is_in_session(opcode::PSK_CHANGE));
    }

    #[test]
    fn unknown_opcode_defaults_to_in_session() {
        // Default-deny: an unknown future opcode is treated as
        // in-session so the default-PSK gate applies to it until it
        // is explicitly classified.
        assert!(is_in_session(SYNTHETIC_FUTURE_OPCODE));
    }

    #[test]
    fn allow_list_is_exactly_psk_change_and_session_close() {
        assert!(allowed_with_default_psk(opcode::PSK_CHANGE));
        assert!(allowed_with_default_psk(opcode::SESSION_CLOSE));
        // Everything else — known or unknown — is NOT allowed.
        for op in [
            opcode::API_REV,
            opcode::SESSION_OPEN_INIT,
            opcode::SESSION_OPEN_FINISH,
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
