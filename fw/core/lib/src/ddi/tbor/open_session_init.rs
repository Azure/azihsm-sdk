// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `OpenSessionInit` handler — Phase 1 of session establishment.
//!
//! Validates the request, looks up the partition's PSK and identity
//! key, runs HPKE `mode_auth_psk` `send_export` to derive the shared
//! `exported` secret and the HSM's response ephemeral, reserves a
//! `Pending` session slot, computes the Phase-1 confirm MAC, and
//! returns `(slot, pk_resp, mac_resp)` to the caller.
//!
//! Resume is no longer multiplexed onto this opcode; the host
//! recovers a prior session's `masking_key` via the MBOR
//! `ReopenSession` command instead.
//!
//! On any error the partial session state is rolled back via the
//! caller-visible TBOR error response; no Pending slot is leaked.
//!
//! All variable-length and crypto-sized buffers are allocated from the
//! per-IO scoped allocator — handler frames never put DMA-targeted
//! arrays on the async stack.

use azihsm_fw_core_crypto_hpke::*;
use azihsm_fw_ddi_tbor_types::*;
use azihsm_fw_hsm_pal_traits::*;

/// Validated `OpenSessionInit` request fields.
struct ParsedRequest<'a> {
    /// Roles
    role: SessionRole,

    /// PSK identifier (0 or 1).
    psk_id: u8,

    /// Channel-level integrity profile selected by the caller.
    session_type: SessionType,

    /// Cryptographic suite negotiated by the caller.
    suite: SessionSuite,

    /// Sub-view of the inbound request buffer (DMA-branded by the
    /// codec), so it can flow straight into HPKE / HMAC inputs
    /// without an intermediate copy.
    pk_init: &'a DmaBuf,
}

/// Map a [`SessionSuite`] to the concrete [`HpkeSuite`] used by the
/// session-establishment handshake.  Today every implemented suite is
/// HPKE-based, so this is a total function; future ML-KEM variants
/// will require a different code path (and a different return type).
const fn hpke_suite_for(suite: SessionSuite) -> HpkeSuite {
    match suite {
        SessionSuite::P384HkdfSha384AesGcm256 => HpkeSuite::DHKemP384Sha384AesGcm256,
    }
}

/// HPKE suite used by the only currently registered `SessionSuite`
/// (`P384HkdfSha384AesGcm256`).  Used at compile time to size the
/// Pending blob; the runtime handler always uses
/// [`hpke_suite_for`] for the actually-negotiated suite.
const DEFAULT_HPKE_SUITE: HpkeSuite = hpke_suite_for(SessionSuite::P384HkdfSha384AesGcm256);

/// Length of the Pending handshake-state blob:
/// `exported (Nh) ‖ pk_init (Npk) ‖ pk_resp (Npk) ‖ session_type (1 B)
/// ‖ suite_id (1 B)`.
///
/// The trailing `session_type` byte tells [`open_session_finish`]
/// which derived-key schedule to run (PlainText: param+masking only;
/// Authenticated: param+masking+mac_tx+mac_rx).  The `suite_id` byte
/// lets `open_session_finish` recover the negotiated cryptographic
/// suite without trusting any client-side state.
pub(super) const PENDING_BLOB_LEN: usize =
    DEFAULT_HPKE_SUITE.nh() + DEFAULT_HPKE_SUITE.npk() + DEFAULT_HPKE_SUITE.npk() + 1 + 1;

/// Compile-time guard: the Pending blob must fit inside the PAL
/// budget.  If the HPKE suite sizes grow past the budget, this
/// assertion fires at build time rather than at runtime.
const _: () = assert!(PENDING_BLOB_LEN <= SESSION_PENDING_BLOB_MAX);

/// Handle a TBOR `OpenSessionInit` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let ParsedRequest {
        role,
        psk_id,
        session_type,
        suite,
        pk_init,
    } = parse_request(req_buf)?;

    let hpke_suite = hpke_suite_for(suite);

    pal.alloc_scoped_async(io, async |alloc| {
        // ── Identity + PSK material (all on the scoped allocator) ──
        let psk = load_psk(pal, io, alloc, psk_id)?;
        let key_id = pal.part_id_key_id(io)?;
        let sk_hsm = pal.vault_key(io, key_id)?;
        let pk_hsm = load_pk_hsm_sec1(pal, io, alloc)?;

        // ── HPKE info = SESSION_HPKE_INFO ‖ psk_id ‖ session_type
        //                                   ‖ suite_id
        // The trailing role+type+suite bytes bind the handshake
        // transcript so a downgrade to a different role, session type
        // or cryptographic suite produces a different `exported`
        // secret on the HSM side, MAC-failing any spoofed Phase-1
        // confirm.
        let info = build_hpke_info(alloc, psk_id, session_type, suite)?;

        // ── HPKE auth_psk send_export ──────────────────────────────
        let psk_id_bytes = &[psk_id];
        let (pk_resp, exported) = hpke_auth_psk_export(
            pal,
            io,
            alloc,
            hpke_suite,
            pk_init,
            sk_hsm,
            pk_hsm,
            psk,
            psk_id_bytes,
            info,
        )
        .await?;

        // ── Pending slot allocation ────────────────────────────────
        let slot = create_pending_slot(
            pal,
            io,
            alloc,
            role,
            session_type,
            suite,
            hpke_suite,
            exported,
            pk_init,
            pk_resp,
        )?;
        let session_id = u16::from(slot);

        // ── Phase-1 confirm MAC ────────────────────────────────────
        let mac_resp = compute_phase1_mac(
            pal, io, alloc, hpke_suite, exported, session_id, pk_init, pk_hsm, pk_resp,
        )
        .await?;

        // ── Encode response from the scoped buffers ────────────────
        encode_response(pal, io, session_id, pk_resp, mac_resp)
    })
    .await
}

/// Decode and validate the wire request.
fn parse_request<'a>(req_buf: &'a DmaBuf) -> HsmResult<ParsedRequest<'a>> {
    let req = TborOpenSessionInitReq::decode(req_buf)?;
    let psk_id = req.psk_id();

    if psk_id > 1 {
        return Err(HsmError::InvalidPskId);
    }

    let role = if psk_id == 0 {
        SessionRole::CryptoOfficer
    } else {
        SessionRole::CryptoUser
    };

    let session_type = SessionType::from_u8(req.session_type())?;
    session_type.validate_for_role(role)?;

    let suite = SessionSuite::from_u8(req.suite_id())?;
    let hpke_suite = hpke_suite_for(suite);

    let pk_init: &DmaBuf = req.pk_init();
    if pk_init.len() != hpke_suite.npk() {
        return Err(HsmError::InvalidArg);
    }

    Ok(ParsedRequest {
        role,
        psk_id,
        session_type,
        suite,
        pk_init,
    })
}

/// Load the partition's PSK into a freshly-allocated scoped buffer.
fn load_psk<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    psk_id: u8,
) -> HsmResult<&'a mut DmaBuf> {
    let psk = alloc.dma_alloc(PSK_LEN)?;
    pal.part_psk(io, psk_id, Some(&mut psk[..]))?;
    Ok(psk)
}

/// SEC1-uncompressed encoding (`0x04 ‖ X_be ‖ Y_be`) of the partition
/// identity public key, in a freshly-allocated scoped buffer.
///
/// The PAL stores the partition identity public key as raw
/// `X_be ‖ Y_be` (matching OpenSSL's natural EC point representation
/// and the form used for cert generation); concatenating with the
/// SEC1 `0x04` prefix yields the RFC 9180 §7.1.1 wire encoding
/// directly.
///
/// Using the PAL's queried coordinate length (rather than a hard-coded
/// suite-derived constant) future-proofs against PAL impls that return
/// a different size; an HPKE-suite mismatch would surface at
/// `send_export` time, not here.
fn load_pk_hsm_sec1<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<&'a mut DmaBuf> {
    let xy_len = pal.part_id_pub_key(io, None)?;
    let pk_hsm = alloc.dma_alloc(xy_len + 1)?;
    pk_hsm[0] = 0x04;
    pal.part_id_pub_key(io, Some(&mut pk_hsm[1..1 + xy_len]))?;
    Ok(pk_hsm)
}

/// Build the HPKE `info` field as
/// `SESSION_HPKE_INFO ‖ psk_id ‖ session_type ‖ suite_id` in a scoped
/// DMA buffer.  Returns a borrow with `'a` so the caller can pass it
/// into [`HpkeSendExportConfig::auth_psk`] without copying.
///
/// Binding `psk_id`, `session_type` and `suite_id` into the HPKE
/// `info` makes the handshake transcript non-malleable: a downgrade
/// to a different role, session type or cryptographic suite would
/// produce a different `exported` secret on the HSM side, causing
/// the Phase-1 confirm MAC to fail.
fn build_hpke_info(
    alloc: &impl HsmScopedAlloc,
    psk_id: u8,
    session_type: SessionType,
    suite: SessionSuite,
) -> HsmResult<&[u8]> {
    let info = alloc.dma_alloc(SESSION_HPKE_INFO.len() + 3)?;
    let mut off = 0;
    info[off..off + SESSION_HPKE_INFO.len()].copy_from_slice(SESSION_HPKE_INFO);
    off += SESSION_HPKE_INFO.len();
    info[off] = psk_id;
    info[off + 1] = session_type.to_u8();
    info[off + 2] = suite.to_u8();
    Ok(&info[..])
}

/// Run HPKE `auth_psk send_export`. Returns `(pk_resp, exported)` in
/// scoped buffers.
#[allow(clippy::too_many_arguments)]
async fn hpke_auth_psk_export<'a, P: HsmPal>(
    pal: &'a P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    suite: HpkeSuite,
    pk_init: &DmaBuf,
    sk_hsm: &DmaBuf,
    pk_hsm: &DmaBuf,
    psk: &DmaBuf,
    psk_id_bytes: &[u8],
    info: &[u8],
) -> HsmResult<(&'a mut DmaBuf, &'a mut DmaBuf)> {
    let pk_resp = alloc.dma_alloc(suite.npk())?;
    let exported = alloc.dma_alloc(suite.nh())?;
    let cfg = HpkeSendExportConfig::auth_psk(
        suite,
        pk_init,
        info,
        SESSION_HPKE_EXPORTER_CONTEXT,
        AuthParams {
            sk_s: sk_hsm,
            pk_s: pk_hsm,
        },
        PskParams {
            psk,
            psk_id: psk_id_bytes,
        },
    );
    send_export(
        pal,
        io,
        &cfg,
        Some(&mut pk_resp[..]),
        Some(&mut exported[..]),
        alloc,
    )
    .await?;
    Ok((pk_resp, exported))
}

/// Pack `exported ‖ pk_init ‖ pk_resp ‖ session_type ‖ suite_id`
/// into a Pending blob and hand it to `session_create_pending`.
#[allow(clippy::too_many_arguments)]
fn create_pending_slot<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    role: SessionRole,
    session_type: SessionType,
    suite: SessionSuite,
    hpke_suite: HpkeSuite,
    exported: &DmaBuf,
    pk_init: &DmaBuf,
    pk_resp: &DmaBuf,
) -> HsmResult<HsmSessId> {
    let nh = hpke_suite.nh();
    let npk = hpke_suite.npk();
    let pending_blob = alloc.dma_alloc(PENDING_BLOB_LEN)?;
    let mut off = 0;
    pending_blob[off..off + nh].copy_from_slice(exported);
    off += nh;
    pending_blob[off..off + npk].copy_from_slice(pk_init);
    off += npk;
    pending_blob[off..off + npk].copy_from_slice(pk_resp);
    off += npk;
    pending_blob[off] = session_type.to_u8();
    pending_blob[off + 1] = suite.to_u8();
    pal.session_create_pending(io, role, pending_blob)
}

/// Compute the Phase-1 confirm MAC:
/// `HMAC-SHA384(exported, (label ‖ session_id_be) ‖ pk_init ‖
/// pk_hsm ‖ pk_resp)`.
///
/// The label and the 2-byte big-endian `session_id` share one DMA
/// buffer so we don't pay for a separate small allocation just to
/// satisfy the PAL `hmac_continue(&DmaBuf)` contract.  `pk_init` is
/// passed through as the codec-supplied `&DmaBuf` sub-view of the
/// inbound request buffer.
#[allow(clippy::too_many_arguments)]
async fn compute_phase1_mac<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    suite: HpkeSuite,
    exported: &DmaBuf,
    session_id: u16,
    pk_init: &DmaBuf,
    pk_hsm: &DmaBuf,
    pk_resp: &DmaBuf,
) -> HsmResult<&'a mut DmaBuf> {
    debug_assert_eq!(SESSION_PHASE1_LABEL.len(), 14);
    let label_sid = alloc.dma_alloc(SESSION_PHASE1_LABEL.len() + 2)?;
    label_sid[..SESSION_PHASE1_LABEL.len()].copy_from_slice(SESSION_PHASE1_LABEL);
    label_sid[SESSION_PHASE1_LABEL.len()..].copy_from_slice(&session_id.to_be_bytes());

    let mac_resp = alloc.dma_alloc(suite.nh())?;
    let mut hmac_ctx = pal
        .hmac_begin(io, HsmHashAlgo::Sha384, exported, alloc)
        .await?;

    pal.hmac_continue(io, &mut hmac_ctx, label_sid).await?;
    pal.hmac_continue(io, &mut hmac_ctx, pk_init).await?;
    pal.hmac_continue(io, &mut hmac_ctx, pk_hsm).await?;
    pal.hmac_continue(io, &mut hmac_ctx, pk_resp).await?;
    pal.hmac_finish_into(io, hmac_ctx, mac_resp).await?;
    Ok(mac_resp)
}

/// Encode the `OpenSessionInit` response into a fresh IO-scoped DmaBuf.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    session_id: u16,
    pk_resp: &DmaBuf,
    mac_resp: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborOpenSessionInitResp::encode(buf, 0, false)?
            .session_id(SessionId(session_id))?
            .pk_resp(pk_resp)?
            .mac_resp(mac_resp)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
