// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `OpenSessionFinish` handler — Phase 2 of session establishment.
//!
//! Loads the Pending slot's handshake state, verifies the client's
//! Phase-2 confirmation MAC in constant time, derives the per-session
//! `param_key`, decrypts the host-supplied `seed_envelope` to recover
//! the 32-byte session seed, derives the per-direction MAC keys (for
//! Authenticated sessions) and the `masking_key`, wraps the
//! `masking_key` under `BK_SESSION = KBKDF(BK_BOOT, "SESSION_BK",
//! seed)` into the response `bmk_session` AEAD envelope, and promotes
//! the slot Pending → Active.
//!
//! On any post-Pending failure (MAC mismatch, seed_envelope AEAD
//! authentication failure) the Pending slot is destroyed before the
//! error is returned to the host, so a tampered envelope cannot be
//! probed repeatedly against the same slot.
//!
//! All variable-length buffers live on the per-IO scoped allocator
//! per the firmware async-discipline convention; no DMA-sized arrays
//! sit on the async stack.

use azihsm_fw_core_crypto_aead_envelope::open as aead_open;
use azihsm_fw_core_crypto_aead_envelope::AeadAlg;
use azihsm_fw_core_crypto_hpke::HpkeSuite;
use azihsm_fw_core_crypto_key_masking::aead::mask as mask_key;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_ddi_tbor_types::*;
use azihsm_fw_hsm_pal_traits::*;

/// Map a [`SessionSuite`] to the concrete [`HpkeSuite`] used by the
/// session-establishment handshake.  Mirrors the function of the same
/// name in [`super::open_session_init`]; kept duplicated to avoid
/// pulling that module's internals into a public surface.
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

/// Length of the Pending blob; mirrors the layout written by
/// [`super::open_session_init`]:
/// `exported ‖ pk_init ‖ pk_resp ‖ session_type ‖ suite_id`.
const PENDING_BLOB_LEN: usize =
    DEFAULT_HPKE_SUITE.nh() + DEFAULT_HPKE_SUITE.npk() + DEFAULT_HPKE_SUITE.npk() + 1 + 1;

/// Length of the API revision tag persisted alongside the session blob.
const API_REV_LEN: usize = 8;

/// API-revision tag persisted into the session vault blob's first 8
/// bytes by [`HsmSessionManager::session_promote`].
const SESSION_API_REV: [u8; API_REV_LEN] = [1, 0, 0, 0, 0, 0, 0, 0];

/// AEAD primitive used for both `seed_envelope` and `bmk_session`.
const AEAD_ALG: AeadAlg = AeadAlg::AesGcm256;

/// Caller-supplied label embedded in the `bmk_session`
/// [`MaskedKeyMetadata`]. Identifies the wrapped key as the
/// per-session boot-masking key recovered on resume.
const BMK_SESSION_KEY_LABEL: &[u8] = b"SESSION_BMK";

/// Validated `OpenSessionFinish` request fields.
struct ParsedRequest<'a> {
    /// Session Id
    sess_id: HsmSessId,
    /// Codec-supplied `&DmaBuf` sub-view of the inbound request
    /// buffer; flows straight into the constant-time MAC compare.
    mac_fin: &'a DmaBuf,
    /// Codec-supplied `&mut DmaBuf` sub-view of the inbound request
    /// buffer.  Decrypted in place by [`aead_open`] — no scratch copy.
    seed_envelope: &'a mut DmaBuf,
}

/// Per-session keys derived from the HPKE `exported` secret.
///
/// * `param_key` — 32 B AES-256 key used to AEAD-open `seed_envelope`
///   (this handler) and to authenticate per-parameter envelopes in
///   in-session commands like `ChangePsk`.  Always populated.
/// * `masking_key` — 80 B `aes32 ‖ hmac48` used by the `cbc::mask`
///   masked-key system.  Always populated.
/// * `mac_tx_key` — 48 B HMAC-SHA-384 key for outbound (HSM → host)
///   message MACs.  `Some` iff `session_type` is `Authenticated`.
/// * `mac_rx_key` — 48 B HMAC-SHA-384 key for inbound (host → HSM)
///   message MACs.  `Some` iff `session_type` is `Authenticated`.
struct DerivedKeys<'a> {
    param_key: &'a mut DmaBuf,
    masking_key: &'a mut DmaBuf,
    mac_tx_key: Option<&'a mut DmaBuf>,
    mac_rx_key: Option<&'a mut DmaBuf>,
}

/// Decoded Pending handshake state, split into the regions the PAL
/// crypto APIs need as distinct `&DmaBuf` arguments (HMAC `key` and
/// `data` must not alias, so the regions cannot be slices of a single
/// backing buffer).
struct HandshakeState<'a> {
    exported: &'a mut DmaBuf,
    pk_init: &'a mut DmaBuf,
    pk_resp: &'a mut DmaBuf,
    session_type: SessionType,
    /// Cryptographic suite recorded by Phase 1.  Drives every
    /// suite-derived size in this handler (Nh, Npk, AEAD parameters).
    suite: HpkeSuite,
}

/// Handle a TBOR `OpenSessionFinish` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let ParsedRequest {
        sess_id,
        mac_fin,
        seed_envelope,
    } = parse_request(req_buf)?;
    ensure_pending_blob_len(pal, io, sess_id)?;

    pal.alloc_scoped_async(io, async |alloc| {
        // ── Load Pending handshake state ──────────────────────────
        let HandshakeState {
            exported,
            pk_init,
            pk_resp,
            session_type,
            suite,
        } = load_pending_state(pal, io, alloc, sess_id)?;
        let pk_hsm = load_pk_hsm(pal, io, alloc)?;

        // The `mac_fin` length is dictated by the suite recorded in
        // the Pending blob, not by the wire schema (which is fixed
        // for the only currently-implemented suite).  Validating here
        // — after the suite is known — keeps the handler honest if a
        // future suite ships with a different MAC length.
        if mac_fin.len() != suite.nh() {
            return Err(HsmError::InvalidArg);
        }

        // ── Verify Phase-2 confirm MAC ────────────────────────────
        verify_mac(
            pal, io, alloc, sess_id, mac_fin, exported, pk_init, pk_hsm, pk_resp,
        )
        .await?;

        // ── Derive param_key once, use it to open the seed envelope
        let param_key = hkdf_expand_labeled(
            pal,
            io,
            alloc,
            exported,
            SESSION_PARAM_KEY_LABEL,
            SESSION_PARAM_KEY_LEN,
        )
        .await?;

        let seed = open_seed_envelope(pal, io, sess_id, param_key, seed_envelope).await?;

        // ── Derive remaining per-session keys ─────────────────────
        let derived =
            derive_remaining_keys(pal, io, alloc, exported, session_type, param_key).await?;

        // ── Build bmk_session (BK_SESSION-wrapped masking-key blob)
        //    BEFORE promote, so a wrap failure leaves the slot Pending
        //    (caller may retry; eviction reclaims it eventually) and
        //    no active session is created without a recovery blob.
        let bmk_session = build_bmk_session(pal, io, alloc, seed, derived.masking_key).await?;

        // ── Promote Pending → Active ──────────────────────────────
        promote_to_active(pal, io, alloc, sess_id, derived)?;

        encode_response(pal, io, bmk_session)
    })
    .await
}

/// Decode and validate the wire request.
fn parse_request<'a>(req_buf: &'a mut DmaBuf) -> HsmResult<ParsedRequest<'a>> {
    let req = TborOpenSessionFinishReq::decode_mut(req_buf)?;
    let id = HsmSessId::from(u16::from(req.session_id));
    // `mac_fin` length is checked once the negotiated suite is known
    // (see [`handle`]); the schema already pins the wire field to 48 B.
    let mac_fin: &DmaBuf = req.mac_fin;
    let seed_envelope: &mut DmaBuf = req.seed_envelope;
    if seed_envelope.len() != SEED_ENVELOPE_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(ParsedRequest {
        sess_id: id,
        mac_fin,
        seed_envelope,
    })
}

/// Cheap pre-check that `id` refers to a live Pending slot whose blob
/// matches the canonical layout.  Done before entering the scoped
/// allocator so a malformed request rejects without consuming any
/// scratch.
fn ensure_pending_blob_len<P: HsmPal>(pal: &P, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
    let pending_len = pal.session_pending_state(io, id, None)?;
    if pending_len != PENDING_BLOB_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Load the Pending slot's blob and split it into `(exported,
/// pk_init, pk_resp, session_type, suite)` scoped buffers.
fn load_pending_state<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    id: HsmSessId,
) -> HsmResult<HandshakeState<'a>> {
    let blob_len = pal.session_pending_state(io, id, None)?;
    let blob = alloc.dma_alloc(blob_len)?;
    pal.session_pending_state(io, id, Some(&mut blob[..]))?;

    // Recover the suite *before* using suite-derived sizes, in case a
    // future build supports more than one suite with different
    // Nh/Npk.  Today only `P384HkdfSha384AesGcm256` is registered, so
    // a mismatch with the wire length pre-check would already have
    // fired in [`ensure_pending_blob_len`].
    let suite = SessionSuite::from_u8(blob[blob.len() - 1])?;
    let hpke_suite = hpke_suite_for(suite);

    let nh = hpke_suite.nh();
    let npk = hpke_suite.npk();
    let exported = alloc.dma_alloc(nh)?;
    exported.copy_from_slice(&blob[..nh]);
    let pk_init = alloc.dma_alloc(npk)?;
    pk_init.copy_from_slice(&blob[nh..nh + npk]);
    let pk_resp = alloc.dma_alloc(npk)?;
    pk_resp.copy_from_slice(&blob[nh + npk..nh + 2 * npk]);
    let session_type = SessionType::from_u8(blob[nh + 2 * npk])?;

    Ok(HandshakeState {
        exported,
        pk_init,
        pk_resp,
        session_type,
        suite: hpke_suite,
    })
}

/// SEC1-uncompressed encoding (`0x04 ‖ X_be ‖ Y_be`) of the partition
/// identity public key, in a freshly-allocated scoped buffer.
fn load_pk_hsm<'a, P: HsmPal>(
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

/// Recompute and constant-time-verify the Phase-2 confirm MAC:
/// `HMAC-SHA384(exported, (label ‖ session_id_be) ‖ pk_init ‖ pk_hsm ‖ pk_resp)`.
///
/// On failure the Pending slot is destroyed and
/// `HsmError::SessionAuthFailure` is returned.
#[allow(clippy::too_many_arguments)]
async fn verify_mac<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    id: HsmSessId,
    mac_fin: &DmaBuf,
    exported: &DmaBuf,
    pk_init: &DmaBuf,
    pk_hsm: &DmaBuf,
    pk_resp: &DmaBuf,
) -> HsmResult<()> {
    debug_assert_eq!(SESSION_PHASE2_LABEL.len(), 14);
    let session_id_be = u16::from(id).to_be_bytes();
    let label_sid = alloc.dma_alloc(SESSION_PHASE2_LABEL.len() + 2)?;
    label_sid[..SESSION_PHASE2_LABEL.len()].copy_from_slice(SESSION_PHASE2_LABEL);
    label_sid[SESSION_PHASE2_LABEL.len()..].copy_from_slice(&session_id_be);

    let mut hmac_ctx = pal
        .hmac_begin(io, HsmHashAlgo::Sha384, exported, alloc)
        .await?;
    pal.hmac_continue(io, &mut hmac_ctx, label_sid).await?;
    pal.hmac_continue(io, &mut hmac_ctx, pk_init).await?;
    pal.hmac_continue(io, &mut hmac_ctx, pk_hsm).await?;
    pal.hmac_continue(io, &mut hmac_ctx, pk_resp).await?;
    let mac_verified = pal.hmac_finish_verify(io, hmac_ctx, mac_fin).await?;
    if !mac_verified {
        let _ = pal.session_destroy(io, id);
        return Err(HsmError::SessionAuthFailure);
    }
    Ok(())
}

/// AEAD-open the host's `seed_envelope` under the freshly-derived
/// `param_key`.  Returns the 32-byte plaintext seed as a `&DmaBuf`
/// sub-view of the envelope buffer (which was decrypted in place).
///
/// Any AEAD failure (bad magic, unsupported alg, tag mismatch) is
/// treated as a session-establishment authentication failure: the
/// Pending slot is destroyed before returning so a tampered envelope
/// cannot be probed repeatedly.
async fn open_seed_envelope<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    id: HsmSessId,
    param_key: &DmaBuf,
    seed_envelope: &'a mut DmaBuf,
) -> HsmResult<&'a DmaBuf> {
    // Decrypt the envelope **in place** on the inbound request
    // buffer; the destructured `seed_envelope` is a `&mut DmaBuf`
    // sub-view of the parent `req_buf`, so no scratch copy is
    // needed.
    let result = aead_open(pal, io, param_key, seed_envelope).await;
    let view = match result {
        Ok(v) => v,
        Err(_) => {
            // Destroy the Pending slot before returning so the
            // tampered envelope is not retry-probeable.
            let _ = pal.session_destroy(io, id);
            return Err(HsmError::SessionAuthFailure);
        }
    };

    if view.payload.len() != SEED_LEN {
        let _ = pal.session_destroy(io, id);
        return Err(HsmError::SessionAuthFailure);
    }
    // Hand the caller the AEAD plaintext view directly: it borrows
    // from the envelope buffer (the parent `req_buf`), which lives
    // until the enclosing scope exits.
    Ok(view.payload)
}

/// HKDF-derive the remaining per-session keys: `masking_key` (always)
/// and `mac_tx_key`/`mac_rx_key` (Authenticated sessions only).
/// `param_key` was derived earlier (we needed it to open the seed
/// envelope) and is plumbed through here so it can be moved straight
/// into the [`DerivedKeys`] carrier without re-deriving.
async fn derive_remaining_keys<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    exported: &DmaBuf,
    session_type: SessionType,
    param_key: &'a mut DmaBuf,
) -> HsmResult<DerivedKeys<'a>> {
    let masking_key = hkdf_expand_labeled(
        pal,
        io,
        alloc,
        exported,
        SESSION_MASKING_KEY_LABEL,
        SESSION_MASKING_KEY_LEN,
    )
    .await?;

    let (mac_tx_key, mac_rx_key) = if session_type.is_authenticated() {
        let tx = hkdf_expand_labeled(
            pal,
            io,
            alloc,
            exported,
            SESSION_MAC_TX_LABEL,
            SESSION_MAC_DIR_KEY_LEN,
        )
        .await?;
        let rx = hkdf_expand_labeled(
            pal,
            io,
            alloc,
            exported,
            SESSION_MAC_RX_LABEL,
            SESSION_MAC_DIR_KEY_LEN,
        )
        .await?;
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    Ok(DerivedKeys {
        param_key,
        masking_key,
        mac_tx_key,
        mac_rx_key,
    })
}

/// `HKDF-Expand(prk, label ‖ len_be, len)` into a freshly-allocated
/// scoped buffer of size `out_len`.
async fn hkdf_expand_labeled<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    prk: &DmaBuf,
    label: &[u8],
    out_len: usize,
) -> HsmResult<&'a mut DmaBuf> {
    let info = alloc.dma_alloc(label.len() + 2)?;
    info[..label.len()].copy_from_slice(label);
    info[label.len()..].copy_from_slice(&(out_len as u16).to_be_bytes());
    let out = alloc.dma_alloc(out_len)?;
    pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, Some(info), out)
        .await?;
    Ok(out)
}

/// Derive `BK_SESSION = SP800-108-KBKDF-SHA-384(BK_BOOT, "SESSION_BK",
/// seed)` (32 bytes) and wrap `masking_key` under it via the
/// [`masked_key::aead`](azihsm_fw_core_crypto_key_masking::aead) module
/// — an AEAD envelope whose 96 B AAD is a fixed
/// [`MaskedKeyMetadata`](azihsm_fw_core_crypto_key_masking::aead::MaskedKeyMetadata)
/// binding `{key_kind = MaskingKey, key_attrs, svn, owner_seed_id,
/// key_label = "SMK"}` to the ciphertext.
///
/// Only the `masking_key` is persisted in `bmk_session` — transport
/// keys (`param_key`, `mac_tx_key`, `mac_rx_key`) are always derived
/// fresh from the HPKE handshake on resume, preserving forward
/// secrecy for every promoted session.
async fn build_bmk_session<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    seed: &DmaBuf,
    masking_key: &DmaBuf,
) -> HsmResult<&'a mut DmaBuf> {
    let bk_session = derive_bk_session(pal, io, alloc, seed).await?;

    let svn = pal.part_svn(io)?;
    let owner_seed_id = pal.part_bks2_id(io)?;

    // `key_label` must be a DmaBuf per the masking-lib API; stage
    // the constant label into one.
    let key_label = alloc.dma_alloc(BMK_SESSION_KEY_LABEL.len())?;
    key_label.copy_from_slice(BMK_SESSION_KEY_LABEL);

    let params = MaskParams {
        key_kind: HsmVaultKeyKind::MaskingKey,
        key_attrs: HsmVaultKeyAttrs::new(),
        svn,
        owner_seed_id,
        key_label,
    };

    // Size-query first, then seal into a freshly-allocated buffer.
    let bmk_len = mask_key(
        pal,
        io,
        alloc,
        AEAD_ALG,
        bk_session,
        &params,
        masking_key,
        None,
    )
    .await?;
    let bmk_buf = alloc.dma_alloc(bmk_len)?;
    mask_key(
        pal,
        io,
        alloc,
        AEAD_ALG,
        bk_session,
        &params,
        masking_key,
        Some(bmk_buf),
    )
    .await?;
    Ok(bmk_buf)
}

/// Derive the 32-byte `BK_SESSION` wrap key into a freshly-allocated
/// scoped buffer.
async fn derive_bk_session<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    seed: &DmaBuf,
) -> HsmResult<&'a mut DmaBuf> {
    let bk_boot_len = pal.part_bk_boot(io, None)?;
    let bk_boot = alloc.dma_alloc(bk_boot_len)?;
    pal.part_bk_boot(io, Some(&mut bk_boot[..]))?;

    let label = alloc.dma_alloc(SESSION_BK_LABEL.len())?;
    label.copy_from_slice(SESSION_BK_LABEL);

    let bk_session = alloc.dma_alloc(SESSION_BK_LEN)?;
    pal.sp800_108_kdf(
        io,
        HsmHashAlgo::Sha384,
        bk_boot,
        Some(label),
        Some(seed),
        bk_session,
    )
    .await?;
    Ok(bk_session)
}

/// Encode the `OpenSessionFinish` response (carrying `bmk_session`)
/// into a fresh IO-scoped DmaBuf.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    bmk_session: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborOpenSessionFinishResp::encode(buf, 0, false)?
            .bmk_session(bmk_session)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}

/// Materialise the api-rev tag in a scoped DmaBuf and call
/// `session_promote` to flip the slot from Pending to Active.
fn promote_to_active<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    id: HsmSessId,
    derived: DerivedKeys<'_>,
) -> HsmResult<()> {
    let api_rev = alloc.dma_alloc(API_REV_LEN)?;
    api_rev.copy_from_slice(&SESSION_API_REV);
    pal.session_promote(
        io,
        id,
        api_rev,
        derived.param_key,
        derived.masking_key,
        derived.mac_tx_key.as_deref().map(|b| &**b),
        derived.mac_rx_key.as_deref().map(|b| &**b),
    )
}
