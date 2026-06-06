// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI OpenSession command handler.
//!
//! Authenticates the host's encrypted session credential and creates
//! a fresh authenticated session against the partition's identity.
//!
//! Flow at a glance (matches the reference firmware, simplified for
//! the std PAL):
//!
//! 1. Decode + fail-fast (sess_id must be `None`, `rev` must be set,
//!    credentials must already be established, partition must be
//!    provisioned, session table must have room, nonce must match).
//! 2. ECDH-P384 between the partition's session-encryption private
//!    key and the host's ephemeral public key → 48-byte secret.
//! 3. HKDF-SHA-384 with empty salt and `info = nonce` → 80-byte OKM
//!    split into a 32-byte AES key and a 48-byte HMAC key.
//! 4. HMAC-SHA-384 verify the encrypted credential tag over
//!    `enc_id ‖ enc_pin ‖ enc_seed ‖ iv ‖ nonce`.
//! 5. `part_nonce_refresh` — consume the nonce so a replayed request
//!    cannot survive any later failure.
//! 6. AES-CBC-256 decrypt id (16 B) → pin (16 B) → seed (48 B) in
//!    place, chaining IVs across blocks just like the host wrap.
//! 7. `part_verify_credential` — constant-time compare decrypted
//!    id+pin against the persisted partition credential.
//! 8. Generate a fresh 80-byte random session masking key
//!    (MK_SESSION) and derive an 80-byte session BK (BK_SESSION) by
//!    SP 800-108 KBKDF rooted in `BK_BOOT` with label `"SESSION_BK"`
//!    and the decrypted seed as context — the host stores the wrapped
//!    blob and re-presents it on `ReopenSession`.
//! 9. `session_create` — install MK_SESSION as the session-vault
//!    blob, get back a guard with the freshly-allocated `HsmSessId`.
//! 10. Encode the response (header echoes the new `sess_id`) and
//!     mask-CBC the MK_SESSION under BK_SESSION into the response's
//!     `bmk_session` slot.
//! 11. Atomic commit via `guard.dismiss()`.  Any failure between
//!     `session_create` and `dismiss` rolls the provisional session
//!     back via the guard's `Drop`.

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_ddi_mbor_types::open_session::DdiOpenSessionReq;
use azihsm_fw_ddi_mbor_types::open_session::DdiOpenSessionResp;
use azihsm_fw_ddi_mbor_types::DdiKeyType;

use super::*;

// ── Labels and metadata ──────────────────────────────────────────────

/// SP 800-108 KBKDF label for deriving the session BK from `BK_BOOT`.
const SESSION_BK_LABEL: &[u8] = b"SESSION_BK";

/// Cleartext label embedded in the BMK_SESSION metadata identifying
/// the wrapped key as the session masking key.
const SMK_KEY_LABEL: &[u8] = b"SMK";

/// Handle `DdiOpenSessionCmd`.
///
/// Returns a DMA buffer holding the encoded response — including the
/// new session id in the header and the wrapped session masking key
/// (`bmk_session`) the host must persist for any future
/// `ReopenSession` against the same credential lineage.
pub(crate) async fn open_session<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let mut body: DdiOpenSessionReq = decoder.decode_data()?;

    let _lock = pal.partition_lock(io).await?;

    check_fail_fast(pal, io, &body)?;
    let api_rev = hdr.rev.ok_or(HsmError::UnsupportedRevision)?;

    // ── Steps 2-3: ECDH + HKDF → 80-byte OKM (aes_key ‖ hmac_key) ────
    let okm = pal.dma_alloc(io, BK_LEN)?;
    derive_session_credential_keys(
        pal,
        io,
        body.pub_key.raw,
        body.encrypted_credential.nonce,
        okm,
    )
    .await?;
    let (aes_key, hmac_key) = okm.split_at(okm.len() - HsmHashAlgo::Sha384.digest_len());

    // ── Step 4: HMAC verify the credential ───────────────────────────
    verify_credential_hmac(pal, io, &body.encrypted_credential, hmac_key).await?;

    // ── Step 5: Reset nonce, then AES-CBC decrypt id, pin, seed ──────
    //
    // Reset the partition nonce *before* decrypting / verifying the
    // credential so the nonce that authenticated this request cannot
    // be replayed if a later step fails partway through.
    pal.part_nonce_refresh(io)?;
    decrypt_session_credential(pal, io, &mut body.encrypted_credential, aes_key).await?;

    // ── Step 6: Verify decrypted credential matches persisted ────────
    let id: &[u8] = body.encrypted_credential.encrypted_id;
    let pin: &[u8] = body.encrypted_credential.encrypted_pin;
    if id == [0u8; CRED_FIELD_LEN] || pin == [0u8; CRED_FIELD_LEN] {
        return Err(HsmError::InvalidAppCredentials);
    }
    pal.part_verify_credential(io, id, pin)?;

    // ── Step 7: Fresh MK_SESSION + derived BK_SESSION ────────────────
    let mk_session = pal.dma_alloc(io, BK_LEN)?;
    pal.rng_fill_bytes(io, mk_session)?;

    let bk_boot_len = pal.part_bk_boot(io, None)?;
    let bk_boot = pal.dma_alloc(io, bk_boot_len)?;
    pal.part_bk_boot(io, Some(bk_boot))?;

    let bk_session = pal.dma_alloc(io, BK_LEN)?;
    let session_bk_label = pal.dma_alloc(io, SESSION_BK_LABEL.len())?;
    session_bk_label.copy_from_slice(SESSION_BK_LABEL);
    pal.sp800_108_kdf(
        io,
        HsmHashAlgo::Sha384,
        bk_boot,
        session_bk_label,
        body.encrypted_credential.encrypted_seed,
        bk_session,
    )
    .await?;

    // ── Step 8: Allocate the session table entry ─────────────────────
    let api_rev_bytes = pack_api_rev(api_rev);
    let guard = pal.session_create(io, &api_rev_bytes, mk_session, None)?;
    let sess_id = guard.sess_id();

    // ── Step 9: Encode response + envelope MK_SESSION under BK_SESSION
    let resp = encode_response(
        pal,
        io,
        hdr,
        sess_id,
        bk_session,
        mk_session,
        pal.part_svn(io)?,
        pal.part_bks2_id(io)?,
    )
    .await?;

    // ── Atomic commit ────────────────────────────────────────────────
    //
    // session_create's guard tears the provisional session down on
    // Drop, so any failure above (notably encode_response) rolls the
    // session back.  The nonce refresh in step 5 stays — required even
    // on failure to prevent replay of the original request.
    guard.dismiss();

    Ok(resp)
}

/// Performs all fail-fast checks before any cryptographic work.
///
/// Must be called under the partition lock so the partition-state
/// checks (nonce, credential-set, provisioned, session-table) stay
/// consistent with the subsequent state mutations.
///
/// Session-id and api-rev presence are validated centrally — see
/// `validate_session` (io.rs) and `check_api_rev` (mod.rs) — so they
/// are not re-checked here.
fn check_fail_fast<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    body: &DdiOpenSessionReq<'_>,
) -> HsmResult<()> {
    // Credential / provisioning state is checked BEFORE the nonce.
    // Matches the mcr-hsm reference (which gates on `verify_cred_is_set`
    // before any other crypto / state work) and gives the host a more
    // actionable error when a request arrives on a freshly-erased
    // partition: NonceMismatch could be hit by any random replay,
    // whereas CredentialsNotEstablished tells the host it must
    // EstablishCredential first.
    if !pal.part_is_credential_set(io)? {
        return Err(HsmError::CredentialsNotEstablished);
    }
    if !pal.part_is_provisioned(io)? {
        return Err(HsmError::PartitionNotProvisioned);
    }
    if pal.session_limit_reached(io) {
        return Err(HsmError::VaultSessionLimitReached);
    }

    pal.part_verify_nonce(io, body.encrypted_credential.nonce)?;

    if body.pub_key.key_kind != DdiKeyType::Ecc384Public {
        return Err(HsmError::InvalidKeyType);
    }
    if body.pub_key.raw.len() != HsmEccCurve::P384.pub_key_len() {
        return Err(HsmError::InvalidArg);
    }

    Ok(())
}

/// Derives the AES-256 ‖ HMAC-SHA-384 OKM used to authenticate and
/// decrypt the session credential payload.
///
/// Mirrors `establish_credential::derive_credential_keys` but keys the
/// ECDH against the partition's `SessionEnc` private key instead of
/// the `EstablishCred` private key.
///
/// `okm_out` must be exactly [`BK_LEN`] (80) bytes.
async fn derive_session_credential_keys<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    host_eph_pub_key_raw: &DmaBuf,
    nonce: &DmaBuf,
    okm_out: &mut DmaBuf,
) -> HsmResult<()> {
    let sess_enc_key_id = pal.part_session_enc_key_id(io)?;

    let secret = pal.dma_alloc(io, HsmEccCurve::P384.secret_len())?;
    {
        let priv_key = pal.vault_key(io, sess_enc_key_id)?;
        pal.ecdh_derive(
            io,
            HsmEccCurve::P384,
            priv_key,
            host_eph_pub_key_raw,
            secret,
        )
        .await?;
    }

    // HKDF-Extract with empty salt (RFC 5869 §2.2).
    let prk_area = pal.dma_alloc(io, HsmHashAlgo::Sha384.digest_len())?;
    let (empty_salt, prk) = prk_area.split_at_mut(0);
    pal.hkdf_extract(io, HsmHashAlgo::Sha384, empty_salt, secret, prk)
        .await?;

    pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, nonce, okm_out)
        .await
}

/// HMAC-SHA-384 verifies the encrypted session credential's tag over
/// `enc_id ‖ enc_pin ‖ enc_seed ‖ iv ‖ nonce`.
async fn verify_credential_hmac<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    enc_cred: &azihsm_fw_ddi_mbor_types::open_session::DdiEncryptedSessionCredential<'_>,
    hmac_key: &DmaBuf,
) -> HsmResult<()> {
    let id_len = enc_cred.encrypted_id.len();
    let pin_len = enc_cred.encrypted_pin.len();
    let seed_len = enc_cred.encrypted_seed.len();
    let iv_len = enc_cred.iv.len();
    let nonce_len = enc_cred.nonce.len();

    let hmac_input = pal.dma_alloc(io, id_len + pin_len + seed_len + iv_len + nonce_len)?;
    let (id_dst, rest) = hmac_input.split_at_mut(id_len);
    let (pin_dst, rest) = rest.split_at_mut(pin_len);
    let (seed_dst, rest) = rest.split_at_mut(seed_len);
    let (iv_dst, nonce_dst) = rest.split_at_mut(iv_len);
    id_dst.copy_from_slice(enc_cred.encrypted_id);
    pin_dst.copy_from_slice(enc_cred.encrypted_pin);
    seed_dst.copy_from_slice(enc_cred.encrypted_seed);
    iv_dst.copy_from_slice(enc_cred.iv);
    nonce_dst.copy_from_slice(enc_cred.nonce);

    if !pal
        .hmac_verify(io, HsmHashAlgo::Sha384, hmac_key, hmac_input, enc_cred.tag)
        .await?
    {
        return Err(HsmError::PinDecryptionFailed);
    }
    Ok(())
}

/// AES-CBC-256 decrypts the host-supplied `enc_id`, `enc_pin`, and
/// `enc_seed` **in place** inside the request buffer.
///
/// The host (`crates/cred_encrypt`) encrypts id, pin, and seed with a
/// single mutable AES-CBC stream under `iv = enc_cred.iv`, so we chain
/// the IVs:
///
/// - Block 1: decrypt `enc_id` with `iv = body.iv`; output IV =
///   original `enc_id` ciphertext.
/// - Block 2: decrypt `enc_pin` with the previous output IV; output
///   IV = original `enc_pin` ciphertext.
/// - Blocks 3-5: decrypt the 48-byte `enc_seed` with the previous
///   output IV.  No further chaining is needed.
async fn decrypt_session_credential<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    enc_cred: &mut azihsm_fw_ddi_mbor_types::open_session::DdiEncryptedSessionCredential<'_>,
    aes_key: &DmaBuf,
) -> HsmResult<()> {
    let iv_chain_a = pal.dma_alloc(io, enc_cred.iv.len())?;
    let iv_chain_b = pal.dma_alloc(io, enc_cred.iv.len())?;

    // Block 1: decrypt `enc_id` in place; snapshot ciphertext into
    // iv_chain_a for use as block 2's IV.
    pal.aes_cbc_enc_dec_in_place(
        io,
        AesOp::Decrypt,
        aes_key,
        enc_cred.encrypted_id,
        enc_cred.iv,
        Some(iv_chain_a),
    )
    .await?;

    // Block 2: decrypt `enc_pin` in place with iv_chain_a; snapshot
    // ciphertext into iv_chain_b for use as block 3's IV.
    pal.aes_cbc_enc_dec_in_place(
        io,
        AesOp::Decrypt,
        aes_key,
        enc_cred.encrypted_pin,
        iv_chain_a,
        Some(iv_chain_b),
    )
    .await?;

    // Blocks 3-5: decrypt `enc_seed` (48 bytes = 3 AES blocks) in
    // place with iv_chain_b.  No subsequent block needs the IV-out.
    pal.aes_cbc_enc_dec_in_place(
        io,
        AesOp::Decrypt,
        aes_key,
        enc_cred.encrypted_seed,
        iv_chain_b,
        None,
    )
    .await
}

/// Envelopes `mk_session` under `bk_session` and encodes the full
/// response — header (with `sess_id = Some`), `sess_id`,
/// `short_app_id`, and the `bmk_session` blob — into a DMA buffer.
///
/// Uses the encoder-frame-then-fill pattern: query the BMK envelope
/// length first, reserve a response buffer with that exact size, then
/// fill the `bmk_session` slot in place.
#[allow(clippy::too_many_arguments)]
async fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    hdr: &DdiReqHdr,
    sess_id: HsmSessId,
    bk_session: &DmaBuf,
    mk_session: &DmaBuf,
    svn: u64,
    bks2_id: u16,
) -> HsmResult<&'p DmaBuf> {
    let bmk_metadata = DdiMaskedKeyMetadata {
        svn,
        key_type: DdiKeyType::AesCbc256Hmac384,
        key_attributes: HsmVaultKeyAttrs::new().into(),
        bks2_index: Some(bks2_id),
        rsvd: None,
        key_label: SMK_KEY_LABEL,
        key_length: BK_LEN as u16,
    };

    let bmk_len = mask(pal, io, bk_session, mk_session, &bmk_metadata, None).await?;

    // OpenSession does not model an app-vault concept; the reference
    // firmware uses `short_app_id` as the user vault id.  Tests on the
    // std PAL do not assert on the value, so we return 0 to mirror the
    // sim's placeholder.
    let short_app_id: u8 = 0;

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::OpenSession, u16::from(sess_id)),
            buf,
        )?;
        let layout =
            DdiOpenSessionResp::reserve(&mut encoder, u16::from(sess_id), short_app_id, bmk_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiOpenSessionResp::from_layout(resp, &layout);

    // `key_masking::cbc::mask` requires `out[..total_len]` to be zero
    // on entry.
    frame.bmk_session.fill(0);
    mask(
        pal,
        io,
        bk_session,
        mk_session,
        &bmk_metadata,
        Some(frame.bmk_session),
    )
    .await?;
    Ok(resp)
}

/// Pack a [`DdiApiRev`] into the 8-byte little-endian form expected by
/// [`HsmSessionManager::session_create`].
fn pack_api_rev(rev: azihsm_fw_ddi_mbor_types::DdiApiRev) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&rev.major.to_le_bytes());
    out[4..].copy_from_slice(&rev.minor.to_le_bytes());
    out
}
