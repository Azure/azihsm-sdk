// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EstablishCredential command handler.
//!
//! Authenticates the host's encrypted credential using an ECDH-derived
//! key, stores the decrypted user ID and PIN, then provisions the
//! partition with a masking key (MK) and returns a BMK envelope for
//! later recovery.

use core::ops::Deref;

use azihsm_fw_core_crypto_masked_key::mask_cbc;
use azihsm_fw_core_crypto_masked_key::unmask_cbc_in_place;
use azihsm_fw_ddi_mbor_types::establish_credential::DdiEstablishCredentialReq;
use azihsm_fw_ddi_mbor_types::establish_credential::DdiEstablishCredentialResp;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_ddi_mbor_types::open_session::DdiEncryptedEstablishCredential;
use azihsm_fw_ddi_mbor_types::DdiKeyType;

use super::*;

// ── Field sizes ──────────────────────────────────────────────────────

/// BK3 plaintext length in bytes — matches `BK3_LEN` in
/// [`init_bk3`](super::init_bk3).
const BK3_LEN: usize = 48;

// ── Labels and metadata ──────────────────────────────────────────────

/// KBKDF label for the BK3 session key derivation.
const SESSION_BK3_LABEL: &[u8] = b"SESSION_BK3";

/// KBKDF label prefix for the partition `BK` derivation.  The full
/// label is `PARTITION_BK_LABEL ‖ body.pota_pub_key.raw`.
const PARTITION_BK_LABEL: &[u8] = b"PARTITION_BK";

/// Cleartext label embedded in the BMK metadata identifying the
/// wrapped key as the partition masking key (MK).
const MK_KEY_LABEL: &[u8] = b"MK";

/// PKCS#11-style vault attributes recorded on the partition `MK`.
///
/// `MK` is the per-partition masking key used to envelope subordinate
/// vault keys.  It is created (or imported) here and persisted via
/// [`HsmPart::part_set_mk_key_id`].  It never leaves the device.
///
/// The `local` bit is intentionally cleared even on the
/// generate-fresh path so the same blob round-trips through the
/// reimport-from-BMK path bit-identically.
const MK_VAULT_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_internal(true)
    .with_never_extractable(true)
    .with_encrypt(true)
    .with_decrypt(true);

/// Handle `DdiEstablishCredentialCmd`.
///
/// Implements protocol steps 1-13 (step 12 — optional unwrapping key
/// import — is rejected up-front with `UnsupportedCmd` until the
/// underlying vault primitives land).
///
/// All partition state mutations are batched into the final
/// atomic-commit block; any failure in steps 8-13 leaves partition
/// state untouched apart from the nonce refresh in step 6 (which is
/// required even on failure to prevent replay of the authenticated
/// request).
pub(crate) async fn establish_credential<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let mut body: DdiEstablishCredentialReq = decoder.decode_data()?;

    let _lock = pal.partition_lock(io).await?;

    check_fail_fast(pal, io, &body)?;

    // ── Step 2: POTA signature verification ──────────────────────────
    verify_pota_signature(pal, io, body.pota_pub_key.raw, body.pota_sig).await?;

    // ── Steps 3-4: ECDH + HKDF → 80-byte OKM (aes_key ‖ hmac_key) ────
    let okm = pal.dma_alloc(io, BK_LEN)?;
    derive_credential_keys(
        pal,
        io,
        body.pub_key.raw,
        body.encrypted_credential.nonce,
        okm,
    )
    .await?;
    // HMAC-SHA-384 key length matches the digest length; AES key is
    // the leading remainder of the 80-byte OKM.
    let (aes_key, hmac_key) = okm.split_at(okm.len() - HsmHashAlgo::Sha384.digest_len());

    // ── Step 5: HMAC verify the credential ───────────────────────────
    //
    // The partition lock acquired above serializes all state-modifying
    // handlers on this partition, and the initial fail-fast above ran
    // under the same lock, so no further nonce or credential-set
    // re-check is needed here.
    verify_credential_hmac(pal, io, &body.encrypted_credential, hmac_key).await?;

    // ── Step 6: Reset nonce, then AES-CBC decrypt id and pin ─────────
    //
    // Reset the partition nonce *before* decrypting / committing the
    // credential so the nonce that authenticated this request cannot
    // be replayed if a later step fails partway through.
    pal.part_nonce_refresh(io)?;
    decrypt_credential(pal, io, &mut body.encrypted_credential, aes_key).await?;

    // Fail-fast on null id or pin before doing the rest of the
    // provisioning work.  `part_set_credential` (called at the final
    // commit) also rejects null credentials; this early check
    // preserves the historical error ordering and avoids wasting
    // BK3 / MK / BMK derivation effort on requests we know will be
    // rejected.
    let id: &[u8] = body.encrypted_credential.encrypted_id.deref();
    let pin: &[u8] = body.encrypted_credential.encrypted_pin.deref();
    if id == [0u8; CRED_FIELD_LEN] || pin == [0u8; CRED_FIELD_LEN] {
        return Err(HsmError::InvalidAppCredentials);
    }

    // Credential commit (`part_set_credential` / `part_clear_establish_cred_key`)
    // and BK3 session commit (`part_set_bk3_session`) are intentionally
    // deferred to the final atomic-commit block at the end of this
    // handler.  Deferring lets a failure in steps 8-13 (e.g. tampered
    // `masked_bk3`) leave the partition in its pre-call state — apart
    // from the refreshed nonce — so the host can retry without re-
    // running `InitBk3` or losing access to the establish-cred
    // encryption key.

    // ── Step 8: Unmask BK3 ───────────────────────────────────────────
    let bk3 = pal.dma_alloc(io, BK3_LEN)?;
    unmask_partition_bk3(pal, io, body.masked_bk3, bk3).await?;

    // ── Step 9: Derive BK3 session key ───────────────────────────────
    let bk3_session = pal.dma_alloc(io, BK3_LEN)?;
    derive_bk3_session(pal, io, bk3, bk3_session).await?;
    // Note: `part_set_bk3_session` is deferred to the final atomic
    // commit below so a failure in steps 10-13 leaves the partition's
    // `bk3_session_set` flag unchanged.

    // ── Step 10: Derive partition BK ─────────────────────────────────
    let svn = pal.part_svn(io)?;
    let bks2_id = pal.part_bks2_id(io)?;
    let bk = pal.dma_alloc(io, BK_LEN)?;
    derive_partition_bk(pal, io, bk3, body.pota_pub_key.raw, svn, bks2_id, bk).await?;

    // ── Step 11: Provision the partition masking key (MK) ────────────
    //
    // TODO(svn-rotation): for cross-SVN/BKS lineage compatibility,
    // the recovery path should parse the cleartext metadata embedded
    // in `body.bmk` to retrieve the BMK's `svn`/`bks2_index` and
    // derive its `bk` with those selectors, instead of reusing the
    // `bk` derived from the current selectors in step 10.  Emu has a
    // single lineage so this is a no-op today.
    let mk_guard = provision_mk(pal, io, body.bmk, bk).await?;
    let mk_key_id = mk_guard.key_id();

    // ── Step 13: Envelope MK into BMK and emit the response ──────────
    let resp = encode_bmk_response(pal, io, hdr, bk, mk_key_id, svn, bks2_id).await?;

    // ── Atomic commit ────────────────────────────────────────────────
    //
    // All partition-state mutations are batched here so that any
    // failure in steps 8-13 (e.g. tampered `masked_bk3`, derivation
    // failure, response encode failure) leaves the partition in its
    // pre-call state — apart from the nonce refresh in step 6, which
    // is required even on failure to prevent replay of the original
    // request.
    //
    // Under the partition lock, every call below is effectively
    // infallible:
    // - `part_set_credential` validates length and non-zero id/pin;
    //   both are pre-checked above so this cannot fail here.
    // - `part_set_bk3_session` validates length (48 B); `bk3_session`
    //   is allocated with `BK3_LEN = 48`.
    // - `part_clear_establish_cred_key` and `part_set_mk_key_id` only
    //   fail if the partition is disabled, which is prevented by the
    //   partition-enabled check at the start of `handle_io`.
    //
    // `part_set_credential` is committed first so a (theoretical)
    // failure here triggers `mk_guard`'s Drop, which removes the
    // provisional MK vault entry. The establish-cred encryption key
    // is cleared only after the credential commit succeeds, so the
    // host can always retry on failure.
    pal.part_set_credential(io, id, pin)?;
    pal.part_set_bk3_session(io, bk3_session)?;
    pal.part_clear_establish_cred_key(io)?;
    pal.part_set_mk_key_id(io, mk_key_id)?;
    mk_guard.dismiss();

    Ok(resp)
}

/// Performs all fail-fast checks before any cryptographic work.
///
/// Must be called under the partition lock so the partition-state
/// checks (nonce, credential-set, provisioned) stay consistent with
/// the atomic-commit gates at the end of the handler.
///
/// Errors are returned in the protocol-preferred order:
/// - `NonceMismatch` — request's authenticated nonce no longer
///   matches the partition's current nonce.
/// - `VaultAppLimitReached` — user credential is already set.
/// - `PartitionAlreadyProvisioned` — partition already has a
///   masking key.
/// - `InvalidKeyType` — `pub_key` / `pota_pub_key` are not P-384.
/// - `InvalidArg` — raw key / signature lengths don't match P-384
///   (`pub_key.raw`, `pota_pub_key.raw`, `pota_sig`).  The MBOR
///   decoder already bounds `masked_bk3` / `bmk` to `max_len = 1024`
///   per the type definition, so no separate upper-bound check is
///   needed for those.
/// - `UnsupportedCmd` — optional unwrapping-key import was requested
///   (not yet implemented; TODO: step 12).
fn check_fail_fast<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    body: &DdiEstablishCredentialReq<'_>,
) -> HsmResult<()> {
    pal.part_verify_nonce(io, body.encrypted_credential.nonce)?;

    if pal.part_is_credential_set(io)? {
        return Err(HsmError::VaultAppLimitReached);
    }
    if pal.part_is_provisioned(io)? {
        return Err(HsmError::PartitionAlreadyProvisioned);
    }

    if body.pub_key.key_kind != DdiKeyType::Ecc384Public
        || body.pota_pub_key.key_kind != DdiKeyType::Ecc384Public
    {
        return Err(HsmError::InvalidKeyType);
    }

    let p384_pub_key_len = HsmEccCurve::P384.pub_key_len();
    if body.pub_key.raw.len() != p384_pub_key_len
        || body.pota_pub_key.raw.len() != p384_pub_key_len
        || body.pota_sig.len() != HsmEccCurve::P384.sig_len()
    {
        return Err(HsmError::InvalidArg);
    }

    if !body.masked_unwrapping_key.is_empty() {
        return Err(HsmError::UnsupportedCmd);
    }

    Ok(())
}

/// Verifies the POTA signature over the partition identity public key.
///
/// The signature is computed by the host over
/// `SHA-384( 0x04 ‖ x ‖ y )`, the SEC1-uncompressed form of the
/// partition identity P-384 public key (big-endian).  We materialize
/// the same 97-byte form locally and verify the supplied signature
/// against it.
async fn verify_pota_signature<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    signer_pub_key_raw: &DmaBuf,
    signature_raw: &DmaBuf,
) -> HsmResult<()> {
    // `part_id_pub_key` returns the raw `x ‖ y` form (96 B); prepend
    // the SEC1 `0x04` uncompressed-point tag in a fresh DMA buffer.
    let id_pub_key_len = pal.part_id_pub_key(io, None)?;
    let id_uncompressed = pal.dma_alloc(io, id_pub_key_len + 1)?;
    id_uncompressed[0] = 0x04;
    pal.part_id_pub_key(io, Some(&mut id_uncompressed[1..]))?;

    let digest = pal.dma_alloc(io, HsmHashAlgo::Sha384.digest_len())?;
    pal.hash(io, HsmHashAlgo::Sha384, id_uncompressed, digest, true)
        .await?;

    if !pal
        .ecc_verify(
            io,
            HsmEccCurve::P384,
            signer_pub_key_raw,
            digest,
            signature_raw,
        )
        .await?
    {
        return Err(HsmError::EccVerifyFailed);
    }
    Ok(())
}

/// Derives the AES-256 ‖ HMAC-SHA-384 OKM used to authenticate and
/// decrypt the credential payload, writing the result into `okm_out`.
///
/// Performs ECDH-P384 between the device's `EstablishCred` private key
/// (held in the vault) and the host's ephemeral public key, then
/// HKDF-SHA-384 with empty salt and `info = nonce` to produce the
/// 80-byte OKM.  The caller splits the OKM into a 32-byte AES key
/// (low half) and a 48-byte HMAC key (high half).
///
/// `okm_out` must be exactly [`BK_LEN`] (80) bytes.
async fn derive_credential_keys<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    host_eph_pub_key_raw: &DmaBuf,
    nonce: &DmaBuf,
    okm_out: &mut DmaBuf,
) -> HsmResult<()> {
    let est_cred_key_id = pal
        .part_establish_cred_key_id(io)?
        .ok_or(HsmError::KeyNotFound)?;

    let secret = pal.dma_alloc(io, HsmEccCurve::P384.secret_len())?;
    {
        let priv_key = pal.vault_key(io, est_cred_key_id)?;
        pal.ecdh_derive(
            io,
            HsmEccCurve::P384,
            priv_key,
            host_eph_pub_key_raw,
            secret,
        )
        .await?;
    }

    // HKDF-Extract with empty salt (RFC 5869 §2.2).  `split_at_mut(0)`
    // yields a zero-length DmaBuf for the salt argument.
    let prk_area = pal.dma_alloc(io, HsmHashAlgo::Sha384.digest_len())?;
    let (empty_salt, prk) = prk_area.split_at_mut(0);
    pal.hkdf_extract(io, HsmHashAlgo::Sha384, empty_salt, secret, prk)
        .await?;

    pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, nonce, okm_out)
        .await
}

/// HMAC-SHA-384 verifies the encrypted credential's tag over
/// `enc_id ‖ enc_pin ‖ iv ‖ nonce`.
///
/// `hmac_key` must be at least 48 bytes (the HMAC-SHA-384 key).
async fn verify_credential_hmac<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    enc_cred: &DdiEncryptedEstablishCredential<'_>,
    hmac_key: &DmaBuf,
) -> HsmResult<()> {
    let id_len = enc_cred.encrypted_id.len();
    let pin_len = enc_cred.encrypted_pin.len();
    let iv_len = enc_cred.iv.len();
    let nonce_len = enc_cred.nonce.len();

    let hmac_input = pal.dma_alloc(io, id_len + pin_len + iv_len + nonce_len)?;
    let (id_dst, rest) = hmac_input.split_at_mut(id_len);
    let (pin_dst, rest) = rest.split_at_mut(pin_len);
    let (iv_dst, nonce_dst) = rest.split_at_mut(iv_len);
    id_dst.copy_from_slice(enc_cred.encrypted_id);
    pin_dst.copy_from_slice(enc_cred.encrypted_pin);
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

/// AES-CBC-256 decrypts the host-supplied `enc_id` and `enc_pin`
/// **in place** inside the request buffer.
///
/// The host (`crates/cred_encrypt`) encrypts id and pin with a single
/// mutable AES-CBC stream under `iv = enc_cred.iv`:
///
/// - Block 1 ciphertext = `enc_id` = `AES_E(aes_key, id XOR iv)`
/// - Block 2 ciphertext = `enc_pin` = `AES_E(aes_key, pin XOR enc_id)`
///
/// Decrypting block 2 needs `enc_id`'s **ciphertext** as the chaining
/// IV.  We use the AES engine's `iv_out` parameter to snapshot that
/// ciphertext into a fresh 16-byte DMA buffer *before* in-place
/// decryption overwrites `enc_id` with its plaintext, then feed the
/// snapshot back as `iv_in` for the second call.  Both 16-byte fields
/// end up overwritten with their respective plaintexts inside the
/// request buffer — no scratch buffer for ciphertext is needed.
async fn decrypt_credential<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    enc_cred: &mut DdiEncryptedEstablishCredential<'_>,
    aes_key: &DmaBuf,
) -> HsmResult<()> {
    let iv_chain = pal.dma_alloc(io, enc_cred.iv.len())?;

    // Block 1: AES-CBC decrypt `enc_id` in place, snapshotting the
    // original ciphertext into `iv_chain` for use as the next IV.
    pal.aes_cbc_enc_dec_in_place(
        io,
        AesOp::Decrypt,
        aes_key,
        enc_cred.encrypted_id,
        enc_cred.iv,
        Some(iv_chain),
    )
    .await?;

    // Block 2: AES-CBC decrypt `enc_pin` in place with `iv_chain`.
    pal.aes_cbc_enc_dec_in_place(
        io,
        AesOp::Decrypt,
        aes_key,
        enc_cred.encrypted_pin,
        iv_chain,
        None,
    )
    .await
}

/// Unmasks the partition `BK3` blob in place using `BK_BOOT` and
/// writes the 48-byte recovered plaintext into `bk3_out`.
///
/// `masked_bk3` is the envelope produced by a prior `InitBk3` call:
/// BK3 plaintext sealed under the partition's `BK_BOOT` (an 80-byte
/// AES-CBC-256 + HMAC-SHA-384 masking key).
///
/// `unmask_cbc_in_place` decrypts the ciphertext slot inside the
/// blob in place, so this helper takes the blob as `&mut DmaBuf` and
/// the caller passes `body.masked_bk3` (whose decoded byte-slice
/// field is mutable — see the MBOR mut-decoder refactor) directly.
/// No staging allocation or input copy is needed.  After unmask, the
/// 48-byte BK3 plaintext is copied out to `bk3_out` so the caller
/// can hold it for the remaining handler steps.
///
/// `bk3_out` must be exactly [`BK3_LEN`] (48) bytes.
async fn unmask_partition_bk3<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    masked_bk3: &mut DmaBuf,
    bk3_out: &mut DmaBuf,
) -> HsmResult<()> {
    let bk_boot_len = pal.part_bk_boot(io, None)?;
    let bk_boot = pal.dma_alloc(io, bk_boot_len)?;
    pal.part_bk_boot(io, Some(bk_boot))?;

    let layout = unmask_cbc_in_place(pal, io, bk_boot, masked_bk3).await?;
    if layout.plaintext_max_len < BK3_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    bk3_out
        .copy_from_slice(&masked_bk3[layout.plaintext_offset..layout.plaintext_offset + BK3_LEN]);
    Ok(())
}

/// Derives the 48-byte BK3 session key into `bk3_session_out`.
///
/// SP 800-108 KBKDF with HMAC-SHA-384 keyed on `bk3`,
/// `label = "SESSION_BK3"`, empty `context`, 48-byte output.
///
/// `bk3_session_out` must be exactly [`BK3_LEN`] (48) bytes.
async fn derive_bk3_session<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    bk3: &DmaBuf,
    bk3_session_out: &mut DmaBuf,
) -> HsmResult<()> {
    let session_label = pal.dma_alloc(io, SESSION_BK3_LABEL.len())?;
    session_label.copy_from_slice(SESSION_BK3_LABEL);

    // Empty 0-length `&DmaBuf` for `context` — borrowed off `bk3` to
    // avoid a separate DMA allocation just for an empty buffer.
    let (empty_context, _) = bk3.split_at(0);

    pal.sp800_108_kdf(
        io,
        HsmHashAlgo::Sha384,
        bk3,
        session_label,
        empty_context,
        bk3_session_out,
    )
    .await
}

/// Derives the 80-byte partition `BK` into `bk_out`.
///
/// SP 800-108 KBKDF-HMAC-SHA-384 keyed on `bk3` with
/// `label = "PARTITION_BK" ‖ signer_pub_key` and
/// `context = BKS1 ‖ BKS2` (contributed by the PAL via
/// [`HsmPart::derive_masking_key`]).
///
/// [`HsmPart::derive_masking_key`] takes `label: &[u8]` (not
/// `&DmaBuf`), so the label is built on the stack — no DMA alloc
/// needed for it.
///
/// `signer_pub_key` must be exactly 96 bytes (P-384 raw `x ‖ y`).
/// `bk_out` must be exactly [`BK_LEN`] (80) bytes.
async fn derive_partition_bk<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    bk3: &DmaBuf,
    signer_pub_key: &DmaBuf,
    svn: u64,
    bks2_id: u16,
    bk_out: &mut DmaBuf,
) -> HsmResult<()> {
    let mut bk_label = [0u8; PARTITION_BK_LABEL.len() + 96];
    bk_label[..PARTITION_BK_LABEL.len()].copy_from_slice(PARTITION_BK_LABEL);
    bk_label[PARTITION_BK_LABEL.len()..].copy_from_slice(signer_pub_key);

    pal.derive_masking_key(io, bk3, &bk_label, &[], svn, bks2_id, bk_out)
        .await
}

/// Provisions the partition masking key (MK) in the vault.
///
/// - **Empty `bmk`**: first ever EstablishCredential on this
///   partition.  Generate a fresh 80-byte MK from the on-device
///   CSPRNG and land it in the vault.
/// - **Non-empty `bmk`**: host is replaying a previously recorded
///   BMK after a reset.  Recover MK by authenticated AES-CBC unmask
///   under `bk` (the partition `BK` from step 10), performed in
///   place inside the request buffer — the caller passes
///   `body.bmk` (whose decoded byte-slice field is mutable — see
///   the MBOR mut-decoder refactor) directly.  No staging
///   allocation or input copy is needed; `vault_key_create` copies
///   the recovered MK plaintext into vault storage.
///
/// Both paths land MK in the vault via [`HsmVault::vault_key_create`]
/// and return an RAII guard so any subsequent failure rolls the
/// provisional entry back.
async fn provision_mk<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    bmk: &mut DmaBuf,
    bk: &DmaBuf,
) -> HsmResult<<P as HsmVault>::KeyGuard<'p>> {
    if bmk.is_empty() {
        let mk_buf = pal.dma_alloc(io, BK_LEN)?;
        pal.rng_fill_bytes(io, mk_buf)?;
        return pal.vault_key_create(
            io,
            mk_buf,
            HsmVaultKeyKind::MaskingKey,
            None,
            MK_VAULT_ATTRS,
            &[],
        );
    }

    let layout = unmask_cbc_in_place(pal, io, bk, bmk).await?;
    if layout.plaintext_max_len < BK_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    let mk_pt = &bmk[layout.plaintext_offset..layout.plaintext_offset + BK_LEN];
    pal.vault_key_create(
        io,
        mk_pt,
        HsmVaultKeyKind::MaskingKey,
        None,
        MK_VAULT_ATTRS,
        &[],
    )
}

/// Envelopes the vault-resident `MK` (referenced by `mk_key_id`) under
/// `bk`, reserves the response frame, and writes the BMK envelope into
/// it.  Returns the response buffer.
///
/// On-wire metadata layout (binds the import path's expectations):
///
/// - `key_attributes` — zero blob.  The on-wire metadata advertises
///   **no** PKCS#11 attributes; the import path re-applies
///   [`MK_VAULT_ATTRS`] when bringing MK back into the vault.
/// - `bks2_index = Some(bks2_id)` — current selector; identifies
///   which BKS2 row anchors `bk`.
/// - `key_label = b"MK"` — fixed role tag.
/// - `key_length = BK_LEN` — plaintext length before AES-CBC pad.
async fn encode_bmk_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    hdr: &DdiReqHdr,
    bk: &DmaBuf,
    mk_key_id: HsmKeyId,
    svn: u64,
    bks2_id: u16,
) -> HsmResult<&'p DmaBuf> {
    let bmk_metadata = DdiMaskedKeyMetadata {
        svn,
        key_type: DdiKeyType::AesCbc256Hmac384,
        key_attributes: HsmVaultKeyAttrs::new().into(),
        bks2_index: Some(bks2_id),
        rsvd: None,
        key_label: MK_KEY_LABEL,
        key_length: BK_LEN as u16,
    };

    // Borrow MK from the vault so `mask_cbc` reads it through a
    // `&DmaBuf` view rather than retaining the original input buffer.
    let mk_dma = pal.vault_key(io, mk_key_id)?;

    // Size-query the BMK envelope length (no crypto performed).
    let bmk_len = mask_cbc(pal, io, bk, mk_dma, &bmk_metadata, None).await?;

    // Reserve the response buffer (encoder-frame-then-fill pattern).
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder =
            super::encode_resp_hdr(&super::success_hdr(hdr, DdiOp::EstablishCredential), buf)?;
        let layout = DdiEstablishCredentialResp::reserve(&mut encoder, bmk_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiEstablishCredentialResp::from_layout(resp, &layout);

    // `mask_cbc` requires `out[..total_len]` to be zero on entry; the
    // MBOR `reserve_offset` path advances the cursor without clearing
    // the reserved data region, so explicitly zero it here.
    frame.bmk.fill(0);
    mask_cbc(pal, io, bk, mk_dma, &bmk_metadata, Some(frame.bmk)).await?;
    Ok(resp)
}
