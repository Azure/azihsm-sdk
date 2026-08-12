// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `HkdfDerive` command handler.
//!
//! Within an open session, derive key material from a caller-held
//! **masked** ECDH shared secret (from [`EcdhDerive`](super::ecdh_derive))
//! via HKDF (RFC 5869: Extract-then-Expand), and return the derived key as
//! a **masked** blob under the requested scope's masking key.  The input
//! secret is unmasked **in place** in the request buffer (no scratch
//! copy); its kind confirms it is an ECDH shared secret.  This is the TBOR
//! analogue of MBOR `HkdfDerive`, re-masking the derived key instead of
//! vaulting it.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use azihsm_fw_core_crypto_key_masking::aead::mask;
use azihsm_fw_core_crypto_key_masking::aead::masked_blob_len;
use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_core_crypto_key_masking::aead::AeadAlg;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_ddi_tbor_types::HashAlgo;
use azihsm_fw_ddi_tbor_types::KdfKeyType;
use azihsm_fw_ddi_tbor_types::TborHkdfDeriveReq;
use azihsm_fw_ddi_tbor_types::TborHkdfDeriveResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyScope;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartState;

use super::resolve_masking_key;
use super::validate_active_session;
use crate::part_state;

/// Envelope key-label recorded in the derived-key masked blob's
/// `MaskedKeyMetadata`.
const HKDF_KEY_LABEL: &[u8] = b"HkdfKey";

/// Which attribute family the derived key is created with — AES keys carry
/// `encrypt`/`decrypt`, HMAC keys carry `sign`/`verify`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KdfClass {
    /// AES key — `encrypt` / `decrypt` usage.
    Aes,
    /// (Variable-length) HMAC key — `sign` / `verify` usage.
    Hmac,
}

/// Resolved derivation target: the vault kind the derived bytes are
/// masked under, how many OKM bytes to derive, and the attribute family.
struct KdfTarget {
    /// Vault kind recorded in the masked blob's metadata.
    kind: HsmVaultKeyKind,
    /// Number of OKM bytes to derive (and mask).
    out_len: usize,
    /// Attribute family for the derived key.
    class: KdfClass,
}

impl KdfTarget {
    /// Attributes recorded in the derived-key masked blob's metadata
    /// (re-applied on unmask).  A KDF output is derived on-device (so
    /// `local`); AES keys `encrypt`/`decrypt`, HMAC keys `sign`/`verify`.
    /// `scope` records the lifecycle / visibility domain.
    fn attrs(&self, scope: HsmKeyScope) -> HsmVaultKeyAttrs {
        let base = HsmVaultKeyAttrs::new().with_local(true).with_scope(scope);
        match self.class {
            KdfClass::Aes => base.with_encrypt(true).with_decrypt(true),
            KdfClass::Hmac => base.with_sign(true).with_verify(true),
        }
    }
}

/// Map the wire [`HashAlgo`] onto the firmware hash algorithm.
fn hkdf_hsm_hash(algo: HashAlgo) -> HsmResult<HsmHashAlgo> {
    match algo {
        HashAlgo::Sha256 => Ok(HsmHashAlgo::Sha256),
        HashAlgo::Sha384 => Ok(HsmHashAlgo::Sha384),
        HashAlgo::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Reject an input secret whose kind is not an ECDH shared secret.
///
/// HKDF derives from an ECDH shared secret (`Secret256` / `Secret384` /
/// `Secret521`); any other kind is [`HsmError::InvalidKeyType`] — mirroring
/// MBOR's [`validate_input_secret`](crate::ddi::mbor::kdf::validate_input_secret).
fn validate_input_secret(kind: HsmVaultKeyKind) -> HsmResult<()> {
    match kind {
        HsmVaultKeyKind::Secret256 | HsmVaultKeyKind::Secret384 | HsmVaultKeyKind::Secret521 => {
            Ok(())
        }
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Resolve the requested output [`KdfKeyType`] (+ `key_length` for the
/// variable-length HMAC types) into the masking kind, OKM length, and
/// attribute family.
///
/// AES / fixed-HMAC outputs derive their natural length; the `VarHmac*`
/// outputs require an explicit non-zero `key_length` within the
/// per-variant range.  Mirrors MBOR's
/// [`resolve_target`](crate::ddi::mbor::kdf::resolve_target); unsupported
/// output types are [`HsmError::InvalidKeyType`].
fn resolve_target(key_type: KdfKeyType, key_length: u8) -> HsmResult<KdfTarget> {
    let aes = |kind, out_len| {
        Ok(KdfTarget {
            kind,
            out_len,
            class: KdfClass::Aes,
        })
    };
    let hmac = |kind, out_len| {
        Ok(KdfTarget {
            kind,
            out_len,
            class: KdfClass::Hmac,
        })
    };

    match key_type {
        KdfKeyType::Aes128 => aes(HsmVaultKeyKind::Aes128, 16),
        KdfKeyType::Aes192 => aes(HsmVaultKeyKind::Aes192, 24),
        KdfKeyType::Aes256 => aes(HsmVaultKeyKind::Aes256, 32),

        KdfKeyType::HmacSha256 => hmac(HsmVaultKeyKind::VarLenHmacSha256, 32),
        KdfKeyType::HmacSha384 => hmac(HsmVaultKeyKind::VarLenHmacSha384, 48),
        KdfKeyType::HmacSha512 => hmac(HsmVaultKeyKind::VarLenHmacSha512, 64),

        KdfKeyType::VarHmac256 => hmac(
            HsmVaultKeyKind::VarLenHmacSha256,
            var_hmac_len(key_length, 32, 64)?,
        ),
        KdfKeyType::VarHmac384 => hmac(
            HsmVaultKeyKind::VarLenHmacSha384,
            var_hmac_len(key_length, 48, 128)?,
        ),
        KdfKeyType::VarHmac512 => hmac(
            HsmVaultKeyKind::VarLenHmacSha512,
            var_hmac_len(key_length, 64, 128)?,
        ),

        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Validate a variable-length HMAC `key_length`.
///
/// A `0` length is [`HsmError::InvalidKeyType`] (the wire sentinel for "var
/// HMAC without an explicit length"); an out-of-range length is
/// [`HsmError::InvalidKeyLength`].
fn var_hmac_len(key_length: u8, min: usize, max: usize) -> HsmResult<usize> {
    let len = usize::from(key_length);
    if len == 0 {
        return Err(HsmError::InvalidKeyType);
    }
    if len < min || len > max {
        return Err(HsmError::InvalidKeyLength);
    }
    Ok(len)
}

/// Handle a TBOR `HkdfDerive` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it unmasks the IKM, derives the OKM, masks it, and returns
/// the blob.  Takes `req_buf: &mut DmaBuf` so the input secret can be
/// unmasked in place (`decode_mut`).
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborHkdfDeriveReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));
    let target_scope = HsmKeyScope(req.scope);
    validate_active_session(pal, io, sess_id)?;

    // The derived key is masked under `target_scope`; a non-`Session` scope
    // needs a masking key provisioned by `PartFinal` / the SD lifecycle.
    // Fail cheaply before any crypto work.
    if target_scope != HsmKeyScope::Session
        && part_state::part_state(pal, io)? != PartState::Initialized
    {
        return Err(HsmError::InvalidArg);
    }

    // Resolve the hash and derivation target (masking kind + OKM length)
    // up front so an unsupported algorithm / key type is rejected before
    // the IKM is unmasked.  `decode_mut` surfaces the inline scalars as raw
    // bytes; re-wrap them in their open-enums (any value is valid — an
    // unrecognized one is rejected by the mapping below).
    let algo = hkdf_hsm_hash(HashAlgo(req.hash_algo))?;
    let target = resolve_target(KdfKeyType(req.key_type), req.key_length)?;

    // Platform identity bound into the derived-key blob (anti-rollback on
    // re-import).
    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    let attrs = target.attrs(target_scope);

    // Optional HKDF inputs: an empty buffer selects the RFC 5869 default
    // (all-zero) salt / omits the info.  These borrow disjoint request
    // fields from `masked_secret`, so they coexist with the in-place
    // unmask below.
    let salt = (!req.salt.is_empty()).then_some(req.salt);
    let info = (!req.info.is_empty()).then_some(req.info);

    // The scope that masked the IKM is recorded (cleartext, tag-bound) in
    // its blob metadata; resolve its masking key before unmasking.  The
    // peek borrow is transient — it ends before the in-place unmask.
    let scope_ikm = peek_metadata(req.masked_secret)?.usage_flags().scope();
    let masking_key_ikm = resolve_masking_key(pal, io, scope_ikm, sess_id)?;

    // Unmask the IKM in place, derive, and mask the OKM inside a block that
    // yields a `Result`, so **every** post-unmask path (success or error)
    // falls through to the `masked_secret` wipe below — the recovered IKM
    // must never survive in the request buffer.
    let outcome: HsmResult<&'p DmaBuf> = async {
        let view = unmask(pal, io, masking_key_ikm, req.masked_secret).await?;
        validate_input_secret(view.key_kind)?;
        if !view.key_attrs.derive() {
            return Err(HsmError::InvalidPermissions);
        }

        let masked_len = masked_blob_len(AeadAlg::AesGcm256, target.out_len);

        // Build the response with the masked-key slot reserved; the derived
        // key is masked straight into it below.
        let resp = pal.dma_alloc_var(io, |buf| {
            let frame = TborHkdfDeriveResp::encode(buf, 0, false)?
                .masked_key_reserve(masked_len)?
                .finish();
            Ok(frame.as_bytes().len())
        })?;
        {
            let out = TborHkdfDeriveResp::decode_mut(resp)?;
            pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
                // Resolve the target masking key and staging label BEFORE
                // deriving, so that once `prk` / `okm` hold key material the
                // only remaining fallible step is `mask` — whose result is
                // bound (not `?`-propagated) so every path reaches the
                // scratch wipes.  Scope exit only resets the bump watermark;
                // it does not zero freed memory.
                let masking_key_target = resolve_masking_key(pal, io, target_scope, sess_id)?;
                let key_label = alloc.dma_alloc(HKDF_KEY_LABEL.len())?;
                key_label.copy_from_slice(HKDF_KEY_LABEL);
                let params = MaskParams {
                    key_kind: target.kind,
                    key_attrs: attrs,
                    svn,
                    owner_seed_id: owner,
                    key_label,
                };

                // `prk` and `okm` are allocated separately (each `dma_alloc`
                // is independently 4-byte aligned, which the crypto DMA
                // engine requires); `okm.len()` is caller-controlled and
                // need not be 4-aligned.
                let prk = alloc.dma_alloc(algo.digest_len())?;
                let okm = alloc.dma_alloc(target.out_len)?;
                let derive_and_mask = async {
                    pal.hkdf_extract(io, algo, salt, view.target_key, prk)
                        .await?;
                    pal.hkdf_expand(io, algo, prk, info, okm).await?;
                    mask(
                        pal,
                        io,
                        alloc,
                        AeadAlg::AesGcm256,
                        masking_key_target,
                        &params,
                        okm,
                        Some(out.masked_key),
                    )
                    .await
                    .map(|_| ())
                }
                .await;
                prk.zeroize();
                okm.zeroize();
                derive_and_mask
            })
            .await?;
        }
        // Coerce the `&mut` response buffer to a shared `&DmaBuf` (preserving
        // the `'p` allocator lifetime) so the async block's output matches
        // the handler's `&'p DmaBuf` return.
        let resp: &'p DmaBuf = resp;
        Ok(resp)
    }
    .await;

    // Scrub the recovered IKM plaintext from the request buffer.
    req.masked_secret.zeroize();
    outcome
}
