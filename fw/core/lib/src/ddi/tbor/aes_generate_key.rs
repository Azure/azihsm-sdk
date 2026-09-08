// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesGenerateKey` command handler.
//!
//! Within an open session, generate a fresh random AES key (128 / 192 /
//! 256 bits), mask it (AEAD-GCM-256) under the requested
//! [`KeyScope`](azihsm_fw_ddi_tbor_types::KeyScope)'s masking key, and
//! return the masked blob.  The key is **not** persisted on-device: the
//! caller holds the masked blob and passes it back to
//! [`AesEncryptDecrypt`](super::aes_encrypt_decrypt) (unmask-on-use).  This
//! is the TBOR analogue of MBOR `AesGenerateKey`, but with no vault
//! `key_id` / `key_tag`.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.  The scope's
//! masking key is resolved by [`resolve_masking_key`](super::resolve_masking_key):
//! `Session` scope uses the per-session masking key; `Ephemeral` / `Local`
//! / `SecurityDomain` use the partition / SD masking keys provisioned by
//! `PartFinal` / the SD lifecycle — an unavailable scope fails cheaply
//! before any key is generated.

use azihsm_fw_core_crypto_key_masking::aead::mask;
use azihsm_fw_core_crypto_key_masking::aead::masked_blob_len;
use azihsm_fw_core_crypto_key_masking::aead::AeadAlg;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_ddi_tbor_types::AesKeySize;
use azihsm_fw_ddi_tbor_types::KeyUsage;
use azihsm_fw_ddi_tbor_types::TborAesGenerateKeyReq;
use azihsm_fw_ddi_tbor_types::TborAesGenerateKeyResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
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

/// Map the wire [`AesKeySize`] onto the key length (bytes) and the AES
/// vault kind stamped into the masked blob's metadata.  An unrecognized
/// discriminant is rejected with [`HsmError::InvalidArg`].
fn aes_size_kind(size: AesKeySize) -> HsmResult<(usize, HsmVaultKeyKind)> {
    match size {
        AesKeySize::Aes128 => Ok((16, HsmVaultKeyKind::Aes128)),
        AesKeySize::Aes192 => Ok((24, HsmVaultKeyKind::Aes192)),
        AesKeySize::Aes256 => Ok((32, HsmVaultKeyKind::Aes256)),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Attributes recorded in the masked blob's metadata (re-applied on
/// unmask), derived from the host-requested [`KeyUsage`].  A generated AES
/// key carries exactly `ENCRYPT | DECRYPT` (mirrors MBOR
/// `key_attrs::for_aes`); any other usage is rejected.  `scope` records
/// the lifecycle / visibility domain selecting the masking key.
fn aes_key_attrs(scope: HsmKeyScope, usage: KeyUsage) -> HsmResult<HsmVaultKeyAttrs> {
    if usage.bits() != (KeyUsage::ENCRYPT | KeyUsage::DECRYPT) {
        return Err(HsmError::InvalidPermissions);
    }
    Ok(HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_encrypt(true)
        .with_decrypt(true)
        .with_scope(scope))
}

/// Handle a TBOR `AesGenerateKey` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it generates a key, masks it, and returns the blob.  It
/// makes no observable state change, so a concurrently-dispatched command
/// can neither observe it half-done nor require its rollback on failure.
/// The masked blob is written straight into the reserved response slot (no
/// scratch copy) and the raw key is wiped once masked.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborAesGenerateKeyReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));

    // Losslessly map the wire `KeyScope` onto the PAL `HsmKeyScope`
    // (byte-identical discriminants; unknown values round-trip and are
    // rejected by `resolve_masking_key`).
    let scope = HsmKeyScope(req.scope().0);
    validate_active_session(pal, io, sess_id)?;

    // Session-scoped keys are masked under the per-session masking key,
    // available to any Active session.  Every other scope's masking key is
    // provisioned by `PartFinal` / the SD lifecycle, so require an
    // `Initialized` partition to fail cheaply and clearly before keygen.
    if scope != HsmKeyScope::Session && part_state::part_state(pal, io)? != PartState::Initialized {
        return Err(HsmError::InvalidArg);
    }

    let (key_len, kind) = aes_size_kind(req.key_size())?;
    // Caller-supplied label stamped into the masked metadata (≤ 32 B,
    // bounded by the wire `max_len`); empty for an unlabeled key.
    let caller_label = req.key_label();
    // The masked-blob length is fixed by the key length (16 / 24 / 32 B →
    // 148 / 156 / 164 B), so the response slot can be reserved up front,
    // before any key material exists.
    let masked_len = masked_blob_len(AeadAlg::AesGcm256, key_len);

    // Platform identity that binds the masked blob (anti-rollback on
    // re-import): SVN (BKS1 lineage) and owner-seed id (BKS2 lineage).
    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    let attrs = aes_key_attrs(scope, req.key_usage())?;

    // Build the response with the masked-key slot reserved (no copy at
    // encode time).
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborAesGenerateKeyResp::encode(buf, 0, false)?
            .masked_key_reserve(masked_len)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    // Generate the key and mask it straight into the reserved slot.  The
    // `decode_mut` view is scoped so its borrow of `resp` ends before
    // `resp` is returned.
    {
        let out = TborAesGenerateKeyResp::decode_mut(resp)?;
        pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
            // Resolve the masking key and build the mask params *before*
            // generating any key material.  Every fallible step here (an
            // unsupported / unprovisioned scope, or the label allocation)
            // must reject before a key exists — both to match this handler's
            // contract that scope failures happen before keygen, and so no
            // early return can leave a raw key sitting in DMA scratch.
            let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
            let key_label = alloc.dma_alloc(caller_label.len())?;
            key_label.copy_from_slice(caller_label);
            let params = MaskParams {
                key_kind: kind,
                key_attrs: attrs,
                svn,
                owner_seed_id: owner,
                key_label,
            };

            // Generate the random AES key into scratch, then mask it
            // straight into the reserved response slot.  The generate +
            // mask run inside a block that yields a `Result`, so the raw
            // key is wiped on *every* path below — keygen failure, mask
            // failure, or a short write — before the error propagates;
            // scope rewind does not clear DMA memory.
            let key_buf = alloc.dma_alloc(key_len)?;
            let outcome = async {
                pal.aes_gen_key(io, key_buf).await?;
                let written = mask(
                    pal,
                    io,
                    alloc,
                    AeadAlg::AesGcm256,
                    masking_key,
                    &params,
                    key_buf,
                    Some(out.masked_key),
                )
                .await?;
                // `mask` returns the number of bytes written and leaves any
                // trailing bytes of the reserved slot untouched; the slot
                // was reserved to exactly `masked_len`, so a short write
                // would leave uninitialized response bytes.  Enforce a full
                // write (same guard as `unwrap_key` / `hmac_generate_key`).
                if written != masked_len {
                    return Err(HsmError::InternalError);
                }
                Ok(())
            }
            .await;
            key_buf.zeroize();
            outcome
        })
        .await?;
    }

    Ok(resp)
}
