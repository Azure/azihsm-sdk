// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EccGenerateKey` command handler.
//!
//! Within an open session, generate a fresh ECC keypair on the requested
//! NIST curve, mask the private key (AEAD-GCM-256) under the requested
//! scope's masking key, and return the masked blob plus the wire public
//! key.  The private key is **not** persisted on-device: the caller holds
//! the masked blob and passes it back to [`EccSign`](super::ecc_sign) /
//! [`EcdhDerive`](super::ecdh_derive) (unmask-on-use).  This is the TBOR
//! analogue of MBOR `EccGenerateKeyPair`, without a vault key id.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use azihsm_fw_core_crypto_key_masking::aead::mask;
use azihsm_fw_core_crypto_key_masking::aead::masked_blob_len;
use azihsm_fw_core_crypto_key_masking::aead::AeadAlg;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_ddi_tbor_types::EccCurve;
use azihsm_fw_ddi_tbor_types::KeyUsage;
use azihsm_fw_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_fw_ddi_tbor_types::TborEccGenerateKeyResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyScope;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;

use super::from_pal::ecc_private;
use super::resolve_masking_key;
use super::validate_active_session;
use crate::part_state;

/// Map the wire [`EccCurve`] onto the PAL's NIST curve selector.  Kept
/// local (single-use, wire→PAL direction) per the TBOR convention that
/// per-handler wire mappings live with their handler.
fn curve_from_wire(curve: EccCurve) -> HsmResult<HsmEccCurve> {
    match curve {
        EccCurve::P256 => Ok(HsmEccCurve::P256),
        EccCurve::P384 => Ok(HsmEccCurve::P384),
        EccCurve::P521 => Ok(HsmEccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Attributes recorded in the masked blob's metadata (re-applied on
/// unmask), derived from the host-requested [`KeyUsage`].  A generated ECC
/// private key is either a signing key (ECDSA) or a derivation key (ECDH)
/// — exactly one, matching the host contract; any other usage is rejected.
/// `scope` records the lifecycle / visibility domain.
fn ecc_key_attrs(scope: HsmKeyScope, usage: KeyUsage) -> HsmResult<HsmVaultKeyAttrs> {
    let sign = usage.sign();
    let derive = usage.derive();
    // Exactly one of sign/derive, and no other usage bit, is valid.
    if sign == derive || usage.bits() & !(KeyUsage::SIGN | KeyUsage::DERIVE) != 0 {
        return Err(HsmError::InvalidPermissions);
    }
    Ok(HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_sign(sign)
        .with_derive(derive)
        .with_scope(scope))
}

/// Handle a TBOR `EccGenerateKey` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it generates a keypair, masks the private key, and returns
/// the blob plus the public key.  The raw private key is wiped once masked.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborEccGenerateKeyReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    let scope = HsmKeyScope(req.scope().0);
    validate_active_session(pal, io, sess_id)?;

    // No partition-state pre-check: the masking key for `scope` is resolved
    // (and its availability validated per-scope) at mask time by
    // `resolve_masking_key`, which returns `UnsupportedKeyScope` for a scope
    // whose masking key has not been provisioned yet.  This mirrors
    // `EccSign` / `UnwrapKey`, which likewise defer scope validation to
    // masking-key resolution rather than gating on a coarse `part_state`.

    let curve: HsmEccCurve = curve_from_wire(req.curve())?;
    let kind = ecc_private(curve);
    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    let attrs = ecc_key_attrs(scope, req.key_usage())?;
    // Caller-supplied label stamped into the masked metadata (≤ 32 B,
    // bounded by the wire `max_len`); empty for an unlabeled key.
    let caller_label = req.key_label();

    // Generate the keypair into IO-scoped buffers sized from the curve's
    // wire lengths (the single source of truth for PAL-boundary buffers).
    let priv_key = pal.dma_alloc(io, curve.wire_priv_key_len())?;
    let pub_key = pal.dma_alloc(io, curve.wire_pub_key_len())?;

    // Generate the keypair and mask the private key into the response
    // inside a block that yields a `Result`, so **every** path (success or
    // error — keygen, length check, encode, or mask failure) falls through
    // to the `priv_key` wipe below.  The raw private scalar must never
    // survive in DMA scratch: scope exit only resets the bump watermark, it
    // does not zero freed memory.
    let outcome: HsmResult<&'p DmaBuf> = async {
        let (priv_len, pub_len) = pal
            .alloc_scoped_async(io, async |a| -> HsmResult<(usize, usize)> {
                pal.ecc_gen_keypair(
                    io,
                    a,
                    curve,
                    Some((&mut *priv_key, &mut *pub_key)),
                    HsmEccPct::SignVerify,
                )
                .await
            })
            .await?;
        // The wire lengths are fixed per curve; a mismatch is an internal bug.
        if priv_len != curve.wire_priv_key_len() || pub_len != curve.wire_pub_key_len() {
            return Err(HsmError::InternalError);
        }

        let masked_len = masked_blob_len(AeadAlg::AesGcm256, priv_len);

        // Build the response with the masked-key slot reserved and the
        // public key copied in; the masked private key is filled in place.
        let resp = pal.dma_alloc_var(io, |buf| {
            let frame = TborEccGenerateKeyResp::encode(buf, 0, false)?
                .masked_key_reserve(masked_len)?
                .pub_key(&pub_key[..pub_len])?
                .finish();
            Ok(frame.as_bytes().len())
        })?;

        // Mask the private key straight into the reserved response slot.
        {
            let out = TborEccGenerateKeyResp::decode_mut(resp)?;
            pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
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
                let written = mask(
                    pal,
                    io,
                    alloc,
                    AeadAlg::AesGcm256,
                    masking_key,
                    &params,
                    priv_key,
                    Some(out.masked_key),
                )
                .await?;
                // `mask` leaves any trailing bytes of the reserved slot
                // untouched; the slot was reserved to exactly `masked_len`,
                // so a short write would leave uninitialized response bytes.
                if written != masked_len {
                    return Err(HsmError::InternalError);
                }
                Ok(())
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

    // Scrub the raw private key from DMA scratch on every path.
    priv_key.zeroize();
    outcome
}
