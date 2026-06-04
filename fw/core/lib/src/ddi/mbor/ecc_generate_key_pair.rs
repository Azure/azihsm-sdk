// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EccGenerateKeyPair command handler.
//!
//! Within an open session, generate a fresh ECC keypair on the
//! requested NIST curve (P-256 / P-384 / P-521), persist the private
//! key in the partition vault — optionally session-scoped so it is
//! torn down by [`CloseSession`](super::close_session) — and return
//! the public key plus an opaque masked-key envelope the host may
//! re-import on a future session.

use azihsm_fw_ddi_mbor_types::ecc_generate_key_pair::DdiEccGenerateKeyPairReq;
use azihsm_fw_ddi_mbor_types::ecc_generate_key_pair::DdiEccGenerateKeyPairResp;
use azihsm_fw_ddi_mbor_types::DdiKeyType;

use super::*;

/// Handle `DdiEccGenerateKeyPairCmd`.
///
/// No `partition_lock` is needed: this handler does not perform any
/// multi-step read-then-mutate against partition state.  Its single
/// state mutation — `vault_key_create` — is sync and atomic.  A
/// concurrent `CloseSession` racing with our `ecc_gen_keypair` await
/// would just turn the subsequent vault create into a clean
/// `SessionNotFound` error, never a partial commit.
pub(crate) async fn ecc_generate_key_pair<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiEccGenerateKeyPairReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let pal_curve = super::from_ddi::curve(body.curve)?;
    let vault_kind = curve_to_vault_kind(pal_curve);
    let attrs = build_attrs_for_curve(pal_curve, &body.key_properties.key_metadata)?;

    // Session-only keys are anonymous — disallow a host-supplied
    // `key_tag` because the key cannot be looked up across sessions.
    // Matches `test_ecc_generate_session_only_key_with_key_tag`.
    if attrs.session() && body.key_tag.is_some() {
        return Err(HsmError::InvalidArg);
    }

    // ECC key generation follows the trait's query-alloc-use flow,
    // wrapped in a single scoped allocator: query reports the PAL's
    // per-curve deterministic sizes (raw HSM scalar for the private
    // key; wire-format LE public-key length), we allocate the
    // IO-lifetime output buffers, then use returns the same lengths.
    let (priv_key, pub_key, priv_len, pub_len) = pal
        .alloc_scoped_async(io, async |a| -> HsmResult<_> {
            let (priv_size, pub_size) = pal
                .ecc_gen_keypair(io, a, pal_curve, None, HsmEccPct::SignVerify)
                .await?;
            let priv_key = pal.dma_alloc(io, priv_size)?;
            let pub_key = pal.dma_alloc(io, pub_size)?;
            let (priv_len, pub_len) = pal
                .ecc_gen_keypair(
                    io,
                    a,
                    pal_curve,
                    Some((&mut *priv_key, &mut *pub_key)),
                    HsmEccPct::SignVerify,
                )
                .await?;
            Ok((priv_key, pub_key, priv_len, pub_len))
        })
        .await?;

    // Store the private key in the vault, session-scoped iff the
    // requested attrs say so.  RAII guard rolls the entry back if
    // the response encoding below fails.
    let session_binding = if attrs.session() {
        Some(HsmSessId::from(sess_id))
    } else {
        None
    };
    let guard = pal.vault_key_create(
        io,
        &priv_key[..priv_len],
        vault_kind,
        session_binding,
        attrs,
        body.key_properties.key_label,
    )?;
    let private_key_id: u16 = guard.key_id().into();

    // Build the response.  `masked_key` is the host's opaque
    // re-import blob; firmware-side masking against the session BK is
    // pending the corresponding `UnmaskKey` handler — emit an empty
    // placeholder for now so the response is wire-valid.
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::EccGenerateKeyPair, sess_id),
            buf,
        )?;
        let layout = DdiEccGenerateKeyPairResp::reserve(
            &mut encoder,
            private_key_id,
            DdiPublicKeyFrameParams {
                raw_len: pub_len,
                key_kind: curve_to_pub_key_kind(pal_curve),
            },
            0, /* masked_key length — empty placeholder */
        )?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiEccGenerateKeyPairResp::from_layout(resp, &layout);

    // PAL already emitted the public key in wire format (LE + P-521
    // padding), so copy directly without further reordering.
    frame.pub_key.raw.copy_from_slice(&pub_key[..pub_len]);

    // Commit the vault entry; response is now fully populated.
    let _ = guard.dismiss();

    Ok(resp)
}

/// Map a `HsmEccCurve` to its private [`HsmVaultKeyKind`].
fn curve_to_vault_kind(curve: HsmEccCurve) -> HsmVaultKeyKind {
    match curve {
        HsmEccCurve::P256 => HsmVaultKeyKind::Ecc256Private,
        HsmEccCurve::P384 => HsmVaultKeyKind::Ecc384Private,
        HsmEccCurve::P521 => HsmVaultKeyKind::Ecc521Private,
    }
}

/// Map a `HsmEccCurve` to the corresponding public-key DDI type.
fn curve_to_pub_key_kind(curve: HsmEccCurve) -> DdiKeyType {
    match curve {
        HsmEccCurve::P256 => DdiKeyType::Ecc256Public,
        HsmEccCurve::P384 => DdiKeyType::Ecc384Public,
        HsmEccCurve::P521 => DdiKeyType::Ecc521Public,
    }
}

/// Translate the requested `key_metadata` bitflags into a vault
/// attribute set.
///
/// Mirrors the host-side `DdiKeyProperties -> DdiTargetKeyProperties`
/// conversion: at most one logical usage is encoded in the metadata
/// (sign+verify, encrypt+decrypt, derive, or unwrap), and the session
/// flag is independent.  We re-derive the usage by inspecting the
/// individual bit flags so an inconsistent/empty metadata fails fast
/// with `InvalidPermissions`.
///
/// Internally-generated keys always carry `local = true` (mirrors
/// PKCS#11 `CKA_LOCAL`).
fn build_attrs_for_curve(
    curve: HsmEccCurve,
    metadata: &azihsm_fw_ddi_mbor_types::DdiTargetKeyMetadata,
) -> HsmResult<HsmVaultKeyAttrs> {
    let mut attrs = HsmVaultKeyAttrs::new().with_local(true);

    let sign_verify = metadata.sign() && metadata.verify();
    let encrypt_decrypt = metadata.encrypt() && metadata.decrypt();
    let derive = metadata.derive();
    let unwrap = metadata.unwrap();
    let wrap = metadata.wrap();

    // Exactly one usage; the host-side helper ensures this, so a
    // multi-usage request is malformed.  `wrap` is folded into the
    // usage count even though no curve currently allows it, so that
    // `sign+verify+wrap` is rejected as multi-usage rather than
    // silently treated as plain sign+verify.
    let usage_count = (sign_verify as u8)
        + (encrypt_decrypt as u8)
        + (derive as u8)
        + (unwrap as u8)
        + (wrap as u8);
    if usage_count != 1 {
        return Err(HsmError::InvalidPermissions);
    }

    // ECC keys can sign / verify / derive (ECDH).  EncryptDecrypt,
    // Unwrap, and Wrap are not valid usages for an ECC key — let
    // the curve dictate which usage flags are accepted, matching
    // the reference firmware's `Kind::allows_usage` check.
    let _ = curve; // all three NIST curves currently allow the same usages
    if encrypt_decrypt || unwrap || wrap {
        return Err(HsmError::InvalidPermissions);
    }

    if sign_verify {
        attrs = attrs.with_sign(true).with_verify(true);
    }
    if derive {
        attrs = attrs.with_derive(true);
    }

    if metadata.session() {
        attrs = attrs.with_session(true);
    }

    Ok(attrs)
}
