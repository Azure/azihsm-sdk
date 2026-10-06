// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `KeyReport` handler.
//!
//! Takes a **masked key** (e.g. the `masked_key` returned by
//! [`SdSealingKeyGen`](super::sd_sealing_key_gen)), unmasks it, derives
//! the attested key's public component on-device, and returns a signed
//! COSE_Sign1 key-attestation report over it. The report is signed by the
//! partition-identity (PID) key — the same signer as the `PartInit` PTA
//! report.
//!
//! Flow:
//!
//! 1. Decode the request; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition (parity with `SdSealingKeyGen`).
//! 2. **Peek** the masked blob's cleartext metadata to read the key
//!    `scope`, and resolve the scope's masking key.
//! 3. Unmask the blob (verifies the AEAD tag), recovering the private key
//!    plus its validated metadata (kind, attributes).
//! 4. Dispatch by key kind to build the attested public key. ECC-private
//!    kinds derive the public key via
//!    [`HsmEcc::ecc_pub_from_priv`](azihsm_fw_hsm_pal_traits::HsmEcc::ecc_pub_from_priv).
//!    RSA-private kinds, including CRT, use `rsa_priv_pub_key`. Symmetric
//!    keys (no public component) and other non-attestable kinds are rejected with
//!    [`HsmError::UnsupportedKeyType`].
//! 5. Build and PID-sign the COSE_Sign1 report over the derived key,
//!    caller-supplied `report_data`, session app id, and VM launch id.
//!
//! The blob's `svn` / `owner_seed_id` are **not** enforced against the
//! current partition lineage: the report reflects the key as-masked (the
//! AEAD tag still guarantees integrity / authenticity).
//!
//! This command is **Crypto-Officer-only**.

use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_core_crypto_key_report::key_report;
use azihsm_fw_core_crypto_key_report::AttestedPubKey;
use azihsm_fw_core_crypto_key_report::KeyFlags;
use azihsm_fw_core_crypto_key_report::KeyReportParams;
use azihsm_fw_ddi_tbor_types::TborKeyReportReq;
use azihsm_fw_ddi_tbor_types::TborKeyReportResp;
use azihsm_fw_ddi_tbor_types::KEY_REPORT_MAX_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartState;

use super::resolve_masking_key;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// Length of the app-UUID field bound into the report.
const APP_UUID_LEN: usize = 16;

/// Fixed width of the public exponent in the RSA wire format.
const RSA_PUB_EXP_LEN: usize = core::mem::size_of::<u32>();

// The report's app-UUID is the session AppId copied verbatim, so the two
// lengths must stay equal for the infallible `copy_from_slice` in
// `build_report_fields` not to panic.  Enforce it at compile time (a
// runtime length check would be unreachable while this holds).
const _: () = assert!(APP_UUID_LEN == azihsm_fw_hsm_pal_traits::APP_ID_LEN);

/// Translate the recovered vault attributes into report [`KeyFlags`].
fn key_flags_from_attrs(attrs: HsmVaultKeyAttrs) -> KeyFlags {
    KeyFlags::new()
        .with_is_imported(!attrs.local())
        .with_is_session_key(attrs.session())
        .with_is_generated(attrs.local())
        .with_can_encrypt(attrs.encrypt())
        .with_can_decrypt(attrs.decrypt())
        .with_can_sign(attrs.sign())
        .with_can_verify(attrs.verify())
        .with_can_wrap(attrs.wrap())
        .with_can_unwrap(attrs.unwrap())
        .with_can_derive(attrs.derive())
}

/// Reverse-copy `src` into `dst[..src.len()]` (LE↔BE per coordinate).
fn reverse_copy(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter().rev()) {
        *d = *s;
    }
}

/// Allocate and populate the report's app-UUID field — the session AppId
/// copied verbatim. It is the only non-key report field that needs owned
/// storage; `report_data` and `vm_launch_id` are borrowed in place.
fn build_app_uuid<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    sess_id: HsmSessId,
) -> HsmResult<&'a mut DmaBuf> {
    let app_id = crate::session::session_app_id(pal, io, sess_id)?;
    let app_uuid = alloc.dma_alloc(APP_UUID_LEN)?;
    app_uuid.copy_from_slice(&app_id);
    Ok(app_uuid)
}

/// Convert the recovered private key into attestable public-key material.
async fn attested_pub_key<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    key_kind: HsmVaultKeyKind,
    priv_key: &DmaBuf,
) -> HsmResult<AttestedPubKey<'a>> {
    if let Ok(rsa) = super::from_pal::rsa_key(key_kind) {
        let modulus_len = rsa.modulus_len();
        let wire_len = modulus_len + RSA_PUB_EXP_LEN;
        if pal.rsa_priv_pub_key(io, priv_key, None)? != wire_len {
            return Err(HsmError::InternalError);
        }
        let pub_le = alloc.dma_alloc(wire_len)?;
        if pal.rsa_priv_pub_key(io, priv_key, Some(&mut *pub_le))? != wire_len {
            return Err(HsmError::InternalError);
        }
        let modulus = alloc.dma_alloc(modulus_len)?;
        let exponent = alloc.dma_alloc(RSA_PUB_EXP_LEN)?;
        reverse_copy(
            modulus,
            pub_le.get(..modulus_len).ok_or(HsmError::InternalError)?,
        );
        reverse_copy(
            exponent,
            pub_le.get(modulus_len..).ok_or(HsmError::InternalError)?,
        );
        return Ok(AttestedPubKey::Rsa {
            n: modulus,
            e: exponent,
        });
    }

    let Some(curve) = super::from_pal::ecc_curve(key_kind) else {
        // Only ECC/RSA-private kinds are attestable. Symmetric keys have
        // no public component; other kinds are non-attestable or internal.
        return Err(HsmError::UnsupportedKeyType);
    };

    let coord_raw = curve.priv_key_len();
    let coord_wire = curve.wire_coord_len();

    let pub_le = alloc.dma_alloc(curve.wire_pub_key_len())?;
    pal.ecc_pub_from_priv(io, curve, priv_key, pub_le).await?;

    // The COSE_Key encodes big-endian coordinates; the PAL emits the
    // wire-LE `x ‖ y`, so reverse each coordinate.
    let x_be = alloc.dma_alloc(coord_raw)?;
    let y_be = alloc.dma_alloc(coord_raw)?;
    reverse_copy(x_be, &pub_le[..coord_raw]);
    reverse_copy(y_be, &pub_le[coord_wire..coord_wire + coord_raw]);

    Ok(AttestedPubKey::Ecc {
        curve,
        x: x_be,
        y: y_be,
    })
}

/// Handle a TBOR `KeyReport` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it unmasks the caller-supplied blob, derives its public
/// component, and returns a signed report.  It makes no observable state
/// change, so a concurrently-dispatched command (IOs run in a task pool
/// and interleave at await points) can neither observe it half-done nor
/// require its rollback on failure.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborKeyReportReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));

    validate_crypto_officer_active_session(pal, io, sess_id)?;

    // Reports bind the finalized partition policy, so the partition must
    // be in the `Initialized` state even for session-scoped keys.
    if part_state::part_state(pal, io)? != PartState::Initialized {
        return Err(HsmError::InvalidArg);
    }

    // Peek the masked-key metadata (cleartext, tag-bound) to route to the
    // right masking key before unmasking.
    let masked_key = req.masked_key();
    let report_data = req.report_data();
    let scope = peek_metadata(masked_key)?.usage_flags().scope();
    let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;

    pal.alloc_scoped_async(io, async |alloc| {
        let (report, report_len) = build_key_report(
            pal,
            io,
            alloc,
            masked_key,
            masking_key,
            sess_id,
            report_data,
        )
        .await?;
        encode_response(pal, io, &report[..report_len])
    })
    .await
}

/// Unmask the key, derive its public component, and build the PID-signed
/// COSE_Sign1 report over it.
///
/// Returns the report bytes in `alloc`-scoped scratch (`&mut DmaBuf`) plus
/// its exact length; the caller copies them into the IO-scoped response.
async fn build_key_report<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    masked_key: &DmaBuf,
    masking_key: &DmaBuf,
    sess_id: HsmSessId,
    report_data: &DmaBuf,
) -> HsmResult<(&'a mut DmaBuf, usize)> {
    // Copy the masked blob into a scratch buffer for in-place unmask.
    let blob = alloc.dma_alloc(masked_key.len())?;
    blob.copy_from_slice(masked_key);

    // Derive the public component before wiping the unmasked key, so no
    // second private-key allocation is needed.
    let key_res = async {
        let view = unmask(pal, io, masking_key, blob).await?;
        let key = attested_pub_key(pal, io, alloc, view.key_kind, view.target_key).await?;
        Ok::<_, HsmError>((key, view.key_attrs))
    }
    .await;

    // `unmask` decrypts the private key in place into `blob`; on tag
    // mismatch it can leave partial plaintext there.  Scope rewind does not
    // clear DMA memory, so wipe it on every path — whether unmask succeeded
    // or failed — before proceeding or propagating, so no key material
    // lingers in, and leaks through, a later per-IO allocation.
    blob.zeroize();
    let (key, key_attrs) = key_res?;
    let flags: u32 = key_flags_from_attrs(key_attrs).into();

    build_signed_report(pal, io, alloc, sess_id, key, flags, report_data).await
}

/// Encode the `KeyReport` response frame around the finished report.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    report_bytes: &[u8],
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborKeyReportResp::encode(buf, 0, false)?
            .report(report_bytes)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}

/// Assemble the report inputs and build the PID-signed COSE_Sign1 report
/// via the key-report crate's two-pass builder.
async fn build_signed_report<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    sess_id: HsmSessId,
    key: AttestedPubKey<'_>,
    flags: u32,
    report_data_src: &DmaBuf,
) -> HsmResult<(&'a mut DmaBuf, usize)> {
    let pid_priv = pal.vault_key(io, part_state::part_id_key_id(pal, io)?)?;

    let vm_launch_id = part_state::part_vm_launch_guid(pal, io)?;

    let app_uuid = build_app_uuid(pal, io, alloc, sess_id)?;

    // `report_data` borrows straight from the request buffer (no copy);
    // `key_report` validates its exact `KEY_REPORT_DATA_LEN` length.
    //
    // TBOR-minted reports are v2: bind the attested key to the partition's
    // provisioned PartPolicy digest (SHA-384) so a verifier can check the
    // report against a policy.
    let policy_hash = part_state::part_policy_hash(pal, io)?;
    let params = KeyReportParams {
        key,
        flags,
        app_uuid,
        report_data: report_data_src,
        vm_launch_id,
        policy_hash: Some(policy_hash),
    };

    // Two-pass: query the exact size, then build into an exact buffer.
    let report_len = key_report(pal, io, alloc, &params, pid_priv, None).await?;
    if report_len > KEY_REPORT_MAX_LEN {
        return Err(HsmError::InternalError);
    }
    let report = alloc.dma_alloc(report_len)?;
    key_report(pal, io, alloc, &params, pid_priv, Some(report)).await?;
    Ok((report, report_len))
}
