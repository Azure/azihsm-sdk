// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartInit` handler.
//!
//! Drives the partition-provisioning Phase 1 pipeline:
//!
//! 1. **Role gate** — only Crypto-Officer sessions may issue
//!    `PartInit`; CU callers receive [`HsmError::InvalidPermissions`].
//!    The default-PSK and session-id cross-checks are already
//!    enforced by the TBOR dispatcher; the per-partition one-shot
//!    gate is enforced by
//!    [`HsmPartitionManager::part_mark_initializing`] (and the
//!    write-once nature of the underlying partition setters).
//!
//! 2. **PartPolicy decode** — re-uses [`super::policy::from_bytes`]
//!    to reject malformed policies before any cryptographic work.
//!
//! 3. **KDF cascade** — [`kdf::derive_ums`] produces the per-
//!    partition Unique Material Secret (UMS); [`kdf::derive_pta_keypair`]
//!    derives the deterministic PTA P-384 keypair from the UMS.
//!
//! 4. **PTACSR build** — assembles a PKCS#10 CertificationRequest
//!    for the PTA public key.  The subject `serialNumber` is the
//!    hex-encoded **PTAID** (`SHA-384("AZIHSM-PTAID-v1" || sec1_pub)[..16]`).
//!    The TBS is hashed (LE digest) and signed via
//!    [`HsmEcc::ecc_sign`]; the resulting LE `(r, s)` are byte-
//!    reversed to BE for DER encoding.
//!
//! 5. **PTAReport build** — produces a COSE_Sign1 key-attestation
//!    report signed by the per-partition identity key (PID, owned
//!    by `alloc_part`).  Claims bind the PTA public key, the
//!    partition policy, and the POTA thumbprint via the
//!    `report_data` field:
//!    `SHA-384("AZIHSM-PTAReport-v1" || u16_be(|policy|) || policy
//!    || u16_be(|thumb|) || thumb) || zeros[..80]`.
//!
//! 6. **Commit** — write-once persistence of PTA pubkey + key ID,
//!    `PartPolicy`, and POTA thumbprint into partition state; vault
//!    the PTA private key as a [`HsmVaultKeyKind::PartitionTrustAnchor`].
//!    `part_mark_initializing` transitions `Enabled → Initializing`
//!    only after the three setters succeed.  PartInit deliberately
//!    does **not** call `part_mark_initialized` — that transition
//!    is owned by the follow-up partition-finalization handler (TBD),
//!    which runs once POTA validation of the returned PTAReport /
//!    PTACSR succeeds.
//!
//! 7. **Response encode** — emits [`TborPartInitResp`] with the
//!    DER-encoded PTACSR and the COSE_Sign1 PTAReport.

use azihsm_fw_core_crypto_aead_envelope::open as aead_open;
use azihsm_fw_core_crypto_key_report::key_report;
use azihsm_fw_core_crypto_key_report::KeyFlags;
use azihsm_fw_core_crypto_key_report::KeyReportParams;
use azihsm_fw_core_crypto_key_report::COSE_SIGN1_MAX_LEN;
use azihsm_fw_core_crypto_key_report::REPORT_DATA_LEN;
use azihsm_fw_core_crypto_key_report::VM_LAUNCH_ID_LEN;
use azihsm_fw_core_crypto_x509_builder::csr;
use azihsm_fw_core_crypto_x509_builder::csr_builder;
use azihsm_fw_core_crypto_x509_builder::padding;
use azihsm_fw_ddi_tbor_types::TborPartInitReq;
use azihsm_fw_ddi_tbor_types::TborPartInitResp;
use azihsm_fw_ddi_tbor_types::MACH_SEED_ENVELOPE_MAX_LEN;
use azihsm_fw_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_fw_ddi_tbor_types::PART_INIT_MACH_SEED_AAD_LABEL;
use azihsm_fw_ddi_tbor_types::PART_INIT_MACH_SEED_AAD_LEN;
use azihsm_fw_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_fw_ddi_tbor_types::PTA_CSR_MAX_LEN;
use azihsm_fw_ddi_tbor_types::PTA_REPORT_MAX_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::SessionRole;
use azihsm_fw_hsm_pal_traits::VaultKeyGuard;
use azihsm_fw_hsm_pal_traits::PART_POLICY_LEN;

use super::*;

// ─── Constants ───────────────────────────────────────────────────────────────

// Cross-crate invariant: the TBOR wire cap must remain ≥ the COSE
// worst case advertised by the key-report builder.  Anchored here
// because this is the only crate that depends on both.
const _: () = assert!(PTA_REPORT_MAX_LEN >= COSE_SIGN1_MAX_LEN);

/// Length of a P-384 raw private scalar in bytes (LE on the PAL wire).
const P384_PRIV_LEN: usize = 48;

/// Length of a single P-384 coordinate (X or Y).
const P384_COORD_LEN: usize = 48;

/// Length of an uncompressed SEC1 P-384 public key (`0x04 || X || Y`).
const P384_PUB_SEC1_LEN: usize = 1 + 2 * P384_COORD_LEN;

/// Length of a SHA-384 digest in bytes.
const SHA384_LEN: usize = 48;

/// Subject Common Name fixed for every PTACSR (24 ASCII chars;
/// space-padded to [`csr::SUBJECT_CN_LEN`] by the builder).
const PTA_SUBJECT_CN: &str = "Azure Integrated HSM PTA";

/// Domain-separation label hashed into the PTAID derivation.
const PTAID_LABEL: &[u8] = b"AZIHSM-PTAID-v1";

/// Bytes of the PTAID hash retained as the partition's short
/// identifier (encoded as 32 hex chars in the CSR's serialNumber).
const PTAID_LEN: usize = 16;

/// Domain-separation label hashed into the PTAReport `report_data`.
const REPORT_DATA_LABEL: &[u8] = b"AZIHSM-PTAReport-v1";

/// Vault attributes for the PTA private key: on-device generated
/// (`local`), firmware-internal (`internal`), never extractable,
/// usable only to sign.  Mirrors the conventions in
/// [`super::super::mbor::init_bk3`].
const PTA_VAULT_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true)
    .with_sign(true);

/// Vault attributes for the partition's Unique Machine Secret (UMS):
/// on-device generated (`local`), firmware-internal (`internal`),
/// never extractable.  UMS is consumed only by further on-device KDF
/// derivations (PTA keypair, future FinalizePart secrets), so no
/// signing / encryption / wrapping bits are set.
const UMS_VAULT_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Handle a TBOR `PartInit` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = parse_request(req_buf)?;

    pal.alloc_scoped_async(io, async |alloc| {
        // `policy` and `pota_thumb` are read-only request fields; the
        // codec already hands them out as `&DmaBuf` sub-views of the
        // inbound request buffer, so they can flow directly into PAL
        // crypto primitives and the write-once partition setters
        // without an extra copy.  `mach_seed_envelope` is decrypted
        // **in place** by `aead_open` on the same inbound buffer —
        // the destructured `&mut DmaBuf` carved by `decode_mut`
        // replaces the previous scratch-copy step.
        let policy_dma = req.policy;
        let _ = super::policy::from_bytes(policy_dma)?;
        let mach_seed_dma =
            open_mach_seed_envelope(pal, io, req.sess_id, req.mach_seed_envelope).await?;
        let pota_thumb_dma = req.pota_thumb;

        // Deterministic key derivation.
        let ums_dma = derive_ums(pal, io, alloc, mach_seed_dma, policy_dma, pota_thumb_dma).await?;
        let pta = derive_pta_keypair(pal, io, alloc, ums_dma).await?;

        // PTACSR + PTAReport: build everything before any partition-
        // state mutation so failures roll back cleanly.
        let csr_assets = build_csr_assets(pal, io, alloc, pta.pub_sec1).await?;
        let (csr_dma, csr_len) =
            build_signed_csr(pal, io, alloc, pta.pub_sec1, pta.priv_scalar, &csr_assets).await?;
        let (report_dma, report_len) = build_pta_report(
            pal,
            io,
            alloc,
            req.sess_id,
            pta.pub_sec1,
            policy_dma,
            pota_thumb_dma,
        )
        .await?;

        // Commit partition state, then encode the response.
        commit_partition_state(
            pal,
            io,
            ums_dma,
            pta.priv_scalar,
            pta.pub_sec1,
            policy_dma,
            pota_thumb_dma,
        )?;
        encode_response(pal, io, &csr_dma[..csr_len], &report_dma[..report_len])
    })
    .await
}

/// Parsed-and-validated PartInit request fields, ready to flow into
/// the cryptographic pipeline.  Variable-length fields are returned
/// as sub-views of the inbound request buffer so they can be handed
/// straight to PAL crypto primitives without copying.
/// `mach_seed_envelope` is held as `&mut DmaBuf` so the FW handler
/// can AEAD-open it in place; `policy` and `pota_thumb` are shared.
struct ParsedRequest<'a> {
    sess_id: HsmSessId,
    mach_seed_envelope: &'a mut DmaBuf,
    policy: &'a DmaBuf,
    pota_thumb: &'a DmaBuf,
}

/// Decode the wire request, enforce the CO-only role gate, and
/// length-check the variable-length fields against the wire schema.
fn parse_request<'a>(req_buf: &'a mut DmaBuf) -> HsmResult<ParsedRequest<'a>> {
    let req = TborPartInitReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));

    // PartInit is CO-only.  The dispatcher's default-PSK gate uses
    // the same `psk_id_for_role` mapping but does not by itself
    // reject CU sessions on this opcode.
    if sess_id.role() != SessionRole::CryptoOfficer {
        return Err(HsmError::InvalidPermissions);
    }

    if req.mach_seed_envelope.is_empty()
        || req.mach_seed_envelope.len() > MACH_SEED_ENVELOPE_MAX_LEN
        || req.part_policy.len() != PART_POLICY_LEN
        || req.pota_thumbprint.len() != POTA_THUMBPRINT_LEN
    {
        return Err(HsmError::InvalidArg);
    }

    Ok(ParsedRequest {
        sess_id,
        mach_seed_envelope: req.mach_seed_envelope,
        policy: req.part_policy,
        pota_thumb: req.pota_thumbprint,
    })
}

/// Materialized PTA keypair: private scalar (LE) plus uncompressed
/// SEC1 public key (`0x04 || X || Y`).  All buffers live in the
/// caller's scoped allocator.
struct PtaKeypair<'a> {
    priv_scalar: &'a mut DmaBuf,
    pub_sec1: &'a mut DmaBuf,
}

/// PTACSR assets used to seed both `build_tbs` and `build_csr` calls.
struct CsrAssets {
    cn: [u8; csr::SUBJECT_CN_LEN],
    sn: [u8; csr::SUBJECT_SN_LEN],
}

// ─── Pipeline stage helpers ──────────────────────────────────────────────────

/// AEAD-open the host-supplied `mach_seed` envelope and return a
/// zero-copy view of the 32-byte plaintext sub-region of the same
/// envelope buffer.
///
/// Cross-session replay is structurally impossible because
/// `param_key` is HPKE-derived per session.  AAD binds the envelope
/// to `(label, session_id)` so an envelope minted for session A
/// fails authentication on session B even if their `param_key`s
/// somehow collided.  AEAD-auth failure and any post-auth wire-shape
/// mismatch (AAD layout or payload length) both surface as
/// [`HsmError::AeadEnvelopeAuthFailed`]: once authentication has
/// succeeded the only way the shape can diverge is a sender that
/// constructed the envelope against a different protocol contract,
/// which is operationally indistinguishable from a forgery attempt.
async fn open_mach_seed_envelope<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    sess_id: HsmSessId,
    envelope: &'a mut DmaBuf,
) -> HsmResult<&'a DmaBuf> {
    let param_key = pal.session_param_key(io, sess_id)?;

    let view = aead_open(pal, io, param_key, envelope)
        .await
        .map_err(|_| HsmError::AeadEnvelopeAuthFailed)?;

    // Wire-shape check: reconstruct the canonical 32-byte AAD and
    // byte-compare.  See the function doc for why a post-auth shape
    // mismatch surfaces as `AeadEnvelopeAuthFailed`.
    let mut expected_aad = [0u8; PART_INIT_MACH_SEED_AAD_LEN];
    {
        fn push<'a>(rest: &'a mut [u8], bytes: &[u8]) -> &'a mut [u8] {
            let (head, tail) = rest.split_at_mut(bytes.len());
            head.copy_from_slice(bytes);
            tail
        }

        let mut rest: &mut [u8] = &mut expected_aad;
        rest = push(rest, PART_INIT_MACH_SEED_AAD_LABEL);
        let _ = push(rest, &u16::from(sess_id).to_le_bytes());
    }

    let aad: &[u8] = view.aad;
    if view.payload.len() != MACH_SEED_LEN || aad != expected_aad {
        return Err(HsmError::AeadEnvelopeAuthFailed);
    }

    Ok(view.payload)
}

/// Run the SP 800-108 / RFC 5869 UMS derivation with UDS plus the
/// three request-side inputs.  `kdf::derive_ums` always emits
/// [`kdf::UMS_LEN`] bytes, so the caller can size the output buffer
/// directly without a query roundtrip.
async fn derive_ums<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    mach_seed: &DmaBuf,
    policy: &DmaBuf,
    pota_thumb: &DmaBuf,
) -> HsmResult<&'a mut DmaBuf> {
    let uds_len = pal.part_uds(io, None)?;
    let uds = alloc.dma_alloc(uds_len)?;
    pal.part_uds(io, Some(uds))?;

    let ums = alloc.dma_alloc(kdf::UMS_LEN)?;
    let _ = kdf::derive_ums(
        pal,
        io,
        alloc,
        uds,
        mach_seed,
        policy,
        pota_thumb,
        Some(ums),
    )
    .await?;
    Ok(ums)
}

/// Derive the deterministic PTA P-384 keypair directly into a
/// scoped SEC1 buffer (with the `0x04` uncompressed-point tag
/// already in place), avoiding any later reshape.
async fn derive_pta_keypair<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    ums: &DmaBuf,
) -> HsmResult<PtaKeypair<'a>> {
    let priv_scalar = alloc.dma_alloc(P384_PRIV_LEN)?;
    let pub_sec1 = alloc.dma_alloc(P384_PUB_SEC1_LEN)?;
    pub_sec1[0] = 0x04;
    let pub_xy = pub_sec1.split_at_mut(1).1;
    let _ = kdf::derive_pta_keypair(pal, io, alloc, ums, Some((priv_scalar, pub_xy))).await?;
    // `ecc_gen_keypair_from_okm` returns each coordinate in PAL-LE
    // wire form, but every downstream consumer here (CSR SPKI,
    // PTAID hash, KeyReport `pk_x`/`pk_y`) expects standard SEC1
    // big-endian. Reverse each coordinate in place so `pub_sec1`
    // is canonical SEC1 (`0x04 || X_be || Y_be`).
    let (x_le, y_le) = pub_xy.split_at_mut(P384_COORD_LEN);
    x_le.reverse();
    y_le.reverse();
    Ok(PtaKeypair {
        priv_scalar,
        pub_sec1,
    })
}

/// Compute the PTACSR subject `commonName` and `serialNumber` slots.
async fn build_csr_assets<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    pub_sec1: &DmaBuf,
) -> HsmResult<CsrAssets> {
    let mut cn = [0u8; csr::SUBJECT_CN_LEN];
    padding::pad_cn_to(PTA_SUBJECT_CN, &mut cn).ok_or(HsmError::InternalError)?;

    // PTAID = SHA-384("AZIHSM-PTAID-v1" || sec1_pub)[..PTAID_LEN].
    let ptaid_input = alloc.dma_alloc(PTAID_LABEL.len() + P384_PUB_SEC1_LEN)?;
    ptaid_input[..PTAID_LABEL.len()].copy_from_slice(PTAID_LABEL);
    ptaid_input[PTAID_LABEL.len()..].copy_from_slice(pub_sec1);
    let ptaid_digest = alloc.dma_alloc(SHA384_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha384, ptaid_input, ptaid_digest, true)
        .await?;

    let mut ptaid_hex = [0u8; PTAID_LEN * 2];
    hex_encode(&ptaid_digest[..PTAID_LEN], &mut ptaid_hex);

    let mut sn = [0u8; csr::SUBJECT_SN_LEN];
    let ptaid_hex_str = core::str::from_utf8(&ptaid_hex).map_err(|_| HsmError::InternalError)?;
    padding::pad_sn_to(ptaid_hex_str, &mut sn).ok_or(HsmError::InternalError)?;

    Ok(CsrAssets { cn, sn })
}

/// Build the unsigned TBS, sign it with the PTA private key, then
/// emit the full DER-encoded CSR.
async fn build_signed_csr<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    pub_sec1: &DmaBuf,
    pta_priv: &DmaBuf,
    assets: &CsrAssets,
) -> HsmResult<(&'a mut DmaBuf, usize)> {
    let input = csr_builder::CsrInput {
        tbs_template: &csr::TBS_TEMPLATE,
        public_key_offset: csr::PUBLIC_KEY_OFFSET,
        public_key: pub_sec1,
        subject_cn_offset: csr::SUBJECT_CN_OFFSET,
        subject_cn: &assets.cn,
        subject_sn_offset: csr::SUBJECT_SN_OFFSET,
        subject_sn: &assets.sn,
    };

    // Single-shot async build: patches TBS, hashes, signs via PAL,
    // emits the full DER-encoded CSR.  See `csr_builder::build_csr`
    // for the unified pal/io/alloc + DmaBuf priv_key API.
    let csr = alloc.dma_alloc(PTA_CSR_MAX_LEN)?;
    let csr_len = csr_builder::build_csr(pal, io, alloc, &input, pta_priv, Some(csr)).await?;
    Ok((csr, csr_len))
}

/// Build the PID-signed COSE_Sign1 PTAReport binding the PTA pubkey
/// to the partition policy and POTA thumbprint.
#[allow(clippy::too_many_arguments)]
async fn build_pta_report<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    sess_id: HsmSessId,
    pub_sec1: &DmaBuf,
    policy: &DmaBuf,
    pota_thumb: &DmaBuf,
) -> HsmResult<(&'a mut DmaBuf, usize)> {
    let pid_priv = pal.vault_key(io, pal.part_id_key_id(io)?)?;
    let app_uuid = super::super::super::session::session_app_id(pal, io, sess_id)?;

    let mut vm_launch_id = [0u8; VM_LAUNCH_ID_LEN];
    let vm_len = pal.part_vm_launch_guid(io, Some(&mut vm_launch_id))?;
    if vm_len != VM_LAUNCH_ID_LEN {
        return Err(HsmError::InternalError);
    }

    let report_data = build_report_data(pal, io, alloc, policy, pota_thumb).await?;

    // PTA's only declared capability inside the attestation report
    // is `is_generated`; downstream policy uses the PartPolicy bytes
    // (bound via `report_data`) for finer-grained authorization.
    let flags: u32 = KeyFlags::new().with_is_generated(true).into();
    let pub_xy = &pub_sec1[1..];
    let params = KeyReportParams {
        pk_x: &pub_xy[..P384_COORD_LEN],
        pk_y: &pub_xy[P384_COORD_LEN..],
        flags,
        app_uuid: &app_uuid,
        report_data: &report_data[..],
        vm_launch_id: &vm_launch_id,
    };

    let report_len = key_report(pal, io, alloc, &params, pid_priv, None).await?;
    if report_len > PTA_REPORT_MAX_LEN {
        return Err(HsmError::InternalError);
    }
    let report = alloc.dma_alloc(report_len)?;
    let written = key_report(pal, io, alloc, &params, pid_priv, Some(report)).await?;
    if written != report_len {
        return Err(HsmError::InternalError);
    }
    Ok((report, report_len))
}

/// Build the 128-byte `report_data` field:
/// `SHA-384(label || u16_be(|policy|) || policy || u16_be(|thumb|)
/// || thumb) || zeros[..80]`.
///
/// The returned DmaBuf is zero-initialised and sized to
/// [`REPORT_DATA_LEN`]; `pal.hash` only writes the leading
/// [`SHA384_LEN`] bytes, leaving the trailing 80 bytes as the
/// required zero pad.
async fn build_report_data<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    policy: &DmaBuf,
    thumb: &DmaBuf,
) -> HsmResult<&'a mut DmaBuf> {
    let input = alloc.dma_alloc(
        REPORT_DATA_LABEL.len() + size_of::<u16>() + policy.len() + size_of::<u16>() + thumb.len(),
    )?;

    {
        fn push<'a>(rest: &'a mut [u8], bytes: &[u8]) -> &'a mut [u8] {
            let (head, tail) = rest.split_at_mut(bytes.len());
            head.copy_from_slice(bytes);
            tail
        }

        let mut rest: &mut [u8] = &mut input[..];
        rest = push(rest, REPORT_DATA_LABEL);
        rest = push(rest, &(policy.len() as u16).to_be_bytes());
        rest = push(rest, policy);
        rest = push(rest, &(thumb.len() as u16).to_be_bytes());
        let _ = push(rest, thumb);
    }

    let report_data = alloc.dma_alloc_zeroed(REPORT_DATA_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha384, input, report_data, true)
        .await?;
    Ok(report_data)
}

/// Vault the PTA and UMS private keys, register the partition
/// write-once fields, and publish the `Enabled → Initializing`
/// transition.
///
/// Setter order is fixed by [`HsmPartitionManager::part_mark_initializing`]
/// (all four write-once fields — PTA key, UMS key, policy, POTA
/// thumbprint — must be set first).  Vault entries are created
/// provisionally; each `key_id()` is stable before `dismiss()`, so
/// the ids flow into the partition setters before commit.  Failures
/// before `dismiss()` roll back both vault entries.
fn commit_partition_state<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    ums: &DmaBuf,
    pta_priv: &DmaBuf,
    pta_pub_sec1: &DmaBuf,
    policy: &DmaBuf,
    pota_thumb: &DmaBuf,
) -> HsmResult<()> {
    // Vault-allocate UMS first.  Both guards are held until every
    // partition-side setter has succeeded; any earlier `?` rolls back
    // both vault entries when the guards drop without `dismiss()`.
    let ums_guard = pal.vault_key_create(
        io,
        ums,
        HsmVaultKeyKind::PartitionUniqueMachineSecret,
        None,
        UMS_VAULT_ATTRS,
        &[],
    )?;
    let ums_key_id = ums_guard.key_id();

    let pta_guard = pal.vault_key_create(
        io,
        pta_priv,
        HsmVaultKeyKind::PartitionTrustAnchor,
        None,
        PTA_VAULT_ATTRS,
        &[],
    )?;
    let pta_key_id = pta_guard.key_id();

    pal.part_set_pta_key(io, pta_key_id, pta_pub_sec1)?;
    pal.part_set_ums_key(io, ums_key_id)?;
    pal.part_set_policy(io, policy)?;
    pal.part_set_pota_thumbprint(io, pota_thumb)?;
    pal.part_mark_initializing(io)?;
    let _ = pta_guard.dismiss();
    let _ = ums_guard.dismiss();
    Ok(())
}

/// Encode the `TborPartInitResp` into a fresh IO-scoped DmaBuf.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    pta_csr_bytes: &[u8],
    pta_report_bytes: &[u8],
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborPartInitResp::encode(buf, 0, false)?
            .pta_csr(pta_csr_bytes)?
            .pta_report(pta_report_bytes)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}

// ─── Low-level helpers ───────────────────────────────────────────────────────

/// Hex-encode `src` into `dst` using lowercase ASCII.
/// `dst.len()` must equal `2 * src.len()`.
fn hex_encode(src: &[u8], dst: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    debug_assert_eq!(dst.len(), src.len() * 2);
    for (i, &b) in src.iter().enumerate() {
        dst[2 * i] = HEX[(b >> 4) as usize];
        dst[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_emits_lowercase_padded_pairs() {
        let mut out = [0u8; 8];
        hex_encode(&[0x0a, 0xff, 0x10, 0x00], &mut out);
        assert_eq!(&out, b"0aff1000");
    }

    #[test]
    fn ptaid_label_is_versioned() {
        // Verifiers reconstruct the PTAID by hashing this exact
        // label || sec1_pub; guard against silent drift.
        assert_eq!(PTAID_LABEL, b"AZIHSM-PTAID-v1");
    }

    #[test]
    fn report_data_label_is_versioned() {
        assert_eq!(REPORT_DATA_LABEL, b"AZIHSM-PTAReport-v1");
    }

    #[test]
    fn pta_subject_cn_fits_template() {
        assert!(PTA_SUBJECT_CN.is_ascii());
        assert!(PTA_SUBJECT_CN.len() <= csr::SUBJECT_CN_LEN);
    }

    #[test]
    fn ptaid_hex_width_equals_subject_sn_len() {
        // The serialNumber field is exactly `2 * PTAID_LEN` hex
        // chars; any future tweak to `PTAID_LEN` or the template's
        // SN length must keep these aligned.
        assert_eq!(PTAID_LEN * 2, csr::SUBJECT_SN_LEN);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Deterministic KDF cascade
// ════════════════════════════════════════════════════════════════════════════

pub(crate) mod kdf {
    //! Deterministic partition KDF for TBOR `PartInit`.
    //!
    //! Produces the per-partition **Unique Master Secret (UMS)** and,
    //! later, per-partition keypairs (PTA / PID) from the device's
    //! Unique Device Secret (UDS) plus operator-supplied binding inputs
    //! (`MachineSeed`, `PartPolicy` thumbprint, and `POTA` thumbprint).
    //! All derivations are deterministic: identical inputs yield
    //! identical outputs, so a partition's identity keys can be
    //! reconstructed across reboots and NSSR cycles without persisting
    //! plaintext key material.
    //!
    //! # KDF cascade
    //!
    //! ```text
    //!   UDS  ──KBKDF-CTR-HMAC-SHA384(label, ctx)──►  UMS  (48 B)
    //!   UMS  ──HKDF-Expand-SHA384(info)──────────►   OKM  (curve-dep.)
    //!   OKM  ──FIPS 186-5 §A.2.1 (Extra Random Bits)─►  (d, Q)
    //! ```
    //!
    //! - The first stage uses **NIST SP 800-108** Counter Mode KBKDF
    //!   with HMAC-SHA384 as the PRF.  Label
    //!   `b"AZIHSM-PartInit-UMS-v1"` ties the derivation to this version
    //!   of the PartInit protocol; rotating the label (e.g. `v2`) is the
    //!   intended way to retire all derived material.
    //! - The second stage uses **RFC 5869 HKDF-Expand** (HMAC-SHA384)
    //!   keyed by the UMS so that multiple per-partition keys (PTA, PID,
    //!   future keys) can be derived from a single UMS without
    //!   re-running the expensive UDS-touching KBKDF.
    //! - The third stage delegates to
    //!   [`azihsm_crypto::EccPrivateKey::from_okm_a2_1`] via the
    //!   PAL trait
    //!   [`HsmEcc::ecc_gen_keypair_from_okm`](azihsm_fw_hsm_pal_traits::HsmEcc::ecc_gen_keypair_from_okm).
    //!
    //! # Public surface
    //!
    //! [`derive_ums`] computes the per-partition UMS; [`derive_pta_keypair`]
    //! consumes that UMS to derive the deterministic PTA P-384 keypair.
    //! Additional per-partition keypair wrappers (e.g. `derive_pid_keypair`)
    //! will land alongside future PartInit phases and reuse the same UMS.
    //!
    //! # Compliance notes
    //!
    //! - **SP 800-108r1**: §4.1 fixes the counter-mode input layout as
    //!   `i ‖ Label ‖ 0x00 ‖ Context ‖ L`; the PAL trait
    //!   [`HsmKdf::sp800_108_kdf`] implements that layout, so callers
    //!   here only need to supply `label`, `context`, and an output
    //!   buffer.
    //! - **SP 800-133r2 §6.2.3**: keys derived from a KDF using a
    //!   source-key of security strength `s` inherit at most `s` bits of
    //!   strength.  UDS is required to have ≥192-bit security strength
    //!   (matching SHA-384's collision resistance) for the resulting
    //!   P-384 partition keys to remain Approved at the 192-bit level.
    //! - The first stage's context is built with **explicit u16-BE
    //!   length prefixes** for every field.  This makes the encoding
    //!   length-injective: two distinct input tuples can never collide
    //!   into the same context bytes.

    use azihsm_fw_hsm_pal_traits::DmaBuf;
    use azihsm_fw_hsm_pal_traits::HsmEccCurve;
    use azihsm_fw_hsm_pal_traits::HsmEccPct;
    use azihsm_fw_hsm_pal_traits::HsmError;
    use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
    use azihsm_fw_hsm_pal_traits::HsmIo;
    use azihsm_fw_hsm_pal_traits::HsmPal;
    use azihsm_fw_hsm_pal_traits::HsmResult;
    use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

    /// Domain-separation label for the UDS → UMS derivation
    /// (SP 800-108 KBKDF input).  Version suffix `v1` reserved for
    /// future protocol revisions.
    pub const UMS_LABEL: &[u8] = b"AZIHSM-PartInit-UMS-v1";

    /// Length of the derived Unique Master Secret, in bytes.
    ///
    /// 48 bytes = 384 bits, matching SHA-384's output and providing the
    /// full security margin needed to seed P-384 partition keys.
    pub const UMS_LEN: usize = 48;

    /// Minimum acceptable `MachineSeed` length.  Below 128 bits the seed
    /// cannot contribute enough entropy to bind the derivation to the
    /// hosting machine.
    pub const MACHINE_SEED_MIN_LEN: usize = 16;

    /// Maximum acceptable `MachineSeed` length.  Caps host-controlled
    /// input so the context buffer remains small and predictable.
    pub const MACHINE_SEED_MAX_LEN: usize = 256;

    /// Derive the per-partition Unique Master Secret (UMS) from the
    /// device's UDS and the operator-supplied binding inputs.
    ///
    /// Implements the first stage of the PartInit KDF cascade
    /// (UDS → UMS) via SP 800-108 Counter Mode KBKDF with HMAC-SHA384.
    ///
    /// Follows the PAL query/copy convention:
    ///
    /// 1. **Query** — call with `ums_out = None`.  No derivation
    ///    happens; the method returns [`UMS_LEN`], the byte count the
    ///    caller must allocate.  Input length validation still runs.
    /// 2. **Alloc** — caller allocates a DMA buffer of that size.
    /// 3. **Use** — call with `ums_out = Some(buf)`.  The method
    ///    derives the UMS and writes [`UMS_LEN`] bytes into the
    ///    caller's buffer.
    ///
    /// # Parameters
    ///
    /// - `pal` — PAL providing [`HsmKdf::sp800_108_kdf`].
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `alloc` — scoped allocator for the small DMA scratch buffers
    ///   used to build the KBKDF `label` and `context` inputs.
    ///   Unused in query mode.
    /// - `uds` — device Unique Device Secret.  Must have security
    ///   strength ≥ 192 bits per SP 800-133r2 §6.2.3.
    /// - `machine_seed` — host-bound entropy.  Length must be in
    ///   `MACHINE_SEED_MIN_LEN..=MACHINE_SEED_MAX_LEN`.
    /// - `part_policy` — `PartPolicy` thumbprint bytes (any length up
    ///   to `u16::MAX`).
    /// - `pota_thumb` — `POTA` thumbprint bytes (any length up to
    ///   `u16::MAX`).
    /// - `ums_out` — `None` to query the required buffer size;
    ///   `Some(buf)` to derive.  When `Some`, `buf.len()` must be
    ///   at least [`UMS_LEN`].
    ///
    /// # Returns
    ///
    /// - `Ok(UMS_LEN)` — in query mode, the buffer size the caller
    ///   must allocate; in use mode, the number of bytes written into
    ///   `ums_out`.
    /// - `Err(HsmError::InvalidArg)` — `machine_seed` length out of
    ///   range, any single input exceeds `u16::MAX` bytes (the
    ///   length-prefix limit), or `ums_out` is `Some` and shorter than
    ///   [`UMS_LEN`].
    /// - `Err(HsmError::NotEnoughSpace)` — scoped alloc exhausted.
    /// - `Err(HsmError)` — PAL KDF driver failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn derive_ums(
        pal: &impl HsmPal,
        io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        uds: &DmaBuf,
        machine_seed: &DmaBuf,
        part_policy: &DmaBuf,
        pota_thumb: &DmaBuf,
        ums_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        if !(MACHINE_SEED_MIN_LEN..=MACHINE_SEED_MAX_LEN).contains(&machine_seed.len()) {
            return Err(HsmError::InvalidArg);
        }
        // Each field is u16-BE length-prefixed in the KBKDF context.
        if part_policy.len() > u16::MAX as usize || pota_thumb.len() > u16::MAX as usize {
            return Err(HsmError::InvalidArg);
        }

        let Some(ums_out) = ums_out else {
            return Ok(UMS_LEN);
        };
        if ums_out.len() < UMS_LEN {
            return Err(HsmError::InvalidArg);
        }

        let label = alloc.dma_alloc(UMS_LABEL.len())?;
        label.copy_from_slice(UMS_LABEL);

        // Length-injective context: u16_be(|f|) ‖ f, for each field.
        let fields: [&DmaBuf; 3] = [machine_seed, part_policy, pota_thumb];
        let ctx_len: usize = fields.iter().map(|f| 2 + f.len()).sum();
        let context = alloc.dma_alloc(ctx_len)?;
        let mut off = 0usize;
        for field in fields {
            context[off..off + 2].copy_from_slice(&(field.len() as u16).to_be_bytes());
            off += 2;
            context[off..off + field.len()].copy_from_slice(field);
            off += field.len();
        }

        pal.sp800_108_kdf(
            io,
            HsmHashAlgo::Sha384,
            uds,
            Some(label),
            Some(context),
            &mut ums_out[..UMS_LEN],
        )
        .await?;
        Ok(UMS_LEN)
    }

    /// Domain-separation label for the UMS → PTA keypair derivation
    /// (HKDF-Expand info prefix).  Mirrors [`UMS_LABEL`] versioning:
    /// rotating the suffix retires the associated key.  Exposed as a
    /// `pub` constant so integration tests can construct alternate
    /// labels and assert domain separation.
    pub const KEYPAIR_LABEL_PTA: &[u8] = b"AZIHSM-PartInit-PTA-v1";

    /// Derive the deterministic per-partition PTA key pair (P-384) from
    /// a UMS produced by [`derive_ums`], composing RFC 5869
    /// HKDF-Expand-SHA384 with FIPS 186-5 §A.2.1 (Extra Random Bits)
    /// keypair generation.
    ///
    /// The HKDF info input is `KEYPAIR_LABEL_PTA ‖ u16_be(okm_len)` so
    /// that two different curves (or two different labels of the same
    /// length) can never share an OKM, and so that increasing `okm_len`
    /// in a future protocol revision is a domain-separating change.
    ///
    /// Same query/copy convention as [`derive_ums`] and as the
    /// underlying PAL primitives
    /// ([`HsmEcc::ecc_gen_keypair_from_okm`]):
    ///
    /// 1. **Query** — call with `out = None`.  No derivation happens;
    ///    returns the per-curve `(priv_len, pub_len)` byte counts the
    ///    caller must allocate.  `ums` is still validated.
    /// 2. **Alloc** — caller allocates two DMA buffers of those sizes.
    /// 3. **Use** — call with `out = Some((priv_out, pub_out))`.  The
    ///    method runs HKDF-Expand to produce 56 B OKM, then dispatches
    ///    to the PAL §A.2.1 derive primitive.
    ///
    /// # Parameters
    ///
    /// - `pal` — PAL providing [`HsmKdf::hkdf_expand`] and
    ///   [`HsmEcc::ecc_gen_keypair_from_okm`].
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `alloc` — scoped allocator for HKDF info and OKM scratch.
    /// - `ums` — Unique Master Secret from [`derive_ums`].  Length
    ///   must equal [`UMS_LEN`].
    /// - `out` — `None` to query buffer sizes; `Some((priv_out,
    ///   pub_out))` to derive.  Each buffer must hold at least the
    ///   length returned by an earlier query call.
    ///
    /// # Returns
    ///
    /// - `Ok((priv_len, pub_len))` — in query mode, the required
    ///   buffer sizes (48, 96 for P-384); in use mode, the actual
    ///   bytes written.
    /// - `Err(HsmError::InvalidArg)` — `ums.len() != UMS_LEN` or an
    ///   output buffer too small.
    /// - `Err(HsmError::NotEnoughSpace)` — scoped alloc exhausted.
    /// - `Err(HsmError)` — PAL KDF / ECC driver failure.
    pub async fn derive_pta_keypair(
        pal: &impl HsmPal,
        io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        ums: &DmaBuf,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let curve = HsmEccCurve::P384;
        let priv_len = curve.wire_coord_len();
        let pub_len = curve.wire_pub_key_len();
        let okm_len = curve.a2_1_okm_len();

        if ums.len() != UMS_LEN {
            return Err(HsmError::InvalidArg);
        }

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, pub_len));
        };
        if priv_out.len() < priv_len || pub_out.len() < pub_len {
            return Err(HsmError::InvalidArg);
        }

        // ── HKDF-Expand info: KEYPAIR_LABEL_PTA ‖ u16_be(okm_len) ──
        let info = alloc.dma_alloc(KEYPAIR_LABEL_PTA.len() + 2)?;
        info[..KEYPAIR_LABEL_PTA.len()].copy_from_slice(KEYPAIR_LABEL_PTA);
        info[KEYPAIR_LABEL_PTA.len()..].copy_from_slice(&(okm_len as u16).to_be_bytes());

        // ── HKDF-Expand → OKM (curve-specific length) ─────────────
        let okm = alloc.dma_alloc(okm_len)?;
        pal.hkdf_expand(io, HsmHashAlgo::Sha384, ums, Some(info), okm)
            .await?;

        // ── §A.2.1 keypair derivation via PAL primitive ────────────
        pal.ecc_gen_keypair_from_okm(
            io,
            alloc,
            curve,
            okm,
            Some((priv_out, pub_out)),
            HsmEccPct::None,
        )
        .await
    }
}
