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
//! 3. **Single-root derivation** — [`kdf::derive_part_root`] produces
//!    the per-partition root secret (`PartRoot`) binding every request
//!    input; [`kdf::derive_pta_keypair`] derives the deterministic PTA
//!    P-384 keypair from it.  (The security-domain local masking keys
//!    are *not* derived here — they belong in a future part-final
//!    command that binds them to the POTA-endorsed PTA cert chain.)
//!
//! 4. **PTACSR build** — assembles a PKCS#10 CertificationRequest
//!    for the PTA public key.  The subject `serialNumber` is the
//!    hex-encoded **PTAID** (`SHA-384("AZIHSM-PTAID-v1" || sec1_pub)[..16]`).
//!    The TBS is hashed (LE digest) and signed via
//!    [`HsmEcc::ecc_sign`]; the resulting LE `(r, s)` are byte-
//!    reversed to BE for DER encoding.
//!
//! 5. **PTAReport build** — produces a COSE_Sign1 key-attestation
//!    report signed by the per-partition identity key (PID).  Claims
//!    bind the PTA public key, the unified partition policy, and the
//!    POTA / SATA / SAPOTA thumbprints via the `report_data` field.
//!
//! 6. **Commit** — write-once persistence of PTA pubkey + key ID,
//!    policy hash, and POTA/SATA/SAPOTA thumbprints into partition
//!    state; vault the PartRoot and PTA private keys.
//!    `part_mark_initializing` transitions `Enabled → Initializing`
//!    only after the setters succeed.  PartInit deliberately does
//!    **not** call `part_mark_initialized` — that transition is owned
//!    by the follow-up partition-finalization handler (TBD).
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
use azihsm_fw_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_fw_ddi_tbor_types::PART_INIT_MACH_SEED_AAD_LABEL;
use azihsm_fw_ddi_tbor_types::PART_INIT_MACH_SEED_AAD_LEN;
use azihsm_fw_ddi_tbor_types::PTA_CSR_MAX_LEN;
use azihsm_fw_ddi_tbor_types::PTA_REPORT_MAX_LEN;
use azihsm_fw_ddi_tbor_types::SAPOTA_THUMBPRINT_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartState;
use azihsm_fw_hsm_pal_traits::SessionRole;

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

/// Vault attributes for the partition's root secret (PartRoot):
/// on-device generated (`local`), firmware-internal (`internal`),
/// never extractable.  PartRoot is consumed only by further on-device
/// KDF derivations (PTA keypair, and future part-final local keys), so
/// no signing / encryption / wrapping bits are set.
const PART_ROOT_VAULT_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
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
        // Read-only request fields are codec sub-views of the inbound
        // buffer, so they flow directly into PAL crypto and the
        // write-once setters without copying.  `mach_seed_envelope` is
        // AEAD-opened **in place** on the same inbound buffer.
        let policy_dma = req.policy;
        let _ = super::policy::from_bytes(policy_dma)?;
        let mach_seed_dma =
            open_mach_seed_envelope(pal, io, req.sess_id, req.mach_seed_envelope).await?;
        let pota_thumb_dma = req.pota_thumb;
        let sata_thumb_dma = req.sata_thumb;
        let sapota_thumb_dma = req.sapota_thumb;

        // ── Single-root derivation ────────────────────────────────
        // PartRoot binds every request input; the PTA keypair fans out
        // from it.  (The security-domain local masking keys are derived
        // later in part-final, bound to the POTA-endorsed PTA cert
        // chain — see the module docs.)
        let root_dma = derive_part_root(
            pal,
            io,
            alloc,
            mach_seed_dma,
            policy_dma,
            pota_thumb_dma,
            sata_thumb_dma,
            sapota_thumb_dma,
        )
        .await?;
        let pta = derive_pta_keypair_buf(pal, io, alloc, root_dma).await?;

        // PTACSR + PTAReport: build everything before any partition-
        // state mutation so failures roll back cleanly.
        let (csr_dma, csr_len) =
            build_signed_csr(pal, io, alloc, pta.pub_sec1, pta.priv_scalar).await?;
        let (report_dma, report_len) = build_pta_report(
            pal,
            io,
            alloc,
            req.sess_id,
            pta.pub_sec1,
            policy_dma,
            pota_thumb_dma,
            sata_thumb_dma,
            sapota_thumb_dma,
        )
        .await?;

        // Persist only the SHA-384 hash of the policy blob; the full
        // PartPolicy is consumed transiently during PartRoot derivation
        // (above) and is never stored in the partition.
        let policy_hash_dma = alloc.dma_alloc(SHA384_LEN)?;
        pal.hash(io, HsmHashAlgo::Sha384, policy_dma, policy_hash_dma, true)
            .await?;

        // Commit partition state, then encode the response.
        commit_partition_state(
            pal,
            io,
            CommitInputs {
                root: root_dma,
                pta_priv: pta.priv_scalar,
                pta_pub_sec1: pta.pub_sec1,
                policy_hash: policy_hash_dma,
                pota_thumb: pota_thumb_dma,
                sata_thumb: sata_thumb_dma,
                sapota_thumb: sapota_thumb_dma,
            },
        )
        .await?;
        encode_response(pal, io, &csr_dma[..csr_len], &report_dma[..report_len])
    })
    .await
}

/// Parsed-and-validated PartInit request fields, ready to flow into
/// the cryptographic pipeline.  Variable-length fields are returned
/// as sub-views of the inbound request buffer so they can be handed
/// straight to PAL crypto primitives without copying.
/// `mach_seed_envelope` is held as `&mut DmaBuf` so the FW handler
/// can AEAD-open it in place; the remaining fields are shared.
struct ParsedRequest<'a> {
    sess_id: HsmSessId,
    mach_seed_envelope: &'a mut DmaBuf,
    policy: &'a DmaBuf,
    pota_thumb: &'a DmaBuf,
    sata_thumb: &'a DmaBuf,
    sapota_thumb: Option<&'a DmaBuf>,
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

    // The fixed-length fields (`mach_seed_envelope` = 100 B,
    // `part_policy` = 484 B, `pota_thumbprint` / `sata_thumbprint` =
    // 48 B) are pinned by the schema, so a malformed length was already
    // rejected at decode with `TborInvalidFixedLength`. Only the
    // optional `sapota_thumbprint` (variable, empty = absent) needs a
    // handler-side length check.

    // SAPOTA thumbprint is optional: an empty field means absent;
    // when present it must be exactly the fixed size.
    let sapota_thumb = if req.sapota_thumbprint.is_empty() {
        None
    } else {
        if req.sapota_thumbprint.len() != SAPOTA_THUMBPRINT_LEN {
            return Err(HsmError::InvalidArg);
        }
        Some(req.sapota_thumbprint)
    };

    Ok(ParsedRequest {
        sess_id,
        mach_seed_envelope: req.mach_seed_envelope,
        policy: req.part_policy,
        pota_thumb: req.pota_thumbprint,
        sata_thumb: req.sata_thumbprint,
        sapota_thumb,
    })
}

/// Materialized PTA keypair: private scalar (LE) plus uncompressed
/// SEC1 public key (`0x04 || X || Y`).  All buffers live in the
/// caller's scoped allocator.
struct PtaKeypair<'a> {
    priv_scalar: &'a mut DmaBuf,
    pub_sec1: &'a mut DmaBuf,
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

/// Run the single-root PartRoot derivation with UDS plus all
/// request-side inputs.  `kdf::derive_part_root` always emits
/// [`kdf::PART_ROOT_LEN`] bytes, so the caller can size the output
/// buffer directly without a query roundtrip.
#[allow(clippy::too_many_arguments)]
async fn derive_part_root<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    mach_seed: &DmaBuf,
    policy: &DmaBuf,
    pota_thumb: &DmaBuf,
    sata_thumb: &DmaBuf,
    sapota_thumb: Option<&DmaBuf>,
) -> HsmResult<&'a mut DmaBuf> {
    let src = crate::part_state::part_uds(pal);

    let root = alloc.dma_alloc(kdf::PART_ROOT_LEN)?;
    // Run the KBKDF in a nested allocator scope so its large transient
    // inputs (the UDS copy and the policy-bearing context buffer) are
    // freed before the rest of the handler — keeping the per-IO DMA
    // arena available for the CSR / report / response.
    pal.alloc_scoped_async(io, async |inner| -> HsmResult<()> {
        let uds = inner.dma_alloc(src.len())?;
        uds.copy_from_slice(src);
        let _ = kdf::derive_part_root(
            pal,
            io,
            inner,
            uds,
            mach_seed,
            policy,
            pota_thumb,
            sata_thumb,
            sapota_thumb,
            Some(root),
        )
        .await?;
        Ok(())
    })
    .await?;
    Ok(root)
}

/// Derive the deterministic PTA P-384 keypair directly into a
/// scoped SEC1 buffer (with the `0x04` uncompressed-point tag
/// already in place), avoiding any later reshape.
async fn derive_pta_keypair_buf<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    root: &DmaBuf,
) -> HsmResult<PtaKeypair<'a>> {
    let priv_scalar = alloc.dma_alloc(P384_PRIV_LEN)?;
    let pub_sec1 = alloc.dma_alloc(P384_PUB_SEC1_LEN)?;
    pub_sec1[0] = 0x04;
    let pub_xy = pub_sec1.split_at_mut(1).1;
    let _ = kdf::derive_pta_keypair(pal, io, alloc, root, Some((priv_scalar, pub_xy))).await?;
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
/// Build the CSR subject fields, then sign with the PTA private key
/// and emit the full DER-encoded CSR.  The `cn`/`sn` arrays are local
/// to this function so they never cross an await boundary in `handle`.
async fn build_signed_csr<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    pub_sec1: &DmaBuf,
    pta_priv: &DmaBuf,
) -> HsmResult<(&'a mut DmaBuf, usize)> {
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

    let input = csr_builder::CsrInput {
        tbs_template: &csr::TBS_TEMPLATE,
        public_key_offset: csr::PUBLIC_KEY_OFFSET,
        public_key: pub_sec1,
        subject_cn_offset: csr::SUBJECT_CN_OFFSET,
        subject_cn: &cn,
        subject_sn_offset: csr::SUBJECT_SN_OFFSET,
        subject_sn: &sn,
    };

    let csr = alloc.dma_alloc(PTA_CSR_MAX_LEN)?;
    let csr_len = csr_builder::build_csr(pal, io, alloc, &input, pta_priv, Some(csr)).await?;
    Ok((csr, csr_len))
}

/// Build the PID-signed COSE_Sign1 PTAReport binding the PTA pubkey
/// to the unified partition policy and the POTA / SATA / SAPOTA
/// thumbprints.
#[allow(clippy::too_many_arguments)]
async fn build_pta_report<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    sess_id: HsmSessId,
    pub_sec1: &DmaBuf,
    policy: &DmaBuf,
    pota_thumb: &DmaBuf,
    sata_thumb: &DmaBuf,
    sapota_thumb: Option<&DmaBuf>,
) -> HsmResult<(&'a mut DmaBuf, usize)> {
    let pid_priv = pal.vault_key(io, crate::part_state::part_id_key_id(pal, io)?)?;
    let app_uuid = super::super::super::session::session_app_id(pal, io, sess_id)?;

    let mut vm_launch_id = [0u8; VM_LAUNCH_ID_LEN];
    {
        let guid = crate::part_state::part_vm_launch_guid(pal, io)?;
        if guid.len() != VM_LAUNCH_ID_LEN {
            return Err(HsmError::InternalError);
        }
        vm_launch_id.copy_from_slice(&guid[..VM_LAUNCH_ID_LEN]);
    }

    let report_data =
        build_report_data(pal, io, alloc, policy, pota_thumb, sata_thumb, sapota_thumb).await?;

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

    // Allocate at max size and build in a single pass — avoids the
    // size-query await that would add an extra state machine variant.
    let report = alloc.dma_alloc(COSE_SIGN1_MAX_LEN)?;
    let report_len = key_report(pal, io, alloc, &params, pid_priv, Some(report)).await?;
    if report_len > PTA_REPORT_MAX_LEN {
        return Err(HsmError::InternalError);
    }
    Ok((report, report_len))
}

/// Build the 128-byte `report_data` field:
/// `SHA-384(label ‖ lp(policy) ‖ lp(pota) ‖ lp(sata) ‖ lp(sapota))
/// ‖ zeros[..80]`, where `lp(f) = u16_be(|f|) ‖ f` is a
/// length-injective prefix and an absent SAPOTA contributes a
/// zero-length field.
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
    pota_thumb: &DmaBuf,
    sata_thumb: &DmaBuf,
    sapota_thumb: Option<&DmaBuf>,
) -> HsmResult<&'a mut DmaBuf> {
    let sapota_bytes: &[u8] = match sapota_thumb {
        Some(t) => t,
        None => &[],
    };
    let fields: [&[u8]; 4] = [policy, pota_thumb, sata_thumb, sapota_bytes];
    let input_len = REPORT_DATA_LABEL.len()
        + fields
            .iter()
            .map(|f| size_of::<u16>() + f.len())
            .sum::<usize>();
    let input = alloc.dma_alloc(input_len)?;

    {
        fn push<'a>(rest: &'a mut [u8], bytes: &[u8]) -> &'a mut [u8] {
            let (head, tail) = rest.split_at_mut(bytes.len());
            head.copy_from_slice(bytes);
            tail
        }

        let mut rest: &mut [u8] = &mut input[..];
        rest = push(rest, REPORT_DATA_LABEL);
        for f in fields {
            rest = push(rest, &(f.len() as u16).to_be_bytes());
            rest = push(rest, f);
        }
    }

    let report_data = alloc.dma_alloc_zeroed(REPORT_DATA_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha384, input, report_data, true)
        .await?;
    Ok(report_data)
}

/// Write-once inputs committed by [`commit_partition_state`].
struct CommitInputs<'a> {
    root: &'a DmaBuf,
    pta_priv: &'a DmaBuf,
    pta_pub_sec1: &'a DmaBuf,
    policy_hash: &'a DmaBuf,
    pota_thumb: &'a DmaBuf,
    sata_thumb: &'a DmaBuf,
    sapota_thumb: Option<&'a DmaBuf>,
}

/// Vault the PartRoot and PTA private keys, register the partition
/// write-once fields (including the security-domain thumbprints), and
/// publish the `Enabled → Initializing` transition.
///
/// Setter order is fixed by [`HsmPartitionManager::part_mark_initializing`]
/// (the write-once fields must be set first).  Vault entries are
/// committed as soon as they are created (`vault_key_create` is
/// awaited), and the returned `key_id`s then flow into the partition
/// setters.  There is no provisional / `dismiss()` rollback stage;
/// undoing a partially-applied `PartInit` is a future undo-log TODO.
async fn commit_partition_state<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    inputs: CommitInputs<'_>,
) -> HsmResult<()> {
    // The keys are committed as they are created; the partition-state
    // setters below run afterwards (a future undo log will handle
    // rollback of a partially-applied PartInit).
    let root_key_id = pal
        .vault_key_create(
            io,
            inputs.root,
            HsmVaultKeyKind::PartitionUniqueMachineSecret,
            None,
            PART_ROOT_VAULT_ATTRS,
        )
        .await?;

    let pta_key_id = pal
        .vault_key_create(
            io,
            inputs.pta_priv,
            HsmVaultKeyKind::PartitionTrustAnchor,
            None,
            PTA_VAULT_ATTRS,
        )
        .await?;

    crate::part_state::part_set_pta_key(pal, io, pta_key_id, inputs.pta_pub_sec1)?;
    crate::part_state::part_set_ups_key_id(pal, io, root_key_id)?;
    crate::part_state::part_set_policy_hash(pal, io, inputs.policy_hash)?;
    crate::part_state::part_set_pota_thumbprint(pal, io, inputs.pota_thumb)?;
    crate::part_state::part_set_sata_thumbprint(pal, io, inputs.sata_thumb)?;
    if let Some(sapota) = inputs.sapota_thumb {
        crate::part_state::part_set_sapota_thumbprint(pal, io, sapota)?;
    }
    crate::part_state::part_set_state(pal, io, PartState::Initializing)?;
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
    //! Produces the per-partition **root secret (`PartRoot`)** and,
    //! from it, the per-partition PTA keypair, from the device's Unique
    //! Device Secret (UDS) plus operator-supplied binding inputs
    //! (`MachineSeed`, the unified `PartPolicy`, and the POTA / SATA /
    //! SAPOTA thumbprints).
    //! All derivations are deterministic: identical inputs yield
    //! identical outputs, so a partition's identity keys can be
    //! reconstructed across reboots and NSSR cycles without persisting
    //! plaintext key material.
    //!
    //! # Single-root derivation
    //!
    //! ```text
    //!   UDS  ──KBKDF-CTR-HMAC-SHA384(label, ctx)──►  PartRoot (48 B)
    //!   PartRoot ──HKDF-Expand-SHA384(info)───────►  OKM
    //!   OKM  ──FIPS 186-5 §A.2.1 (Extra Random Bits)─►  (d, Q)
    //! ```
    //!
    //! - The first stage uses **NIST SP 800-108** Counter Mode KBKDF
    //!   with HMAC-SHA384 as the PRF to derive a single per-partition
    //!   root secret (`PartRoot`) binding *all* request inputs: the
    //!   machine seed, the unified `PartPolicy`, and the POTA / SATA /
    //!   SAPOTA certificate thumbprints.  Label
    //!   `b"AZIHSM-PartInit-PartRoot-v1"` ties the derivation to this
    //!   version of the PartInit protocol; rotating the label (e.g.
    //!   `v2`) retires all derived material.
    //! - The second stage uses **RFC 5869 HKDF-Expand** (HMAC-SHA384)
    //!   keyed by `PartRoot` so the PTA keypair fans out from the single
    //!   root via a distinct domain-separation label, without re-running
    //!   the expensive UDS-touching KBKDF.  (Future part-final local
    //!   keys will fan out from `PartRoot` the same way.)
    //! - The third stage delegates to
    //!   [`azihsm_crypto::EccPrivateKey::from_okm_a2_1`] via the
    //!   PAL trait
    //!   [`HsmEcc::ecc_gen_keypair_from_okm`](azihsm_fw_hsm_pal_traits::HsmEcc::ecc_gen_keypair_from_okm).
    //!
    //! # Public surface
    //!
    //! [`derive_part_root`] computes the per-partition root secret;
    //! [`derive_pta_keypair`] consumes that root to derive the
    //! deterministic PTA P-384 keypair.
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

    /// Domain-separation label for the UDS → PartRoot derivation
    /// (SP 800-108 KBKDF input).  Version suffix `v1` reserved for
    /// future protocol revisions.
    pub const PART_ROOT_LABEL: &[u8] = b"AZIHSM-PartInit-PartRoot-v1";

    /// Length of the derived per-partition root secret, in bytes.
    ///
    /// 48 bytes = 384 bits, matching SHA-384's output and providing the
    /// full security margin needed to seed P-384 partition keys.
    pub const PART_ROOT_LEN: usize = 48;

    /// Minimum acceptable `MachineSeed` length.  Below 128 bits the seed
    /// cannot contribute enough entropy to bind the derivation to the
    /// hosting machine.
    pub const MACHINE_SEED_MIN_LEN: usize = 16;

    /// Maximum acceptable `MachineSeed` length.  Caps host-controlled
    /// input so the context buffer remains small and predictable.
    pub const MACHINE_SEED_MAX_LEN: usize = 256;

    /// Derive the per-partition root secret (`PartRoot`) from the
    /// device's UDS and *all* the operator-supplied binding inputs.
    ///
    /// Implements the single-root first stage of the PartInit KDF
    /// (UDS → PartRoot) via SP 800-108 Counter Mode KBKDF with
    /// HMAC-SHA384.  Every per-partition key is later fanned out from
    /// this root, so the root binds the machine seed, the unified
    /// `PartPolicy`, and the POTA / SATA / SAPOTA thumbprints.
    ///
    /// Follows the PAL query/copy convention:
    ///
    /// 1. **Query** — call with `root_out = None`.  No derivation
    ///    happens; the method returns [`PART_ROOT_LEN`], the byte count
    ///    the caller must allocate.  Input length validation still runs.
    /// 2. **Alloc** — caller allocates a DMA buffer of that size.
    /// 3. **Use** — call with `root_out = Some(buf)`.  The method
    ///    derives `PartRoot` and writes [`PART_ROOT_LEN`] bytes into the
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
    /// - `part_policy` — unified `PartPolicy` bytes (any length up to
    ///   `u16::MAX`).
    /// - `pota_thumb` / `sata_thumb` — POTA / SATA thumbprint bytes.
    /// - `sapota_thumb` — optional SAPOTA thumbprint bytes; `None`
    ///   contributes a zero-length field (the length-prefix keeps the
    ///   absent and empty-present cases unambiguous).
    /// - `root_out` — `None` to query the required buffer size;
    ///   `Some(buf)` to derive.  When `Some`, `buf.len()` must be at
    ///   least [`PART_ROOT_LEN`].
    ///
    /// # Returns
    ///
    /// - `Ok(PART_ROOT_LEN)` — query/use byte count.
    /// - `Err(HsmError::InvalidArg)` — `machine_seed` length out of
    ///   range, any single input exceeds `u16::MAX` bytes, or
    ///   `root_out` is `Some` and shorter than [`PART_ROOT_LEN`].
    /// - `Err(HsmError::NotEnoughSpace)` — scoped alloc exhausted.
    /// - `Err(HsmError)` — PAL KDF driver failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn derive_part_root(
        pal: &impl HsmPal,
        io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        uds: &DmaBuf,
        machine_seed: &DmaBuf,
        part_policy: &DmaBuf,
        pota_thumb: &DmaBuf,
        sata_thumb: &DmaBuf,
        sapota_thumb: Option<&DmaBuf>,
        root_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        if !(MACHINE_SEED_MIN_LEN..=MACHINE_SEED_MAX_LEN).contains(&machine_seed.len()) {
            return Err(HsmError::InvalidArg);
        }
        let sapota_len = sapota_thumb.map_or(0, |t| t.len());
        // Each field is u16-BE length-prefixed in the KBKDF context.
        if part_policy.len() > u16::MAX as usize
            || pota_thumb.len() > u16::MAX as usize
            || sata_thumb.len() > u16::MAX as usize
            || sapota_len > u16::MAX as usize
        {
            return Err(HsmError::InvalidArg);
        }

        let Some(root_out) = root_out else {
            return Ok(PART_ROOT_LEN);
        };
        if root_out.len() < PART_ROOT_LEN {
            return Err(HsmError::InvalidArg);
        }

        let label = alloc.dma_alloc(PART_ROOT_LABEL.len())?;
        label.copy_from_slice(PART_ROOT_LABEL);

        // Length-injective context: u16_be(|f|) ‖ f, for each field.
        // SAPOTA is bound as a zero-length field when absent.
        let sapota_bytes: &[u8] = match sapota_thumb {
            Some(t) => t,
            None => &[],
        };
        let fields: [&[u8]; 5] = [
            machine_seed,
            part_policy,
            pota_thumb,
            sata_thumb,
            sapota_bytes,
        ];
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
            &mut root_out[..PART_ROOT_LEN],
        )
        .await?;
        Ok(PART_ROOT_LEN)
    }

    /// Domain-separation label for the PartRoot → PTA keypair derivation
    /// (HKDF-Expand info prefix).  Mirrors [`PART_ROOT_LABEL`]
    /// versioning: rotating the suffix retires the associated key.
    /// Exposed as a `pub` constant so integration tests can construct
    /// alternate labels and assert domain separation.
    pub const KEYPAIR_LABEL_PTA: &[u8] = b"AZIHSM-PartInit-PTA-v1";

    /// Derive the deterministic per-partition PTA key pair (P-384) from
    /// a `PartRoot` produced by [`derive_part_root`], composing RFC 5869
    /// HKDF-Expand-SHA384 with FIPS 186-5 §A.2.1 (Extra Random Bits)
    /// keypair generation.
    ///
    /// The HKDF info input is `KEYPAIR_LABEL_PTA ‖ u16_be(okm_len)` so
    /// that two different curves (or two different labels of the same
    /// length) can never share an OKM, and so that increasing `okm_len`
    /// in a future protocol revision is a domain-separating change.
    ///
    /// Same query/copy convention as [`derive_part_root`] and as the
    /// underlying PAL primitives
    /// ([`HsmEcc::ecc_gen_keypair_from_okm`]):
    ///
    /// 1. **Query** — call with `out = None`.  No derivation happens;
    ///    returns the per-curve `(priv_len, pub_len)` byte counts the
    ///    caller must allocate.  `root` is still validated.
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
    /// - `root` — `PartRoot` from [`derive_part_root`].  Length
    ///   must equal [`PART_ROOT_LEN`].
    /// - `out` — `None` to query buffer sizes; `Some((priv_out,
    ///   pub_out))` to derive.  Each buffer must hold at least the
    ///   length returned by an earlier query call.
    ///
    /// # Returns
    ///
    /// - `Ok((priv_len, pub_len))` — in query mode, the required
    ///   buffer sizes (48, 96 for P-384); in use mode, the actual
    ///   bytes written.
    /// - `Err(HsmError::InvalidArg)` — `root.len() != PART_ROOT_LEN` or
    ///   an output buffer too small.
    /// - `Err(HsmError::NotEnoughSpace)` — scoped alloc exhausted.
    /// - `Err(HsmError)` — PAL KDF / ECC driver failure.
    pub async fn derive_pta_keypair(
        pal: &impl HsmPal,
        io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        root: &DmaBuf,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let curve = HsmEccCurve::P384;
        let priv_len = curve.wire_coord_len();
        let pub_len = curve.wire_pub_key_len();
        let okm_len = curve.a2_1_okm_len();

        if root.len() != PART_ROOT_LEN {
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
        pal.hkdf_expand(io, HsmHashAlgo::Sha384, root, Some(info), okm)
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
