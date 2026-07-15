// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Receiver attestation-evidence verification for Security-Domain (SD)
//! backup commands.
//!
//! Several TBOR SD commands (`SdCreateRemoteBackup`, `SdReseal`,
//! `SdRestore*`, `SdCreatePeerBackup`) carry an attestation **evidence**
//! context out of band: three ECDSA-P384 X.509 certificate chains
//! (manufacturer / owner / partition-owner) plus a COSE_Sign1 key-
//! attestation report. [`verify_evidence`] validates one such context and
//! recovers the attested public key it vouches for.
//!
//! It enforces, in order:
//!
//! 1. all three certificate chains validate as X.509 ECDSA chains;
//! 2. the manufacturer and owner chains are validated but **not** anchored;
//! 3. the partition-owner chain is anchored to the policy SATA key (a
//!    non-leaf certificate's public key must equal it — SATA endorses the
//!    leaf directly or indirectly);
//! 4. all three chains share the **same** leaf public key;
//! 5. that shared leaf key signed the COSE_Sign1 attestation report.
//!
//! The bulk DER/COSE items travel out of band as NVMe SGL Data Blocks; the
//! caller passes the [`OobPtr`] locating them plus the per-item
//! descriptors (see [`EvidenceRefs`]). Each certificate is copied into a
//! nested, per-chain allocator scope that frees on return, so peak DMA use
//! stays bounded regardless of chain depth.
//!
//! Keys and reports are P-384 / ES384 throughout (the SD sealing curve and
//! the report signature algorithm).

#![no_std]

use azihsm_fw_core_crypto_key_report::parse_ec2_cose_key;
use azihsm_fw_core_crypto_key_report::parse_key_report;
use azihsm_fw_core_crypto_key_report::verify_key_report;
use azihsm_fw_core_crypto_key_report::KEY_REPORT_MAX_LEN;
use azihsm_fw_core_crypto_key_report::POLICY_HASH_LEN;
use azihsm_fw_core_crypto_x509_chain::validate_chain as validate_cert_chain;
use azihsm_fw_ddi_tbor_types::CertDescriptor;
use azihsm_fw_ddi_tbor_types::ReportDescriptor;
use azihsm_fw_hsm_oob::copy_oob;
use azihsm_fw_hsm_oob::OobPtr;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmGdmaController;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

/// NIST curve of the leaf / attested keys and the report signature (SD
/// sealing keys are P-384; reports are ES384).
const CURVE: HsmEccCurve = HsmEccCurve::P384;

/// P-384 coordinate length (`priv_key_len`).
const COORD_LEN: usize = 48;

/// Length of a leaf / attested public point (`X ‖ Y`, big-endian).
const POINT_LEN: usize = 2 * COORD_LEN;

/// SEC1 uncompressed attested-key length (`0x04 ‖ X ‖ Y`).
pub const ATTESTED_KEY_LEN: usize = 1 + POINT_LEN;

/// SEC1 uncompressed point tag (`0x04 ‖ X ‖ Y`).
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Reverse-copy `src` into `dst[..src.len()]` (LE↔BE per coordinate).
fn reverse_copy(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter().rev()) {
        *d = *s;
    }
}

/// Out-of-band locations of one attestation context's items: the three
/// certificate-chain descriptor lists plus the attestation-report
/// descriptor. Obtained from a command's [`Evidence`] field-group view.
///
/// [`Evidence`]: azihsm_fw_ddi_tbor_types::evidence::Evidence
pub struct EvidenceRefs<'a> {
    /// Manufacturer certificate-chain descriptors (root→leaf).
    pub mfgr_chain: &'a [CertDescriptor],
    /// Owner certificate-chain descriptors (root→leaf).
    pub owner_chain: &'a [CertDescriptor],
    /// Partition-owner certificate-chain descriptors (root→leaf).
    pub part_owner_chain: &'a [CertDescriptor],
    /// COSE_Sign1 attestation-report descriptor.
    pub report: &'a ReportDescriptor,
}

/// Trust anchors the evidence must chain to, taken from the partition
/// policy. The manufacturer and owner chains are validated but unanchored;
/// the partition-owner chain must be endorsed (directly or indirectly) by
/// [`sata`](Self::sata).
pub struct TrustAnchors<'a> {
    /// SATA (Sealing Authority Trust Anchor) public key: raw `X ‖ Y`,
    /// big-endian, exactly [`POINT_LEN`] bytes.
    pub sata: &'a [u8],
}

/// Verify a receiver's attestation evidence and recover the attested key.
///
/// Validates the three certificate chains in `refs`, anchors the
/// partition-owner chain to `anchors.sata`, requires a single shared leaf
/// key across the chains, and confirms that leaf key signed the report.
/// On success the attested public key recovered from the report's COSE_Key
/// is written to `attested_key` in SEC1 uncompressed big-endian form
/// (`0x04 ‖ X ‖ Y`, [`ATTESTED_KEY_LEN`] bytes).
///
/// When `policy_hash_out` is `Some`, the report's v2 `policy_hash` (the
/// SHA-384 PartPolicy digest) is copied into it ([`POLICY_HASH_LEN`]
/// bytes); the report must be **v2** (a v1 report with no `policy_hash` is
/// rejected). This lets callers (e.g. the security-domain reseal flow) bind
/// the attested key to a specific policy. Pass `None` to ignore it.
///
/// # Errors
///
/// * [`HsmError::InvalidArg`] — a chain is empty, the partition-owner chain
///   is not anchored to `anchors.sata`, the chains disagree on a leaf key,
///   the report signature does not verify, the attested key is not P-384,
///   `attested_key` is too small, or `policy_hash_out` is `Some` but the
///   report carries no v2 `policy_hash` (or the buffer is too small).
/// * `X509…` errors — a certificate is malformed or its signature / chain
///   linkage is invalid (propagated from the chain validator).
/// * Other [`HsmError`] values propagated from the PAL / OOB copy.
pub async fn verify_evidence<P>(
    pal: &P,
    io: &impl HsmIo,
    oob: &OobPtr,
    refs: &EvidenceRefs<'_>,
    anchors: &TrustAnchors<'_>,
    attested_key: &mut DmaBuf,
    policy_hash_out: Option<&mut DmaBuf>,
) -> HsmResult<()>
where
    P: HsmGdmaController + HsmAlloc + HsmCrypto,
{
    if anchors.sata.len() != POINT_LEN || attested_key.len() < ATTESTED_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    let coord = COORD_LEN;

    // Reqs 1–2: the manufacturer chain (no anchor) fixes the canonical leaf
    // key; the owner chain (no anchor) must share it (req 4).
    let mut canonical = [0u8; POINT_LEN];
    validate_chain(pal, io, oob, refs.mfgr_chain, None, &mut canonical).await?;

    let mut leaf = [0u8; POINT_LEN];
    validate_chain(pal, io, oob, refs.owner_chain, None, &mut leaf).await?;
    if leaf != canonical {
        return Err(HsmError::InvalidArg);
    }

    // Reqs 1, 3, 4: the partition-owner chain must validate, be anchored to
    // the policy SATA key, and share the canonical leaf key.
    validate_chain(
        pal,
        io,
        oob,
        refs.part_owner_chain,
        Some(anchors.sata),
        &mut leaf,
    )
    .await?;
    if leaf != canonical {
        return Err(HsmError::InvalidArg);
    }

    // Req 5: the shared leaf key must endorse the attestation report.
    let report_index = refs.report.index as usize;
    let report_len = refs.report.length.get() as usize;
    // `report_len` is attacker-controlled and sizes the DMA allocation and
    // OOB copy below. A report larger than `KEY_REPORT_MAX_LEN` cannot be a
    // valid COSE_Sign1 key report (`parse_key_report` would reject it), so
    // cap it here to keep a hostile length from forcing an oversized copy.
    if report_len == 0 || report_len > KEY_REPORT_MAX_LEN {
        return Err(HsmError::InvalidArg);
    }

    pal.alloc_scoped_async(io, async |ra| -> HsmResult<()> {
        let report = ra.dma_alloc(report_len)?;
        copy_oob(pal, io, oob, report_index, report).await?;

        // The leaf point is big-endian (X.509); `verify_key_report`'s
        // `signer_pub` is the `ecc_verify` wire form (little-endian per
        // coordinate).
        let leaf_le = ra.dma_alloc(POINT_LEN)?;
        reverse_copy(&mut leaf_le[..coord], &canonical[..coord]);
        reverse_copy(&mut leaf_le[coord..2 * coord], &canonical[coord..2 * coord]);

        if !verify_key_report(pal, io, ra, report, leaf_le).await? {
            return Err(HsmError::InvalidArg);
        }

        // The report is now authenticated: recover the attested public key
        // (SEC1 uncompressed big-endian) from its COSE_Key.
        let view = parse_key_report(report)?;
        let cose_key = &view.public_key[..view.public_key_size as usize];
        let rcvr = parse_ec2_cose_key(cose_key)?;
        if rcvr.curve != CURVE {
            return Err(HsmError::InvalidArg);
        }

        attested_key[0] = SEC1_UNCOMPRESSED;
        attested_key[1..1 + coord].copy_from_slice(rcvr.x);
        attested_key[1 + coord..1 + 2 * coord].copy_from_slice(rcvr.y);

        // When requested, surface the report's v2 PartPolicy digest so the
        // caller can bind the attested key to a policy (used by the
        // security-domain reseal flow). The report must be v2.
        if let Some(out) = policy_hash_out {
            let ph = view.policy_hash.ok_or(HsmError::InvalidArg)?;
            if out.len() < POLICY_HASH_LEN || ph.len() != POLICY_HASH_LEN {
                return Err(HsmError::InvalidArg);
            }
            out[..POLICY_HASH_LEN].copy_from_slice(&ph[..POLICY_HASH_LEN]);
        }
        Ok(())
    })
    .await
}

/// Validate one DER certificate chain and recover its leaf public key.
///
/// Thin OOB adapter over the shared [`validate_cert_chain`] walker: it
/// sources each certificate's DER from the OOB SGL page (by descriptor
/// index) and runs the whole walk inside a nested allocator scope that
/// frees on return, so only the caller's small `leaf_out` survives. The
/// walker double-buffers, so peak DMA stays bounded regardless of chain
/// depth. On success the validated leaf public point (`X ‖ Y`, big-endian)
/// is copied into `leaf_out`.
///
/// When `anchor` is `Some`, at least one **non-leaf** certificate's public
/// point must byte-match it (both big-endian) — the trust-anchor binding.
/// A chain with no matching anchor is rejected with [`HsmError::InvalidArg`].
async fn validate_chain<P>(
    pal: &P,
    io: &impl HsmIo,
    oob: &OobPtr,
    chain: &[CertDescriptor],
    anchor: Option<&[u8]>,
    leaf_out: &mut [u8],
) -> HsmResult<()>
where
    P: HsmGdmaController + HsmAlloc + HsmCrypto,
{
    pal.alloc_scoped_async(io, async |ca| -> HsmResult<()> {
        validate_cert_chain(
            pal,
            io,
            ca,
            chain,
            anchor,
            leaf_out,
            async |index: usize, buf: &mut DmaBuf| copy_oob(pal, io, oob, index, buf).await,
        )
        .await
    })
    .await
}
