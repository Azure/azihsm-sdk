// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdCreateRemoteBackup` command.
//!
//! `SdCreateRemoteBackup` creates a security domain: it mints a fresh
//! BKS3 and a random security-domain masking key (`SDMK`), provisions
//! `SDMK` in the vault as the partition's SecurityDomain-scope masking
//! key, and returns three backups — the 161-byte HPKE-Auth
//! `pok_remote_backup`, the 180-byte `pok_local_backup` (BKS3 masked
//! under `PartLocalMK`), and the 164-byte `sd_mk_backup` (`SDMK` masked
//! under the derived `SDBMK`).
//!
//! These tests run a **self-backup** (sender == receiver): one partition
//! mints an SD sealing key, attests it via `KeyReport`, then seals to its
//! own attested public key.  This exercises the full path — the OOB SGL
//! transport, the COSE_Key `RcvrPub` extraction, the sealing-key unmask,
//! the HPKE-Auth seal, and the SDMK provisioning — without a second
//! device.
//!
//! Coverage:
//! * Happy path — non-zero `pok_remote_backup` (161 B), `pok_local_backup`
//!   (180 B), and `sd_mk_backup` (164 B).
//! * One-shot: a second create on the now-initialized partition →
//!   `SdAlreadyInitialized`.
//! * Missing OOB evidence → `InvalidArg`.
//! * Policy that does not name this partition as the backing partition
//!   (`backup_part_id` / `backup_part_pub_key` absent) → `InvalidArg`.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::tbor_int::U16;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::TborKeyReportReq;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use zerocopy::TryFromBytes;

use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::known_good_part_policy;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::part_policy_with_pota;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::x509_fixture::make_chain;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::GeneratedChain;
use crate::harness::x509_fixture::RAW_PUB_LEN;
use crate::harness::SessionHandshake;
use crate::harness::TestCtx;

/// `KeyScope::Local` discriminant (wire mirror of the firmware
/// `HsmKeyScope`).
const SCOPE_LOCAL: u8 = 0b011;

/// Byte offset of the SATA public-key **data** inside the 484-byte
/// `PartPolicy` image: `sata_pub_key` starts at 102 (`kind(2) ‖ len(2) ‖
/// data(96)`), so the raw `X ‖ Y` coordinates begin at 106.
const OFF_SATA_PUB_KEY_DATA: usize = 106;

/// Byte offsets of the backing-partition fields inside the 484-byte
/// `PartPolicy` image (mirror of `fw/core/ddi/tbor/types/src/policy.rs`).
const OFF_BACKUP_PART_ID: usize = 302;
const OFF_BACKUP_PART_PUB_KEY: usize = 318;
const BACKUP_PART_ID_LEN: usize = 16;

/// Build a policy naming **this** partition as the backing partition
/// (`backup_part_id = PID`, `backup_part_pub_key = PID public key`) and
/// anchoring the security domain to `sata_pub` (raw `X ‖ Y`, big-endian).
///
/// The caller learns the PID / PID public key from `PartInfo` (before
/// `PartInit`); the SATA key is a synthetic trust anchor the test also
/// uses to sign the partition-owner certificate chain.
fn backing_part_policy(
    pid: &[u8],
    pid_pub: &[u8],
    sata_pub: &[u8; RAW_PUB_LEN],
    pota_pub: &[u8; RAW_PUB_LEN],
) -> [u8; PART_POLICY_LEN] {
    // Anchor the policy to a real POTA key so `PartFinal` can validate a
    // PTA certificate chain against it.
    let mut bytes = part_policy_with_pota(pota_pub);

    // Overwrite the placeholder SATA key with the test anchor's real
    // P-384 public coordinates (kind / len already Ecc384 / 96).
    bytes[OFF_SATA_PUB_KEY_DATA..OFF_SATA_PUB_KEY_DATA + RAW_PUB_LEN].copy_from_slice(sata_pub);

    bytes[OFF_BACKUP_PART_ID..OFF_BACKUP_PART_ID + BACKUP_PART_ID_LEN].copy_from_slice(pid);

    // backup_part_pub_key = { kind: Ecc384 (LE), len: 96 (LE), data }.
    let off = OFF_BACKUP_PART_PUB_KEY;
    bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
    bytes[off + 2..off + 4].copy_from_slice(&(POLICY_MAX_KEY_LEN as u16).to_le_bytes());
    bytes[off + 4..off + 4 + POLICY_MAX_KEY_LEN].copy_from_slice(pid_pub);

    bytes
}

/// Drive `PartInit → PartFinal` with a backing-partition policy anchored
/// to `sata_key` and return the live CO session, the exact policy image
/// (needed verbatim by `SdCreateRemoteBackup` for the `policy_hash`
/// re-check), and the partition-identity (PID) public key that every
/// evidence leaf certificate must carry.
pub(crate) fn finalized_backing_session(
    ctx: &TestCtx,
    sata_key: &CaKey,
) -> (SessionHandshake, [u8; PART_POLICY_LEN], [u8; RAW_PUB_LEN]) {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

    // PID / PID public key are materialized before PartInit.
    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);

    // POTA anchor for the PTA certificate chain `PartFinal` validates.
    let pota = CaKey::generate();
    let policy = backing_part_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata_key.raw_pub(),
        &pota.raw_pub(),
    );

    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    (session, policy, pid_pub)
}

/// Mint an SD sealing key and attest it, returning
/// `(masked_sealing_key, key_report_bytes)`.  In the self-backup tests
/// this key is both the sender's authentication key and (via its report)
/// the receiver's `RcvrPub` source; the report is signed by the PID key.
pub(crate) fn masked_key_and_report(ctx: &TestCtx, session_id: u16) -> (Vec<u8>, Vec<u8>) {
    let seal = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("SdSealingKeyGen");
    let masked = seal.masked_key.to_vec();

    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id,
            masked_key: masked.clone(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("KeyReport")
        .report;

    (masked, report)
}

/// Receiver attestation evidence: the OOB items (three cert chains then
/// the report, in index order) plus the descriptors referencing them.
pub(crate) struct ReceiverEvidence {
    /// OOB SGL items in index order: `[mfgr root, mfgr leaf, owner root,
    /// owner leaf, part-owner root, part-owner leaf, report]`.
    oob_items: Vec<Vec<u8>>,
    mfgr: Vec<CertDescriptor>,
    owner: Vec<CertDescriptor>,
    part_owner: Vec<CertDescriptor>,
    report: ReportDescriptor,
}

impl ReceiverEvidence {
    /// Borrow the OOB items as the `&[&[u8]]` slice `tbor_oob` expects.
    pub(crate) fn oob(&self) -> Vec<&[u8]> {
        self.oob_items.iter().map(Vec::as_slice).collect()
    }
}

/// Append `der` as the next OOB item and return a descriptor for it.
fn push_item(items: &mut Vec<Vec<u8>>, der: &[u8]) -> CertDescriptor {
    let index = items.len() as u8;
    items.push(der.to_vec());
    CertDescriptor {
        index,
        length: U16::new(der.len() as u16),
    }
}

/// Assemble receiver evidence from three explicit chains plus the report,
/// laying the DER items out in the OOB page in index order.
fn evidence_from_chains(
    mfgr: &GeneratedChain,
    owner: &GeneratedChain,
    part_owner: &GeneratedChain,
    report: &[u8],
) -> ReceiverEvidence {
    let mut items = Vec::new();
    let mfgr_desc = vec![
        push_item(&mut items, &mfgr.root_der),
        push_item(&mut items, &mfgr.leaf_der),
    ];
    let owner_desc = vec![
        push_item(&mut items, &owner.root_der),
        push_item(&mut items, &owner.leaf_der),
    ];
    let part_owner_desc = vec![
        push_item(&mut items, &part_owner.root_der),
        push_item(&mut items, &part_owner.leaf_der),
    ];
    let report_desc = push_item(&mut items, report);

    ReceiverEvidence {
        oob_items: items,
        mfgr: mfgr_desc,
        owner: owner_desc,
        part_owner: part_owner_desc,
        report: ReportDescriptor {
            index: report_desc.index,
            length: report_desc.length,
        },
    }
}

/// Build the three-chain receiver evidence for `pid_pub`: manufacturer and
/// owner chains rooted at fresh CAs, and a partition-owner chain rooted at
/// the policy `sata_key`.  Every leaf certifies `pid_pub` (the report
/// signer), so all three share one leaf key.
pub(crate) fn build_receiver_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    report: &[u8],
) -> ReceiverEvidence {
    let mfgr = make_chain(&CaKey::generate(), pid_pub);
    let owner = make_chain(&CaKey::generate(), pid_pub);
    let part_owner = make_chain(sata_key, pid_pub);
    evidence_from_chains(&mfgr, &owner, &part_owner, report)
}

/// Assemble a `SdCreateRemoteBackup` request carrying the three receiver
/// certificate chains and the attestation-report descriptor.
pub(crate) fn backup_request(
    session_id: u16,
    masked_sealing_key: Vec<u8>,
    evidence: &ReceiverEvidence,
    policy: &[u8; PART_POLICY_LEN],
) -> TborSdCreateRemoteBackupReq {
    TborSdCreateRemoteBackupReq {
        session_id,
        masked_sealing_key: masked_sealing_key
            .as_slice()
            .try_into()
            .expect("masked sealing key is exactly MASKED_SEALING_KEY_LEN bytes"),
        receiver_mfgr_cert_chain: evidence.mfgr.clone(),
        receiver_owner_cert_chain: evidence.owner.clone(),
        receiver_part_owner_cert_chain: evidence.part_owner.clone(),
        receiver_report: evidence.report,
        policy: PartPolicy::try_read_from_bytes(policy).expect("policy image is canonical"),
    }
}

/// Minimal evidence (one report OOB item, empty cert chains) for reject
/// tests that fail **before** evidence validation — missing OOB page, or a
/// policy whose backing-partition binding is rejected first.
fn dummy_evidence(report: &[u8]) -> ReceiverEvidence {
    ReceiverEvidence {
        oob_items: vec![report.to_vec()],
        mfgr: Vec::new(),
        owner: Vec::new(),
        part_owner: Vec::new(),
        report: ReportDescriptor {
            index: 0,
            length: U16::new(report.len() as u16),
        },
    }
}

#[test]
fn sd_create_remote_backup_roundtrip_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (masked, report) = masked_key_and_report(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &sata_key, &report);

    let req = backup_request(session.session_id, masked, &evidence, &policy);
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup roundtrip");

    // HPKE-Auth seal: enc(97) ‖ ct(64) = 161 B, non-zero.
    assert_eq!(resp.pok_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        resp.pok_remote_backup.iter().any(|&b| b != 0),
        "pok_remote_backup must not be all-zero",
    );

    // Local backup: BKS3 masked under PartLocalMK, 180 B, non-zero.
    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );

    // Masking-key backup: SDMK masked under the derived SDBMK, 164 B,
    // non-zero.
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

#[test]
fn sd_create_remote_backup_is_one_shot_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (masked, report) = masked_key_and_report(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &sata_key, &report);

    let req = backup_request(session.session_id, masked, &evidence, &policy);
    let first = ctx.tbor_oob(&req, &evidence.oob()).expect("first create");
    assert!(
        first.pok_remote_backup.iter().any(|&b| b != 0),
        "first backup must be a real seal",
    );

    // The security domain is now initialized (SDMK provisioned); a second
    // create on the same partition is rejected by the one-shot gate.
    ctx.expect_fw_reject_oob(&req, &evidence.oob(), TborStatus::SdAlreadyInitialized);
}

#[test]
fn sd_create_remote_backup_rejects_missing_oob_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, _pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (masked, report) = masked_key_and_report(&ctx, session.session_id);

    // The receiver evidence descriptors reference OOB items, but no OOB
    // page is supplied → the handler rejects before any crypto.
    let evidence = dummy_evidence(&report);
    let req = backup_request(session.session_id, masked, &evidence, &policy);
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn sd_create_remote_backup_rejects_non_backing_policy_emu() {
    let ctx = TestCtx::new();

    // `finalized_co_session` binds `known_good_part_policy` — POTA/SATA
    // populated but the backing-partition fields left absent.  The policy
    // hash re-check passes (same policy), but the backing-partition
    // identity binding fails (before any evidence validation) because
    // `backup_part_id` / `backup_part_pub_key` do not name this partition.
    let session = finalized_co_session(&ctx);
    let (masked, report) = masked_key_and_report(&ctx, session.session_id);

    let policy = known_good_part_policy();
    let evidence = dummy_evidence(&report);
    let req = backup_request(session.session_id, masked, &evidence, &policy);
    ctx.expect_fw_reject_oob(&req, &evidence.oob(), TborStatus::InvalidArg);
}

/// Flip the final byte of a DER/COSE blob — corrupts the trailing ECDSA
/// signature value without disturbing the outer length-prefixed structure.
fn flip_last_byte(mut bytes: Vec<u8>) -> Vec<u8> {
    let n = bytes.len();
    bytes[n - 1] ^= 0xFF;
    bytes
}

#[test]
fn sd_create_remote_backup_rejects_wrong_sata_anchor_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (masked, report) = masked_key_and_report(&ctx, session.session_id);

    // The partition-owner chain is internally valid but rooted at a CA the
    // policy SATA key does not match → the anchor binding (req 3) fails.
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&CaKey::generate(), &pid_pub);
    let evidence = evidence_from_chains(&mfgr, &owner, &part_owner, &report);

    let req = backup_request(session.session_id, masked, &evidence, &policy);
    ctx.expect_fw_reject_oob(&req, &evidence.oob(), TborStatus::InvalidArg);
}

#[test]
fn sd_create_remote_backup_rejects_leaf_key_mismatch_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (masked, report) = masked_key_and_report(&ctx, session.session_id);

    // The owner chain certifies a *different* leaf key, so the three chains
    // do not agree on a single leaf (req 4) → reject.
    let other_pub = CaKey::generate().raw_pub();
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &other_pub);
    let part_owner = make_chain(&sata_key, &pid_pub);
    let evidence = evidence_from_chains(&mfgr, &owner, &part_owner, &report);

    let req = backup_request(session.session_id, masked, &evidence, &policy);
    ctx.expect_fw_reject_oob(&req, &evidence.oob(), TborStatus::InvalidArg);
}

#[test]
fn sd_create_remote_backup_rejects_tampered_cert_sig_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (masked, report) = masked_key_and_report(&ctx, session.session_id);

    // Corrupt the partition-owner leaf's signature: the chain is structurally
    // valid but the leaf's ECDSA signature no longer verifies (req 1).
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let mut part_owner = make_chain(&sata_key, &pid_pub);
    part_owner.leaf_der = flip_last_byte(part_owner.leaf_der);
    let evidence = evidence_from_chains(&mfgr, &owner, &part_owner, &report);

    let req = backup_request(session.session_id, masked, &evidence, &policy);
    ctx.expect_fw_reject_oob(&req, &evidence.oob(), TborStatus::X509SignatureInvalid);
}

#[test]
fn sd_create_remote_backup_rejects_tampered_report_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (masked, report) = masked_key_and_report(&ctx, session.session_id);

    // All three chains are valid and share the leaf key, but the report's
    // signature no longer verifies against that leaf key (req 5).
    let tampered_report = flip_last_byte(report);
    let evidence = build_receiver_evidence(&pid_pub, &sata_key, &tampered_report);

    let req = backup_request(session.session_id, masked, &evidence, &policy);
    ctx.expect_fw_reject_oob(&req, &evidence.oob(), TborStatus::InvalidArg);
}
