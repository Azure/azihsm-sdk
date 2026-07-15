// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdResealRemoteBackup` command.
//!
//! `SdResealRemoteBackup` reseals a remote backup from a source recipient
//! to a destination recipient: it HPKE-Auth-opens the caller-supplied
//! `src_remote_backup` with the masked **receiver** key (recovering the
//! BKS3, authenticated by the source **sender** public key from
//! `src_evidence`) and HPKE-Auth-seals that BKS3 to the destination
//! **receiver** public key (from `dest_evidence`), returning
//! `dst_remote_backup`.  Nothing is persisted.
//!
//! These tests run a **self-reseal** on one partition: it mints receiver /
//! sender / destination SD sealing keys, uses `SdCreateRemoteBackup` to
//! produce a real source backup (BKS3 sealed to the receiver by the
//! sender), then reseals it.  A successful reseal is itself the correctness
//! check: the HPKE-Auth **open** only succeeds if the receiver key and the
//! attested sender key match those that sealed the source, so a non-error
//! result proves the BKS3 was recovered and resealed.
//!
//! Coverage:
//! * Happy path — a 161-byte, non-zero `dst_remote_backup`.
//! * Re-randomization — two reseals of the same source differ (fresh HPKE
//!   ephemeral each call).
//! * Tampered `src_remote_backup` → the open's AEAD auth fails → reject.
//! * Missing OOB evidence → `InvalidArg`.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::tbor_int::U16;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::TborSdResealRemoteBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use zerocopy::TryFromBytes;

use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::finalized_backing_session;
use crate::commands::sd_create_remote_backup::masked_key_and_report;
use crate::harness::x509_fixture::make_chain;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::GeneratedChain;
use crate::harness::x509_fixture::RAW_PUB_LEN;
use crate::harness::TestCtx;

/// Both attestation evidences (source sender, destination receiver) laid
/// out in a single OOB page, with descriptors indexing into it.
struct ResealEvidence {
    /// OOB items in index order: the source evidence's `[mfgr root, mfgr
    /// leaf, owner root, owner leaf, part-owner root, part-owner leaf,
    /// report]` (indices 0..=6) followed by the destination evidence's
    /// (indices 7..=13).
    oob_items: Vec<Vec<u8>>,
    src_mfgr: Vec<CertDescriptor>,
    src_owner: Vec<CertDescriptor>,
    src_part_owner: Vec<CertDescriptor>,
    src_report: ReportDescriptor,
    dest_mfgr: Vec<CertDescriptor>,
    dest_owner: Vec<CertDescriptor>,
    dest_part_owner: Vec<CertDescriptor>,
    dest_report: ReportDescriptor,
}

impl ResealEvidence {
    fn oob(&self) -> Vec<&[u8]> {
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

/// Push one evidence's three chains and report into `items`, returning
/// their descriptors.
fn push_evidence(
    items: &mut Vec<Vec<u8>>,
    mfgr: &GeneratedChain,
    owner: &GeneratedChain,
    part_owner: &GeneratedChain,
    report: &[u8],
) -> (
    Vec<CertDescriptor>,
    Vec<CertDescriptor>,
    Vec<CertDescriptor>,
    ReportDescriptor,
) {
    let m = vec![
        push_item(items, &mfgr.root_der),
        push_item(items, &mfgr.leaf_der),
    ];
    let o = vec![
        push_item(items, &owner.root_der),
        push_item(items, &owner.leaf_der),
    ];
    let p = vec![
        push_item(items, &part_owner.root_der),
        push_item(items, &part_owner.leaf_der),
    ];
    let r = push_item(items, report);
    (
        m,
        o,
        p,
        ReportDescriptor {
            index: r.index,
            length: r.length,
        },
    )
}

/// Build the combined source + destination evidence.  Each side's three
/// chains all certify `pid_pub` (the report signer), with the
/// partition-owner chain rooted at the policy `sata_key`.
fn build_reseal_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    src_report: &[u8],
    dest_report: &[u8],
) -> ResealEvidence {
    let mut items = Vec::new();
    let (src_mfgr, src_owner, src_part_owner, src_report_desc) = push_evidence(
        &mut items,
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(sata_key, pid_pub),
        src_report,
    );
    let (dest_mfgr, dest_owner, dest_part_owner, dest_report_desc) = push_evidence(
        &mut items,
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(sata_key, pid_pub),
        dest_report,
    );
    ResealEvidence {
        oob_items: items,
        src_mfgr,
        src_owner,
        src_part_owner,
        src_report: src_report_desc,
        dest_mfgr,
        dest_owner,
        dest_part_owner,
        dest_report: dest_report_desc,
    }
}

/// Assemble a `SdResealRemoteBackup` request.
fn reseal_request(
    session_id: u16,
    masked_receiver_key: Vec<u8>,
    evidence: &ResealEvidence,
    policy: &[u8; PART_POLICY_LEN],
    src_remote_backup: &[u8; POK_REMOTE_BACKUP_LEN],
) -> TborSdResealRemoteBackupReq {
    TborSdResealRemoteBackupReq {
        session_id,
        masked_sealing_key: masked_receiver_key
            .as_slice()
            .try_into()
            .expect("masked receiver key is exactly MASKED_SEALING_KEY_LEN bytes"),
        policy: PartPolicy::try_read_from_bytes(policy).expect("policy image is canonical"),
        src_mfgr_cert_chain: evidence.src_mfgr.clone(),
        src_owner_cert_chain: evidence.src_owner.clone(),
        src_part_owner_cert_chain: evidence.src_part_owner.clone(),
        src_report: evidence.src_report,
        dest_mfgr_cert_chain: evidence.dest_mfgr.clone(),
        dest_owner_cert_chain: evidence.dest_owner.clone(),
        dest_part_owner_cert_chain: evidence.dest_part_owner.clone(),
        dest_report: evidence.dest_report,
        src_remote_backup: *src_remote_backup,
    }
}

/// Create a real source backup: a fresh BKS3 sealed to the receiver's
/// attested public key (from `receiver_report`) by the sender's masked key.
fn create_source_backup(
    ctx: &TestCtx,
    session_id: u16,
    pid_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    masked_sender_key: Vec<u8>,
    receiver_report: &[u8],
    policy: &[u8; PART_POLICY_LEN],
) -> [u8; POK_REMOTE_BACKUP_LEN] {
    let rcvr_ev = build_receiver_evidence(pid_pub, sata_key, receiver_report);
    let req = backup_request(session_id, masked_sender_key, &rcvr_ev, policy);
    ctx.tbor_oob(&req, &rcvr_ev.oob())
        .expect("SdCreateRemoteBackup source backup")
        .pok_remote_backup
}

#[test]
fn sd_reseal_remote_backup_roundtrip_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let sid = session.session_id;

    // Receiver (unseals the source), sender (sealed the source), and
    // destination (the reseal target) SD sealing keys, each attested.
    let (masked_rcvr, report_rcvr) = masked_key_and_report(&ctx, sid);
    let (masked_sndr, report_sndr) = masked_key_and_report(&ctx, sid);
    let (_masked_dst, report_dst) = masked_key_and_report(&ctx, sid);

    // Source backup: BKS3 sealed to the receiver by the sender.
    let src_backup = create_source_backup(
        &ctx,
        sid,
        &pid_pub,
        &sata_key,
        masked_sndr,
        &report_rcvr,
        &policy,
    );

    // Reseal: open with the receiver key (auth = sender), reseal to the
    // destination receiver.
    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &report_sndr, &report_dst);
    let req = reseal_request(sid, masked_rcvr, &evidence, &policy, &src_backup);
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdResealRemoteBackup roundtrip");

    // A successful HPKE open→seal yields a 161-byte, non-zero backup.
    assert_eq!(resp.dst_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        resp.dst_remote_backup.iter().any(|&b| b != 0),
        "dst_remote_backup must not be all-zero",
    );
    // The resealed backup is a fresh HPKE encapsulation, distinct from the
    // source ciphertext.
    assert_ne!(
        resp.dst_remote_backup, src_backup,
        "reseal must produce a fresh encapsulation, not echo the source",
    );
}

#[test]
fn sd_reseal_remote_backup_rerandomizes_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let sid = session.session_id;

    let (masked_rcvr, report_rcvr) = masked_key_and_report(&ctx, sid);
    let (masked_sndr, report_sndr) = masked_key_and_report(&ctx, sid);
    let (_masked_dst, report_dst) = masked_key_and_report(&ctx, sid);

    let src_backup = create_source_backup(
        &ctx,
        sid,
        &pid_pub,
        &sata_key,
        masked_sndr,
        &report_rcvr,
        &policy,
    );

    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &report_sndr, &report_dst);
    let req = reseal_request(sid, masked_rcvr, &evidence, &policy, &src_backup);

    let first = ctx.tbor_oob(&req, &evidence.oob()).expect("first reseal");
    let second = ctx.tbor_oob(&req, &evidence.oob()).expect("second reseal");

    // Each reseal uses a fresh HPKE ephemeral → distinct ciphertexts.
    assert_ne!(
        first.dst_remote_backup, second.dst_remote_backup,
        "each reseal must re-randomize the HPKE encapsulation",
    );
}

#[test]
fn sd_reseal_remote_backup_rejects_tampered_src_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let sid = session.session_id;

    let (masked_rcvr, report_rcvr) = masked_key_and_report(&ctx, sid);
    let (masked_sndr, report_sndr) = masked_key_and_report(&ctx, sid);
    let (_masked_dst, report_dst) = masked_key_and_report(&ctx, sid);

    let mut src_backup = create_source_backup(
        &ctx,
        sid,
        &pid_pub,
        &sata_key,
        masked_sndr,
        &report_rcvr,
        &policy,
    );
    // Flip a byte in the ciphertext region so the HPKE-Auth open fails.
    src_backup[POK_REMOTE_BACKUP_LEN - 1] ^= 0xFF;

    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &report_sndr, &report_dst);
    let req = reseal_request(sid, masked_rcvr, &evidence, &policy, &src_backup);

    // The evidence still validates, but the unseal's AEAD tag check fails.
    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("tampered source backup must fail the HPKE open");
}

#[test]
fn sd_reseal_remote_backup_rejects_missing_oob_emu() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let sid = session.session_id;

    let (masked_rcvr, report_rcvr) = masked_key_and_report(&ctx, sid);
    let (masked_sndr, report_sndr) = masked_key_and_report(&ctx, sid);
    let (_masked_dst, report_dst) = masked_key_and_report(&ctx, sid);

    let src_backup = create_source_backup(
        &ctx,
        sid,
        &pid_pub,
        &sata_key,
        masked_sndr,
        &report_rcvr,
        &policy,
    );

    // The evidence descriptors reference OOB items, but no OOB page is
    // supplied → the handler rejects before any crypto.
    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &report_sndr, &report_dst);
    let req = reseal_request(sid, masked_rcvr, &evidence, &policy, &src_backup);
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}
