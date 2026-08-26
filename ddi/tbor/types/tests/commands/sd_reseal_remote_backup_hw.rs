// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware-only `SdResealRemoteBackup` integration tests.
//!
//! Manticore does not yet implement `TborKeyReport`, so these tests build
//! unsigned policy-bound v2 reports from real `SdSealingKeyGen` public keys.

use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_ddi_mbor_test_helpers::fake_manticore_key_report_bytes;
use azihsm_ddi_tbor_types::tbor_int::U16;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::TborSdResealRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use zerocopy::TryFromBytes;

use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::finalized_backing_session;
use crate::commands::sd_create_remote_backup::sealing_pub_to_sec1;
use crate::harness::x509_fixture::make_chain;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::GeneratedChain;
use crate::harness::x509_fixture::RAW_PUB_LEN;
use crate::harness::SessionHandshake;
use crate::harness::TestCtx;

const SCOPE_LOCAL: u8 = 0b011;

#[test]
fn synthetic_report_binds_policy_hw() {
    let mut public_key = [0x5A; 97];
    public_key[0] = 0x04;
    let policy = [0xA5; PART_POLICY_LEN];
    let report = fake_manticore_key_report_bytes(&public_key, &policy);
    let mut digest = [0u8; 48];
    HashAlgo::sha384()
        .hash(&policy, Some(&mut digest))
        .expect("SHA-384 policy digest");

    assert!(report.windows(digest.len()).any(|window| window == digest));
}

struct ResealEvidence {
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

fn push_item(items: &mut Vec<Vec<u8>>, bytes: &[u8]) -> CertDescriptor {
    let index = items.len() as u8;
    items.push(bytes.to_vec());
    CertDescriptor {
        index,
        length: U16::new(bytes.len() as u16),
    }
}

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
    let mfgr = vec![
        push_item(items, &mfgr.root_der),
        push_item(items, &mfgr.leaf_der),
    ];
    let owner = vec![
        push_item(items, &owner.root_der),
        push_item(items, &owner.leaf_der),
    ];
    let part_owner = vec![
        push_item(items, &part_owner.root_der),
        push_item(items, &part_owner.leaf_der),
    ];
    let report = push_item(items, report);
    (
        mfgr,
        owner,
        part_owner,
        ReportDescriptor {
            index: report.index,
            length: report.length,
        },
    )
}

fn build_reseal_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    src_report: &[u8],
    dest_report: &[u8],
) -> ResealEvidence {
    let mut items = Vec::new();
    let (src_mfgr, src_owner, src_part_owner, src_report) = push_evidence(
        &mut items,
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(sata_key, pid_pub),
        src_report,
    );
    let (dest_mfgr, dest_owner, dest_part_owner, dest_report) = push_evidence(
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
        src_report,
        dest_mfgr,
        dest_owner,
        dest_part_owner,
        dest_report,
    }
}

fn sealing_key_and_report(
    ctx: &TestCtx,
    session_id: u16,
    policy: &[u8; PART_POLICY_LEN],
) -> (Vec<u8>, Vec<u8>) {
    let sealing_key = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("SdSealingKeyGen");
    let report =
        fake_manticore_key_report_bytes(&sealing_pub_to_sec1(&sealing_key.pub_key), policy);
    (sealing_key.masked_key.to_vec(), report)
}

fn create_source_backup(
    ctx: &TestCtx,
    session_id: u16,
    pid_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    masked_sender_key: Vec<u8>,
    receiver_report: &[u8],
    policy: &[u8; PART_POLICY_LEN],
) -> [u8; POK_REMOTE_BACKUP_LEN] {
    let receiver = build_receiver_evidence(pid_pub, sata_key, receiver_report);
    let request = backup_request(session_id, masked_sender_key, &receiver, policy);
    ctx.tbor_oob(&request, &receiver.oob())
        .expect("SdCreateRemoteBackup source backup")
        .pok_remote_backup
}

fn reseal_request(
    session_id: u16,
    masked_receiver_key: &[u8],
    evidence: &ResealEvidence,
    policy: &[u8; PART_POLICY_LEN],
    src_remote_backup: &[u8; POK_REMOTE_BACKUP_LEN],
) -> TborSdResealRemoteBackupReq {
    TborSdResealRemoteBackupReq {
        session_id,
        masked_sealing_key: masked_receiver_key
            .try_into()
            .expect("masked receiver key length"),
        policy: PartPolicy::try_read_from_bytes(policy).expect("canonical policy"),
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

struct HardwareFixture {
    ctx: TestCtx,
    session: SessionHandshake,
    policy: [u8; PART_POLICY_LEN],
    masked_receiver_key: Vec<u8>,
    source_backup: [u8; POK_REMOTE_BACKUP_LEN],
    evidence: ResealEvidence,
}

impl HardwareFixture {
    fn new() -> Self {
        let ctx = TestCtx::new();
        let sata_key = CaKey::generate();
        let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
        let session_id = session.session_id;
        let (masked_receiver_key, receiver_report) =
            sealing_key_and_report(&ctx, session_id, &policy);
        let (masked_sender_key, sender_report) = sealing_key_and_report(&ctx, session_id, &policy);
        let (_masked_destination_key, destination_report) =
            sealing_key_and_report(&ctx, session_id, &policy);
        let source_backup = create_source_backup(
            &ctx,
            session_id,
            &pid_pub,
            &sata_key,
            masked_sender_key,
            &receiver_report,
            &policy,
        );
        let evidence =
            build_reseal_evidence(&pid_pub, &sata_key, &sender_report, &destination_report);
        Self {
            ctx,
            session,
            policy,
            masked_receiver_key,
            source_backup,
            evidence,
        }
    }

    fn request(&self) -> TborSdResealRemoteBackupReq {
        reseal_request(
            self.session.session_id,
            &self.masked_receiver_key,
            &self.evidence,
            &self.policy,
            &self.source_backup,
        )
    }
}

#[test]
fn sd_reseal_remote_backup_roundtrip_hw() {
    let fixture = HardwareFixture::new();
    let response = fixture
        .ctx
        .tbor_oob(&fixture.request(), &fixture.evidence.oob())
        .expect("SdResealRemoteBackup hardware roundtrip");

    assert!(response.dst_remote_backup.iter().any(|&byte| byte != 0));
    assert_ne!(response.dst_remote_backup, fixture.source_backup);
}

#[test]
fn sd_reseal_remote_backup_rerandomizes_hw() {
    let fixture = HardwareFixture::new();
    let request = fixture.request();
    let first = fixture
        .ctx
        .tbor_oob(&request, &fixture.evidence.oob())
        .expect("first reseal");
    let second = fixture
        .ctx
        .tbor_oob(&request, &fixture.evidence.oob())
        .expect("second reseal");

    assert_ne!(first.dst_remote_backup, second.dst_remote_backup);
}

#[test]
fn sd_reseal_remote_backup_rejects_tampered_source_hw() {
    let mut fixture = HardwareFixture::new();
    fixture.source_backup[POK_REMOTE_BACKUP_LEN - 1] ^= 0xFF;

    fixture
        .ctx
        .tbor_oob(&fixture.request(), &fixture.evidence.oob())
        .expect_err("tampered source backup must fail");
}

#[test]
fn sd_reseal_remote_backup_rejects_missing_oob_hw() {
    let fixture = HardwareFixture::new();
    fixture
        .ctx
        .expect_fw_reject(&fixture.request(), TborStatus::InvalidArg);
}
