// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::x509_fixture::*;
use azihsm_ddi_tbor_test_harness::*;
use azihsm_ddi_tbor_types::tbor_int::U16;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;

const CHAIN_LEAF_INDEX: usize = 1;
const POLICY_MUTATION_MASK: u8 = 1;

/// Every case starts with real keys, evidence, policy, and a source backup.
/// Mutations therefore exercise handler validation and crypto paths rather
/// than spending most fuzz iterations on undecodable request bytes.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Mutation {
    Valid,
    ResealTwice,
    MissingOob,
    EmptySourceChain,
    EmptyDestinationChain,
    PolicyHashMismatch,
    SourceReportOutOfRange,
    DestinationReportOutOfRange,
    TamperSourceEvidence { mask: u8 },
    TamperDestinationEvidence { mask: u8 },
    WrongReceiverKey,
    TamperSourceBackup { offset: u16, mask: u8 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    mutation: Mutation,
    key_scope: common::KeyScope,
}

impl Default for FuzzInput {
    /// Select an untampered reseal request with partition-local sealing keys.
    fn default() -> Self {
        Self {
            mutation: Mutation::Valid,
            key_scope: common::KeyScope::Local,
        }
    }
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
    src_leaf_index: usize,
    dest_leaf_index: usize,
}

impl ResealEvidence {
    /// Borrow the source and destination OOB evidence items as request slices.
    fn oob(&self) -> Vec<&[u8]> {
        self.oob_items.iter().map(Vec::as_slice).collect()
    }
}

struct Fixture {
    session_id: u16,
    request: TborSdResealRemoteBackupReq,
    evidence: ResealEvidence,
    src_remote_backup: [u8; POK_REMOTE_BACKUP_LEN],
    wrong_receiver_key: Option<[u8; MASKED_SEALING_KEY_LEN]>,
}

/// Append a certificate or report to the OOB items and return its descriptor.
fn push_item(items: &mut Vec<Vec<u8>>, bytes: &[u8]) -> CertDescriptor {
    let index = u8::try_from(items.len()).expect("fixture OOB item count is bounded");
    let length = u16::try_from(bytes.len()).expect("fixture evidence length fits U16");
    items.push(bytes.to_vec());
    CertDescriptor {
        index,
        length: U16::new(length),
    }
}

/// Append the root and leaf certificates to the OOB items in chain order
/// and return their descriptors.
fn push_chain(items: &mut Vec<Vec<u8>>, chain: &GeneratedChain) -> Vec<CertDescriptor> {
    vec![
        push_item(items, &chain.root_der),
        push_item(items, &chain.leaf_der),
    ]
}

/// Append manufacturer, owner, and SATA-rooted partition-owner chains for
/// the PID plus a key report. Return the chain descriptors, report descriptor,
/// and report's OOB index.
fn push_evidence(
    items: &mut Vec<Vec<u8>>,
    pid_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    report: &[u8],
) -> (
    Vec<CertDescriptor>,
    Vec<CertDescriptor>,
    Vec<CertDescriptor>,
    ReportDescriptor,
    usize,
) {
    let mfgr = push_chain(items, &make_chain(&CaKey::generate(), pid_pub));
    let owner = push_chain(items, &make_chain(&CaKey::generate(), pid_pub));
    let part_owner = push_chain(items, &make_chain(sata_key, pid_pub));
    let report_item = push_item(items, report);
    let report = ReportDescriptor {
        index: report_item.index,
        length: report_item.length,
    };
    (
        mfgr,
        owner,
        part_owner,
        report,
        usize::from(report_item.index),
    )
}

/// Build source and destination evidence in a shared OOB item list, retaining
/// manufacturer leaf indices for targeted certificate mutations.
fn build_reseal_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    src_report: &[u8],
    dest_report: &[u8],
) -> ResealEvidence {
    let mut oob_items = Vec::new();
    let (src_mfgr, src_owner, src_part_owner, src_report, src_report_index) =
        push_evidence(&mut oob_items, pid_pub, sata_key, src_report);
    let src_leaf_index = usize::from(src_mfgr[CHAIN_LEAF_INDEX].index);
    let (dest_mfgr, dest_owner, dest_part_owner, dest_report, dest_report_index) =
        push_evidence(&mut oob_items, pid_pub, sata_key, dest_report);
    let dest_leaf_index = usize::from(dest_mfgr[CHAIN_LEAF_INDEX].index);

    debug_assert_eq!(src_report_index, usize::from(src_report.index));
    debug_assert_eq!(dest_report_index, usize::from(dest_report.index));

    ResealEvidence {
        oob_items,
        src_mfgr,
        src_owner,
        src_part_owner,
        src_report,
        dest_mfgr,
        dest_owner,
        dest_part_owner,
        dest_report,
        src_leaf_index,
        dest_leaf_index,
    }
}

/// Convert a wire-LE P-384 public key into big-endian `x || y` bytes for
/// certificate generation.
fn public_key_from_wire(pub_key: &[u8]) -> [u8; RAW_PUB_LEN] {
    const COORD_LEN: usize = RAW_PUB_LEN / 2;
    assert_eq!(pub_key.len(), RAW_PUB_LEN);

    let mut raw = [0u8; RAW_PUB_LEN];
    for (dst, src) in raw[..COORD_LEN]
        .iter_mut()
        .zip(pub_key[..COORD_LEN].iter().rev())
    {
        *dst = *src;
    }
    for (dst, src) in raw[COORD_LEN..]
        .iter_mut()
        .zip(pub_key[COORD_LEN..].iter().rev())
    {
        *dst = *src;
    }
    raw
}

/// Generate a sealing key with the requested scope and attest it with
/// `KeyReport`. Return its masked key, report, and big-endian public key.
fn sealing_key_report_and_pub(
    ctx: &TestCtx,
    session_id: u16,
    key_scope: common::KeyScope,
) -> ([u8; MASKED_SEALING_KEY_LEN], Vec<u8>, [u8; RAW_PUB_LEN]) {
    let seal = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id,
            scope: key_scope.to_tbor(),
        })
        .expect("SdSealingKeyGen");
    let masked_key: [u8; MASKED_SEALING_KEY_LEN] = seal
        .masked_key
        .as_slice()
        .try_into()
        .expect("SdSealingKeyGen returns a fixed-length masked key");
    let pub_key = public_key_from_wire(&seal.pub_key);
    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id,
            masked_key: masked_key.to_vec(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("KeyReport")
        .report;
    (masked_key, report, pub_key)
}

/// Bind a policy to the partition's PID and supplied SATA key, then initialize
/// and finalize the partition. Return the policy bytes and PID public key.
fn build_policy_and_finalize(
    ctx: &TestCtx,
    session: &azihsm_ddi_tbor_test_harness::SessionHandshake,
    sata_key: &CaKey,
) -> ([u8; PART_POLICY_LEN], [u8; RAW_PUB_LEN]) {
    let part_info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let pid_pub: [u8; RAW_PUB_LEN] = part_info
        .pid_pub_key
        .as_slice()
        .try_into()
        .expect("PartInfo public key is P-384");

    let pota_key = CaKey::generate();
    let mut policy_bytes = common::known_good_part_policy(pota_key.raw_pub());
    let mut policy =
        PartPolicy::try_read_from_bytes(&policy_bytes).expect("known-good policy must decode");
    policy.sata_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        sata_key.raw_pub(),
    );
    policy.backup_part_id.copy_from_slice(&part_info.pid);
    policy.backup_part_pub_key =
        PolicyPubKey::new(PolicyKeyKind::Ecc384, POLICY_MAX_KEY_LEN as u16, pid_pub);
    policy_bytes.copy_from_slice(policy.as_bytes());

    let init = ctx
        .part_init(
            session,
            &common::mach_seed(),
            &policy_bytes,
            &common::pota_thumbprint(),
        )
        .expect("PartInit");
    let pta_chain = make_pta_chain(&pota_key, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy_bytes, &[], &pta_chain.der_items())
        .expect("PartFinal");

    (policy_bytes, pid_pub)
}

/// Create a real source remote backup and a reseal request with source and
/// destination evidence. Optionally generate an unrelated receiver key for
/// the wrong-key rejection case.
fn build_fixture(ctx: &TestCtx, wrong_receiver_key: bool, key_scope: common::KeyScope) -> Fixture {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let sata_key = CaKey::generate();
    let (policy, pid_pub) = build_policy_and_finalize(ctx, &session, &sata_key);

    let (masked_receiver, receiver_report, receiver_pub) =
        sealing_key_report_and_pub(ctx, session.session_id, key_scope);
    let (masked_sender, sender_report, _) =
        sealing_key_report_and_pub(ctx, session.session_id, key_scope);
    let (_masked_destination, destination_report, _) =
        sealing_key_report_and_pub(ctx, session.session_id, key_scope);
    let wrong_receiver_key = wrong_receiver_key
        .then(|| sealing_key_report_and_pub(ctx, session.session_id, key_scope).0);

    let mut oob_items = Vec::new();
    let receiver_chain = push_chain(&mut oob_items, &make_chain(&sata_key, &receiver_pub));
    let mfgr = push_chain(&mut oob_items, &make_chain(&CaKey::generate(), &pid_pub));
    let owner = push_chain(&mut oob_items, &make_chain(&CaKey::generate(), &pid_pub));
    let part_owner = push_chain(&mut oob_items, &make_chain(&sata_key, &pid_pub));
    let report_item = push_item(&mut oob_items, &receiver_report);
    let oob: Vec<&[u8]> = oob_items.iter().map(Vec::as_slice).collect();

    let request = TborSdCreateRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: masked_sender,
        receiver_cert_chain: receiver_chain,
        receiver_mfgr_cert_chain: mfgr,
        receiver_owner_cert_chain: owner,
        receiver_part_owner_cert_chain: part_owner,
        receiver_report: ReportDescriptor {
            index: report_item.index,
            length: report_item.length,
        },
        policy: PartPolicy::try_read_from_bytes(&policy).expect("policy image is canonical"),
    };
    let src_remote_backup = ctx
        .tbor_oob(&request, &oob)
        .expect("create real source remote backup")
        .pok_remote_backup;

    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &sender_report, &destination_report);
    let request = TborSdResealRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: masked_receiver,
        policy: PartPolicy::try_read_from_bytes(&policy).expect("policy image is canonical"),
        src_mfgr_cert_chain: evidence.src_mfgr.clone(),
        src_owner_cert_chain: evidence.src_owner.clone(),
        src_part_owner_cert_chain: evidence.src_part_owner.clone(),
        src_report: evidence.src_report,
        dest_mfgr_cert_chain: evidence.dest_mfgr.clone(),
        dest_owner_cert_chain: evidence.dest_owner.clone(),
        dest_part_owner_cert_chain: evidence.dest_part_owner.clone(),
        dest_report: evidence.dest_report,
        src_remote_backup,
    };

    Fixture {
        session_id: session.session_id,
        request,
        evidence,
        src_remote_backup,
        wrong_receiver_key,
    }
}

/// Submit the reseal request and check that the destination backup has the
/// schema length, is nonzero, and differs from the source. Return the backup
/// for freshness checks across repeated calls.
fn assert_success(ctx: &TestCtx, fixture: &Fixture) -> [u8; POK_REMOTE_BACKUP_LEN] {
    let oob = fixture.evidence.oob();
    let response = ctx
        .tbor_oob(&fixture.request, &oob)
        .expect("valid SdResealRemoteBackup fixture must succeed");
    assert_eq!(response.dst_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        response.dst_remote_backup.iter().any(|byte| *byte != 0),
        "resealed remote backup must not be all zero",
    );
    assert_ne!(
        response.dst_remote_backup, fixture.src_remote_backup,
        "resealing must produce a fresh HPKE encapsulation",
    );
    response.dst_remote_backup
}

/// Check that the reseal request is rejected with a firmware status rather
/// than a transport or host-side error.
fn assert_rejected(ctx: &TestCtx, fixture: &Fixture) {
    let oob = fixture.evidence.oob();
    let result = ctx.tbor_oob(&fixture.request, &oob);
    assert!(
        matches!(&result, Err(azihsm_ddi_interface::DdiError::TborStatus(_))),
        "invalid SdResealRemoteBackup fixture must be rejected by firmware",
    );
}

/// XOR the final byte of a nonempty buffer and return whether a nonzero
/// mask was applied.
fn flip_last_byte(bytes: &mut [u8], mask: u8) -> bool {
    if mask == 0 || bytes.is_empty() {
        return false;
    }
    let last = bytes.len() - 1;
    bytes[last] ^= mask;
    true
}

/// Exercise the selected reseal mutation, including repeated-call freshness
/// and zero-mask no-ops. Route non-partition key scopes through the shared
/// scope-validation helper and close the fixture's CO session afterward.
fn run_case(ctx: &TestCtx, mutation: Mutation, key_scope: common::KeyScope) {
    if !matches!(
        key_scope,
        common::KeyScope::Ephemeral | common::KeyScope::Local
    ) {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        common::exercise_non_partition_key_scope(ctx, &session, key_scope);
        ctx.session_close(session.session_id)
            .expect("close key-scope CO session");
        return;
    }

    let needs_wrong_receiver = matches!(mutation, Mutation::WrongReceiverKey);
    let mut fixture = build_fixture(ctx, needs_wrong_receiver, key_scope);

    match mutation {
        Mutation::Valid => {
            assert_success(ctx, &fixture);
        }
        Mutation::ResealTwice => {
            let first = assert_success(ctx, &fixture);
            let second = assert_success(ctx, &fixture);
            assert_ne!(
                first, second,
                "repeated reseals must use fresh HPKE encapsulations",
            );
        }
        Mutation::MissingOob => {
            ctx.expect_fw_reject(&fixture.request, TborStatus::InvalidArg);
        }
        Mutation::EmptySourceChain => {
            fixture.request.src_mfgr_cert_chain.clear();
            ctx.expect_fw_reject_oob(
                &fixture.request,
                &fixture.evidence.oob(),
                TborStatus::InvalidArg,
            );
        }
        Mutation::EmptyDestinationChain => {
            fixture.request.dest_part_owner_cert_chain.clear();
            ctx.expect_fw_reject_oob(
                &fixture.request,
                &fixture.evidence.oob(),
                TborStatus::InvalidArg,
            );
        }
        Mutation::PolicyHashMismatch => {
            fixture.request.policy.info[0] ^= POLICY_MUTATION_MASK;
            assert_rejected(ctx, &fixture);
        }
        Mutation::SourceReportOutOfRange => {
            fixture.request.src_report.index = u8::MAX;
            assert_rejected(ctx, &fixture);
        }
        Mutation::DestinationReportOutOfRange => {
            fixture.request.dest_report.index = u8::MAX;
            assert_rejected(ctx, &fixture);
        }
        Mutation::TamperSourceEvidence { mask } => {
            let changed = flip_last_byte(
                &mut fixture.evidence.oob_items[fixture.evidence.src_leaf_index],
                mask,
            );
            if changed {
                assert_rejected(ctx, &fixture);
            } else {
                assert_success(ctx, &fixture);
            }
        }
        Mutation::TamperDestinationEvidence { mask } => {
            let changed = flip_last_byte(
                &mut fixture.evidence.oob_items[fixture.evidence.dest_leaf_index],
                mask,
            );
            if changed {
                assert_rejected(ctx, &fixture);
            } else {
                assert_success(ctx, &fixture);
            }
        }
        Mutation::WrongReceiverKey => {
            fixture.request.masked_sealing_key = fixture
                .wrong_receiver_key
                .expect("wrong receiver key generated for this case");
            assert_rejected(ctx, &fixture);
        }
        Mutation::TamperSourceBackup { offset, mask } => {
            if mask == 0 {
                assert_success(ctx, &fixture);
            } else {
                let index = usize::from(offset) % POK_REMOTE_BACKUP_LEN;
                fixture.request.src_remote_backup[index] ^= mask;
                assert_rejected(ctx, &fixture);
            }
        }
    }

    ctx.session_close(fixture.session_id)
        .expect("close fuzz CO session");
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        run_case(ctx, input.mutation, input.key_scope);
    });
});
