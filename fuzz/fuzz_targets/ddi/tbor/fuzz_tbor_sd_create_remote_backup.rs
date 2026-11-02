// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::x509_fixture::*;
use azihsm_ddi_tbor_test_harness::*;
use azihsm_ddi_tbor_types::*;
use common::COORD_LEN;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;

const CHAIN_LEAF_INDEX: usize = 1;
const POLICY_MUTATION_MASK: u8 = 1;

/// Each variant starts from a freshly provisioned, otherwise-valid
/// partition and request. Mutations therefore reach distinct handler gates
/// instead of spending most inputs on malformed TBOR framing.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Mutation {
    Valid,
    ValidTrustedSa,
    MissingOob,
    EmptyReceiverChain,
    WrongSataAnchor,
    WrongBackingPartition,
    PolicyHashMismatch,
    TamperReceiverCertificate { offset: u16, mask: u8 },
    CorruptMaskedSealingKey { offset: u16, mask: u8 },
    TamperTrustedReport { mask: u8 },
    TrustedReceiverKeyMismatch,
    TrustedEvidenceLeafMismatch,
    OneShot,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    mutation: Mutation,
    key_scope: common::KeyScope,
}

struct Fixture {
    session_id: u16,
    policy: [u8; PART_POLICY_LEN],
    request: TborSdCreateRemoteBackupReq,
    oob_items: Vec<Vec<u8>>,
    receiver_leaf_index: usize,
    report_index: Option<usize>,
}

/// Build a remote-backup policy with optional trusted-SA enforcement and
/// optional binding to the backing partition's PID and public key.
fn build_policy(
    pota_pub: [u8; POLICY_MAX_KEY_LEN],
    sata_pub: [u8; POLICY_MAX_KEY_LEN],
    sapota_pub: Option<[u8; POLICY_MAX_KEY_LEN]>,
    pid: &[u8],
    pid_pub: &[u8],
    bind_backing_partition: bool,
) -> [u8; PART_POLICY_LEN] {
    let mut policy_bytes = common::known_good_part_policy(pota_pub);
    let mut policy =
        <PartPolicy as TryFromBytes>::try_read_from_bytes(&policy_bytes).expect("known policy");

    policy.sata_pub_key =
        PolicyPubKey::new(PolicyKeyKind::Ecc384, POLICY_MAX_KEY_LEN as u16, sata_pub);
    if let Some(sapota_pub) = sapota_pub {
        policy.sapota_pub_key =
            PolicyPubKey::new(PolicyKeyKind::Ecc384, POLICY_MAX_KEY_LEN as u16, sapota_pub);
        policy.flags = PolicyFlags::from_bits(PolicyFlags::REQUIRE_TRUSTED_SA_KEY);
    }

    if bind_backing_partition {
        policy.backup_part_id.copy_from_slice(pid);
        let pid_pub: [u8; POLICY_MAX_KEY_LEN] =
            pid_pub.try_into().expect("PartInfo public key is P-384");
        policy.backup_part_pub_key =
            PolicyPubKey::new(PolicyKeyKind::Ecc384, POLICY_MAX_KEY_LEN as u16, pid_pub);
    }

    policy_bytes.copy_from_slice(policy.as_bytes());
    policy_bytes
}

/// Append the root and leaf certificates to the OOB items in chain order
/// and return their descriptors.
fn push_chain(items: &mut Vec<Vec<u8>>, chain: GeneratedChain) -> Vec<CertDescriptor> {
    vec![
        common::add_evidence_item(items, &chain.root_der),
        common::add_evidence_item(items, &chain.leaf_der),
    ]
}

/// Convert a wire-LE P-384 public key into big-endian `x || y` bytes for
/// the receiver certificate fixture.
fn raw_pub_from_wire(pub_key: &[u8]) -> [u8; POLICY_MAX_KEY_LEN] {
    assert_eq!(pub_key.len(), POLICY_MAX_KEY_LEN);

    let mut raw = [0u8; POLICY_MAX_KEY_LEN];
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

/// Finalize a partition and generate a receiver sealing key, certificate
/// chains, and optional trusted-SA report. Apply certificate-key and anchor
/// mismatches during fixture construction for the selected mutation.
fn build_fixture(
    ctx: &TestCtx,
    trusted_sa: bool,
    bind_backing_partition: bool,
    mutation: &Mutation,
    key_scope: common::KeyScope,
) -> Fixture {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let part_info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");

    let pota = CaKey::generate();
    let sata = CaKey::generate();
    let sapota = trusted_sa.then(CaKey::generate);
    let policy = build_policy(
        pota.raw_pub(),
        sata.raw_pub(),
        sapota.as_ref().map(CaKey::raw_pub),
        &part_info.pid,
        &part_info.pid_pub_key,
        bind_backing_partition,
    );

    let init = ctx
        .part_init(
            &session,
            &common::mach_seed(),
            &policy,
            &common::pota_thumbprint(),
        )
        .expect("PartInit");
    let pta_chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &pta_chain.der_items())
        .expect("PartFinal");

    let sealing_key = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: session.session_id,
            scope: key_scope.to_tbor(),
        })
        .expect("SdSealingKeyGen");
    let masked_sealing_key = sealing_key.masked_key.to_vec();
    let receiver_pub = raw_pub_from_wire(&sealing_key.pub_key);
    let report = trusted_sa.then(|| {
        ctx.tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: masked_sealing_key.clone(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("KeyReport")
        .report
    });

    let receiver_pub = if matches!(mutation, Mutation::TrustedReceiverKeyMismatch) {
        CaKey::generate().raw_pub()
    } else {
        receiver_pub
    };
    let receiver_chain = if matches!(mutation, Mutation::WrongSataAnchor) {
        let wrong_sata = CaKey::generate();
        make_chain(&wrong_sata, &receiver_pub)
    } else {
        make_chain(&sata, &receiver_pub)
    };

    let mut oob_items = Vec::new();
    let receiver_desc = push_chain(&mut oob_items, receiver_chain);
    let receiver_leaf_index = usize::from(receiver_desc[CHAIN_LEAF_INDEX].index);
    let mut mfgr_desc = Vec::new();
    let mut owner_desc = Vec::new();
    let mut part_owner_desc = Vec::new();
    let mut report_desc = ReportDescriptor::default();
    let mut report_index = None;

    if trusted_sa {
        let pid_pub: [u8; POLICY_MAX_KEY_LEN] = part_info
            .pid_pub_key
            .as_slice()
            .try_into()
            .expect("PartInfo public key is P-384");
        let mfgr = make_chain(&CaKey::generate(), &pid_pub);
        let owner = if matches!(mutation, Mutation::TrustedEvidenceLeafMismatch) {
            let other_pid_pub = CaKey::generate().raw_pub();
            make_chain(&CaKey::generate(), &other_pid_pub)
        } else {
            make_chain(&CaKey::generate(), &pid_pub)
        };
        let part_owner = make_chain(
            sapota.as_ref().expect("trusted policy has SAPOTA"),
            &pid_pub,
        );
        mfgr_desc = push_chain(&mut oob_items, mfgr);
        owner_desc = push_chain(&mut oob_items, owner);
        part_owner_desc = push_chain(&mut oob_items, part_owner);

        let report_item = common::add_evidence_item(
            &mut oob_items,
            report.as_deref().expect("trusted fixture has report"),
        );
        report_index = Some(usize::from(report_item.index));
        report_desc = ReportDescriptor {
            index: report_item.index,
            length: report_item.length,
        };
    }

    let policy_value =
        <PartPolicy as TryFromBytes>::try_read_from_bytes(&policy).expect("policy image");
    let request = TborSdCreateRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: masked_sealing_key
            .as_slice()
            .try_into()
            .expect("SdSealingKeyGen returns a fixed-length key"),
        receiver_cert_chain: receiver_desc,
        receiver_mfgr_cert_chain: mfgr_desc,
        receiver_owner_cert_chain: owner_desc,
        receiver_part_owner_cert_chain: part_owner_desc,
        receiver_report: report_desc,
        policy: policy_value,
    };

    Fixture {
        session_id: session.session_id,
        policy,
        request,
        oob_items,
        receiver_leaf_index,
        report_index,
    }
}

/// Submit the remote-backup request with its OOB evidence and check that
/// all three returned backups have their schema lengths and nonzero contents.
fn assert_success(ctx: &TestCtx, fixture: &Fixture) {
    let oob: Vec<&[u8]> = fixture.oob_items.iter().map(Vec::as_slice).collect();
    let response = ctx
        .tbor_oob(&fixture.request, &oob)
        .expect("valid SdCreateRemoteBackup request should succeed");

    assert_eq!(response.pok_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(response.pok_remote_backup.iter().any(|byte| *byte != 0));
    assert_eq!(response.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(response.pok_local_backup.iter().any(|byte| *byte != 0));
    assert_eq!(response.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(response.sd_mk_backup.iter().any(|byte| *byte != 0));
}

/// Check that the remote-backup request and its OOB evidence are rejected
/// with the expected firmware status.
fn assert_rejected(ctx: &TestCtx, fixture: &Fixture, expected: TborStatus) {
    let oob: Vec<&[u8]> = fixture.oob_items.iter().map(Vec::as_slice).collect();
    ctx.expect_fw_reject_oob(&fixture.request, &oob, expected);
}

/// XOR a byte at the offset modulo the buffer length. Return whether a
/// nonzero mask was applied to a nonempty buffer.
fn flip_byte(bytes: &mut [u8], offset: u16, mask: u8) -> bool {
    if mask == 0 {
        return false;
    }
    if bytes.is_empty() {
        return false;
    }
    let index = usize::from(offset) % bytes.len();
    bytes[index] ^= mask;
    true
}

/// Exercise the selected remote-backup mutation and check success or firmware
/// rejection, treating zero-mask mutations as valid requests. Route non-partition
/// key scopes through the shared scope-validation helper.
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

    let trusted_sa = matches!(
        mutation,
        Mutation::ValidTrustedSa
            | Mutation::TamperTrustedReport { .. }
            | Mutation::TrustedReceiverKeyMismatch
            | Mutation::TrustedEvidenceLeafMismatch
    );
    let bind_backing_partition = !matches!(mutation, Mutation::WrongBackingPartition);
    let mut fixture = build_fixture(
        ctx,
        trusted_sa,
        bind_backing_partition,
        &mutation,
        key_scope,
    );

    match mutation {
        Mutation::Valid | Mutation::ValidTrustedSa => {
            assert_success(ctx, &fixture);
        }
        Mutation::MissingOob => {
            ctx.expect_fw_reject(&fixture.request, TborStatus::InvalidArg);
        }
        Mutation::EmptyReceiverChain => {
            fixture.request.receiver_cert_chain.clear();
            assert_rejected(ctx, &fixture, TborStatus::InvalidArg);
        }
        Mutation::WrongSataAnchor | Mutation::WrongBackingPartition => {
            assert_rejected(ctx, &fixture, TborStatus::InvalidArg);
        }
        Mutation::PolicyHashMismatch => {
            fixture.request.policy.info[0] ^= POLICY_MUTATION_MASK;
            let bound_policy = <PartPolicy as TryFromBytes>::try_read_from_bytes(&fixture.policy)
                .expect("bound policy image");
            assert_ne!(
                fixture.request.policy.info, bound_policy.info,
                "policy mutation must differ from the bound policy",
            );
            assert_rejected(ctx, &fixture, TborStatus::InvalidArg);
        }
        Mutation::TamperReceiverCertificate { offset, mask } => {
            let changed = flip_byte(
                &mut fixture.oob_items[fixture.receiver_leaf_index],
                offset,
                mask,
            );
            if changed {
                let oob: Vec<&[u8]> = fixture.oob_items.iter().map(Vec::as_slice).collect();
                let result = ctx.tbor_oob(&fixture.request, &oob);
                assert!(
                    matches!(&result, Err(azihsm_ddi_interface::DdiError::TborStatus(_))),
                    "tampered receiver certificate must be rejected by firmware",
                );
            } else {
                assert_success(ctx, &fixture);
            }
        }
        Mutation::CorruptMaskedSealingKey { offset, mask } => {
            let byte = &mut fixture.request.masked_sealing_key
                [usize::from(offset) % MASKED_SEALING_KEY_LEN];
            *byte ^= mask;
            if mask == 0 {
                assert_success(ctx, &fixture);
            } else {
                let oob: Vec<&[u8]> = fixture.oob_items.iter().map(Vec::as_slice).collect();
                let result = ctx.tbor_oob(&fixture.request, &oob);
                assert!(
                    matches!(&result, Err(azihsm_ddi_interface::DdiError::TborStatus(_))),
                    "corrupted masked sealing key must be rejected by firmware",
                );
            }
        }
        Mutation::TamperTrustedReport { mask } => {
            let index = fixture.report_index.expect("trusted fixture has report");
            let report_len = fixture.oob_items[index].len();
            let changed = flip_byte(
                &mut fixture.oob_items[index],
                u16::try_from(report_len - 1).expect("bounded report length"),
                mask,
            );
            if changed {
                assert_rejected(ctx, &fixture, TborStatus::InvalidArg);
            } else {
                assert_success(ctx, &fixture);
            }
        }
        Mutation::TrustedReceiverKeyMismatch | Mutation::TrustedEvidenceLeafMismatch => {
            assert_rejected(ctx, &fixture, TborStatus::InvalidArg);
        }
        Mutation::OneShot => {
            assert_success(ctx, &fixture);
            let oob: Vec<&[u8]> = fixture.oob_items.iter().map(Vec::as_slice).collect();
            ctx.expect_fw_reject_oob(&fixture.request, &oob, TborStatus::SdAlreadyInitialized);
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
