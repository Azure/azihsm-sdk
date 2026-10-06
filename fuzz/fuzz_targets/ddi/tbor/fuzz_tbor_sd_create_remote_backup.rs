// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::GeneratedChain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyFlags;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::TborKeyReportReq;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::tbor_int::U16;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;

const SCOPE_LOCAL: u8 = 0b011;

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

#[derive(Debug)]
struct FuzzInput {
    mutation: Mutation,
}

impl Default for FuzzInput {
    fn default() -> Self {
        Self {
            mutation: Mutation::Valid,
        }
    }
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            mutation: Mutation::arbitrary(u)?,
        })
    }
}

struct Fixture {
    session_id: u16,
    policy: [u8; PART_POLICY_LEN],
    request: TborSdCreateRemoteBackupReq,
    oob_items: Vec<Vec<u8>>,
    receiver_leaf_index: usize,
    report_index: Option<usize>,
}

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

fn push_oob_item(items: &mut Vec<Vec<u8>>, der: &[u8]) -> CertDescriptor {
    let index = u8::try_from(items.len()).expect("bounded OOB item count");
    let length = u16::try_from(der.len()).expect("bounded fixture DER length");
    items.push(der.to_vec());
    CertDescriptor {
        index,
        length: U16::new(length),
    }
}

fn push_chain(items: &mut Vec<Vec<u8>>, chain: GeneratedChain) -> Vec<CertDescriptor> {
    vec![
        push_oob_item(items, &chain.root_der),
        push_oob_item(items, &chain.leaf_der),
    ]
}

fn raw_pub_from_wire(pub_key: &[u8]) -> [u8; POLICY_MAX_KEY_LEN] {
    const COORD_LEN: usize = POLICY_MAX_KEY_LEN / 2;
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

fn build_fixture(
    ctx: &TestCtx,
    trusted_sa: bool,
    bind_backing_partition: bool,
    mutation: &Mutation,
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
            scope: SCOPE_LOCAL,
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
    let receiver_leaf_index = usize::from(receiver_desc[1].index);
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

        let report_item = push_oob_item(
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

fn assert_rejected(ctx: &TestCtx, fixture: &Fixture, expected: TborStatus) {
    let oob: Vec<&[u8]> = fixture.oob_items.iter().map(Vec::as_slice).collect();
    ctx.expect_fw_reject_oob(&fixture.request, &oob, expected);
}

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

fn run_case(ctx: &TestCtx, mutation: Mutation) {
    let trusted_sa = matches!(
        mutation,
        Mutation::ValidTrustedSa
            | Mutation::TamperTrustedReport { .. }
            | Mutation::TrustedReceiverKeyMismatch
            | Mutation::TrustedEvidenceLeafMismatch
    );
    let bind_backing_partition = !matches!(mutation, Mutation::WrongBackingPartition);
    let mut fixture = build_fixture(ctx, trusted_sa, bind_backing_partition, &mutation);

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
            fixture.request.policy.info[0] ^= 1;
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
                assert!(
                    ctx.tbor_oob(&fixture.request, &oob).is_err(),
                    "tampered receiver certificate must be rejected",
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
                assert!(
                    ctx.tbor_oob(&fixture.request, &oob).is_err(),
                    "corrupted masked sealing key must be rejected",
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

fuzz_target!(|data: &[u8]| {
    let mut unstructured = arbitrary::Unstructured::new(data);
    let input = FuzzInput::arbitrary(&mut unstructured).unwrap_or_default();

    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        run_case(ctx, input.mutation);
    });
});
