// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::ROTATED_CU_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_cu;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::KEY_REPORT_MAX_LEN;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyFlags;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::TborKeyReportReq;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdCreatePeerBackupReq;
use azihsm_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::tbor_int::U16;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;

const LOCAL_SCOPE: u8 = 0b011;

#[derive(Debug, Clone, Copy)]
enum Fault {
    ValidSelfPeer,
    ValidDistinctKeys,
    Repeat,
    NotFinalized,
    MissingOob,
    PolicyMismatch,
    CloningDisabled,
    EmptyMfgrChain,
    EmptyOwnerChain,
    EmptyPartOwnerChain,
    WrongSataAnchor,
    MismatchedEvidenceLeaf,
    InvalidReportSignature,
    InvalidSenderTag,
    InvalidBackupTag,
    WrongKindBackup,
    ZeroReportLength,
    OversizedReportLength,
    ReportIndexOutOfRange,
    ActiveCuSession,
    InactiveCoSession,
}

#[derive(Debug)]
struct FuzzInput {
    fault: Fault,
    policy_info: [u8; 64],
    report_data: [u8; KEY_REPORT_DATA_LEN],
    mutation_mask: u8,
    repeat_count: u8,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let fault = match u8::arbitrary(u)? % 21 {
            0 => Fault::ValidSelfPeer,
            1 => Fault::ValidDistinctKeys,
            2 => Fault::Repeat,
            3 => Fault::NotFinalized,
            4 => Fault::MissingOob,
            5 => Fault::PolicyMismatch,
            6 => Fault::CloningDisabled,
            7 => Fault::EmptyMfgrChain,
            8 => Fault::EmptyOwnerChain,
            9 => Fault::EmptyPartOwnerChain,
            10 => Fault::WrongSataAnchor,
            11 => Fault::MismatchedEvidenceLeaf,
            12 => Fault::InvalidReportSignature,
            13 => Fault::InvalidSenderTag,
            14 => Fault::InvalidBackupTag,
            15 => Fault::WrongKindBackup,
            16 => Fault::ZeroReportLength,
            17 => Fault::OversizedReportLength,
            18 => Fault::ReportIndexOutOfRange,
            19 => Fault::ActiveCuSession,
            _ => Fault::InactiveCoSession,
        };
        Ok(Self {
            fault,
            policy_info: <[u8; 64]>::arbitrary(u)?,
            report_data: <[u8; KEY_REPORT_DATA_LEN]>::arbitrary(u)?,
            mutation_mask: u8::arbitrary(u)?,
            repeat_count: u8::arbitrary(u)?,
        })
    }
}

struct Evidence {
    receiver: Vec<CertDescriptor>,
    mfgr: Vec<CertDescriptor>,
    owner: Vec<CertDescriptor>,
    part_owner: Vec<CertDescriptor>,
    report: ReportDescriptor,
    oob: Vec<Vec<u8>>,
}

impl Evidence {
    fn oob_slices(&self) -> Vec<&[u8]> {
        self.oob.iter().map(Vec::as_slice).collect()
    }
}

fn push_item(oob: &mut Vec<Vec<u8>>, bytes: &[u8]) -> CertDescriptor {
    let descriptor = CertDescriptor {
        index: oob.len() as u8,
        length: U16::new(bytes.len() as u16),
    };
    oob.push(bytes.to_vec());
    descriptor
}

fn push_chain(
    oob: &mut Vec<Vec<u8>>,
    chain: &azihsm_ddi_tbor_test_harness::x509_fixture::GeneratedChain,
) -> Vec<CertDescriptor> {
    vec![
        push_item(oob, &chain.root_der),
        push_item(oob, &chain.leaf_der),
    ]
}

fn make_evidence_with_sata(
    sata: &CaKey,
    pid_pub: &[u8; RAW_PUB_LEN],
    recipient_pub: &[u8; RAW_PUB_LEN],
    report_bytes: &[u8],
) -> Evidence {
    let mut oob = Vec::new();
    let receiver = push_chain(&mut oob, &make_chain(sata, recipient_pub));
    let mfgr = push_chain(&mut oob, &make_chain(&CaKey::generate(), pid_pub));
    let owner = push_chain(&mut oob, &make_chain(&CaKey::generate(), pid_pub));
    let part_owner = push_chain(&mut oob, &make_chain(sata, pid_pub));
    let report = push_item(&mut oob, report_bytes);

    Evidence {
        receiver,
        mfgr,
        owner,
        part_owner,
        report: ReportDescriptor {
            index: report.index,
            length: report.length,
        },
        oob,
    }
}

fn public_key_be(wire_le: &[u8; 96]) -> [u8; 96] {
    let mut out = [0u8; 96];
    for i in 0..48 {
        out[i] = wire_le[47 - i];
        out[48 + i] = wire_le[95 - i];
    }
    out
}

fn build_policy(
    pota: &CaKey,
    sata: &CaKey,
    pid: &[u8],
    pid_pub: &[u8; RAW_PUB_LEN],
    info: [u8; 64],
    allow_cloning: bool,
) -> PartPolicy {
    let mut bytes = common::known_good_part_policy(pota.raw_pub());
    let mut policy =
        PartPolicy::try_read_from_bytes(&bytes).expect("known-good policy must decode");
    policy.sata_pub_key =
        PolicyPubKey::new(PolicyKeyKind::Ecc384, RAW_PUB_LEN as u16, sata.raw_pub());
    policy.backup_part_id.copy_from_slice(pid);
    policy.backup_part_pub_key =
        PolicyPubKey::new(PolicyKeyKind::Ecc384, RAW_PUB_LEN as u16, *pid_pub);
    policy.flags = if allow_cloning {
        PolicyFlags::from_bits(PolicyFlags::ALLOW_PEER_CLONING)
    } else {
        PolicyFlags::new()
    };
    policy.info = info;
    bytes.copy_from_slice(policy.as_bytes());
    PartPolicy::try_read_from_bytes(&bytes).expect("constructed policy must decode")
}

fn checked_success(ctx: &TestCtx, req: &TborSdCreatePeerBackupReq, oob: &[&[u8]]) {
    let response = ctx
        .tbor_oob(req, oob)
        .expect("SdCreatePeerBackup should succeed for a valid fixture");
    assert_eq!(
        response.pok_peer_backup.len(),
        POK_REMOTE_BACKUP_LEN,
        "peer backup response must have the schema length",
    );
    assert!(
        response.pok_peer_backup.iter().any(|&byte| byte != 0),
        "peer backup response must not be all zero",
    );
    assert_eq!(
        response.pok_peer_backup[0], 0x04,
        "HPKE encapsulated key must begin with an uncompressed P-384 point",
    );
}

fn setup_unfinalized(ctx: &TestCtx) {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let req = TborSdCreatePeerBackupReq {
        session_id: session.session_id,
        masked_sealing_key: [0; MASKED_SEALING_KEY_LEN],
        policy: PartPolicy::zeroed(),
        dst_mfgr_cert_chain: Vec::new(),
        dst_owner_cert_chain: Vec::new(),
        dst_part_owner_cert_chain: Vec::new(),
        dst_report: ReportDescriptor::default(),
        pok_local_backup: [0; MASKED_SD_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    ctx.session_close(session.session_id)
        .expect("close unfinalized CO session");
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        if matches!(input.fault, Fault::NotFinalized) {
            setup_unfinalized(ctx);
            return;
        }

        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let info = ctx
            .tbor(&TborPartInfoReq::new())
            .expect("PartInfo should succeed");
        let pid_pub: [u8; RAW_PUB_LEN] = info
            .pid_pub_key
            .as_slice()
            .try_into()
            .expect("PartInfo PID public key must be P-384");

        let pota = CaKey::generate();
        let sata = CaKey::generate();
        let allow_cloning = !matches!(input.fault, Fault::CloningDisabled);
        let policy = build_policy(
            &pota,
            &sata,
            &info.pid,
            &pid_pub,
            input.policy_info,
            allow_cloning,
        );
        let policy_bytes: [u8; PART_POLICY_LEN] =
            policy.as_bytes().try_into().expect("policy size is pinned");

        let init = ctx
            .part_init(
                &session,
                &common::mach_seed(),
                &policy_bytes,
                &common::pota_thumbprint(),
            )
            .expect("PartInit should succeed for the valid policy");
        let pta = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
        let pta_items = pta.der_items();
        let finalized = ctx
            .part_final(&session, &policy_bytes, &[], &pta_items)
            .expect("PartFinal should succeed for the valid PTA chain");

        let recipient = ctx
            .tbor(&TborSdSealingKeyGenReq {
                session_id: session.session_id,
                scope: LOCAL_SCOPE,
            })
            .expect("recipient SdSealingKeyGen should succeed");
        let report = ctx
            .tbor(&TborKeyReportReq {
                session_id: session.session_id,
                masked_key: recipient.masked_key.to_vec(),
                report_data: input.report_data,
            })
            .expect("recipient KeyReport should succeed");
        let recipient_pub = public_key_be(&recipient.pub_key);

        let mut evidence = make_evidence_with_sata(&sata, &pid_pub, &recipient_pub, &report.report);

        let sender = if matches!(input.fault, Fault::ValidSelfPeer | Fault::Repeat) {
            recipient.masked_key
        } else {
            ctx.tbor(&TborSdSealingKeyGenReq {
                session_id: session.session_id,
                scope: LOCAL_SCOPE,
            })
            .expect("sender SdSealingKeyGen should succeed")
            .masked_key
        };

        let remote_req = TborSdCreateRemoteBackupReq {
            session_id: session.session_id,
            masked_sealing_key: recipient.masked_key,
            receiver_cert_chain: evidence.receiver.clone(),
            receiver_mfgr_cert_chain: evidence.mfgr.clone(),
            receiver_owner_cert_chain: evidence.owner.clone(),
            receiver_part_owner_cert_chain: evidence.part_owner.clone(),
            receiver_report: evidence.report,
            policy: policy.clone(),
        };
        let oob = evidence.oob_slices();
        let local_backup = ctx
            .tbor_oob(&remote_req, &oob)
            .expect("SdCreateRemoteBackup fixture must create a valid local backup")
            .pok_local_backup;

        // Reboot and restore only PartLocalMK. The generated local backup and
        // sealing-key envelopes remain valid, but the security domain itself
        // is not restored, so the fuzzed command exercises its pre-SD-init
        // lifecycle path as well as its stateless repeatability.
        ctx.session_close(session.session_id)
            .expect("close setup CO session before reboot");
        ctx.erase()
            .expect("factory-reset between backup generation and peer create");
        let mut session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let restore_init = ctx
            .part_init(
                &session,
                &common::mach_seed(),
                &policy_bytes,
                &common::pota_thumbprint(),
            )
            .expect("PartInit should succeed after fixture reboot");
        let restore_pta = make_pta_chain(&pota, &pta_pub_from_csr(&restore_init.pta_csr));
        let restore_pta_items = restore_pta.der_items();
        ctx.part_final(
            &session,
            &policy_bytes,
            &finalized.local_mk_backup,
            &restore_pta_items,
        )
        .expect("PartFinal should restore only the local masking key");

        // Apply only mutations with a deterministic semantic outcome. A zero
        // mask deliberately leaves the fixture valid and must remain success.
        let mutation_is_noop = input.mutation_mask == 0;
        match input.fault {
            Fault::WrongSataAnchor => {
                let wrong_sata = CaKey::generate();
                let chain = make_chain(&wrong_sata, &pid_pub);
                evidence.part_owner = push_chain(&mut evidence.oob, &chain);
            }
            Fault::MismatchedEvidenceLeaf => {
                let other_leaf = CaKey::generate().raw_pub();
                let chain = make_chain(&CaKey::generate(), &other_leaf);
                evidence.owner = push_chain(&mut evidence.oob, &chain);
            }
            Fault::InvalidReportSignature if !mutation_is_noop => {
                let desc = evidence.report;
                evidence.oob[usize::from(desc.index)][usize::from(desc.length.get()) - 1] ^=
                    input.mutation_mask;
            }
            Fault::EmptyMfgrChain => evidence.mfgr.clear(),
            Fault::EmptyOwnerChain => evidence.owner.clear(),
            Fault::EmptyPartOwnerChain => evidence.part_owner.clear(),
            Fault::ZeroReportLength => evidence.report.length = U16::new(0),
            Fault::OversizedReportLength => {
                evidence.report.length = U16::new((KEY_REPORT_MAX_LEN + 1) as u16)
            }
            Fault::ReportIndexOutOfRange => evidence.report.index = u8::MAX,
            _ => {}
        }

        let mut session_open = true;
        if matches!(
            input.fault,
            Fault::ActiveCuSession | Fault::InactiveCoSession
        ) {
            ctx.session_close(session.session_id)
                .expect("close CO session before session-gate scenario");
            session_open = false;
            if matches!(input.fault, Fault::ActiveCuSession) {
                session = bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK);
                session_open = true;
            }
        }

        let mut req = TborSdCreatePeerBackupReq {
            session_id: session.session_id,
            masked_sealing_key: sender,
            policy: policy.clone(),
            dst_mfgr_cert_chain: evidence.mfgr.clone(),
            dst_owner_cert_chain: evidence.owner.clone(),
            dst_part_owner_cert_chain: evidence.part_owner.clone(),
            dst_report: evidence.report,
            pok_local_backup: local_backup,
        };

        match input.fault {
            Fault::PolicyMismatch => req.policy.info[0] ^= 1,
            Fault::InvalidSenderTag if !mutation_is_noop => {
                req.masked_sealing_key[MASKED_SEALING_KEY_LEN - 1] ^= input.mutation_mask;
            }
            Fault::InvalidBackupTag if !mutation_is_noop => {
                req.pok_local_backup[MASKED_SD_LEN - 1] ^= input.mutation_mask;
            }
            Fault::WrongKindBackup => {
                // SdSealingKeyGen returns a genuine Local-scope masked-key
                // envelope with the same fixed size, but the recovery
                // primitive requires SdPartitionOwnerSeed.
                req.pok_local_backup = ctx
                    .tbor(&TborSdSealingKeyGenReq {
                        session_id: session.session_id,
                        scope: LOCAL_SCOPE,
                    })
                    .expect("wrong-kind envelope fixture should be valid")
                    .masked_key;
            }
            _ => {}
        }

        let expected_reject = match input.fault {
            Fault::MissingOob => Some(TborStatus::InvalidArg),
            Fault::PolicyMismatch => Some(TborStatus::InvalidArg),
            Fault::CloningDisabled => Some(TborStatus::SdPeerCloningNotAllowed),
            Fault::EmptyMfgrChain | Fault::EmptyOwnerChain | Fault::EmptyPartOwnerChain => {
                Some(TborStatus::InvalidArg)
            }
            Fault::WrongSataAnchor | Fault::MismatchedEvidenceLeaf => Some(TborStatus::InvalidArg),
            Fault::InvalidReportSignature if !mutation_is_noop => Some(TborStatus::InvalidArg),
            Fault::InvalidSenderTag if !mutation_is_noop => {
                Some(TborStatus::AesGcmDecryptTagDoesNotMatch)
            }
            Fault::InvalidBackupTag if !mutation_is_noop => {
                Some(TborStatus::AesGcmDecryptTagDoesNotMatch)
            }
            Fault::WrongKindBackup => Some(TborStatus::UnsupportedKeyType),
            Fault::ZeroReportLength
            | Fault::OversizedReportLength
            | Fault::ReportIndexOutOfRange => Some(TborStatus::InvalidArg),
            Fault::ActiveCuSession => Some(TborStatus::InvalidPermissions),
            Fault::InactiveCoSession => Some(TborStatus::SessionNotFound),
            _ => None,
        };

        let should_succeed = expected_reject.is_none();
        let missing_oob = matches!(input.fault, Fault::MissingOob);
        if should_succeed {
            let oob = evidence.oob_slices();
            let calls = if matches!(input.fault, Fault::Repeat) {
                2 + usize::from(input.repeat_count % 3)
            } else {
                1
            };
            for _ in 0..calls {
                checked_success(ctx, &req, &oob);
            }
        } else {
            let status = expected_reject.expect("rejection classification set above");
            if missing_oob {
                ctx.expect_fw_reject(&req, status);
            } else {
                let oob = evidence.oob_slices();
                ctx.expect_fw_reject_oob(&req, &oob, status);
            }
        }

        if session_open {
            ctx.session_close(session.session_id)
                .expect("close fuzz session");
        }
    });
});
