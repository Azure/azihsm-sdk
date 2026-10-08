// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::TborKeyReportReq;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdRestoreRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::tbor_int::U16;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MutationTarget {
    Valid,
    SessionId,
    MaskedSealingKey,
    Policy,
    SenderCertChain,
    SenderMfgrCertChain,
    SenderOwnerCertChain,
    SenderPartOwnerCertChain,
    SenderReport,
    SrcRemoteBackup,
    PrevSdMkBackup,
    SenderCertOob,
    SenderMfgrCertOob,
    SenderOwnerCertOob,
    SenderPartOwnerCertOob,
    SenderReportOob,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    target: MutationTarget,
    offset: u16,
    mask: u8,
    key_scope: common::KeyScope,
}

#[derive(Clone)]
struct SenderEvidence {
    items: Vec<Vec<u8>>,
    sender_cert_chain: Vec<CertDescriptor>,
    mfgr_cert_chain: Vec<CertDescriptor>,
    owner_cert_chain: Vec<CertDescriptor>,
    part_owner_cert_chain: Vec<CertDescriptor>,
    report: ReportDescriptor,
}

impl SenderEvidence {
    fn oob(&self) -> Vec<&[u8]> {
        self.items.iter().map(Vec::as_slice).collect()
    }
}

struct RestoreFixture {
    session_id: u16,
    masked_sealing_key: [u8; azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN],
    policy: PartPolicy,
    evidence: SenderEvidence,
    src_remote_backup: [u8; azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN],
    prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
}

fn push_oob_item(items: &mut Vec<Vec<u8>>, bytes: &[u8]) -> CertDescriptor {
    let descriptor = CertDescriptor {
        index: items.len() as u8,
        length: U16::new(bytes.len() as u16),
    };
    items.push(bytes.to_vec());
    descriptor
}

fn push_chain(items: &mut Vec<Vec<u8>>, chain: [&[u8]; 2]) -> Vec<CertDescriptor> {
    chain
        .into_iter()
        .map(|cert| push_oob_item(items, cert))
        .collect()
}

fn build_sender_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    sender_pub: &[u8; RAW_PUB_LEN],
    sata: &CaKey,
    sapota: &CaKey,
    report_bytes: &[u8],
) -> SenderEvidence {
    let sender = make_chain(sata, sender_pub);
    let mfgr = make_chain(&CaKey::generate(), pid_pub);
    let owner = make_chain(&CaKey::generate(), pid_pub);
    let part_owner = make_chain(sapota, pid_pub);

    let mut items = Vec::new();
    let sender_cert_chain = push_chain(&mut items, sender.der_items());
    let mfgr_cert_chain = push_chain(&mut items, mfgr.der_items());
    let owner_cert_chain = push_chain(&mut items, owner.der_items());
    let part_owner_cert_chain = push_chain(&mut items, part_owner.der_items());
    let report = push_oob_item(&mut items, report_bytes);

    SenderEvidence {
        items,
        sender_cert_chain,
        mfgr_cert_chain,
        owner_cert_chain,
        part_owner_cert_chain,
        report: ReportDescriptor {
            index: report.index,
            length: report.length,
        },
    }
}

fn build_policy(
    policy_bytes: &mut [u8; azihsm_ddi_tbor_types::PART_POLICY_LEN],
    policy: &mut PartPolicy,
    pid: &[u8],
    pid_pub: &[u8; RAW_PUB_LEN],
    sata: &CaKey,
    sapota: &CaKey,
) {
    policy.sata_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        sata.raw_pub(),
    );
    policy.sapota_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        sapota.raw_pub(),
    );
    policy.backup_part_id.copy_from_slice(pid);
    policy.backup_part_pub_key =
        PolicyPubKey::new(PolicyKeyKind::Ecc384, POLICY_MAX_KEY_LEN as u16, *pid_pub);
    policy.flags = policy.flags.with_require_trusted_sa_key(true);
    policy_bytes.copy_from_slice(policy.as_bytes());
}

fn create_restore_fixture(ctx: &TestCtx, key_scope: common::KeyScope) -> Option<RestoreFixture> {
    let source_session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let part_info = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo should succeed");
    let pid_pub: [u8; RAW_PUB_LEN] = part_info
        .pid_pub_key
        .as_slice()
        .try_into()
        .expect("partition public key must be P-384");

    let pota = CaKey::generate();
    let sata = CaKey::generate();
    let sapota = CaKey::generate();

    let mut policy_bytes = common::known_good_part_policy(pota.raw_pub());
    let mut policy = PartPolicy::try_read_from_bytes(&policy_bytes)
        .expect("common known-good policy should decode");
    build_policy(
        &mut policy_bytes,
        &mut policy,
        &part_info.pid,
        &pid_pub,
        &sata,
        &sapota,
    );

    let init = ctx
        .part_init(
            &source_session,
            &common::mach_seed(),
            &policy_bytes,
            &common::pota_thumbprint(),
        )
        .expect("PartInit should succeed");
    let pta_chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&source_session, &policy_bytes, &[], &pta_chain.der_items())
        .expect("PartFinal should succeed")
        .local_mk_backup;

    let bootstrap_scope = if key_scope == common::KeyScope::SecurityDomain {
        common::KeyScope::Local
    } else {
        key_scope
    };
    let sealing_key = match ctx.tbor(&TborSdSealingKeyGenReq {
        session_id: source_session.session_id,
        scope: bootstrap_scope.to_tbor(),
    }) {
        Ok(key) => key,
        Err(DdiError::TborStatus(status)) if status == TborStatus::UnsupportedKeyScope => {
            ctx.session_close(source_session.session_id)
                .expect("session close after unsupported key scope should succeed");
            return None;
        }
        Err(err) => panic!("bootstrap SD sealing-key generation failed: {err}"),
    };
    let mut sealing_pub = [0u8; RAW_PUB_LEN];
    for (dst, src) in sealing_pub[..48]
        .iter_mut()
        .zip(sealing_key.pub_key[..48].iter().rev())
    {
        *dst = *src;
    }
    for (dst, src) in sealing_pub[48..]
        .iter_mut()
        .zip(sealing_key.pub_key[48..].iter().rev())
    {
        *dst = *src;
    }

    let report_bytes = ctx
        .tbor(&TborKeyReportReq {
            session_id: source_session.session_id,
            masked_key: sealing_key.masked_key.to_vec(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("KeyReport should succeed")
        .report;
    let evidence = build_sender_evidence(&pid_pub, &sealing_pub, &sata, &sapota, &report_bytes);

    let create_req = TborSdCreateRemoteBackupReq {
        session_id: source_session.session_id,
        masked_sealing_key: sealing_key.masked_key,
        receiver_cert_chain: evidence.sender_cert_chain.clone(),
        receiver_mfgr_cert_chain: evidence.mfgr_cert_chain.clone(),
        receiver_owner_cert_chain: evidence.owner_cert_chain.clone(),
        receiver_part_owner_cert_chain: evidence.part_owner_cert_chain.clone(),
        receiver_report: evidence.report,
        policy: policy.clone(),
    };
    let created = ctx
        .tbor_oob(&create_req, &evidence.oob())
        .expect("SdCreateRemoteBackup should succeed");

    let (restore_sealing_key, restore_evidence) = if key_scope == common::KeyScope::SecurityDomain {
        let sealing_key = ctx
            .tbor(&TborSdSealingKeyGenReq {
                session_id: source_session.session_id,
                scope: key_scope.to_tbor(),
            })
            .expect("SecurityDomain-scope key generation should succeed after SD creation");
        let report = ctx
            .tbor(&TborKeyReportReq {
                session_id: source_session.session_id,
                masked_key: sealing_key.masked_key.to_vec(),
                report_data: [0u8; KEY_REPORT_DATA_LEN],
            })
            .expect("SecurityDomain-scope KeyReport should succeed")
            .report;
        let mut public_key = [0u8; RAW_PUB_LEN];
        for (dst, src) in public_key[..48]
            .iter_mut()
            .zip(sealing_key.pub_key[..48].iter().rev())
        {
            *dst = *src;
        }
        for (dst, src) in public_key[48..]
            .iter_mut()
            .zip(sealing_key.pub_key[48..].iter().rev())
        {
            *dst = *src;
        }
        (
            sealing_key,
            build_sender_evidence(&pid_pub, &public_key, &sata, &sapota, &report),
        )
    } else {
        (sealing_key, evidence)
    };

    ctx.session_close(source_session.session_id)
        .expect("source session close should succeed");
    ctx.erase().expect("partition reset should succeed");

    let restore_session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(
            &restore_session,
            &common::mach_seed(),
            &policy_bytes,
            &common::pota_thumbprint(),
        )
        .expect("PartInit after reset should succeed");
    let pta_chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &restore_session,
        &policy_bytes,
        &local_mk_backup,
        &pta_chain.der_items(),
    )
    .expect("PartFinal should restore the prior local masking key");

    Some(RestoreFixture {
        session_id: restore_session.session_id,
        masked_sealing_key: restore_sealing_key.masked_key,
        policy,
        evidence: restore_evidence,
        src_remote_backup: created.pok_remote_backup,
        prev_sd_mk_backup: created.sd_mk_backup,
    })
}

fn flip(bytes: &mut [u8], offset: u16, mask: u8) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let index = usize::from(offset) % bytes.len();
    bytes[index] ^= mask | 1;
    true
}

fn invalidate_descriptor(descriptors: &mut [CertDescriptor], input: &FuzzInput) -> bool {
    if descriptors.is_empty() {
        return false;
    }
    let descriptor = &mut descriptors[usize::from(input.offset) % descriptors.len()];
    if input.mask & 1 == 0 {
        descriptor.index = u8::MAX;
    } else {
        descriptor.length = U16::new(descriptor.length.get() ^ (u16::from(input.mask) | 1));
    }
    true
}

fn invalidate_report(report: &mut ReportDescriptor, input: &FuzzInput) {
    if input.mask & 1 == 0 {
        report.index = u8::MAX;
    } else {
        report.length = U16::new(report.length.get() ^ (u16::from(input.mask) | 1));
    }
}

fn mutate_oob_item(
    evidence: &mut SenderEvidence,
    descriptors: &[CertDescriptor],
    input: &FuzzInput,
) -> bool {
    if descriptors.is_empty() {
        return false;
    }
    let descriptor = descriptors[usize::from(input.offset) % descriptors.len()];
    let Some(item) = evidence.items.get_mut(usize::from(descriptor.index)) else {
        return false;
    };
    flip(item, input.offset, input.mask)
}

fn mutate_request(
    input: &FuzzInput,
    fixture: &RestoreFixture,
    req: &mut TborSdRestoreRemoteBackupReq,
    evidence: &mut SenderEvidence,
) -> bool {
    match input.target {
        MutationTarget::Valid => false,
        MutationTarget::SessionId => {
            req.session_id ^= 0x8000;
            true
        }
        MutationTarget::MaskedSealingKey => {
            flip(&mut req.masked_sealing_key, input.offset, input.mask)
        }
        MutationTarget::Policy => flip(&mut req.policy.info, input.offset, input.mask),
        MutationTarget::SenderCertChain => invalidate_descriptor(&mut req.sender_cert_chain, input),
        MutationTarget::SenderMfgrCertChain => {
            invalidate_descriptor(&mut req.sender_mfgr_cert_chain, input)
        }
        MutationTarget::SenderOwnerCertChain => {
            invalidate_descriptor(&mut req.sender_owner_cert_chain, input)
        }
        MutationTarget::SenderPartOwnerCertChain => {
            invalidate_descriptor(&mut req.sender_part_owner_cert_chain, input)
        }
        MutationTarget::SenderReport => {
            invalidate_report(&mut req.sender_report, input);
            true
        }
        MutationTarget::SrcRemoteBackup => {
            flip(&mut req.src_remote_backup, input.offset, input.mask)
        }
        MutationTarget::PrevSdMkBackup => {
            flip(&mut req.prev_sd_mk_backup, input.offset, input.mask)
        }
        MutationTarget::SenderCertOob => {
            mutate_oob_item(evidence, &fixture.evidence.sender_cert_chain, input)
        }
        MutationTarget::SenderMfgrCertOob => {
            mutate_oob_item(evidence, &fixture.evidence.mfgr_cert_chain, input)
        }
        MutationTarget::SenderOwnerCertOob => {
            mutate_oob_item(evidence, &fixture.evidence.owner_cert_chain, input)
        }
        MutationTarget::SenderPartOwnerCertOob => {
            mutate_oob_item(evidence, &fixture.evidence.part_owner_cert_chain, input)
        }
        MutationTarget::SenderReportOob => {
            let report = [fixture.evidence.report.index.into()];
            let descriptors = [CertDescriptor {
                index: report[0],
                length: fixture.evidence.report.length,
            }];
            mutate_oob_item(evidence, &descriptors, input)
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let Some(fixture) = create_restore_fixture(ctx, input.key_scope) else {
            return;
        };
        let mut evidence = fixture.evidence.clone();
        let mut req = TborSdRestoreRemoteBackupReq {
            session_id: fixture.session_id,
            masked_sealing_key: fixture.masked_sealing_key,
            policy: fixture.policy.clone(),
            sender_cert_chain: evidence.sender_cert_chain.clone(),
            sender_mfgr_cert_chain: evidence.mfgr_cert_chain.clone(),
            sender_owner_cert_chain: evidence.owner_cert_chain.clone(),
            sender_part_owner_cert_chain: evidence.part_owner_cert_chain.clone(),
            sender_report: evidence.report,
            src_remote_backup: fixture.src_remote_backup,
            prev_sd_mk_backup: fixture.prev_sd_mk_backup,
        };

        let changed = mutate_request(&input, &fixture, &mut req, &mut evidence);
        let oob = evidence.oob();
        let result = ctx.tbor_oob(&req, &oob);

        if changed || input.key_scope != common::KeyScope::Local {
            assert!(
                result.is_err(),
                "the selected mutation should make SdRestoreRemoteBackup fail: {:?}",
                input.target
            );
        } else {
            let response = result.expect("the unmodified valid remote restore should succeed");
            assert_eq!(response.pok_local_backup.len(), MASKED_SD_LEN);
            assert_eq!(response.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
            assert!(
                response.pok_local_backup.iter().any(|&byte| byte != 0),
                "successful restore must return a nonzero local backup"
            );
            assert!(
                response.sd_mk_backup.iter().any(|&byte| byte != 0),
                "successful restore must return a nonzero SDMK backup"
            );
        }

        ctx.session_close(fixture.session_id)
            .expect("restore session close should succeed");
    });
});
