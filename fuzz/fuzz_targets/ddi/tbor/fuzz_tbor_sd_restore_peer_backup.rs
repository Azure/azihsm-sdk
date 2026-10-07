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
use azihsm_ddi_tbor_types::EVIDENCE_CHAIN_MAX_CERTS;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::TborKeyReportReq;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdCreatePeerBackupReq;
use azihsm_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdRestorePeerBackupReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::tbor_int::U16;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;

const SCOPE_LOCAL: u8 = 0b011;

#[derive(Arbitrary, Debug)]
enum ByteMutation {
    Keep,
    Flip { offset: u16, mask: u8 },
}

impl ByteMutation {
    fn apply(&self, bytes: &mut [u8]) -> bool {
        match self {
            Self::Keep => false,
            Self::Flip { offset, mask } if *mask != 0 && !bytes.is_empty() => {
                let index = usize::from(*offset) % bytes.len();
                bytes[index] ^= *mask;
                true
            }
            Self::Flip { .. } => false,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum DescriptorMutation {
    Keep,
    InvalidIndex { descriptor: u16 },
    WrongLength { descriptor: u16, mask: u16 },
    Oversized,
}

impl DescriptorMutation {
    fn apply(&self, descriptors: &mut Vec<CertDescriptor>) -> bool {
        match self {
            Self::Keep => false,
            Self::InvalidIndex { descriptor } if !descriptors.is_empty() => {
                let index = usize::from(*descriptor) % descriptors.len();
                descriptors[index].index = u8::MAX;
                true
            }
            Self::InvalidIndex { .. } => false,
            Self::WrongLength { descriptor, mask } if !descriptors.is_empty() => {
                let index = usize::from(*descriptor) % descriptors.len();
                descriptors[index].length = U16::new(descriptors[index].length.get() ^ (*mask | 1));
                true
            }
            Self::WrongLength { .. } => false,
            Self::Oversized => {
                let descriptor = descriptors[0];
                while descriptors.len() <= EVIDENCE_CHAIN_MAX_CERTS {
                    descriptors.push(descriptor);
                }
                true
            }
        }
    }
}

#[derive(Arbitrary, Debug)]
enum ReportMutation {
    Keep,
    InvalidIndex,
    WrongLength { mask: u16 },
}

impl ReportMutation {
    fn apply(&self, report: &mut ReportDescriptor) -> bool {
        match self {
            Self::Keep => false,
            Self::InvalidIndex => {
                report.index = u8::MAX;
                true
            }
            Self::WrongLength { mask } => {
                report.length = U16::new(report.length.get() ^ (*mask | 1));
                true
            }
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MutationTarget {
    Valid,
    SessionId,
    MaskedSealingKey,
    Policy,
    ManufacturerChain,
    OwnerChain,
    PartitionOwnerChain,
    Report,
    PeerBackup,
    PreviousSdMkBackup,
    OobEvidence,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    target: MutationTarget,
    bytes: ByteMutation,
    descriptors: DescriptorMutation,
    report: ReportMutation,
}

struct Evidence {
    items: Vec<Vec<u8>>,
    receiver: Vec<CertDescriptor>,
    manufacturer: Vec<CertDescriptor>,
    owner: Vec<CertDescriptor>,
    partition_owner: Vec<CertDescriptor>,
    report: ReportDescriptor,
}

impl Evidence {
    fn oob(&self) -> Vec<&[u8]> {
        self.items.iter().map(Vec::as_slice).collect()
    }

    fn referenced_indices(&self) -> Vec<u8> {
        self.manufacturer
            .iter()
            .chain(&self.owner)
            .chain(&self.partition_owner)
            .map(|descriptor| descriptor.index)
            .chain(core::iter::once(self.report.index))
            .collect()
    }
}

fn push_cert(items: &mut Vec<Vec<u8>>, bytes: &[u8]) -> CertDescriptor {
    let descriptor = CertDescriptor {
        index: items.len() as u8,
        length: U16::new(bytes.len() as u16),
    };
    items.push(bytes.to_vec());
    descriptor
}

fn build_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    sealing_pub: &[u8; RAW_PUB_LEN],
    sata: &CaKey,
    report_bytes: &[u8],
) -> Evidence {
    let receiver = make_chain(sata, sealing_pub);
    let manufacturer = make_chain(&CaKey::generate(), pid_pub);
    let owner = make_chain(&CaKey::generate(), pid_pub);
    let partition_owner = make_chain(sata, pid_pub);

    let mut items = Vec::new();
    let receiver_descriptors = receiver
        .der_items()
        .iter()
        .map(|cert| push_cert(&mut items, cert))
        .collect();
    let manufacturer_descriptors = manufacturer
        .der_items()
        .iter()
        .map(|cert| push_cert(&mut items, cert))
        .collect();
    let owner_descriptors = owner
        .der_items()
        .iter()
        .map(|cert| push_cert(&mut items, cert))
        .collect();
    let partition_owner_descriptors = partition_owner
        .der_items()
        .iter()
        .map(|cert| push_cert(&mut items, cert))
        .collect();
    let report_descriptor = push_cert(&mut items, report_bytes);

    Evidence {
        items,
        receiver: receiver_descriptors,
        manufacturer: manufacturer_descriptors,
        owner: owner_descriptors,
        partition_owner: partition_owner_descriptors,
        report: ReportDescriptor {
            index: report_descriptor.index,
            length: report_descriptor.length,
        },
    }
}

struct PeerBackup {
    masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN],
    policy: PartPolicy,
    evidence: Evidence,
    peer_backup: [u8; POK_REMOTE_BACKUP_LEN],
    previous_sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
    session_id: u16,
}

fn create_peer_backup(ctx: &TestCtx) -> PeerBackup {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let part_info = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo should succeed");
    let pota = CaKey::generate();
    let sata = CaKey::generate();

    let mut policy_bytes = common::known_good_part_policy(pota.raw_pub());
    let mut policy = PartPolicy::try_read_from_bytes(&policy_bytes)
        .expect("common known-good policy should decode");
    policy.sata_pub_key = azihsm_ddi_tbor_types::PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        sata.raw_pub(),
    );
    policy.backup_part_id.copy_from_slice(&part_info.pid);
    let pid_pub: [u8; RAW_PUB_LEN] = part_info
        .pid_pub_key
        .as_slice()
        .try_into()
        .expect("partition public key must be P-384");
    policy.backup_part_pub_key = azihsm_ddi_tbor_types::PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        pid_pub,
    );
    policy.flags = policy.flags.with_allow_peer_cloning(true);
    policy_bytes.copy_from_slice(policy.as_bytes());

    let init = ctx
        .part_init(
            &session,
            &common::mach_seed(),
            &policy_bytes,
            &common::pota_thumbprint(),
        )
        .expect("PartInit should succeed");
    let pta_chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy_bytes, &[], &pta_chain.der_items())
        .expect("PartFinal should succeed")
        .local_mk_backup;

    let sealing_key = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("SdSealingKeyGen should succeed");
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

    let key_report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: sealing_key.masked_key.to_vec(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("KeyReport should succeed")
        .report;
    let evidence = build_evidence(&pid_pub, &sealing_pub, &sata, &key_report);

    let create_remote = TborSdCreateRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: sealing_key.masked_key,
        receiver_cert_chain: evidence.receiver.clone(),
        receiver_mfgr_cert_chain: evidence.manufacturer.clone(),
        receiver_owner_cert_chain: evidence.owner.clone(),
        receiver_part_owner_cert_chain: evidence.partition_owner.clone(),
        receiver_report: evidence.report,
        policy: policy.clone(),
    };
    let create_remote_response = ctx
        .tbor_oob(&create_remote, &evidence.oob())
        .expect("SdCreateRemoteBackup should succeed");

    let create_peer = TborSdCreatePeerBackupReq {
        session_id: session.session_id,
        masked_sealing_key: sealing_key.masked_key,
        policy: policy.clone(),
        dst_mfgr_cert_chain: evidence.manufacturer.clone(),
        dst_owner_cert_chain: evidence.owner.clone(),
        dst_part_owner_cert_chain: evidence.partition_owner.clone(),
        dst_report: evidence.report,
        pok_local_backup: create_remote_response.pok_local_backup,
    };
    let create_peer_response = ctx
        .tbor_oob(&create_peer, &evidence.oob())
        .expect("SdCreatePeerBackup should succeed");

    ctx.session_close(session.session_id)
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

    PeerBackup {
        masked_sealing_key: sealing_key.masked_key,
        policy,
        evidence,
        peer_backup: create_peer_response.pok_peer_backup,
        previous_sd_mk_backup: create_remote_response.sd_mk_backup,
        session_id: restore_session.session_id,
    }
}

fn mutate_request(
    input: &FuzzInput,
    session_id: u16,
    backup: &PeerBackup,
    req: &mut TborSdRestorePeerBackupReq,
    evidence: &mut Evidence,
) -> bool {
    match input.target {
        MutationTarget::Valid => false,
        MutationTarget::SessionId => {
            req.session_id = session_id ^ 0x8000;
            true
        }
        MutationTarget::MaskedSealingKey => input.bytes.apply(&mut req.masked_sealing_key),
        MutationTarget::Policy => input.bytes.apply(&mut req.policy.info),
        MutationTarget::ManufacturerChain => input.descriptors.apply(&mut req.src_mfgr_cert_chain),
        MutationTarget::OwnerChain => input.descriptors.apply(&mut req.src_owner_cert_chain),
        MutationTarget::PartitionOwnerChain => {
            input.descriptors.apply(&mut req.src_part_owner_cert_chain)
        }
        MutationTarget::Report => input.report.apply(&mut req.src_report),
        MutationTarget::PeerBackup => input.bytes.apply(&mut req.pok_peer_backup),
        MutationTarget::PreviousSdMkBackup => input.bytes.apply(&mut req.prev_sd_mk_backup),
        MutationTarget::OobEvidence => {
            let indices = backup.evidence.referenced_indices();
            if indices.is_empty() {
                return false;
            }
            match &input.bytes {
                ByteMutation::Keep => false,
                ByteMutation::Flip { offset, mask } if *mask != 0 => {
                    let item_index = usize::from(*offset) % indices.len();
                    let item = &mut evidence.items[usize::from(indices[item_index])];
                    if item.is_empty() {
                        false
                    } else {
                        let byte_index = usize::from(*offset) % item.len();
                        item[byte_index] ^= *mask;
                        true
                    }
                }
                ByteMutation::Flip { .. } => false,
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let backup = create_peer_backup(ctx);

        let mut evidence = Evidence {
            items: backup.evidence.items.clone(),
            receiver: backup.evidence.receiver.clone(),
            manufacturer: backup.evidence.manufacturer.clone(),
            owner: backup.evidence.owner.clone(),
            partition_owner: backup.evidence.partition_owner.clone(),
            report: backup.evidence.report,
        };
        let mut req = TborSdRestorePeerBackupReq {
            session_id: backup.session_id,
            masked_sealing_key: backup.masked_sealing_key,
            policy: backup.policy.clone(),
            src_mfgr_cert_chain: evidence.manufacturer.clone(),
            src_owner_cert_chain: evidence.owner.clone(),
            src_part_owner_cert_chain: evidence.partition_owner.clone(),
            src_report: evidence.report,
            pok_peer_backup: backup.peer_backup,
            prev_sd_mk_backup: backup.previous_sd_mk_backup,
        };
        let changed = mutate_request(&input, backup.session_id, &backup, &mut req, &mut evidence);
        let oob = evidence.oob();
        let result = ctx.tbor_oob(&req, &oob);

        if changed {
            match result {
                Err(err @ DdiError::DriverError(_)) => {
                    panic!("SdRestorePeerBackup transport/driver failure: {err:?}");
                }
                Err(_) => {}
                Ok(response) => panic!(
                    "the selected mutation should make SdRestorePeerBackup fail: \
                     target={:?}, response={response:?}",
                    input.target
                ),
            }
        } else {
            let response = result.expect("the unmodified valid peer restore should succeed");
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

        ctx.session_close(backup.session_id)
            .expect("restore session close should succeed");
    });
});
