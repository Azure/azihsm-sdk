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
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::tbor_int::U16;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;

const ENVELOPE_CIPHERTEXT_OFFSET: usize = 8 + 12 + 192;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Mutation {
    Valid,
    TamperPok { offset: u16, mask: u8 },
    TamperSdMk { offset: u16, mask: u8 },
    OneShot,
    NotFinalized,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
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

struct SourceBackups {
    session_id: u16,
    policy: [u8; PART_POLICY_LEN],
    local_mk_backup: Vec<u8>,
    pok_local_backup: Vec<u8>,
    sd_mk_backup: Vec<u8>,
    pota: CaKey,
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

fn build_source_backups(ctx: &TestCtx) -> SourceBackups {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let part_info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");

    let pota = CaKey::generate();
    let sata = CaKey::generate();
    let mut policy = common::known_good_part_policy(pota.raw_pub());
    let mut policy_value =
        <PartPolicy as TryFromBytes>::try_read_from_bytes(&policy).expect("known policy");
    policy_value.sata_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        sata.raw_pub(),
    );
    policy_value.backup_part_id.copy_from_slice(&part_info.pid);
    let pid_pub: [u8; POLICY_MAX_KEY_LEN] = part_info
        .pid_pub_key
        .as_slice()
        .try_into()
        .expect("PartInfo public key is P-384");
    policy_value.backup_part_pub_key =
        PolicyPubKey::new(PolicyKeyKind::Ecc384, POLICY_MAX_KEY_LEN as u16, pid_pub);
    policy.copy_from_slice(policy_value.as_bytes());

    let init = ctx
        .part_init(
            &session,
            &common::mach_seed(),
            &policy,
            &common::pota_thumbprint(),
        )
        .expect("PartInit");
    let pta_chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &pta_chain.der_items())
        .expect("PartFinal")
        .local_mk_backup
        .to_vec();

    let sealing_key = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: session.session_id,
            scope: common::KEY_SCOPE_LOCAL,
        })
        .expect("SdSealingKeyGen");
    let receiver_pub = raw_pub_from_wire(&sealing_key.pub_key);
    let receiver_chain = make_chain(&sata, &receiver_pub);
    let mut oob_items = Vec::new();
    let receiver_cert_chain = push_chain(&mut oob_items, receiver_chain);
    let policy_value =
        <PartPolicy as TryFromBytes>::try_read_from_bytes(&policy).expect("policy image");
    let request = TborSdCreateRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: sealing_key.masked_key,
        receiver_cert_chain,
        receiver_mfgr_cert_chain: Vec::new(),
        receiver_owner_cert_chain: Vec::new(),
        receiver_part_owner_cert_chain: Vec::new(),
        receiver_report: Default::default(),
        policy: policy_value,
    };
    let oob: Vec<&[u8]> = oob_items.iter().map(Vec::as_slice).collect();
    let response = ctx
        .tbor_oob(&request, &oob)
        .expect("valid SdCreateRemoteBackup fixture");

    SourceBackups {
        session_id: session.session_id,
        policy,
        local_mk_backup,
        pok_local_backup: response.pok_local_backup.to_vec(),
        sd_mk_backup: response.sd_mk_backup.to_vec(),
        pota,
    }
}

fn flip_ciphertext_or_tag_byte(bytes: &mut [u8], offset: u16, mask: u8) -> bool {
    if mask == 0 || bytes.len() <= ENVELOPE_CIPHERTEXT_OFFSET {
        return false;
    }

    let body_len = bytes.len() - ENVELOPE_CIPHERTEXT_OFFSET;
    let index = ENVELOPE_CIPHERTEXT_OFFSET + usize::from(offset) % body_len;
    bytes[index] ^= mask;
    true
}

fn restore_after_reboot(ctx: &TestCtx, backups: &SourceBackups, mutation: Mutation) {
    ctx.session_close(backups.session_id)
        .expect("close source CO session");
    ctx.erase().expect("factory-reset before restore");

    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(
            &session,
            &common::mach_seed(),
            &backups.policy,
            &common::pota_thumbprint(),
        )
        .expect("PartInit after reboot");
    let pta_chain = make_pta_chain(&backups.pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &backups.policy,
        &backups.local_mk_backup,
        &pta_chain.der_items(),
    )
    .expect("PartFinal restores PartLocalMK");

    let mut pok_local_backup = backups.pok_local_backup.clone();
    let mut sd_mk_backup = backups.sd_mk_backup.clone();
    let expected_rejection = match mutation {
        Mutation::TamperPok { offset, mask } => {
            if flip_ciphertext_or_tag_byte(&mut pok_local_backup, offset, mask) {
                Some(TborStatus::AesGcmDecryptTagDoesNotMatch)
            } else {
                None
            }
        }
        Mutation::TamperSdMk { offset, mask } => {
            if flip_ciphertext_or_tag_byte(&mut sd_mk_backup, offset, mask) {
                Some(TborStatus::AesGcmDecryptTagDoesNotMatch)
            } else {
                None
            }
        }
        Mutation::Valid => None,
        Mutation::OneShot | Mutation::NotFinalized => {
            unreachable!("these scenarios do not use the rebooted fixture")
        }
    };

    let request = TborSdRestoreLocalBackupReq {
        session_id: session.session_id,
        pok_local_backup,
        sd_mk_backup,
    };
    if let Some(status) = expected_rejection {
        ctx.expect_fw_reject(&request, status);
    } else {
        let response = ctx
            .tbor(&request)
            .expect("untampered or no-op-mutated restore should succeed");
        assert_eq!(response.pok_local_backup.len(), MASKED_SD_LEN);
        assert!(
            response.pok_local_backup.iter().any(|byte| *byte != 0),
            "refreshed POK backup must not be all zero",
        );
        assert_eq!(response.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
        assert!(
            response.sd_mk_backup.iter().any(|byte| *byte != 0),
            "refreshed SD-MK backup must not be all zero",
        );
        ctx.expect_fw_reject(&request, TborStatus::SdAlreadyInitialized);
    }

    ctx.session_close(session.session_id)
        .expect("close restore CO session");
}

fn run_case(ctx: &TestCtx, mutation: Mutation) {
    match mutation {
        Mutation::NotFinalized => {
            let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
            ctx.expect_fw_reject(
                &TborSdRestoreLocalBackupReq {
                    session_id: session.session_id,
                    pok_local_backup: vec![0u8; MASKED_SD_LEN],
                    sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
                },
                TborStatus::InvalidArg,
            );
            ctx.session_close(session.session_id)
                .expect("close not-finalized CO session");
        }
        Mutation::OneShot => {
            let backups = build_source_backups(ctx);
            ctx.expect_fw_reject(
                &TborSdRestoreLocalBackupReq {
                    session_id: backups.session_id,
                    pok_local_backup: backups.pok_local_backup,
                    sd_mk_backup: backups.sd_mk_backup,
                },
                TborStatus::SdAlreadyInitialized,
            );
            ctx.session_close(backups.session_id)
                .expect("close one-shot CO session");
        }
        Mutation::Valid | Mutation::TamperPok { .. } | Mutation::TamperSdMk { .. } => {
            let backups = build_source_backups(ctx);
            restore_after_reboot(ctx, &backups, mutation);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = arbitrary::Unstructured::new(data);
    let input = FuzzInput::arbitrary(&mut unstructured).unwrap_or_default();

    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        run_case(ctx, input.mutation);
    });
});
