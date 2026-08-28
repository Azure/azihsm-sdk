// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborSdRestorePeerBackupReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN],
    pok_peer_backup: [u8; POK_REMOTE_BACKUP_LEN],
    prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
    report_index: u8,
    report_length: u16,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    let req = TborSdRestorePeerBackupReq {
        session_id: session.session_id(),
        masked_sealing_key: input.masked_sealing_key,
        policy: PartPolicy::zeroed(),
        src_mfgr_cert_chain: Vec::new(),
        src_owner_cert_chain: Vec::new(),
        src_part_owner_cert_chain: Vec::new(),
        src_report: ReportDescriptor {
            index: input.report_index,
            length: zerocopy::little_endian::U16::new(input.report_length),
        },
        pok_peer_backup: input.pok_peer_backup,
        prev_sd_mk_backup: input.prev_sd_mk_backup,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
