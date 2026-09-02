// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

fn bounded_pok(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = usize::arbitrary(u)? % (180 + 1);
    Ok(u.bytes(len)?.to_vec())
}

fn bounded_sd_mk(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = usize::arbitrary(u)? % (164 + 1);
    Ok(u.bytes(len)?.to_vec())
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    #[arbitrary(with = bounded_pok)]
    pok_local_backup: Vec<u8>,
    #[arbitrary(with = bounded_sd_mk)]
    sd_mk_backup: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    let req = TborSdRestoreLocalBackupReq {
        session_id: session.session_id(),
        pok_local_backup: input.pok_local_backup,
        sd_mk_backup: input.sd_mk_backup,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
