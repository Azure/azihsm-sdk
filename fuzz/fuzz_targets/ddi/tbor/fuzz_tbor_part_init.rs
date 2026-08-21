// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::MACH_SEED_ENVELOPE_MAX_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::SAPOTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPartInitReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CO: u8 = 0;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Fixed-length fuzzed mach_seed_envelope buffer.
    mach_seed_envelope: [u8; MACH_SEED_ENVELOPE_MAX_LEN],
    /// Fixed-length fuzzed POTA thumbprint.
    pota_thumbprint: [u8; POTA_THUMBPRINT_LEN],
    /// Fixed-length fuzzed SATA thumbprint.
    sata_thumbprint: [u8; SATA_THUMBPRINT_LEN],
    /// Whether to include a SAPOTA thumbprint (empty = absent).
    sapota_present: bool,
    /// Fixed-length fuzzed SAPOTA thumbprint (used when `sapota_present`).
    sapota_thumbprint: [u8; SAPOTA_THUMBPRINT_LEN],
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CO, SessionType::PlainText)
        .expect("session open should succeed");

    let part_init_req = TborPartInitReq {
        session_id: session.session_id(),
        mach_seed_envelope: input.mach_seed_envelope.to_vec(),
        part_policy: PartPolicy::zeroed(),
        pota_thumbprint: input.pota_thumbprint,
        sata_thumbprint: input.sata_thumbprint,
        sapota_thumbprint: input.sapota_thumbprint.to_vec(),
    };
    let _ = ctx.tbor(&part_init_req);

    session.close().expect("session close should succeed");
});
