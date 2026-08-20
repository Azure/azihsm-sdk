// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::CERT_DESCRIPTOR_LEN;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::MAX_CERTS;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPartFinalReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zerocopy::FromBytes;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Fixed-length fuzzed cert_descriptors buffer.
    cert_descriptors: [u8; MAX_CERTS * CERT_DESCRIPTOR_LEN],
    /// Fixed-length fuzzed prev_local_mk_backup buffer.
    prev_local_mk_backup: [u8; LOCAL_MK_BACKUP_LEN],
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    // Reinterpret the fuzzed byte array as CertDescriptor slice.
    let cert_descriptors: Vec<CertDescriptor> = input
        .cert_descriptors
        .chunks_exact(CERT_DESCRIPTOR_LEN)
        .map(|chunk| CertDescriptor::read_from_bytes(chunk).unwrap())
        .collect();

    let part_final_req = TborPartFinalReq {
        session_id: session.session_id(),
        part_policy: PartPolicy::zeroed(),
        cert_descriptors,
        prev_local_mk_backup: input.prev_local_mk_backup.to_vec(),
    };
    let _ = ctx.tbor(&part_final_req);

    session.close().expect("session close should succeed");
});
