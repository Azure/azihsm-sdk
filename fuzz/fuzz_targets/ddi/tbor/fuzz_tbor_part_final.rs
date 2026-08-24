// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::SessionOpenInitOptions;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::SessionType;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CO: u8 = 0;

/// Non-default CO PSK used to clear the default-PSK gate before `PartInit`.
const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
    0xBF, 0xC0,
];

static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Fuzzed prior local_mk backup (empty = first-instantiation path).
    prev_local_mk_backup: Vec<u8>,
}

/// Build a `PartPolicy` with `pota_raw` (raw P-384 `X ‖ Y`) as the POTA
/// trust anchor so `PartFinal` can validate the cert chain against it.
fn part_policy_with_pota(pota_raw: &[u8; 96]) -> [u8; PART_POLICY_LEN] {
    const OFF_POTA: usize = 2;
    const OFF_SATA: usize = 102;
    const OFF_FLAGS: usize = 418;
    const OFF_INFO: usize = 419;

    fn write_pubkey(bytes: &mut [u8], off: usize, fill: u8) {
        bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
        bytes[off + 2..off + 4].copy_from_slice(&96u16.to_le_bytes());
        for (i, b) in bytes[off + 4..off + 4 + 96].iter_mut().enumerate() {
            *b = (fill.wrapping_add(i as u8)) | 0x80;
        }
    }

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes[0] = 1; // version major
    bytes[1] = 0; // version minor
    write_pubkey(&mut bytes, OFF_POTA, 0x10);
    write_pubkey(&mut bytes, OFF_SATA, 0x20);
    bytes[OFF_FLAGS] = 0;
    for b in bytes[OFF_INFO..OFF_INFO + 64].iter_mut() {
        *b = 0xAB;
    }
    // Overwrite the POTA key data with the real public key.
    bytes[OFF_POTA + 4..OFF_POTA + 4 + 96].copy_from_slice(pota_raw);
    bytes
}

fn mach_seed() -> [u8; MACH_SEED_LEN] {
    let mut v = [0u8; MACH_SEED_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    v
}

fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    let mut v = [0u8; POTA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x80 ^ i as u8;
    }
    v
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    // Rotate the CO PSK to clear the default-PSK gate before PartInit.
    let bootstrap = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("bootstrap session open should succeed");
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CO_PSK)
        .expect("PSK rotation should succeed");
    bootstrap.close().expect("bootstrap session close should succeed");

    // Open a CO session under the rotated PSK.
    let opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&ROTATED_CO_PSK);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("session_open_init should succeed");
    let session = ctx
        .session_open_finish(pending)
        .expect("session_open_finish should succeed");

    // Generate a POTA trust anchor and embed its public key in the policy.
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());

    // PartInit: transition the partition to PartState::Initializing.
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit should succeed");

    // Build a valid PTA cert chain anchored to the POTA key, using the CSR
    // returned by PartInit to certify the correct partition PTA public key.
    let pta_pub = pta_pub_from_csr(&init.pta_csr);
    let chain = make_pta_chain(&pota, &pta_pub);

    // PartFinal: the valid chain clears both the lifecycle and OOB gates,
    // so the fuzzed prev_local_mk_backup reaches the handler logic.
    let _ = ctx.part_final(&session, &policy, &input.prev_local_mk_backup, &chain.der_items());

    ctx.session_close(session.session_id)
        .expect("session close should succeed");
});
