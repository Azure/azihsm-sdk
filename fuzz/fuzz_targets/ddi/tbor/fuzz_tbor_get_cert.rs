// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exercise both certificate lookup paths with raw and boundary-biased inputs.
//!
//! The oracle uses the constructed request, the advertised slot-0 count, and
//! successful lifecycle setup, never the result of the fuzzed command. Slot 0
//! is stable and agrees with MBOR; slot 2 mints fresh PID certificates after
//! finalization, so its DER and thumbprints must not be compared across reads.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::x509_fixture::*;
use azihsm_ddi_tbor_test_harness::*;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;
use x509::*;

/// Four independent bytes keep raw requests and directed smoke-test seeds small.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Forwarded unchanged in raw mode; otherwise selects a slot boundary.
    slot_id: u8,
    /// Forwarded unchanged in raw mode; otherwise selects an index boundary.
    cert_id: u8,
    /// Modulo three selects reset, PartInit-only, or finalized state.
    lifecycle: u8,
    /// Modulo eleven selects raw fields or a targeted lookup scenario.
    scenario: u8,
}

/// Partition state established successfully before the certificate request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    Fresh,
    PartInit,
    Finalized,
}

/// Establish the selected state and close the setup session before any lookup.
fn prepare_partition(ctx: &TestCtx, selector: u8) -> Lifecycle {
    let state = match selector % 3 {
        0 => Lifecycle::Fresh,
        1 => Lifecycle::PartInit,
        _ => Lifecycle::Finalized,
    };
    if state == Lifecycle::Fresh {
        return state;
    }

    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    if state == Lifecycle::Finalized {
        common::finalize_partition(ctx, &session);
    } else {
        let pota = CaKey::generate();
        let policy = common::known_good_part_policy(pota.raw_pub());
        ctx.part_init(
            &session,
            &common::mach_seed(),
            &policy,
            &common::pota_thumbprint(),
        )
        .expect("PartInit setup must succeed");
    }
    ctx.session_close(session.session_id)
        .expect("close lifecycle setup session");
    state
}

/// Construct a raw or boundary-biased request without losing either raw field.
fn make_request(input: &FuzzInput, count: u8) -> TborGetCertReq {
    let invalid_slots = [1, 3, u8::MAX];
    let invalid_slot = invalid_slots[usize::from(input.slot_id) % invalid_slots.len()];
    let (slot_id, cert_id) = match input.scenario % 11 {
        0 => (input.slot_id, input.cert_id),
        1 => (0, 0),
        2 => (0, count - 1),
        3 => (0, input.cert_id % count),
        4 => (0, count),
        5 => (0, u8::MAX),
        6 => (2, 0),
        7 => (2, 1 + input.cert_id % u8::MAX),
        8 => (invalid_slot, input.cert_id % count),
        9 => (invalid_slot, u8::MAX),
        _ => {
            let slots = [0, 1, 2, 3, u8::MAX];
            (
                slots[usize::from(input.slot_id) % slots.len()],
                input.cert_id,
            )
        }
    };
    TborGetCertReq::new(slot_id, cert_id)
}

/// Read a known-valid request and validate the complete returned certificate.
fn read_certificate(ctx: &TestCtx, request: &TborGetCertReq, state: Lifecycle) -> TborGetCertResp {
    let response = ctx
        .tbor(request)
        .unwrap_or_else(|err| panic!("valid TborGetCertReq in {state:?} failed: {err:?}"));
    let der = &response.certificate;
    assert!(
        !der.is_empty() && der.len() <= CERT_MAX_LEN,
        "TborGetCertReq in {state:?}: invalid certificate length",
    );
    assert_eq!(
        der[0], 0x30,
        "TborGetCertReq in {state:?}: certificate must be a DER SEQUENCE",
    );
    X509Certificate::from_der(der)
        .unwrap_or_else(|err| panic!("TborGetCertReq in {state:?}: invalid X.509: {err:?}"));
    response
}

/// Assert the independent lookup oracle and slot-specific stability properties.
fn exercise_request(ctx: &TestCtx, request: &TborGetCertReq, count: u8, state: Lifecycle) {
    let expect_success = match request.slot_id {
        0 => request.cert_id < count,
        2 => request.cert_id == 0 && state == Lifecycle::Finalized,
        _ => false,
    };

    if expect_success {
        let response = read_certificate(ctx, request, state);
        if request.slot_id == 0 {
            let mbor = ctx.get_certificate(request.cert_id).unwrap_or_else(|err| {
                panic!(
                    "TborGetCertReq in {state:?} failed: {err:?}"
                )
            });
            assert_eq!(
                response.certificate.as_slice(),
                mbor.data.certificate.as_slice(),
                "TborGetCertReq in {state:?}: TBOR and MBOR disagree",
            );
            let repeated = read_certificate(ctx, request, state);
            assert_eq!(
                response, repeated,
                "TborGetCertReq in {state:?}: slot-0 reads must be stable",
            );
        }
    } else {
        let baseline_request = TborGetCertReq::new(0, 0);
        let before = read_certificate(ctx, &baseline_request, state);
        match ctx.tbor(request) {
            Ok(_response) => {
                panic!("invalid TborGetCertReq in {state:?} unexpectedly succeeded");
            }
            Err(err) => {
                if !matches!(&err, azihsm_ddi_interface::DdiError::TborStatus(status)
                    if *status == TborStatus::InvalidArg)
                {
                    eprintln!("invalid TborGetCertReq in {state:?} returned unexpected error type");
                }
                assertions::assert_fw_rejects(&err, TborStatus::InvalidArg);
            }
        }
        let after = read_certificate(ctx, &baseline_request, state);
        assert_eq!(
            before, after,
            "rejected TborGetCertReq in {state:?} changed the valid slot-0 certificate",
        );
        if request.slot_id == 2 && state == Lifecycle::Finalized {
            read_certificate(ctx, &TborGetCertReq::new(2, 0), state);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let state = prepare_partition(ctx, input.lifecycle);
        let count = ctx
            .tbor(&TborGetCertChainInfoReq::new(0))
            .expect("slot-0 chain metadata must be available")
            .num_certs;
        assert!(count > 0, "slot-0 certificate chain must be nonempty");
        let request = make_request(&input, count);
        exercise_request(ctx, &request, count, state);
    });
});
