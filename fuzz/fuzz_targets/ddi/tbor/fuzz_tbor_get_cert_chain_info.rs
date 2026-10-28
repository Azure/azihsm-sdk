// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exercise certificate-chain metadata across partition lifecycle states.
//!
//! Slot 0 is stable and agrees with MBOR. Slot 2 generates a fresh PID leaf
//! only after finalization, so its thumbprint is not compared across reads.
//! Malformed bodies retain a valid envelope to reach firmware schema checks.

#![no_main]

#[path = "../../common.rs"]
mod common;

use arbitrary::*;
use azihsm_ddi_tbor_codec::*;
use azihsm_ddi_tbor_test_harness::x509_fixture::*;
use azihsm_ddi_tbor_test_harness::*;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::*;

/// Three independent bytes keep lifecycle and request scenarios easy to mutate.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Forwarded unchanged in raw mode, or used to select an invalid boundary.
    slot_id: u8,
    /// Modulo three selects fresh, initializing, or initialized state.
    lifecycle: u8,
    /// Modulo seven selects four typed scenarios or three malformed bodies.
    scenario: u8,
}

/// State established successfully before issuing any metadata requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    Fresh,
    Initializing,
    Initialized,
}

/// Controlled schema violations with valid protocol and sessionless framing.
#[derive(Debug)]
enum MalformedRequest {
    /// The mandatory scalar is absent, represented by a `None` TOC entry.
    MissingSlot,
    /// A present slot uses `Uint16`, not the required `Uint8`.
    WrongType(u8),
    /// The firmware schema requires exactly one TOC entry, not two.
    ExtraEntry(u8),
}

impl TborOpReq for MalformedRequest {
    const OPCODE: u8 = TBOR_OP_GET_CERT_CHAIN_INFO;
    type OpResp = TborGetCertChainInfoResp;

    /// Encode a valid envelope whose body violates one firmware schema rule.
    fn encode_request<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8], EncodeError> {
        let encoder = RequestEncoder::new(buf, PROTOCOL_VERSION, Self::OPCODE);
        match self {
            Self::MissingSlot => encoder.none()?.finish(),
            Self::WrongType(slot_id) => encoder.uint16(u16::from(*slot_id))?.finish(),
            Self::ExtraEntry(slot_id) => encoder.uint8(*slot_id)?.uint8(*slot_id)?.finish(),
        }
    }
}

/// Independent oracle computed from the request shape and established state.
#[derive(Clone, Copy, Debug)]
enum Expected {
    Success(u8),
    Reject(TborStatus),
}

/// Establish the selected lifecycle and close its provisioning session.
fn prepare_partition(ctx: &TestCtx, selector: u8) -> Lifecycle {
    let state = match selector % 3 {
        0 => Lifecycle::Fresh,
        1 => Lifecycle::Initializing,
        _ => Lifecycle::Initialized,
    };
    if state == Lifecycle::Fresh {
        return state;
    }

    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    if state == Lifecycle::Initialized {
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

/// Read stable slot-0 metadata and cross-check it against the MBOR path.
fn read_slot_zero(ctx: &TestCtx) -> TborGetCertChainInfoResp {
    let response = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("sessionless slot-0 metadata must be available");
    validate_metadata(&response);
    let mbor = ctx.cert_chain_info().expect("MBOR slot-0 metadata");
    assert_eq!(
        response.num_certs, mbor.data.num_certs,
        "TBOR and MBOR certificate counts disagree",
    );
    assert_eq!(
        response.thumbprint.as_slice(),
        mbor.data.thumbprint.as_slice(),
        "TBOR and MBOR chain thumbprints disagree",
    );
    response
}

/// Validate metadata content without assuming a particular chain fingerprint.
fn validate_metadata(response: &TborGetCertChainInfoResp) {
    assert!(response.num_certs > 0, "certificate chain must be nonempty");
    assert_eq!(response.thumbprint.len(), CERT_THUMBPRINT_LEN);
    assert!(
        response.thumbprint.iter().any(|&byte| byte != 0),
        "certificate thumbprint must be materialized",
    );
}

/// Enforce the precomputed oracle, rejecting transport and unexpected errors.
fn exercise_request<R: TborOpReq<OpResp = TborGetCertChainInfoResp> + core::fmt::Debug>(
    ctx: &TestCtx,
    request: &R,
    expected: Expected,
    state: Lifecycle,
    baseline: &TborGetCertChainInfoResp,
) {
    match expected {
        Expected::Reject(status) => {
            ctx.expect_fw_reject(request, status);
        }
        Expected::Success(slot_id) => {
            let response = ctx
                .tbor(request)
                .unwrap_or_else(|err| panic!("valid TborGetCertChainInfoReq in {state:?} failed: {err:?}"));
            validate_metadata(&response);
            if slot_id == 0 {
                assert_eq!(
                    &response, baseline,
                    "slot-0 metadata must be stable in {state:?}",
                );
            } else {
                assert_eq!(
                    response.num_certs, 1,
                    "slot 2 must report exactly one freshly generated PID leaf",
                );
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let state = prepare_partition(ctx, input.lifecycle);
        let baseline = read_slot_zero(ctx);
        match input.scenario % 7 {
            scenario @ 0..=3 => {
                let slot_id = match scenario {
                    0 => input.slot_id,
                    1 => 0,
                    2 => 2,
                    _ => {
                        let boundaries = [1, 3, 127, 254, u8::MAX];
                        boundaries[usize::from(input.slot_id) % boundaries.len()]
                    }
                };
                let expected = match slot_id {
                    0 => Expected::Success(0),
                    2 if state == Lifecycle::Initialized => Expected::Success(2),
                    _ => Expected::Reject(TborStatus::InvalidArg),
                };
                exercise_request(
                    ctx,
                    &TborGetCertChainInfoReq::new(slot_id),
                    expected,
                    state,
                    &baseline,
                );
            }
            scenario => {
                let (request, status) = match scenario {
                    4 => (
                        MalformedRequest::MissingSlot,
                        TborStatus::TborUnexpectedTocType,
                    ),
                    5 => (
                        MalformedRequest::WrongType(input.slot_id),
                        TborStatus::TborUnexpectedTocType,
                    ),
                    _ => (
                        MalformedRequest::ExtraEntry(input.slot_id),
                        TborStatus::TborMessageTruncated,
                    ),
                };
                exercise_request(ctx, &request, Expected::Reject(status), state, &baseline);
            }
        }
        let after = read_slot_zero(ctx);
        assert_eq!(
            baseline, after,
            "{input:?} in {state:?} changed stable slot-0 metadata",
        );
    });
});
