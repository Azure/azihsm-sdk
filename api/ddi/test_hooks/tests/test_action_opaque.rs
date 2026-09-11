//! Wire-contract tests for the `TestAction` opaque payload.
//!
//! `TestAction` (DDI op 2004) uses the fixed request shape
//! `{1: action, 2: payload?}`, where `payload` is a byte string carrying the
//! MBOR encoding of the action's own request-info body. These tests exercise
//! that contract end to end on the host — encode a request, decode it back,
//! then re-decode the inner body out of the opaque payload — mirroring exactly
//! what the firmware dispatch does. They need no device, so they run under a
//! plain `cargo test`.

use azihsm_ddi_mbor_codec::MborDecode;
use azihsm_ddi_mbor_codec::MborDecoder;
use azihsm_ddi_mbor_codec::MborEncode;
use azihsm_ddi_mbor_codec::MborEncoder;
use azihsm_ddi_test_hooks::encode_test_action_payload;
use azihsm_ddi_test_hooks::DdiTestAction;
use azihsm_ddi_test_hooks::DdiTestActionCrashReqInfo;
use azihsm_ddi_test_hooks::DdiTestActionCrashType;
use azihsm_ddi_test_hooks::DdiTestActionReq;
use azihsm_ddi_test_hooks::DdiTestActionSocCpuId;

// The workspace pins the codec with `pre_encode`/`post_decode` on, so
// `MborEncoder::new`/`MborDecoder::new` always take this flag. Opaque payloads
// are plain bytes, so no pre/post transform is wanted here.
const NO_TRANSFORM: bool = false;

/// A request carrying an opaque body round-trips: the outer map decodes, and
/// the inner request-info struct re-decodes byte-for-byte out of the payload.
#[test]
fn test_action_opaque_payload_round_trips() {
    let body = DdiTestActionCrashReqInfo {
        crash_type: DdiTestActionCrashType::HardFault,
        cpu_id: DdiTestActionSocCpuId::Hsm,
    };
    let req = DdiTestActionReq {
        action: DdiTestAction::TriggerCrash,
        payload: Some(encode_test_action_payload(&body).expect("encode payload")),
    };

    // Encode the request exactly as the firmware receives it.
    let mut buf = [0u8; 128];
    let mut encoder = MborEncoder::new(&mut buf, NO_TRANSFORM);
    req.mbor_encode(&mut encoder).expect("encode request");
    let len = encoder.position();

    // Decode the outer map back.
    let mut decoder = MborDecoder::new(&buf[..len], NO_TRANSFORM);
    let back = DdiTestActionReq::mbor_decode(&mut decoder).expect("decode request");
    assert_eq!(back.action, DdiTestAction::TriggerCrash);

    // Re-decode the inner body out of the opaque payload — the firmware's step.
    let payload = back.payload.expect("payload present");
    let mut inner = MborDecoder::new(payload.as_slice(), NO_TRANSFORM);
    let body_back = DdiTestActionCrashReqInfo::mbor_decode(&mut inner).expect("decode body");
    assert_eq!(body_back.crash_type, DdiTestActionCrashType::HardFault);
    assert_eq!(body_back.cpu_id, DdiTestActionSocCpuId::Hsm);
}

/// A parameterless action encodes no payload entry and decodes back with
/// `payload == None`, so the firmware sees a bare `{1: action}` map.
#[test]
fn test_action_without_payload_omits_the_field() {
    let req = DdiTestActionReq {
        action: DdiTestAction::ClearUserCredentials,
        payload: None,
    };

    let mut buf = [0u8; 32];
    let mut encoder = MborEncoder::new(&mut buf, NO_TRANSFORM);
    req.mbor_encode(&mut encoder).expect("encode request");
    let len = encoder.position();

    let mut decoder = MborDecoder::new(&buf[..len], NO_TRANSFORM);
    let back = DdiTestActionReq::mbor_decode(&mut decoder).expect("decode request");
    assert_eq!(back.action, DdiTestAction::ClearUserCredentials);
    assert!(back.payload.is_none());
}
