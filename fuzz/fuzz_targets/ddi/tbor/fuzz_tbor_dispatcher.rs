// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::KEY_USAGE_DERIVE;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const KEY_SCOPE_SESSION: u8 = 0b001;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Use arbitrary bytes as the request label instead of the numeric seed.
    use_rand_data: bool,
    /// Arbitrary request bytes; TBOR's typed API cannot dispatch a raw frame,
    /// so these bytes are carried in the command's key-label field.
    rand_data: Vec<u8>,
    /// Seed used to create request data when `use_rand_data` is false.
    request_seed: u64,
    /// Session identifier supplied in place of the original MBOR request
    /// header's session id.
    request_header: FuzzRequestHeader,
    /// Whether the command parameters should describe a valid request.
    valid_request: bool,
    /// Selects which one field is made invalid when `valid_request` is false.
    invalid_field: InvalidField,
    /// Valid curve choice used when constructing a valid request.
    curve: common::EccCurve,
    /// Fuzzed usage value used for invalid usage requests.
    key_usage: u64,
}

#[derive(Arbitrary, Debug)]
struct FuzzRequestHeader {
    session_id: u16,
}

#[derive(Arbitrary, Debug)]
enum InvalidField {
    SessionId,
    Scope,
    Curve,
    KeyUsage,
    KeyLabel,
}

fn request_label(input: &FuzzInput) -> Vec<u8> {
    let mut label = if input.use_rand_data {
        input.rand_data.clone()
    } else {
        input.request_seed.to_le_bytes().to_vec()
    };
    label.truncate(TBOR_KEY_LABEL_MAX_LEN);
    label
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        // A rotated CO session exercises the authenticated, in-session command
        // path and leaves the per-session masking key ready for key generation.
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let label = request_label(&input);

        let mut req = TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: KEY_SCOPE_SESSION,
            curve: input.curve.to_tbor(),
            key_usage: KEY_USAGE_SIGN,
            key_label: label,
        };

        if !input.valid_request {
            match input.invalid_field {
                InvalidField::SessionId => {
                    req.session_id = if input.request_header.session_id == session.session_id {
                        session.session_id.wrapping_add(1)
                    } else {
                        input.request_header.session_id
                    };
                }
                InvalidField::Scope => req.scope = 0xff,
                InvalidField::Curve => req.curve = 0xff,
                InvalidField::KeyUsage => {
                    req.key_usage = match input.key_usage {
                        KEY_USAGE_SIGN | KEY_USAGE_DERIVE => 0,
                        invalid => invalid,
                    };
                }
                InvalidField::KeyLabel => {
                    req.key_label = vec![0xA5; TBOR_KEY_LABEL_MAX_LEN + 1];
                }
            }
        }

        let result = ctx.tbor(&req);
        if input.valid_request {
            let resp = result.expect("valid EccGenerateKey request should succeed");
            let wire_coord_len = match req.curve {
                ECC_CURVE_P256 => 32,
                ECC_CURVE_P384 => 48,
                ECC_CURVE_P521 => 68,
                _ => unreachable!("valid request uses a supported curve"),
            };
            assert_eq!(resp.pub_key.len(), wire_coord_len * 2);
            assert_eq!(resp.masked_key.len(), 228 + wire_coord_len);
            assert!(resp.pub_key.iter().any(|byte| *byte != 0));
            assert!(resp.masked_key.iter().any(|byte| *byte != 0));
        } else {
            match result {
                Err(err @ azihsm_ddi_interface::DdiError::DriverError(_)) => {
                    panic!("Crash Detected: {err}")
                }
                Err(_) => {}
                Ok(_) => panic!("invalid EccGenerateKey request unexpectedly succeeded"),
            }
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
