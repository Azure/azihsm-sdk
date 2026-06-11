// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error-shape assertion helpers shared by every TBOR command test.
//!
//! These helpers exist so per-command negative-path tests can express
//! intent at the call site (`assert_fw_rejects(err, TborStatus::…)`)
//! rather than match-arm the same `DdiError` variant tree in every
//! file. They also centralise the encoding of *how* an FW logical
//! error surfaces today — see [`assert_fw_rejects`] — so a future
//! change to that contract only touches this one place.

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::TborStatus;

/// Assert that `err` is a backend-side "this wire encoding is not
/// implemented" rejection. The `mock` backend returns this for every
/// `exec_op_tbor` call (it has not opted into TBOR).
#[track_caller]
pub fn assert_unsupported_encoding(err: &DdiError) {
    assert!(
        matches!(err, DdiError::UnsupportedEncoding),
        "expected DdiError::UnsupportedEncoding, got {err:?}",
    );
}

/// Assert that `err` is a host-side TBOR decode failure (malformed
/// response, schema mismatch, etc.). Distinct from
/// [`assert_fw_rejects`] — a `TborDecodeError` means the FW response
/// was structurally invalid, not that the FW *logically* rejected the
/// request.
#[track_caller]
pub fn assert_tbor_decode_error(err: &DdiError) {
    assert!(
        matches!(err, DdiError::TborDecodeError),
        "expected DdiError::TborDecodeError, got {err:?}",
    );
}

/// Assert that the FW dispatcher logically rejected the request with
/// the given [`TborStatus`] discriminant.
///
/// The TBOR FW dispatcher encodes such rejections via
/// `encode_tbor_err`, which writes the `TborStatus.0` u32 into the
/// response header `status` field. The host-side `decode_response`
/// short-circuits on `status != 0` and the conversion in
/// `azihsm_ddi_interface::error` maps that to
/// [`DdiError::DdiError(status)`]. If the contract ever changes, this
/// is the single site that needs updating.
#[track_caller]
pub fn assert_fw_rejects(err: &DdiError, expected: TborStatus) {
    let expected_code = expected.0;
    match err {
        DdiError::DdiError(code) => assert_eq!(
            *code, expected_code,
            "FW rejected with wrong TborStatus: expected {expected:?} (0x{expected_code:08X}), \
             got 0x{code:08X}",
        ),
        other => panic!(
            "expected DdiError::DdiError(0x{expected_code:08X}) for {expected:?}, got {other:?}",
        ),
    }
}
