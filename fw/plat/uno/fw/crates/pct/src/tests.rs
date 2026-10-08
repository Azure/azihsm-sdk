// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host tests for the helpers that need no PAL.

use azihsm_fw_hsm_pal_traits::HsmError;

use super::*;

#[test]
fn ct_eq_compares_whole_strings() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
}

#[test]
fn agreement_result_fails_an_invalid_public_key() {
    for err in [
        HsmError::EccPublicKeyValidationFailed,
        HsmError::EccPointValidationFailed,
    ] {
        assert_eq!(ecc::agreement_result(Err(err), true), Ok(false));
    }
    assert_eq!(
        ecc::agreement_result(Err(HsmError::NotEnoughSpace), false),
        Err(HsmError::NotEnoughSpace)
    );
    assert_eq!(ecc::agreement_result(Ok(()), true), Ok(true));
    assert_eq!(ecc::agreement_result(Ok(()), false), Ok(false));
}

#[test]
fn round_trip_result_fails_an_invalid_input() {
    assert_eq!(
        rsa::round_trip_result(Err(HsmError::InvalidArg), true),
        Ok(false)
    );
    assert_eq!(
        rsa::round_trip_result(Err(HsmError::NotEnoughSpace), false),
        Err(HsmError::NotEnoughSpace)
    );
    assert_eq!(rsa::round_trip_result(Ok(()), true), Ok(true));
    assert_eq!(rsa::round_trip_result(Ok(()), false), Ok(false));
}
