// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for TBOR `GetApiRev`.
//!
//! `round_trip_emu` exercises the full path host → emu backend → fw
//! `handle_tbor_op` → response. `unsupported_on_mock` asserts the
//! design contract that backends opt in to TBOR.
//!
//! Both tests need a real backend handle, so the module is entirely
//! gated on at least one backend feature being enabled. Without that
//! gate, `open_dev` and the `azihsm_ddi` re-exports become dead code
//! that trips `-D warnings`.

#![cfg(any(feature = "emu", feature = "mock"))]

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;

fn open_dev() -> <AzihsmDdi as Ddi>::Dev {
    let ddi = AzihsmDdi::default();
    let infos = ddi.dev_info_list();
    let info = infos.first().expect("backend should advertise a device");
    ddi.open_dev(&info.path).expect("open test backend device")
}

#[cfg(feature = "emu")]
#[test]
fn round_trip_emu() {
    use azihsm_ddi_tbor_test_helpers::helper_get_api_rev_tbor;
    use azihsm_ddi_tbor_types::TborGetApiRevResp;

    let dev = open_dev();
    let resp = helper_get_api_rev_tbor(&dev).expect("TBOR GetApiRev round-trip");
    assert_eq!(
        resp,
        TborGetApiRevResp {
            min_protocol_version: 1,
            max_protocol_version: 1,
        },
        "firmware should report min=max=1 for the bootstrap TBOR protocol version",
    );
}

#[cfg(all(feature = "mock", not(feature = "emu")))]
#[test]
fn unsupported_on_mock() {
    use azihsm_ddi_interface::DdiError;
    use azihsm_ddi_tbor_test_helpers::helper_get_api_rev_tbor;

    let dev = open_dev();
    let err =
        helper_get_api_rev_tbor(&dev).expect_err("mock backend must not implement exec_op_tbor");
    assert!(
        matches!(err, DdiError::UnsupportedEncoding),
        "expected DdiError::UnsupportedEncoding, got {err:?}",
    );
}
