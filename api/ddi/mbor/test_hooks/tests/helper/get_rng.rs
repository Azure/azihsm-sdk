// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Suite-private helpers for the `GetRng` integration tests.

use azihsm_ddi::Ddi;
use azihsm_ddi_mbor_test_hooks::helper_get_rng;
use azihsm_ddi_mbor_test_hooks::DdiGetRngCmdResp;
use azihsm_ddi_mbor_types::DdiDeviceKind;

use crate::common::*;

pub(super) fn require_physical_device(dev: &mut <DdiTest as Ddi>::Dev) -> bool {
    if get_device_kind(dev) != DdiDeviceKind::Physical {
        println!("Physical device NOT found. Test only supported on physical device.");
        return false;
    }
    true
}

pub(super) fn retrieve_random(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    rng_len: u8,
) -> Option<DdiGetRngCmdResp> {
    match helper_get_rng(dev, Some(session_id), rng_len) {
        Ok(resp) => {
            assert_eq!(resp.data.rng_number.len(), usize::from(rng_len));
            Some(resp)
        }
        Err(err) if is_unsupported_cmd(&err) => None,
        Err(err) => panic!("Unexpected GetRng error: {err:?}"),
    }
}

pub(super) fn validate_random_output(dev: &<DdiTest as Ddi>::Dev, session_id: u16, rng_len: u8) {
    let Some(first) = retrieve_random(dev, session_id, rng_len) else {
        return;
    };
    let second =
        helper_get_rng(dev, Some(session_id), rng_len).expect("second RNG call must succeed");
    assert_eq!(second.data.rng_number.len(), usize::from(rng_len));
    assert!(
        first.data.rng_number.as_slice() != second.data.rng_number.as_slice(),
        "Successive RNG outputs must differ"
    );
}
