// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the `GetPrivKey` FIPS-validation hook
//! (`DdiOp` 2005).
//!
//! These generate a key on the device and read its private material back
//! with `GetPrivKey`. They only run on a physical device whose firmware
//! is built with `fips_validation_hooks`; otherwise they skip.
//!
//! Requires the `helpers` feature for the host send helpers.

#![cfg(feature = "helpers")]
#![allow(clippy::unwrap_used)]

mod common;

use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_types::DdiApiRev;
use azihsm_ddi_mbor_types::DdiDeviceKind;
use azihsm_ddi_mbor_types::DdiEccCurve;
use azihsm_ddi_mbor_types::DdiKeyUsage;
use azihsm_ddi_mbor_types::DdiStatus;
use azihsm_ddi_test_hooks::helper_get_priv_key;
use common::*;
use test_with_tracing::test;

#[test]
fn test_ecc_get_privkey_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (private_key_id, _pub_key, _) = ecc_gen_key_mcr(
                dev,
                DdiEccCurve::P256,
                None,
                Some(session_id),
                DdiKeyUsage::SignVerify,
            );

            let resp = helper_get_priv_key(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "Expected FileHandleSessionIdDoesNotMatch error, got {:?}",
                resp
            );
        },
    );
}
