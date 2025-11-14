// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_ecc_generate_with_fixed_engine_instance() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Force the PKA instance to a fixed instance ID
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::ForcePkaInstance,
                None,
                None,
                None,
                Some(0),
                None,
                None,
                None,
            );

            match resp {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("fips_validation_hooks not enabled in the device firmware");
                    return;
                }
                Err(_) => {
                    panic!("Unexpected error {:?}", resp);
                }
                Ok(_) => (),
            }

            {
                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
                let resp = helper_ecc_generate_key_pair(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    DdiEccCurve::P256,
                    None,
                    key_props,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.data.pub_key.is_some());
            }

            {
                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
                let resp = helper_ecc_generate_key_pair(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    DdiEccCurve::P384,
                    None,
                    key_props,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.data.pub_key.is_some());
            }

            {
                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
                let resp = helper_ecc_generate_key_pair(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    DdiEccCurve::P521,
                    None,
                    key_props,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.data.pub_key.is_some());
            }

            // Release the force PKA instance allocation
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::ForcePkaInstance,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );
            match resp {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("fips_validation_hooks not enabled in the device firmware")
                }
                Err(_) => {
                    panic!("Unexpected error {:?}", resp)
                }
                Ok(_) => (),
            }
        },
    );
}
