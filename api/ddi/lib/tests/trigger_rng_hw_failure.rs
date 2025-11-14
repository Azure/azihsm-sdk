// Copyright (C) Microsoft Corporation. All rights reserved.

// Import the macro from the self_test module
mod common;

use std::env;
use std::error::Error;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn trigger_rng_hw_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            // Read the first parameter from an environment variable
            let rng_test_id =
                match read_rng_hw_failure_test_env_variable("RNG_HW_FAILURE_TEST_NUMBER") {
                    Ok(test_number) => test_number,
                    Err(err) => {
                        tracing::debug!("Invalid environment variable input with err: {:?}", err);
                        return;
                    }
                };

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            send_rng_hw_failure_request(path.to_string(), rng_test_id);
        },
    );
}

fn read_rng_hw_failure_test_env_variable(var_name: &str) -> Result<u32, Box<dyn Error>> {
    // Get the environment variable
    let env_var = env::var(var_name)?;

    // Parse the environment variable as u32
    let value: u32 = env_var.parse()?;

    Ok(value)
}

fn is_unsupported_cmd(err: &DdiError) -> bool {
    if let DdiError::DdiStatus(DdiStatus::UnsupportedCmd) = err {
        println!("Firmware is not built with fips_validation_hooks.");
        true
    } else {
        false
    }
}

fn send_rng_hw_failure_request(device_path: String, test: u32) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    tracing::debug!("Send negative self test {:?}", test);

    if get_device_kind(&mut dev) == DdiDeviceKind::Virtual {
        tracing::debug!(
            "Periodic Self Test is only support in Physical platform. Skipping the test..."
        );
        return;
    }

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);

    let resp = helper_open_session(
        &dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    );
    assert!(resp.is_ok(), "{:?}", resp);

    let resp = resp.unwrap();
    let vault_manager_sess_id = resp.data.sess_id;

    let resp = helper_test_action_cmd(
        &mut dev,
        vault_manager_sess_id,
        DdiTestAction::TriggerRngHwFailure,
        None,
        Some(test),
        None,
        None,
        None,
        None,
        None,
    );

    if let Err(err) = &resp {
        if is_unsupported_cmd(err) {
            return;
        }
    }

    assert!(resp.is_ok(), "resp {:?}", resp);
}
