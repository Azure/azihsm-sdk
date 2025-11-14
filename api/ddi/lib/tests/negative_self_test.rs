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
fn trigger_negative_periodic_cast() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            // Read the first parameter from an environment variable
            let test_number = match read_neg_self_test_env_variable("NEGATIVE_CAST_IDENTIFIER") {
                Ok(neg_self_test_number) => neg_self_test_number,
                Err(err) => {
                    tracing::warn!("Invalid environment variable input with err: {:?}", err);
                    return;
                }
            };

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            send_negative_self_test(path.to_string(), test_number);
        },
    );
}

fn read_neg_self_test_env_variable(var_name: &str) -> Result<u32, Box<dyn Error>> {
    // Get the environment variable
    let env_var = env::var(var_name)?;

    // Parse the environment variable as u32
    let value: u32 = env_var.parse()?;

    Ok(value)
}

fn send_negative_self_test(device_path: String, test: u32) {
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

    if !set_test_action(&ddi, device_path.as_str(), DdiTestAction::TriggerIoFailure) {
        println!("Firmware is not built with test_action test_hooks.");
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
        DdiTestAction::ExecuteNegativeSelfTest,
        None,
        Some(test),
        None,
        None,
        None,
        None,
        None,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
}
