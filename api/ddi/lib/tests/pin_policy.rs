// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::thread;
use std::time::Instant;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

const NUM_SECS: u64 = 5 * 60;
// Maximum allowable attempts
const MAX_ALLOWABLE_ATTEMPTS: u16 = 1000;
const EXECUTION_DELAY_IN_SEC: u64 = 2;

pub fn pin_policy_cleanup(
    dev: &mut <DdiTest as Ddi>::Dev,
    ddi: &DdiTest,
    path: &str,
    session_to_close: Option<u16>,
) {
    // Attempt to clear the pin policy for the session
    if let Some(session_id) = session_to_close {
        let resp = helper_test_action_cmd(
            dev,
            session_id,
            DdiTestAction::PinPolicyClear,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        if let Err(err) = resp {
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::UnsupportedCmd)),
                "{:?}",
                err
            );
        }
    }

    common_cleanup(dev, ddi, path, session_to_close);
}

fn test_create_thread<F>(device_path: String, thread_fn: F, expected_error: DdiError)
where
    F: FnOnce(&<DdiTest as Ddi>::Dev, DdiError) + Send + 'static,
{
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    thread_fn(&dev, expected_error);
}

fn open_session_and_assert_failure(dev: &<DdiTest as Ddi>::Dev, expected_error: &DdiError) {
    // Encrypt with alternate cred pin for open session
    let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
        dev,
        TEST_CRED_ID,
        TEST_CRED_PIN_ALT,
        TEST_SESSION_SEED,
    );

    // Check if the device is still locked out
    let resp = helper_open_session(
        dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    );
    assert!(resp.is_err(), "resp {:?}", resp);

    match expected_error {
        DdiError::DdiStatus(DdiStatus::InvalidAppCredentials) => {
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
            ));
        }
        DdiError::DdiStatus(DdiStatus::LoginFailed) => {
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::LoginFailed)
            ));
        }
        _ => {
            panic!("Unexpected error: {:?}", resp);
        }
    }
}

fn open_valid_session(device_path: String) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    // Encrypt with valid cred pin for open session
    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);

    // Open session
    let resp = helper_open_session(
        &dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
}

fn pin_policy_sample_login_availability(
    device_path: String,
    sample_period_in_ms: u64,
    duration: u64,
) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    let start_time = Instant::now();
    let mut count = 0_usize;

    thread::sleep(std::time::Duration::from_millis(sample_period_in_ms));

    while Instant::now().duration_since(start_time).as_secs() < duration {
        if count % 2 == 0 {
            open_session_and_assert_failure(&dev, &DdiError::DdiStatus(DdiStatus::LoginFailed));
        } else {
            open_session_and_assert_failure(
                &dev,
                &DdiError::DdiStatus(DdiStatus::InvalidAppCredentials),
            );
        }

        count += 1;
        thread::sleep(std::time::Duration::from_millis(sample_period_in_ms));
    }

    tracing::debug!("Number of login attempts: {}", count);
}

fn pin_policy_delay_factor_test(
    dev: &mut <DdiTest as Ddi>::Dev,
    path: &str,
    session_id: u16,
    desired_delay_factor_min: u64,
    sample_period_in_ms: u64,
    delay_increment: u64,
    duration: u64,
) {
    if get_device_kind(dev) != DdiDeviceKind::Physical {
        println!("Physical device NOT found. Test only supported on physical device.");
        return;
    }

    // Set the pin policy delay factor increment to 0 while we fast track
    // to the desired delay factor we want to test
    let pin_policy_config = Some(DdiTestActionPinPolicyConfig {
        delay_increment: Some(0),
        state: None,
        delay: None,
        allowed_attempts: None,
        lockout_delay: None,
    });

    let resp = helper_test_action_cmd(
        dev,
        session_id,
        DdiTestAction::PinPolicyOverride,
        None,
        None,
        pin_policy_config,
        None,
        None,
        None,
        None,
    );
    if let Err(err) = resp {
        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::UnsupportedCmd)),
            "{:?}",
            err
        );
    }

    // Fast track to the desired delay factor
    let thread_device_path = path.to_string();
    let thread = thread::spawn(move || {
        test_create_thread(
            thread_device_path,
            move |dev, expected_error| {
                for _ in 0..desired_delay_factor_min * 1000 {
                    open_session_and_assert_failure(dev, &expected_error);
                }
            },
            DdiError::DdiStatus(DdiStatus::InvalidAppCredentials),
        );
    });
    thread.join().unwrap();

    // Set the delay increment to 1 second to test the desired delay factor
    let pin_policy_config = Some(DdiTestActionPinPolicyConfig {
        delay_increment: Some(delay_increment as u16),
        state: None,
        delay: None,
        allowed_attempts: None,
        lockout_delay: None,
    });

    let resp = helper_test_action_cmd(
        dev,
        session_id,
        DdiTestAction::PinPolicyOverride,
        None,
        None,
        pin_policy_config,
        None,
        None,
        None,
        None,
    );
    if let Err(err) = resp {
        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::UnsupportedCmd)),
            "{:?}",
            err
        );
    }

    // Execute testing the desired delay factor
    let thread_device_path = path.to_string();

    let thread = thread::spawn(move || {
        pin_policy_sample_login_availability(thread_device_path, sample_period_in_ms, duration);
    });

    thread.join().unwrap();

    // Reset the lockout time and attempt to login
    let pin_policy_config = Some(DdiTestActionPinPolicyConfig {
        delay_increment: None,
        state: None,
        delay: None,
        allowed_attempts: None,
        lockout_delay: Some(0),
    });

    let resp = helper_test_action_cmd(
        dev,
        session_id,
        DdiTestAction::PinPolicyOverride,
        None,
        None,
        pin_policy_config,
        None,
        None,
        None,
        None,
    );
    if let Err(err) = resp {
        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::UnsupportedCmd)),
            "{:?}",
            err
        );
    }

    // Attempt to login with valid credentials
    let thread_device_path = path.to_string();

    let thread = thread::spawn(move || open_valid_session(thread_device_path));

    thread.join().unwrap();

    // Verify that the pin policy context is back to ready state
    let thread_device_path = path.to_string();

    let thread = thread::spawn(move || {
        test_create_thread(
            thread_device_path,
            move |dev, expected_error| {
                for _ in 0..1000 {
                    open_session_and_assert_failure(dev, &expected_error);
                }
            },
            DdiError::DdiStatus(DdiStatus::InvalidAppCredentials),
        );
    });

    thread.join().unwrap();
}

#[test]
fn test_pin_policy_invalid_pin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            // Encrypt with alternate cred pin for open session
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN_ALT,
                TEST_SESSION_SEED,
            );

            // Open session
            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
            ));
        },
    );
}

#[test]
fn test_pin_policy_failed_auth_then_valid_auth() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, _session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Spawn a thread to fail open session validation for 1000 times to trigger the delay factor increase

            let thread_device_path = path.to_string();

            let thread = thread::spawn(move || {
                test_create_thread(
                    thread_device_path,
                    move |dev, expected_error| {
                        for _ in 0..1000 {
                            open_session_and_assert_failure(dev, &expected_error);
                        }
                    },
                    DdiError::DdiStatus(DdiStatus::InvalidAppCredentials),
                );
            });

            thread.join().unwrap();

            // The pin policy should have incremented the delay factor
            // so the device should be locked out for 1 min

            let thread_device_path = path.to_string();

            let thread = thread::spawn(move || {
                test_create_thread(
                    thread_device_path,
                    move |dev, expected_error| {
                        open_session_and_assert_failure(dev, &expected_error);
                    },
                    DdiError::DdiStatus(DdiStatus::LoginFailed),
                );
            });

            thread.join().unwrap();

            thread::sleep(std::time::Duration::from_secs(60 + EXECUTION_DELAY_IN_SEC));

            let thread_device_path = path.to_string();

            let thread = thread::spawn(move || {
                test_create_thread(
                    thread_device_path,
                    move |dev, expected_error| {
                        open_session_and_assert_failure(dev, &expected_error);
                    },
                    DdiError::DdiStatus(DdiStatus::InvalidAppCredentials),
                );
            });

            thread.join().unwrap();

            // Try a valid open session
            thread::sleep(std::time::Duration::from_secs(60 + EXECUTION_DELAY_IN_SEC));

            let thread_device_path = path.to_string();

            let thread = thread::spawn(move || open_valid_session(thread_device_path));

            thread.join().unwrap();
        },
    );
}

#[test]
fn test_pin_policy_increase_delay_factor() {
    ddi_dev_test(
        common_setup,
        pin_policy_cleanup,
        |dev, _ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Clear the pin policy to make sure we start with a clean slate
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyClear,
                None,
                None,
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

            // Spawn a thread to fail open session validation for 1000 times to trigger the delay factor increase

            let thread_device_path = path.to_string();

            let thread = thread::spawn(move || {
                test_create_thread(
                    thread_device_path,
                    move |dev, expected_error| {
                        for _ in 0..1000 {
                            open_session_and_assert_failure(dev, &expected_error);
                        }
                    },
                    DdiError::DdiStatus(DdiStatus::InvalidAppCredentials),
                );
            });

            thread.join().unwrap();

            // The pin policy should have incremented the delay factor
            // so the device should be locked out for 1 min

            let thread_device_path = path.to_string();

            let thread = thread::spawn(move || {
                test_create_thread(
                    thread_device_path,
                    move |dev, expected_error| {
                        for _ in 0..100 {
                            open_session_and_assert_failure(dev, &expected_error);
                        }
                    },
                    DdiError::DdiStatus(DdiStatus::LoginFailed),
                );
            });

            thread.join().unwrap();

            // Wait for lockout to expire (with a 2 sec buffer)
            thread::sleep(std::time::Duration::from_secs(60 + EXECUTION_DELAY_IN_SEC));

            let thread_device_path = path.to_string();

            let thread = thread::spawn(move || {
                test_create_thread(
                    thread_device_path,
                    move |dev, expected_error| {
                        open_session_and_assert_failure(dev, &expected_error);
                    },
                    DdiError::DdiStatus(DdiStatus::InvalidAppCredentials),
                );
            });

            thread.join().unwrap();
        },
    );
}

#[test]
fn test_pin_policy_delay_factor_rollover() {
    ddi_dev_test(
        common_setup,
        pin_policy_cleanup,
        |dev, _ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Clear the pin policy to make sure we start with a clean slate
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyClear,
                None,
                None,
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

            const ROLLOVER_OFFSET: u16 = 2;

            // Set the pin policy context to be ROLLOVER_OFFSET invalid attempts
            // from delay factor rolling over
            let pin_policy_config = Some(DdiTestActionPinPolicyConfig {
                delay_increment: Some(1),
                state: Some(false),
                delay: Some(32),
                allowed_attempts: Some(MAX_ALLOWABLE_ATTEMPTS - ROLLOVER_OFFSET),
                lockout_delay: Some(0),
            });

            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyOverride,
                None,
                None,
                pin_policy_config,
                None,
                None,
                None,
                None,
            );
            if let Err(err) = resp {
                assert!(
                    matches!(err, DdiError::DdiStatus(DdiStatus::UnsupportedCmd)),
                    "{:?}",
                    err
                );
            }

            // Trigger rollover
            let thread_device_path = path.to_string();
            let thread = thread::spawn(move || {
                test_create_thread(
                    thread_device_path,
                    move |dev, expected_error| {
                        for _ in 0..ROLLOVER_OFFSET {
                            open_session_and_assert_failure(dev, &expected_error);

                            // Sleep for 32 seconds due to the lockout
                            thread::sleep(std::time::Duration::from_secs(
                                32 + EXECUTION_DELAY_IN_SEC,
                            ));
                        }

                        // Make sure that the delay factor is reset to 0; we should have 1000 free attempts
                        for _ in 0..MAX_ALLOWABLE_ATTEMPTS - 1 {
                            open_session_and_assert_failure(dev, &expected_error);
                        }
                    },
                    DdiError::DdiStatus(DdiStatus::InvalidAppCredentials),
                );
            });
            thread.join().unwrap();

            // Use last free attempt to open a valid session
            open_valid_session(path.to_string());
        },
    );
}

#[test]
fn test_pin_policy_delay_factor_1_min_for_idfu_test() {
    ddi_dev_test(
        common_setup,
        pin_policy_cleanup,
        |dev, _ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Clear the pin policy to make sure we start with a clean slate
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyClear,
                None,
                None,
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

            // 10 min test duration
            let duration: u64 = 10 * 60;
            // 2 sec buffer for idfu reset and ddi request latency
            let execution_buffer_in_ms: u64 = 2_000;
            // 1 min sample period
            let sample_period_in_ms: u64 = 60_000;

            // Set the pin policy context to match the conditions of a 1 min delay factor.
            // Since the delay increment override is not persistent across reboots,
            // we can only set the pin policy context.
            // i.e state = lockout, delay = 1 min, allowed attempts = 0,
            let pin_policy_config = Some(DdiTestActionPinPolicyConfig {
                delay_increment: None,
                state: Some(false),
                delay: Some(1),
                allowed_attempts: Some(0),
                lockout_delay: Some(0),
            });

            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyOverride,
                None,
                None,
                pin_policy_config,
                None,
                None,
                None,
                None,
            );
            if let Err(err) = resp {
                assert!(
                    matches!(err, DdiError::DdiStatus(DdiStatus::UnsupportedCmd)),
                    "{:?}",
                    err
                );
            }

            // Execute invalid authorization attempts for the duration of the test
            let thread_device_path = path.to_string();
            let thread = thread::spawn(move || {
                test_create_thread(
                    thread_device_path,
                    move |dev, expected_error| {
                        let start_time = Instant::now();
                        while Instant::now().duration_since(start_time).as_secs() < duration {
                            open_session_and_assert_failure(dev, &expected_error);

                            open_session_and_assert_failure(
                                dev,
                                &DdiError::DdiStatus(DdiStatus::LoginFailed),
                            );

                            thread::sleep(std::time::Duration::from_millis(
                                sample_period_in_ms + execution_buffer_in_ms,
                            ));
                        }
                    },
                    DdiError::DdiStatus(DdiStatus::InvalidAppCredentials),
                );
            });
            thread.join().unwrap();
        },
    );
}

#[test]
fn test_pin_policy_1_delay_factor() {
    ddi_dev_test(
        common_setup,
        pin_policy_cleanup,
        |dev, _ddi, path, session_id| {
            let duration = NUM_SECS;
            let desired_delay_factor_in_min: u64 = 1;
            let execution_buffer_in_ms: u64 = 50;
            let delay_increment_sec: u64 = 1;
            let sample_period_in_ms: u64 =
                desired_delay_factor_in_min * delay_increment_sec * 1000 / 2;

            // Clear the pin policy to make sure we start with a clean slate
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyClear,
                None,
                None,
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

            pin_policy_delay_factor_test(
                dev,
                path,
                session_id,
                desired_delay_factor_in_min,
                sample_period_in_ms + execution_buffer_in_ms,
                delay_increment_sec,
                duration,
            );
        },
    );
}

#[test]
fn test_pin_policy_2_delay_factor() {
    ddi_dev_test(
        common_setup,
        pin_policy_cleanup,
        |dev, _ddi, path, session_id| {
            let duration = NUM_SECS;
            let desired_delay_factor_in_min: u64 = 2;
            let execution_buffer_in_ms: u64 = 50;
            let delay_increment_sec: u64 = 1;
            let sample_period_in_ms: u64 =
                desired_delay_factor_in_min * delay_increment_sec * 1000 / 2;

            // Clear the pin policy to make sure we start with a clean slate
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyClear,
                None,
                None,
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

            pin_policy_delay_factor_test(
                dev,
                path,
                session_id,
                desired_delay_factor_in_min,
                sample_period_in_ms + execution_buffer_in_ms,
                delay_increment_sec,
                duration,
            );
        },
    );
}

#[test]
fn test_pin_policy_8_delay_factor() {
    ddi_dev_test(
        common_setup,
        pin_policy_cleanup,
        |dev, _ddi, path, session_id| {
            let duration = NUM_SECS;
            let desired_delay_factor_in_min: u64 = 8;
            let execution_buffer_in_ms: u64 = 50;
            let delay_increment_sec: u64 = 1;
            let sample_period_in_ms: u64 =
                desired_delay_factor_in_min * delay_increment_sec * 1000 / 2;

            // Clear the pin policy to make sure we start with a clean slate
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyClear,
                None,
                None,
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

            pin_policy_delay_factor_test(
                dev,
                path,
                session_id,
                desired_delay_factor_in_min,
                sample_period_in_ms + execution_buffer_in_ms,
                delay_increment_sec,
                duration,
            );
        },
    );
}

#[test]
fn test_pin_policy_16_delay_factor() {
    ddi_dev_test(
        common_setup,
        pin_policy_cleanup,
        |dev, _ddi, path, session_id| {
            let duration = NUM_SECS;
            let desired_delay_factor_in_min: u64 = 16;
            let execution_buffer_in_ms: u64 = 50;
            let delay_increment_sec: u64 = 1;
            let sample_period_in_ms: u64 =
                desired_delay_factor_in_min * delay_increment_sec * 1000 / 2;

            // Clear the pin policy to make sure we start with a clean slate
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyClear,
                None,
                None,
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

            pin_policy_delay_factor_test(
                dev,
                path,
                session_id,
                desired_delay_factor_in_min,
                sample_period_in_ms + execution_buffer_in_ms,
                delay_increment_sec,
                duration,
            );
        },
    );
}

#[test]
fn test_pin_policy_32_delay_factor() {
    ddi_dev_test(
        common_setup,
        pin_policy_cleanup,
        |dev, _ddi, path, session_id| {
            let duration = NUM_SECS;
            let desired_delay_factor_in_min: u64 = 32;
            let execution_buffer_in_ms: u64 = 50;
            let delay_increment_sec: u64 = 1;
            let sample_period_in_ms: u64 =
                desired_delay_factor_in_min * delay_increment_sec * 1000 / 2;

            // Clear the pin policy to make sure we start with a clean slate
            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::PinPolicyClear,
                None,
                None,
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

            pin_policy_delay_factor_test(
                dev,
                path,
                session_id,
                desired_delay_factor_in_min,
                sample_period_in_ms + execution_buffer_in_ms,
                delay_increment_sec,
                duration,
            );
        },
    );
}
