// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_get_rng_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let resp = helper_get_rng(dev, Some(0x5), Some(DdiApiRev { major: 1, minor: 0 }), 32u8);

            // Validate error for incorrect session.
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

#[test]
fn test_get_rng_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let resp = helper_get_rng(dev, None, Some(DdiApiRev { major: 1, minor: 0 }), 32u8);

            // Validate error for no session.
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

#[test]
fn test_get_rng_smaller_than_max() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rng_len = 32u8;

            let resp_1 = helper_get_rng(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                rng_len,
            );

            if let Err(err) = &resp_1 {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp_1 = resp_1.unwrap();
            let resp_1 = resp_1.data;

            // Check the response
            assert_eq!(resp_1.rng_number.len(), rng_len as usize);

            // Get the second random number
            let resp_2 = helper_get_rng(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                rng_len,
            );
            // Extract the response
            let resp_2 = resp_2.unwrap();
            let resp_2 = resp_2.data;

            // Check the response
            assert_eq!(resp_2.rng_number.len(), rng_len as usize);

            // Verify both random numbers are different
            assert_ne!(resp_1.rng_number, resp_2.rng_number);
        },
    );
}

#[test]
fn test_get_rng_equal_to_max() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rng_len = 64u8;

            let resp_1 = helper_get_rng(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                rng_len,
            );
            // Get the first random number

            if let Err(err) = &resp_1 {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp_1 = resp_1.unwrap();
            let resp_1 = resp_1.data;

            // Check the response
            assert_eq!(resp_1.rng_number.len(), rng_len as usize);

            // Get the second random number
            let resp_2 = helper_get_rng(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                rng_len,
            );
            // Extract the response
            let resp_2 = resp_2.unwrap();
            let resp_2 = resp_2.data;

            // Check the response
            assert_eq!(resp_2.rng_number.len(), rng_len as usize);

            // Verify both random numbers are different
            assert_ne!(resp_1.rng_number, resp_2.rng_number);
        },
    );
}

#[test]
fn test_get_rng_greater_than_max() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rng_len = 65u8;

            let resp = helper_get_rng(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                rng_len,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));
        },
    );
}
