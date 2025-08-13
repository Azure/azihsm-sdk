// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

fn create_get_rng_request(session_id: Option<u16>, rng_len: u8) -> DdiGetRngGenerateCmdReq {
    DdiGetRngGenerateCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetRandomNumber,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetRngGenerateReq { rng_len },
        ext: None,
    }
}

#[test]
fn test_get_rng_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let req = create_get_rng_request(Some(0x5), 32u8);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

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
            let req = create_get_rng_request(None, 32u8);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

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

            let req = create_get_rng_request(Some(session_id), rng_len);
            let mut cookie = None;

            // Get the first random number
            let resp_1 = dev.exec_op(&req, &mut cookie);

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
            let resp_2 = dev.exec_op(&req, &mut cookie);

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

            let req = create_get_rng_request(Some(session_id), rng_len);
            let mut cookie = None;

            // Get the first random number
            let resp_1 = dev.exec_op(&req, &mut cookie);

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
            let resp_2 = dev.exec_op(&req, &mut cookie);

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

            let req = create_get_rng_request(Some(session_id), rng_len);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

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
