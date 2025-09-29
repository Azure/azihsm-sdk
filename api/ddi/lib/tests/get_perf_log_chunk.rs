// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_get_perf_log_chunk_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let resp =
                helper_get_perf_log_chunk(dev, None, Some(DdiApiRev { major: 1, minor: 0 }), 0);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_get_perf_log_chunk_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let session_id = 20;
            let resp = helper_get_perf_log_chunk(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_get_perf_log_chunk() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) == DdiDeviceKind::Physical {
                println!("Physical device found. Test not supported on Physical device yet.");
                return;
            }

            let resp = helper_get_perf_log_chunk(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}
