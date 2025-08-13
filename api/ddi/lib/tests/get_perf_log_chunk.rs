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
            let req = DdiGetPerfLogChunkCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetPerfLogChunk,
                    sess_id: None,
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetPerfLogChunkReq { chunk_id: 0 },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

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
            let req = DdiGetPerfLogChunkCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetPerfLogChunk,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetPerfLogChunkReq { chunk_id: 0 },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

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

            let req = DdiGetPerfLogChunkCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetPerfLogChunk,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetPerfLogChunkReq { chunk_id: 0 },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}
