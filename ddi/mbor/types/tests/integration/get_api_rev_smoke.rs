// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GetApiRev smoke tests for the emu backend.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn setup(_dev: &mut <DdiTest as Ddi>::Dev, _ddi: &DdiTest, _path: &str) -> u16 {
    0
}

pub fn cleanup(
    _dev: &mut <DdiTest as Ddi>::Dev,
    _ddi: &DdiTest,
    _path: &str,
    _setup_session_id: Option<u16>,
) {
}

#[test]
fn test_get_api_rev() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let resp = helper_get_api_rev(dev, None, None).unwrap();

        assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
        assert!(resp.hdr.rev.is_none());
        assert!(resp.hdr.sess_id.is_none());
        assert_eq!(resp.hdr.status, DdiStatus::Success);

        assert!(resp.data.min.major <= resp.data.max.major);

        if resp.data.min.major == resp.data.max.major {
            assert!(resp.data.min.minor <= resp.data.max.minor);
        }

        assert_eq!(resp.data.min.major, 1);
        assert_eq!(resp.data.min.minor, 0);
        assert_eq!(resp.data.max.major, 1);
        assert_eq!(resp.data.max.minor, 0);
    });
}

#[test]
fn test_get_api_rev_with_invalid_session() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let resp = helper_get_api_rev(dev, Some(0x50), None);

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::InvalidArg)
        ));
    });
}

#[test]
fn test_get_api_rev_with_invalid_rev() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let resp = helper_get_api_rev(dev, None, Some(DdiApiRev { major: 1, minor: 0 }));

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::UnsupportedRevision)
        ));
    });
}
