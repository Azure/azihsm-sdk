// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SetSealedBk3 / GetSealedBk3 smoke tests for the emu/mock backend.

#![cfg(any(feature = "emu", feature = "mock"))]
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

fn ensure_bk3_provisioned(dev: &<DdiTest as Ddi>::Dev) {
    match helper_init_bk3(dev, vec![0u8; 48]) {
        Ok(_) | Err(DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized)) => {}
        Err(err) => panic!("InitBk3 must provision BK3 or report it already initialized: {err:?}"),
    }
}

#[test]
fn test_set_then_get_sealed_bk3() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        ensure_bk3_provisioned(dev);
        let blob: Vec<u8> = (10..73u8).collect();

        let set_resp = helper_set_sealed_bk3(dev, blob.clone()).unwrap();
        assert_eq!(set_resp.hdr.op, DdiOp::SetSealedBk3);
        assert_eq!(set_resp.hdr.status, DdiStatus::Success);

        let get_resp = helper_get_sealed_bk3(dev).unwrap();
        assert_eq!(get_resp.hdr.op, DdiOp::GetSealedBk3);
        assert_eq!(get_resp.data.sealed_bk3.as_slice(), blob.as_slice());
    });
}

#[test]
fn test_set_sealed_bk3_twice_fails() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        ensure_bk3_provisioned(dev);
        let blob: Vec<u8> = (10..73u8).collect();

        let set_resp = helper_set_sealed_bk3(dev, blob.clone()).unwrap();
        assert_eq!(set_resp.hdr.status, DdiStatus::Success);

        let err = helper_set_sealed_bk3(dev, blob).unwrap_err();
        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet)),
            "expected SealedBk3AlreadySet, got {:?}",
            err
        );
    });
}

#[test]
fn test_get_sealed_bk3_before_set_fails() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        ensure_bk3_provisioned(dev);
        let err = helper_get_sealed_bk3(dev).unwrap_err();
        assert!(matches!(
            err,
            DdiError::DdiStatus(DdiStatus::SealedBk3NotPresent)
        ));
    });
}
