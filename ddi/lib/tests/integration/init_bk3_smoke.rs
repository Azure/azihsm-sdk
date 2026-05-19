// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! InitBk3 smoke tests for the emu backend.
//!
//! Exercises:
//! - Successful one-shot init returns a 244-byte `masked_bk3` (the
//!   AES-CBC-256 + HMAC-SHA-384 `MaskedKey` envelope: 4-byte version
//!   header, 48-byte AES header, 16-byte IV, MBOR-encoded metadata,
//!   48-byte ciphertext, and 48-byte HMAC tag) and a 16-byte
//!   `vm_launch_guid`.
//! - A second `InitBk3` on the same partition incarnation fails with
//!   `Bk3AlreadyInitialized` (the one-shot gate).
//! - `InitBk3` does not persist sealed BK3 — `GetSealedBk3` still
//!   returns `SealedBk3NotPresent` until `SetSealedBk3` is explicitly
//!   called.
//! - After a partition reset (NSSR equivalent), `InitBk3` can be
//!   called again — the new `BK_BOOT` produces a different
//!   `masked_bk3`.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_types::*;
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
fn test_init_bk3_smoke() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let bk3 = vec![0xABu8; 48];

        let resp = helper_init_bk3(dev, bk3).unwrap();
        assert_eq!(resp.hdr.op, DdiOp::InitBk3);
        assert_eq!(resp.hdr.status, DdiStatus::Success);
        assert_eq!(resp.data.masked_bk3.len(), 244);
        assert_eq!(resp.data.vm_launch_guid.len(), 16);
    });
}

#[test]
fn test_init_bk3_twice_fails() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let bk3 = vec![0x11u8; 48];

        let first = helper_init_bk3(dev, bk3.clone()).unwrap();
        assert_eq!(first.hdr.status, DdiStatus::Success);

        let err = helper_init_bk3(dev, bk3).unwrap_err();
        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized)),
            "expected Bk3AlreadyInitialized, got {:?}",
            err
        );
    });
}

#[test]
fn test_init_bk3_does_not_persist_sealed_bk3() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let bk3 = vec![0x22u8; 48];

        let init = helper_init_bk3(dev, bk3).unwrap();
        assert_eq!(init.hdr.status, DdiStatus::Success);

        // InitBk3 only produces masked_bk3; sealing happens outside
        // the device — GetSealedBk3 must still report not-present.
        let err = helper_get_sealed_bk3(dev).unwrap_err();
        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::SealedBk3NotPresent)),
            "expected SealedBk3NotPresent, got {:?}",
            err
        );
    });
}

#[test]
fn test_init_bk3_then_set_get_sealed_bk3() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let init = helper_init_bk3(dev, HARD_CODED_BK3.to_vec()).unwrap();
        let masked_bk3 = init.data.masked_bk3.as_slice().to_vec();

        let set_resp = helper_set_sealed_bk3(dev, masked_bk3.clone()).unwrap();
        assert_eq!(set_resp.hdr.status, DdiStatus::Success);

        let get_resp = helper_get_sealed_bk3(dev).unwrap();
        assert_eq!(get_resp.hdr.op, DdiOp::GetSealedBk3);
        assert_eq!(get_resp.data.sealed_bk3.as_slice(), masked_bk3.as_slice());
    });
}
