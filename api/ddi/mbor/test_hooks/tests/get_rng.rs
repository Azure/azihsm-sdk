// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the `TestAction::GetRng` FIPS-validation hook.
//!
//! These require a physical device built with `fips_validation_hooks`.
//! Non-physical devices and unsupported actions skip, like the other
//! FIPS-validation suites. Random payloads are never printed.

#![allow(clippy::unwrap_used)]

mod common;
#[path = "helper/get_rng.rs"]
mod helper;

use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_test_hooks::helper_get_rng;
use azihsm_ddi_mbor_types::DdiStatus;
use common::*;
use helper::*;
use test_with_tracing::test;

#[test]
fn test_get_rng_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }
            let resp = helper_get_rng(dev, Some(session_id ^ 1), 32);
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch
                ))
            ));
        },
    );
}

#[test]
fn test_get_rng_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            if !require_physical_device(dev) {
                return;
            }
            let resp = helper_get_rng(dev, None, 32);
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch
                ))
            ));
        },
    );
}

#[test]
fn test_get_rng_smaller_than_max() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }
            validate_random_output(dev, session_id, 32);
        },
    );
}

#[test]
fn test_get_rng_equal_to_max() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }
            validate_random_output(dev, session_id, 64);
        },
    );
}

#[test]
fn test_get_rng_greater_than_max() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }
            if retrieve_random(dev, session_id, 32).is_none() {
                return;
            }
            let resp = helper_get_rng(dev, Some(session_id), 65);
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::InvalidArg))
            ));
        },
    );
}

#[test]
fn test_get_rng_boundary_lengths() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }
            for rng_len in [0, 1, 3, 63] {
                if retrieve_random(dev, session_id, rng_len).is_none() {
                    return;
                }
            }
        },
    );
}

#[test]
fn test_get_rng_max_u8_rejected() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }
            if retrieve_random(dev, session_id, 32).is_none() {
                return;
            }
            let resp = helper_get_rng(dev, Some(session_id), u8::MAX);
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::InvalidArg))
            ));
        },
    );
}
