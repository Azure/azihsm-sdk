// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crash-injection / recovery integration tests, driven through the opaque
//! `TestAction` payload path.
//!
//! Each test opens a session, injects a crash into a named SoC core with
//! [`DdiTestAction::TriggerCrash`] — whose parameters travel as the opaque
//! [`DdiTestActionCrashReqInfo`] body inside the `TestAction` payload — then
//! waits for the firmware and driver to recover and confirms the device is
//! healthy again (close the crashed session, re-provision, re-open, and read
//! the API revision).
//!
//! This mirrors `~/Martichoras/api/ddi/test_hooks/tests/crash_recovery.rs`,
//! adapted to this crate's harness (`resp.hdr.sess_id`,
//! `helper_common_establish_credential_no_unwrap`, `get_device_kind`).
//!
//! Behaviour on this firmware:
//! - Requires a **physical** device — virtual/mock devices are skipped.
//! - Requires firmware built with `mcr_test_hooks`; otherwise `TriggerCrash`
//!   returns [`DdiStatus::UnsupportedCmd`] and the case is skipped.
//! - CP1 firmware currently only implements crashing the **HSM** core; a
//!   request naming another core returns `UnsupportedCmd`, so those cases
//!   skip until the cross-core crash path exists. They are kept here so the
//!   suite documents the full intended matrix.

#![cfg(feature = "helpers")]
#![allow(clippy::unwrap_used)]

mod common;

use std::thread;
use std::time::Duration;

use azihsm_ddi::*;
use azihsm_ddi_mbor_test_hooks::helper_test_action_cmd;
use azihsm_ddi_mbor_test_hooks::DdiTestActionCrashReqInfo;
use azihsm_ddi_mbor_test_hooks::DdiTestActionCrashType;
use azihsm_ddi_mbor_test_hooks::DdiTestActionSocCpuId;
use azihsm_ddi_mbor_test_hooks::TestActionRequest;
use azihsm_ddi_mbor_types::*;
use common::*;
use test_with_tracing::test;

const REV: DdiApiRev = DdiApiRev { major: 1, minor: 0 };

/// Seconds to wait for the firmware and driver to recover after a crash.
const RECOVERY_WAIT_SECS: u64 = 10;

fn close_setup_session(dev: &<DdiTest as Ddi>::Dev, session_id: u16) {
    let resp = helper_close_session(dev, Some(session_id), Some(REV));
    assert!(resp.is_ok(), "Failed to close setup session: {resp:?}");
}

/// Trigger a hard fault in the Admin core.
#[test]
fn test_trigger_hard_fault_crash_admin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Admin,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger a panic in the Admin core.
#[test]
fn test_trigger_panic_in_admin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Admin,
                DdiTestActionCrashType::Panic,
            );
        },
    );
}

/// Trigger a hang in the Admin core.
#[test]
fn test_trigger_hang_crash_admin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Admin,
                DdiTestActionCrashType::Hang,
            );
        },
    );
}

/// Trigger an explicit crash in the Admin core.
#[test]
fn test_trigger_explicit_fault_crash_admin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Admin,
                DdiTestActionCrashType::ExplicitCrash,
            );
        },
    );
}

/// Trigger a hard fault in the HSM core.
#[test]
fn test_trigger_hard_fault_crash_hsm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Hsm,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger a panic in the HSM core.
#[test]
fn test_trigger_panic_in_hsm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Hsm,
                DdiTestActionCrashType::Panic,
            );
        },
    );
}

/// Trigger an explicit crash in the HSM core.
#[test]
fn test_trigger_explicit_fault_crash_hsm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Hsm,
                DdiTestActionCrashType::ExplicitCrash,
            );
        },
    );
}

/// Trigger a hard fault in the FP0 core.
#[test]
fn test_trigger_hard_fault_crash_fp0() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp0,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger a hard fault in the FP1 core.
#[test]
fn test_trigger_hard_fault_crash_fp1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp1,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger a hard fault in the FP2 core.
#[test]
fn test_trigger_hard_fault_crash_fp2() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp2,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger an explicit crash in the FP2 core.
#[test]
fn test_trigger_explicit_fault_crash_fp2() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp2,
                DdiTestActionCrashType::ExplicitCrash,
            );
        },
    );
}

/// Trigger a hang in the FP2 core.
#[test]
fn test_trigger_hang_in_fp2() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp2,
                DdiTestActionCrashType::Hang,
            );
        },
    );
}

/// Trigger a hang in the FP1 core.
#[test]
fn test_trigger_hang_in_fp1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp1,
                DdiTestActionCrashType::Hang,
            );
        },
    );
}

/// Trigger a hang in the FP0 core.
#[test]
fn test_trigger_hang_in_fp0() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            close_setup_session(dev, session_id);
            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp0,
                DdiTestActionCrashType::Hang,
            );
        },
    );
}

/// Inject a crash into `cpu_id` of the requested `crash_type`, then confirm
/// the device recovers.
///
/// Physical-device only; virtual devices and firmware without
/// `mcr_test_hooks` (or without support for the requested core) are skipped.
fn trigger_crash(
    device_path: String,
    cpu_id: DdiTestActionSocCpuId,
    crash_type: DdiTestActionCrashType,
) {
    let ddi = AzihsmDdi::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();

    if get_device_kind(&mut dev) == DdiDeviceKind::Virtual {
        println!("Skipped crash test for virtual device.");
        return;
    }

    // Open a session using the credential established by `common_setup`.
    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);
    let resp = helper_open_session(&dev, None, Some(REV), encrypted_credential, pub_key);
    assert!(resp.is_ok(), "resp {:?}", resp);
    let session_id = resp.unwrap().hdr.sess_id.unwrap();

    // Inject the crash. Parameters ride in the opaque `TestAction` payload.
    let resp = helper_test_action_cmd(
        &mut dev,
        session_id,
        TestActionRequest::TriggerCrash(DdiTestActionCrashReqInfo { crash_type, cpu_id }),
    );

    // A clean `UnsupportedCmd` means no crash happened: either the firmware
    // lacks `mcr_test_hooks` or it does not implement crashing this core.
    // Skip rather than assert a recovery that never had a crash to recover
    // from.
    if let Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) = resp {
        println!("TriggerCrash for {cpu_id:?} not supported by this firmware; skipping.");
        return;
    }

    // A real crash never returns a success CQE — the op aborts or times out.
    assert!(resp.is_err(), "resp {:?}", resp);

    // Wait for the firmware and driver to recover.
    thread::sleep(Duration::from_secs(RECOVERY_WAIT_SECS));

    // Closing the crashed session should still succeed (same as LM).
    let resp = helper_close_session(&dev, Some(session_id), Some(REV));
    assert!(resp.is_ok(), "resp {:?}", resp);

    // Re-provision and re-open a session to prove the device is back.
    let _ = helper_common_establish_credential_no_unwrap(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);
    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);
    let resp = helper_open_session(&dev, None, Some(REV), encrypted_credential, pub_key);
    assert!(resp.is_ok(), "resp {:?}", resp);

    // Read the API revision to confirm the firmware is healthy again.
    let resp = helper_get_api_rev(&dev, None, None).unwrap();
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
}
