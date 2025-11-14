// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use core::option::Option::None;
use std::thread;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

/// Trigger hard fault in the Admin Core.
#[test]
fn test_trigger_hard_fault_crash_admin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Admin,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger a Panic in the Admin Core.
#[test]
fn test_trigger_panic_in_admin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Admin,
                DdiTestActionCrashType::Panic,
            );
        },
    );
}

/// Trigger a Hang in the Admin Core.
#[test]
fn test_trigger_hang_crash_admin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Admin,
                DdiTestActionCrashType::Hang,
            );
        },
    );
}

/// Trigger an explicit fault in the Admin Core.
#[test]
fn test_trigger_explicit_fault_crash_admin() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Admin,
                DdiTestActionCrashType::ExplicitCrash,
            );
        },
    );
}

/// Trigger hard fault in the HSM core.
#[test]
fn test_trigger_hard_fault_crash_hsm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Hsm,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger a Panic in the HSM core.
#[test]
fn test_trigger_panic_in_hsm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let _resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Hsm,
                DdiTestActionCrashType::Panic,
            );
        },
    );
}

/// Trigger an explicit fault in the HSM core.
#[test]
fn test_trigger_explicit_fault_crash_hsm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Hsm,
                DdiTestActionCrashType::ExplicitCrash,
            );
        },
    );
}

/// Trigger hard fault in the FP0 core.
#[test]
fn test_trigger_hard_fault_crash_fp0() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp0,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger hard fault in the FP1 core.
#[test]
fn test_trigger_hard_fault_crash_fp1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let _resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp1,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger hard fault in the FP2 core.
#[test]
fn test_trigger_hard_fault_crash_fp2() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp2,
                DdiTestActionCrashType::HardFault,
            );
        },
    );
}

/// Trigger an explicit fault in the FP2 core.
#[test]
fn test_trigger_explicit_fault_crash_fp2() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp2,
                DdiTestActionCrashType::ExplicitCrash,
            );
        },
    );
}

/// Trigger an hang in the FP2 core.
#[test]
fn test_trigger_hang_in_fp2() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp2,
                DdiTestActionCrashType::Hang,
            );
        },
    );
}

/// Trigger an hang in the FP1 core.
#[test]
fn test_trigger_hang_in_fp1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let _resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp1,
                DdiTestActionCrashType::Hang,
            );
        },
    );
}

/// Trigger an hang in the FP0 core.
#[test]
fn test_trigger_hang_in_fp0() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            trigger_crash(
                path.to_string(),
                DdiTestActionSocCpuId::Fp0,
                DdiTestActionCrashType::Hang,
            );
        },
    );
}

/// This test is only for physical Manticore.
fn trigger_crash(
    device_path: String,
    cpu_id: DdiTestActionSocCpuId,
    crash_type: DdiTestActionCrashType,
) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    if get_device_kind(&mut dev) == DdiDeviceKind::Virtual {
        tracing::debug!("Skipped trigger crash test for virtual device");
        return;
    }

    if !set_test_action(&ddi, device_path.as_str(), DdiTestAction::TriggerIoFailure) {
        println!("Firmware is not built with test_action test_hooks.");
        return;
    }

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);

    let resp = helper_open_session(
        &dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    );
    assert!(resp.is_ok(), "{:?}", resp);

    let resp = resp.unwrap();
    let vault_manager_sess_id = resp.data.sess_id;

    let resp = helper_test_action_cmd(
        &mut dev,
        vault_manager_sess_id,
        DdiTestAction::TriggerCrash,
        Some(DdiTestActionCrashReqInfo { crash_type, cpu_id }),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(resp.is_err(), "resp {:?}", resp);

    // Wait for 10 seconds for the FW and driver to recover.
    thread::sleep(std::time::Duration::from_secs(10));

    // Open a manager session and send get api rev DDI command.
    // close manger session first.

    let resp = helper_close_session(
        &dev,
        Some(vault_manager_sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
    );
    assert!(resp.is_ok(), "Resp {:?}", resp); // Note that, even after a crash, close session should work, which is the same behavior as LM.

    let ddi = DdiTest::default();
    let mut mngr_dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut mngr_dev);

    helper_common_establish_credential(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);

    let resp = helper_open_session(
        &mngr_dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    );
    assert!(resp.is_ok(), "Resp {:?}", resp);

    // now get API rev to see if the FW is working fine.

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
