// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session management utilities for HSM testing.
//!
//! This module provides helper functions for creating and managing HSM sessions
//! in test scenarios. It handles partition discovery, opening, initialization,
//! session creation, and cleanup operations.

use azihsm_api::*;
use azihsm_api_tests_macro::*;
use tracing::*;

use crate::utils::partition::*;

const SESSION_EX_MIN_TEST_API_REV: HsmApiRev = HsmApiRev { major: 1, minor: 1 };
#[cfg(feature = "session-ex-tests")]
const ROTATED_CO_PSK: [u8; PSK_LEN] = [0xA5; PSK_LEN];

/// Executes a test function with the compile-time-selected HSM session API.
///
/// This fixture calls `open_session` by default and `open_session_ex` when
/// `session-ex-tests` is enabled.
///
/// # Partition State
///
/// Each discovered partition is reset before the test, including on hardware.
/// Use only dedicated test partitions. The partition lock covers setup and the
/// test closure within this process; it does not coordinate separate processes.
///
/// Legacy setup initializes credentials and reuses a cached MOBK when available.
/// Hardware reset does not clear the one-time BK3 initialization state, so warm
/// hardware runs in separate processes need a matching `AZIHSM_MOBK_PATH` cache.
/// The default cache path is process-specific.
///
/// EX setup opens a CO session and rotates its default PSK. It does not call
/// `part_init_ex` or `part_final_ex`; tests requiring partition-local or
/// security-domain masking keys need additional provisioning.
///
/// # Type Parameters
///
/// * `F` - A closure that accepts an `HsmSession`
///
/// # Panics
///
/// Panics if:
/// - No partitions are found in the system
/// - A partition does not advertise a compatible API revision range
/// - A partition fails to open
/// - Partition reset or legacy initialization fails
/// - Session creation fails
/// - EX setup cannot rotate the default CO PSK
#[allow(unused)]
#[allow(clippy::expect_used)]
pub(crate) fn with_session<F>(mut test: F)
where
    F: FnMut(HsmSession),
{
    let _partition_guard = PARTITION_LOCK.lock();
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");

    for part_info in part_mgr {
        let range = part_info
            .api_rev_range
            .expect("Partition did not advertise an API revision range");

        #[cfg(not(feature = "session-ex-tests"))]
        let (session_api, rev, session) = {
            let rev = session_revision(range);
            let session = open_session_test_session(&part_info.path);
            ("session", rev, session)
        };

        #[cfg(feature = "session-ex-tests")]
        let (session_api, rev, session) = {
            let rev = session_ex_revision(range);
            let session = open_session_ex_test_session(&part_info.path, rev);
            ("session_ex", rev, session)
        };

        let span = info_span!(
            "api_test_session",
            session_api,
            api_rev = ?rev,
            partition_path = %part_info.path
        );
        let _span_guard = span.enter();
        test(session);
    }
}

#[allow(clippy::expect_used)]
#[cfg(not(feature = "session-ex-tests"))]
fn open_session_test_session(path: &str) -> HsmSession {
    let part = HsmPartitionManager::open_partition(path, SESSION_TEST_API_REV)
        .expect("Failed to open the partition for an open_session test");
    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);

    part.reset().expect("Partition reset failed");
    let (obk_info, pota_endorsement) = make_init_params(&part);
    init_with_mobk_fallback(&part, creds, obk_info, pota_endorsement, None);

    part.open_session(SESSION_TEST_API_REV, &creds, None)
        .expect("Failed to call open_session for a test")
}

#[allow(clippy::expect_used)]
#[cfg(feature = "session-ex-tests")]
fn open_session_ex_test_session(path: &str, rev: HsmApiRev) -> HsmSession {
    let part = HsmPartitionManager::open_partition(path, rev)
        .expect("Failed to open the partition for an open_session_ex test");

    part.reset().expect("Partition reset failed");
    let session = part
        .open_session_ex(
            rev,
            HsmSessionPsk::new(HsmPskId::CO),
            HsmSessionExType::Authenticated,
        )
        .expect("Failed to call open_session_ex for a test");
    session
        .change_psk(&ROTATED_CO_PSK)
        .expect("Failed to rotate the default CO PSK");
    session
}

fn session_revision(range: HsmApiRevRange) -> HsmApiRev {
    assert!(
        range.min() <= SESSION_TEST_API_REV && SESSION_TEST_API_REV <= range.max(),
        "open_session tests require API revision {SESSION_TEST_API_REV:?}, but the advertised range is {range:?}"
    );
    SESSION_TEST_API_REV
}

fn session_ex_revision(range: HsmApiRevRange) -> HsmApiRev {
    assert!(
        range.max() >= SESSION_EX_MIN_TEST_API_REV,
        "open_session_ex tests require API revision {SESSION_EX_MIN_TEST_API_REV:?} or newer, but the advertised range is {range:?}"
    );
    range.max()
}

#[test]
fn test_session_revisions_follow_capabilities() {
    let rev_1_0 = HsmApiRev { major: 1, minor: 0 };
    let rev_1_1 = HsmApiRev { major: 1, minor: 1 };
    // Synthetic future maximum: verifies that session_ex follows the advertised max
    // instead of pinning every capable target to revision 1.1.
    let rev_1_2 = HsmApiRev { major: 1, minor: 2 };

    assert_eq!(
        session_revision(HsmApiRevRange::new(rev_1_0, rev_1_0)),
        rev_1_0
    );
    assert_eq!(
        session_ex_revision(HsmApiRevRange::new(rev_1_0, rev_1_1)),
        rev_1_1
    );
    assert_eq!(
        session_ex_revision(HsmApiRevRange::new(rev_1_0, rev_1_2)),
        rev_1_2
    );
}

#[test]
fn test_with_session_uses_compiled_revision() {
    let expected = HsmPartitionManager::partition_info_list()
        .into_iter()
        .map(|part_info| {
            let range = part_info
                .api_rev_range
                .expect("Partition did not advertise an API revision range");

            #[cfg(not(feature = "session-ex-tests"))]
            return session_revision(range);

            #[cfg(feature = "session-ex-tests")]
            return session_ex_revision(range);
        })
        .collect::<Vec<_>>();
    let mut observed = Vec::new();

    with_session(|session| observed.push(session.api_rev()));

    assert_eq!(observed, expected);
}

#[session_test]
fn test_with_session(session: HsmSession) {
    info!("Testing with session: {:?}", session.id());
}
