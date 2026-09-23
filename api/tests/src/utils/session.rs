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

const API_TEST_PROTOCOL_ENV: &str = "AZIHSM_API_TEST_PROTOCOL";
const TBOR_MIN_TEST_API_REV: HsmApiRev = HsmApiRev { major: 1, minor: 1 };
const ROTATED_CO_PSK: [u8; PSK_LEN] = [0xA5; PSK_LEN];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestSessionProtocol {
    Mbor,
    Tbor,
}

impl TestSessionProtocol {
    fn from_env_value(value: Option<&str>) -> Self {
        match value {
            None | Some("") => Self::Mbor,
            Some(value) if value.eq_ignore_ascii_case("mbor") => Self::Mbor,
            Some(value) if value.eq_ignore_ascii_case("tbor") => Self::Tbor,
            Some(value) => panic!(
                "Unsupported {API_TEST_PROTOCOL_ENV} value {value:?}; expected `mbor` or `tbor`"
            ),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Mbor => "MBOR",
            Self::Tbor => "TBOR",
        }
    }
}

fn selected_test_session_protocol() -> TestSessionProtocol {
    let value = std::env::var(API_TEST_PROTOCOL_ENV).ok();
    TestSessionProtocol::from_env_value(value.as_deref())
}

fn uses_disposable_test_partition() -> bool {
    cfg!(any(feature = "mock", feature = "emu", feature = "res-test"))
}

/// Executes a test function with an initialized HSM session.
///
/// This MBOR-only utility runs in the default/MBOR test pass and is skipped in
/// the TBOR pass. Simulator backends reset and initialize each partition with
/// test credentials. Real hardware opens the already initialized partition
/// without resetting it.
///
/// # Type Parameters
///
/// * `F` - A closure that accepts an `HsmSession`
///
/// # Panics
///
/// Panics if:
/// - No partitions are found in the system
/// - A partition fails to open
/// - Partition initialization fails
/// - Session creation fails
#[allow(unused)]
#[allow(clippy::expect_used)]
pub(crate) fn with_session<F>(mut test: F)
where
    F: FnMut(HsmSession),
{
    if selected_test_session_protocol() == TestSessionProtocol::Mbor {
        with_protocol_session(TestSessionProtocol::Mbor, &mut test);
    } else {
        debug!("Skipping MBOR-only session test in the TBOR test pass");
    }
}

#[allow(clippy::expect_used)]
fn open_mbor_test_session(path: &str) -> HsmSession {
    let part = HsmPartitionManager::open_partition(path, MBOR_TEST_API_REV)
        .expect("Failed to open the partition for an MBOR test session");
    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);

    if uses_disposable_test_partition() {
        part.reset().expect("Partition reset failed");
        let (obk_info, pota_endorsement) = make_init_params(&part);
        init_with_mobk_fallback(&part, creds, obk_info, pota_endorsement, None);
    }

    part.open_session(MBOR_TEST_API_REV, &creds, None)
        .expect("Failed to open an MBOR test session")
}

#[allow(clippy::expect_used)]
fn open_tbor_test_session(path: &str, rev: HsmApiRev) -> HsmSession {
    let part = HsmPartitionManager::open_partition(path, rev)
        .expect("Failed to open the partition for a TBOR test session");

    if !uses_disposable_test_partition() {
        return part
            .open_session_ex(
                rev,
                HsmSessionPsk::with_psk(HsmPskId::CO, &ROTATED_CO_PSK),
                HsmSessionExType::Authenticated,
            )
            .expect("Failed to open a hardware TBOR session with the test CO PSK");
    }

    part.reset().expect("Partition reset failed");
    let session = part
        .open_session_ex(
            rev,
            HsmSessionPsk::new(HsmPskId::CO),
            HsmSessionExType::Authenticated,
        )
        .expect("Failed to open a TBOR test session");
    session
        .change_psk(&ROTATED_CO_PSK)
        .expect("Failed to rotate the default CO PSK");
    session
}

fn protocol_revision(protocol: TestSessionProtocol, range: HsmApiRevRange) -> HsmApiRev {
    match protocol {
        TestSessionProtocol::Mbor => {
            assert!(
                range.min() <= MBOR_TEST_API_REV && MBOR_TEST_API_REV <= range.max(),
                "MBOR tests require API revision {MBOR_TEST_API_REV:?}, but the advertised range is {range:?}"
            );
            MBOR_TEST_API_REV
        }
        TestSessionProtocol::Tbor => {
            assert!(
                range.max() >= TBOR_MIN_TEST_API_REV,
                "TBOR tests require API revision {TBOR_MIN_TEST_API_REV:?} or newer, but the advertised range is {range:?}"
            );
            range.max()
        }
    }
}

#[allow(clippy::expect_used)]
fn with_protocol_session<F>(protocol: TestSessionProtocol, mut test: F)
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
        let rev = protocol_revision(protocol, range);
        let span = info_span!(
            "api_test_session",
            protocol = protocol.name(),
            api_rev = ?rev,
            partition_path = %part_info.path
        );
        let _span_guard = span.enter();

        let session = match protocol {
            TestSessionProtocol::Mbor => open_mbor_test_session(&part_info.path),
            TestSessionProtocol::Tbor => open_tbor_test_session(&part_info.path, rev),
        };
        test(session);
    }
}

/// Executes an eligible test once with the protocol selected for this test run.
///
/// Set `AZIHSM_API_TEST_PROTOCOL=tbor` for the TBOR pass. An unset variable or
/// `mbor` selects MBOR. Running separate test passes keeps protocol failures in
/// separate nextest reports.
pub(crate) fn with_dual_session<F>(test: F)
where
    F: FnMut(HsmSession),
{
    with_protocol_session(selected_test_session_protocol(), test);
}

/// Executes a TBOR-only test during the TBOR pass.
#[allow(unused)]
pub(crate) fn with_tbor_session<F>(test: F)
where
    F: FnMut(HsmSession),
{
    if selected_test_session_protocol() == TestSessionProtocol::Tbor {
        with_protocol_session(TestSessionProtocol::Tbor, test);
    } else {
        debug!("Skipping TBOR-only session test in the MBOR test pass");
    }
}

#[test]
fn test_session_protocol_from_env_value() {
    assert_eq!(
        TestSessionProtocol::from_env_value(None),
        TestSessionProtocol::Mbor
    );
    assert_eq!(
        TestSessionProtocol::from_env_value(Some("mbor")),
        TestSessionProtocol::Mbor
    );
    assert_eq!(
        TestSessionProtocol::from_env_value(Some("TBOR")),
        TestSessionProtocol::Tbor
    );
}

#[test]
#[should_panic(expected = "expected `mbor` or `tbor`")]
fn test_session_protocol_rejects_unknown_value() {
    TestSessionProtocol::from_env_value(Some("unknown"));
}

#[test]
fn test_protocol_revision_follows_capabilities() {
    let rev_1_0 = HsmApiRev { major: 1, minor: 0 };
    let rev_1_1 = HsmApiRev { major: 1, minor: 1 };
    // Synthetic future maximum: verifies that TBOR follows the advertised max
    // instead of pinning every capable target to revision 1.1.
    let rev_1_2 = HsmApiRev { major: 1, minor: 2 };

    assert_eq!(
        protocol_revision(
            TestSessionProtocol::Mbor,
            HsmApiRevRange::new(rev_1_0, rev_1_0)
        ),
        rev_1_0
    );
    assert_eq!(
        protocol_revision(
            TestSessionProtocol::Tbor,
            HsmApiRevRange::new(rev_1_0, rev_1_1)
        ),
        rev_1_1
    );
    assert_eq!(
        protocol_revision(
            TestSessionProtocol::Tbor,
            HsmApiRevRange::new(rev_1_0, rev_1_2)
        ),
        rev_1_2
    );
}

#[test]
fn test_with_dual_session_uses_selected_protocol() {
    let protocol = selected_test_session_protocol();
    let expected = HsmPartitionManager::partition_info_list()
        .into_iter()
        .map(|part_info| {
            protocol_revision(
                protocol,
                part_info
                    .api_rev_range
                    .expect("Partition did not advertise an API revision range"),
            )
        })
        .collect::<Vec<_>>();
    let mut observed = Vec::new();

    with_dual_session(|session| observed.push(session.api_rev()));

    assert_eq!(observed, expected);
}

#[session_test]
fn test_with_session(session: HsmSession) {
    info!("Testing with session: {:?}", session.id());
}
