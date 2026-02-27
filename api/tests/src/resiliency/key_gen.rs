// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests for key generation operations.
//!
//! These tests exercise the `#[resiliency_key_gen]` macro's
//! restore-partition + session-reopen recovery on key-generation
//! operations using two complementary strategies:
//!
//! 1. Fault-injection tests — inject transient DDI faults through
//!    the resiliency mock device and verify the retry path recovers.
//! 2. NSSR-triggered tests — trigger an NVMe Subsystem Reset during
//!    a DDI operation via `FaultRule::reset_on_next` (simulating a live
//!    migration event occurring mid-operation) so the DDI returns
//!    `SessionNeedsRenegotiation` naturally, then verify that
//!    `restore_partition` + `reopen_session_if_needed` recovers.
//!
//! Key generation retries only when resiliency is enabled (a
//! [`HsmResiliencyConfig`] was passed to [`HsmPartition::init`]).
//!
//! On a retryable failure the `#[resiliency_key_gen]` macro:
//! 1. Applies exponential backoff for IO-abort / `PendingKeyGeneration`
//!    errors (not for `SessionNeedsRenegotiation`).
//! 2. Calls `restore_partition` to re-establish credentials.
//! 3. Calls `reopen_session_if_needed` to reopen the stale session.
//! 4. Retries the key-generation call.
//!
//! # DDI operations under test
//!
//! | Key generation          | DDI op            |
//! |-------------------------|-------------------|
//! | AES `generate_key`      | `AesGenerateKey`  |
//! | ECC `generate_key_pair` | `EccGenerateKeyPair` |
//!
//! # Adding a new retryable error
//!
//! Append the new [`FaultError`] variant to [`RETRYABLE_ERRORS`] and all
//! loop-based tests will automatically cover it.

use azihsm_res_test_dev::DdiOp;
use azihsm_res_test_dev::DdiStatus;
use azihsm_res_test_dev::DriverError;
use azihsm_res_test_dev::FaultError;
use azihsm_res_test_dev::FaultRule;
use azihsm_res_test_dev::clear_faults;
use azihsm_res_test_dev::inject_fault;
use azihsm_res_test_dev::op_call_count;

use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

/// All error codes that trigger `resiliency_key_gen` retry when resiliency is enabled.
const RETRYABLE_ERRORS: &[FaultError] = &[
    FaultError::Driver(DriverError::IoAborted),
    FaultError::Driver(DriverError::IoAbortInProgress),
    FaultError::Status(DdiStatus::SessionNeedsRenegotiation),
    FaultError::Status(DdiStatus::PendingKeyGeneration),
];

/// Helper: open and init a partition with resiliency enabled, open a
/// session, and return all handles plus the RAII cleanup context.
fn init_with_resiliency_and_session() -> (HsmPartition, HsmSession, ResiliencyTestCtx) {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    let part =
        HsmPartitionManager::open_partition(&list[0].path).expect("Failed to open partition");
    part.reset().expect("Partition reset failed");

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);
    let (resiliency_config, ctx) = make_resiliency_config(&part);
    part.init(
        creds,
        None,
        None,
        obk_info,
        pota_endorsement,
        Some(resiliency_config),
    )
    .expect("Partition init failed");

    let rev = part.api_rev_range().max();
    let session = part
        .open_session(rev, &creds, None)
        .expect("Failed to open session");

    (part, session, ctx)
}

/// Helper: open and init a partition without resiliency, open a session.
fn init_without_resiliency_and_session() -> (HsmPartition, HsmSession) {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    let part =
        HsmPartitionManager::open_partition(&list[0].path).expect("Failed to open partition");
    part.reset().expect("Partition reset failed");

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);
    part.init(creds, None, None, obk_info, pota_endorsement, None)
        .expect("Partition init failed");

    let rev = part.api_rev_range().max();
    let session = part
        .open_session(rev, &creds, None)
        .expect("Failed to open session");

    (part, session)
}

/// Build AES key properties for test key generation.
fn aes_key_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES key props")
}

/// Build ECC private key properties for test key pair generation.
fn ecc_priv_key_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC private key props")
}

/// Build ECC public key properties for test key pair generation.
fn ecc_pub_key_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC public key props")
}

// =========================================================================
// AES key generation — single-fault recovery
// =========================================================================

/// AES `generate_key` recovers from a single transient fault on
/// `AesGenerateKey`, for every retryable error code.
#[api_test]
fn test_aes_generate_key_recovers_from_single_fault() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        inject_fault(FaultRule::fail_nth(DdiOp::AesGenerateKey, 1, *error));

        let mut algo = HsmAesKeyGenAlgo::default();
        let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
        clear_faults();

        assert!(
            result.is_ok(),
            "AES generate_key should recover after a single {error:?} on AesGenerateKey, got: {:?}",
            result.as_ref().map(|_| ())
        );
    }
}

// =========================================================================
// AES key generation — last-retry recovery
// =========================================================================

/// AES `generate_key` recovers on the last retry when `AesGenerateKey`
/// fails for the first `MAX_RETRIES` attempts.
#[api_test]
fn test_aes_generate_key_recovers_on_last_retry() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        inject_fault(FaultRule::fail_next(
            DdiOp::AesGenerateKey,
            MAX_RETRIES,
            *error,
        ));

        let mut algo = HsmAesKeyGenAlgo::default();
        let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
        clear_faults();

        assert!(
            result.is_ok(),
            "AES generate_key should recover on the last retry after {MAX_RETRIES} consecutive {error:?}, got: {:?}",
            result.as_ref().map(|_| ())
        );
    }
}

// =========================================================================
// ECC key pair generation — single-fault recovery
// =========================================================================

/// ECC `generate_key_pair` recovers from a single transient fault on
/// `EccGenerateKeyPair`, for every retryable error code.
#[api_test]
fn test_ecc_generate_key_pair_recovers_from_single_fault() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        inject_fault(FaultRule::fail_nth(DdiOp::EccGenerateKeyPair, 1, *error));

        let mut algo = HsmEccKeyGenAlgo::default();
        let result = HsmKeyManager::generate_key_pair(
            &session,
            &mut algo,
            ecc_priv_key_props(),
            ecc_pub_key_props(),
        );
        clear_faults();

        assert!(
            result.is_ok(),
            "ECC generate_key_pair should recover after a single {error:?} on EccGenerateKeyPair, got: {:?}",
            result.as_ref().map(|_| ())
        );
    }
}

// =========================================================================
// ECC key pair generation — last-retry recovery
// =========================================================================

/// ECC `generate_key_pair` recovers on the last retry when
/// `EccGenerateKeyPair` fails for the first `MAX_RETRIES` attempts.
#[api_test]
fn test_ecc_generate_key_pair_recovers_on_last_retry() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        inject_fault(FaultRule::fail_next(
            DdiOp::EccGenerateKeyPair,
            MAX_RETRIES,
            *error,
        ));

        let mut algo = HsmEccKeyGenAlgo::default();
        let result = HsmKeyManager::generate_key_pair(
            &session,
            &mut algo,
            ecc_priv_key_props(),
            ecc_pub_key_props(),
        );
        clear_faults();

        assert!(
            result.is_ok(),
            "ECC generate_key_pair should recover on the last retry after {MAX_RETRIES} consecutive {error:?}, got: {:?}",
            result.as_ref().map(|_| ())
        );
    }
}

// =========================================================================
// No retry without resiliency
// =========================================================================

/// Without resiliency, AES `generate_key` does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_aes_generate_key_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();

    inject_fault(FaultRule::fail_nth(
        DdiOp::AesGenerateKey,
        1,
        DriverError::IoAborted,
    ));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();

    assert_eq!(
        result.map(|_| ()).unwrap_err(),
        HsmError::IoAborted,
        "AES generate_key without resiliency should propagate IoAborted immediately"
    );
}

/// Without resiliency, ECC `generate_key_pair` does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_ecc_generate_key_pair_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();

    inject_fault(FaultRule::fail_nth(
        DdiOp::EccGenerateKeyPair,
        1,
        DriverError::IoAborted,
    ));

    let mut algo = HsmEccKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key_pair(
        &session,
        &mut algo,
        ecc_priv_key_props(),
        ecc_pub_key_props(),
    );
    clear_faults();

    assert_eq!(
        result.map(|_| ()).unwrap_err(),
        HsmError::IoAborted,
        "ECC generate_key_pair without resiliency should propagate IoAborted immediately"
    );
}

// =========================================================================
// Exhaustion — all retries fail
// =========================================================================

/// When all retry attempts are exhausted, AES `generate_key` returns
/// the last transient error.
#[api_test]
fn test_aes_generate_key_fails_after_all_retries_exhausted() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    // Fail MAX_RETRIES + 1 times → 1 initial + MAX_RETRIES retries all fail.
    inject_fault(FaultRule::fail_next(
        DdiOp::AesGenerateKey,
        MAX_RETRIES + 1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();

    assert_eq!(
        result.map(|_| ()).unwrap_err(),
        HsmError::IoAborted,
        "AES generate_key should return IoAborted after exhausting all retries"
    );
}

// =========================================================================
// Non-retryable error propagates
// =========================================================================

/// A non-retryable error (e.g., `InvalidArgument`) is not retried
/// and propagates immediately, even with resiliency enabled.
#[api_test]
fn test_aes_generate_key_non_retryable_error_propagates() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    inject_fault(FaultRule::fail_nth(
        DdiOp::AesGenerateKey,
        1,
        FaultError::Status(DdiStatus::InvalidArg),
    ));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();

    assert!(
        result.is_err(),
        "AES generate_key should fail on a non-retryable error even with resiliency enabled"
    );
}

// =========================================================================
// restore_partition verification
// =========================================================================

/// When AES `generate_key` retries, `restore_partition` re-establishes
/// credentials (calls `InitBk3`).
#[api_test]
fn test_restore_partition_called_on_aes_generate_key_retry() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    let bk3_before = op_call_count(DdiOp::InitBk3);

    inject_fault(FaultRule::fail_nth(
        DdiOp::AesGenerateKey,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());

    let bk3_after = op_call_count(DdiOp::InitBk3);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES generate_key should recover after restore_partition re-establishes credentials"
    );
    assert!(
        bk3_after > bk3_before,
        "InitBk3 should have been called during restore_partition \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

// =========================================================================
// NSSR-triggered tests — AES key generation
// =========================================================================

/// After an NSSR on `AesGenerateKey`, `generate_key` triggers
/// `restore_partition` + `reopen_session_if_needed` and recovers.
#[api_test]
fn test_aes_generate_key_recovers_after_nssr() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    let bk3_before = op_call_count(DdiOp::InitBk3);

    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());

    let bk3_after = op_call_count(DdiOp::InitBk3);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES generate_key should recover after NSSR via restore_partition, got: {:?}",
        result.as_ref().map(|_| ())
    );
    assert!(
        bk3_after > bk3_before,
        "InitBk3 should have been called during restore_partition after NSSR \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, AES `generate_key` does not recover from
/// an NSSR — the error propagates immediately.
#[api_test]
fn test_aes_generate_key_fails_after_nssr_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();

    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();

    assert!(
        result.is_err(),
        "AES generate_key without resiliency should fail after NSSR, got: {:?}",
        result.as_ref().map(|_| ())
    );
}

/// Two consecutive NSSRs on `AesGenerateKey` are each followed by a
/// successful recovery.
#[api_test]
fn test_aes_generate_key_recovers_after_consecutive_nssr() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    // First NSSR → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));
    let mut algo = HsmAesKeyGenAlgo::default();
    let key1 = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();
    assert!(
        key1.is_ok(),
        "First AES generate_key should recover after NSSR"
    );

    // Second NSSR → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));
    let mut algo = HsmAesKeyGenAlgo::default();
    let key2 = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();
    assert!(
        key2.is_ok(),
        "Second AES generate_key should recover after NSSR"
    );
}

// =========================================================================
// NSSR-triggered tests — ECC key pair generation
// =========================================================================

/// After an NSSR on `EccGenerateKeyPair`, `generate_key_pair` triggers
/// `restore_partition` + `reopen_session_if_needed` and recovers.
#[api_test]
fn test_ecc_generate_key_pair_recovers_after_nssr() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    let bk3_before = op_call_count(DdiOp::InitBk3);

    inject_fault(FaultRule::reset_on_next(DdiOp::EccGenerateKeyPair, 1));

    let mut algo = HsmEccKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key_pair(
        &session,
        &mut algo,
        ecc_priv_key_props(),
        ecc_pub_key_props(),
    );

    let bk3_after = op_call_count(DdiOp::InitBk3);
    clear_faults();

    assert!(
        result.is_ok(),
        "ECC generate_key_pair should recover after NSSR via restore_partition, got: {:?}",
        result.as_ref().map(|_| ())
    );
    assert!(
        bk3_after > bk3_before,
        "InitBk3 should have been called during restore_partition after NSSR \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Two consecutive NSSRs on `EccGenerateKeyPair` are each followed by a
/// successful recovery.
#[api_test]
fn test_ecc_generate_key_pair_recovers_after_consecutive_nssr() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    // First NSSR → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::EccGenerateKeyPair, 1));
    let mut algo = HsmEccKeyGenAlgo::default();
    let result1 = HsmKeyManager::generate_key_pair(
        &session,
        &mut algo,
        ecc_priv_key_props(),
        ecc_pub_key_props(),
    );
    clear_faults();
    assert!(
        result1.is_ok(),
        "First ECC generate_key_pair should recover after NSSR"
    );

    // Second NSSR → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::EccGenerateKeyPair, 1));
    let mut algo = HsmEccKeyGenAlgo::default();
    let result2 = HsmKeyManager::generate_key_pair(
        &session,
        &mut algo,
        ecc_priv_key_props(),
        ecc_pub_key_props(),
    );
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second ECC generate_key_pair should recover after NSSR"
    );
}

// =========================================================================
// Compound fault: key gen + restore's init_part
// =========================================================================

/// When `generate_key` retries and `restore_partition`'s inner
/// `init_part` also hits a transient fault on `InitBk3`, both
/// retry mechanisms recover and the key generation ultimately succeeds.
#[api_test]
fn test_aes_generate_key_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    // AesGenerateKey → IoAborted → triggers retry path.
    inject_fault(FaultRule::fail_nth(
        DdiOp::AesGenerateKey,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    // During restore, init_part's InitBk3 also fails transiently.
    inject_fault(FaultRule::fail_next(
        DdiOp::InitBk3,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();

    assert!(
        result.is_ok(),
        "AES generate_key should recover from compound faults on AesGenerateKey + InitBk3, got: {:?}",
        result.as_ref().map(|_| ())
    );
}
