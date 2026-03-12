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
//! 2. reset-triggered tests — trigger an NVMe Subsystem Reset during
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
//! | Key generation          | DDI op               |
//! |-------------------------|----------------------|
//! | AES `generate_key`      | `AesGenerateKey`     |
//! | ECC `generate_key_pair` | `EccGenerateKeyPair` |
//! | AES-XTS `unmask_key`    | `UnmaskKey`          |
//!
//! # Adding a new retryable error
//!
//! Append the new [`FaultError`] variant to [`super::KEY_OP_RETRYABLE_ERRORS`] and all
//! loop-based tests will automatically cover it.

use azihsm_res_test_dev::DdiOp;
use azihsm_res_test_dev::DdiStatus;
use azihsm_res_test_dev::DriverError;
use azihsm_res_test_dev::FaultError;
use azihsm_res_test_dev::FaultRule;
use azihsm_res_test_dev::clear_faults;
use azihsm_res_test_dev::inject_fault;
use azihsm_res_test_dev::op_call_count;

use super::super::helpers::*;
use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

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
    for error in super::KEY_OP_RETRYABLE_ERRORS {
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
    for error in super::KEY_OP_RETRYABLE_ERRORS {
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
    for error in super::KEY_OP_RETRYABLE_ERRORS {
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
    for error in super::KEY_OP_RETRYABLE_ERRORS {
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
/// credentials (calls `InitBk3` or `GetSealedBk3` depending on source).
#[api_test]
fn test_restore_partition_called_on_aes_generate_key_retry() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::fail_nth(
        DdiOp::AesGenerateKey,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES generate_key should recover after restore_partition re-establishes credentials"
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

// =========================================================================
// reset-triggered tests — AES key generation
// =========================================================================

/// After a reset on `AesGenerateKey`, `generate_key` triggers
/// `restore_partition` + `reopen_session_if_needed` and recovers.
#[api_test]
fn test_aes_generate_key_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES generate_key should recover after reset via restore_partition, got: {:?}",
        result.as_ref().map(|_| ())
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, AES `generate_key` does not recover from
/// a reset — the error propagates immediately.
#[api_test]
fn test_aes_generate_key_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();

    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));

    let mut algo = HsmAesKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();

    assert!(
        result.is_err(),
        "AES generate_key without resiliency should fail after reset, got: {:?}",
        result.as_ref().map(|_| ())
    );
}

/// Two consecutive resets on `AesGenerateKey` are each followed by a
/// successful recovery.
#[api_test]
fn test_aes_generate_key_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    // First reset → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));
    let mut algo = HsmAesKeyGenAlgo::default();
    let key1 = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();
    assert!(
        key1.is_ok(),
        "First AES generate_key should recover after reset"
    );

    // Second reset → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));
    let mut algo = HsmAesKeyGenAlgo::default();
    let key2 = HsmKeyManager::generate_key(&session, &mut algo, aes_key_props());
    clear_faults();
    assert!(
        key2.is_ok(),
        "Second AES generate_key should recover after reset"
    );
}

// =========================================================================
// reset-triggered tests — ECC key pair generation
// =========================================================================

/// After a reset on `EccGenerateKeyPair`, `generate_key_pair` triggers
/// `restore_partition` + `reopen_session_if_needed` and recovers.
#[api_test]
fn test_ecc_generate_key_pair_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::EccGenerateKeyPair, 1));

    let mut algo = HsmEccKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key_pair(
        &session,
        &mut algo,
        ecc_priv_key_props(),
        ecc_pub_key_props(),
    );

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "ECC generate_key_pair should recover after reset via restore_partition, got: {:?}",
        result.as_ref().map(|_| ())
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Two consecutive resets on `EccGenerateKeyPair` are each followed by a
/// successful recovery.
#[api_test]
fn test_ecc_generate_key_pair_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    // First reset → recover.
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
        "First ECC generate_key_pair should recover after reset"
    );

    // Second reset → recover again.
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
        "Second ECC generate_key_pair should recover after reset"
    );
}

// =========================================================================
// Compound fault: key gen + restore's init_part
// =========================================================================

/// When `generate_key` retries and `restore_partition`'s inner
/// `init_part` also hits a transient fault on `InitBk3`, both
/// retry mechanisms recover and the key generation ultimately succeeds.
///
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set
/// (TPM path uses `GetSealedBk3`, not `InitBk3`).
#[api_test]
fn test_aes_generate_key_recovers_from_compound_fault() {
    if use_tpm() {
        return;
    }
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

// =========================================================================
// AES-XTS unmask key helpers
// =========================================================================

/// Generate an AES-XTS key and return its masked key blob for unmask tests.
fn generate_xts_masked_key(session: &HsmSession) -> Vec<u8> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES-XTS key props");
    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(session, &mut algo, props)
        .expect("Failed to generate AES-XTS key for unmask test");
    key.masked_key_vec().expect("Failed to get masked key")
}

/// Unmask an AES-XTS key from a masked blob.
fn unmask_xts_key(session: &HsmSession, masked_key: &[u8]) -> HsmResult<HsmAesXtsKey> {
    let mut unmask_algo = HsmAesXtsKeyUnmaskAlgo::default();
    HsmKeyManager::unmask_key(session, &mut unmask_algo, masked_key)
}

// =========================================================================
// AES-XTS unmask key — fault-injection tests
// =========================================================================

/// AES-XTS `unmask_key` recovers from a single transient fault on
/// `UnmaskKey`, for every retryable error code.
#[api_test]
fn test_aes_xts_unmask_key_recovers_from_single_fault() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let masked_key = generate_xts_masked_key(&session);

        inject_fault(FaultRule::fail_nth(DdiOp::UnmaskKey, 1, *error));

        let result = unmask_xts_key(&session, &masked_key);
        clear_faults();

        assert!(
            result.is_ok(),
            "AES-XTS unmask_key should recover after a single {error:?} on UnmaskKey, got: {:?}",
            result.as_ref().map(|_| ())
        );
    }
}

/// AES-XTS `unmask_key` recovers on the last retry when `UnmaskKey`
/// fails for the first `MAX_RETRIES` attempts.
#[api_test]
fn test_aes_xts_unmask_key_recovers_on_last_retry() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let masked_key = generate_xts_masked_key(&session);

        inject_fault(FaultRule::fail_next(DdiOp::UnmaskKey, MAX_RETRIES, *error));

        let result = unmask_xts_key(&session, &masked_key);
        clear_faults();

        assert!(
            result.is_ok(),
            "AES-XTS unmask_key should recover on the last retry after {MAX_RETRIES} consecutive {error:?}, got: {:?}",
            result.as_ref().map(|_| ())
        );
    }
}

/// AES-XTS `unmask_key` fails after all retries are exhausted.
/// Both the outer `aes_xts_unmask_key` and the inner `unmask_key`
/// have `#[resiliency_key_gen]` retry loops, so exhausting all
/// retries requires (MAX_RETRIES + 1)² faults.
#[api_test]
fn test_aes_xts_unmask_key_fails_after_all_retries_exhausted() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let masked_key = generate_xts_masked_key(&session);

    // Nested retries: the outer function retries (MAX_RETRIES + 1)
    // times, and each outer attempt triggers a full inner retry
    // cycle of (MAX_RETRIES + 1) DDI calls.
    inject_fault(FaultRule::fail_next(
        DdiOp::UnmaskKey,
        (MAX_RETRIES + 1) * (MAX_RETRIES + 1),
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = unmask_xts_key(&session, &masked_key);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-XTS unmask_key should fail after exhausting all retries, got: {:?}",
        result.as_ref().map(|_| ())
    );
}

/// Without resiliency, AES-XTS `unmask_key` does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_aes_xts_unmask_key_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let masked_key = generate_xts_masked_key(&session);

    inject_fault(FaultRule::fail_nth(
        DdiOp::UnmaskKey,
        1,
        DriverError::IoAborted,
    ));

    let result = unmask_xts_key(&session, &masked_key);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-XTS unmask_key without resiliency should propagate IoAborted immediately"
    );
}

/// A non-retryable error propagates immediately, even with resiliency enabled.
#[api_test]
fn test_aes_xts_unmask_key_non_retryable_error_propagates() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let masked_key = generate_xts_masked_key(&session);

    inject_fault(FaultRule::fail_nth(
        DdiOp::UnmaskKey,
        1,
        FaultError::Status(DdiStatus::InvalidArg),
    ));

    let result = unmask_xts_key(&session, &masked_key);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-XTS unmask_key should fail on a non-retryable error even with resiliency enabled"
    );
}

/// When AES-XTS `unmask_key` retries, `restore_partition` re-establishes
/// credentials.
#[api_test]
fn test_restore_partition_called_on_aes_xts_unmask_key_retry() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let masked_key = generate_xts_masked_key(&session);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::fail_nth(
        DdiOp::UnmaskKey,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = unmask_xts_key(&session, &masked_key);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-XTS unmask_key should recover after restore_partition re-establishes credentials"
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

// =========================================================================
// AES-XTS unmask key — reset-triggered tests
// =========================================================================

/// After a reset on `UnmaskKey`, `unmask_key` triggers
/// `restore_partition` + `reopen_session_if_needed` and recovers.
#[api_test]
fn test_aes_xts_unmask_key_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let masked_key = generate_xts_masked_key(&session);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::UnmaskKey, 1));

    let result = unmask_xts_key(&session, &masked_key);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-XTS unmask_key should recover after reset via restore_partition, got: {:?}",
        result.as_ref().map(|_| ())
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, AES-XTS `unmask_key` does not recover from a reset.
#[api_test]
fn test_aes_xts_unmask_key_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let masked_key = generate_xts_masked_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::UnmaskKey, 1));

    let result = unmask_xts_key(&session, &masked_key);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-XTS unmask_key without resiliency should fail after reset, got: {:?}",
        result.as_ref().map(|_| ())
    );
}

/// Two consecutive resets on `UnmaskKey` are each followed by a
/// successful recovery.
#[api_test]
fn test_aes_xts_unmask_key_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let masked_key = generate_xts_masked_key(&session);

    // First reset → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::UnmaskKey, 1));
    let result1 = unmask_xts_key(&session, &masked_key);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First AES-XTS unmask_key should recover after reset"
    );

    // Second reset → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::UnmaskKey, 1));
    let result2 = unmask_xts_key(&session, &masked_key);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second AES-XTS unmask_key should recover after reset"
    );
}

// =========================================================================
// AES-XTS key generation — fault-injection tests
// =========================================================================

/// Build AES-XTS key properties for test key generation.
fn aes_xts_key_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES-XTS key props")
}

/// AES-XTS `generate_key` recovers from a single transient fault on
/// `AesGenerateKey`, for every retryable error code.
#[api_test]
fn test_aes_xts_generate_key_recovers_from_single_fault() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        inject_fault(FaultRule::fail_nth(DdiOp::AesGenerateKey, 1, *error));

        let mut algo = HsmAesXtsKeyGenAlgo::default();
        let result = HsmKeyManager::generate_key(&session, &mut algo, aes_xts_key_props());
        clear_faults();

        assert!(
            result.is_ok(),
            "AES-XTS generate_key should recover after a single {error:?}"
        );
    }
}

/// AES-XTS `generate_key` recovers on the last retry.
#[api_test]
fn test_aes_xts_generate_key_recovers_on_last_retry() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        inject_fault(FaultRule::fail_next(
            DdiOp::AesGenerateKey,
            MAX_RETRIES,
            *error,
        ));

        let mut algo = HsmAesXtsKeyGenAlgo::default();
        let result = HsmKeyManager::generate_key(&session, &mut algo, aes_xts_key_props());
        clear_faults();

        assert!(
            result.is_ok(),
            "AES-XTS generate_key should recover on the last retry after \
             {MAX_RETRIES} consecutive {error:?}"
        );
    }
}

/// AES-XTS `generate_key` fails when all retries are exhausted.
#[api_test]
fn test_aes_xts_generate_key_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        inject_fault(FaultRule::fail_next(
            DdiOp::AesGenerateKey,
            MAX_RETRIES + 1,
            *error,
        ));

        let mut algo = HsmAesXtsKeyGenAlgo::default();
        let result = HsmKeyManager::generate_key(&session, &mut algo, aes_xts_key_props());
        clear_faults();

        assert!(
            result.is_err(),
            "AES-XTS generate_key should fail after exhausting retries \
             with {error:?}"
        );
    }
}

/// Without resiliency, AES-XTS `generate_key` does not retry.
#[api_test]
fn test_aes_xts_generate_key_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();

    inject_fault(FaultRule::fail_next(
        DdiOp::AesGenerateKey,
        1,
        DriverError::IoAborted,
    ));

    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_xts_key_props());
    clear_faults();

    assert!(
        result.is_err(),
        "AES-XTS generate_key without resiliency should fail"
    );
}

/// AES-XTS `generate_key` recovers from compound fault on
/// AesGenerateKey + InitBk3.
#[api_test]
fn test_aes_xts_generate_key_recovers_from_compound_fault() {
    if use_tpm() {
        return;
    }
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    inject_fault(FaultRule::fail_next(
        DdiOp::AesGenerateKey,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::InitBk3,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_xts_key_props());
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-XTS generate_key should recover from compound faults"
    );
}

// =========================================================================
// AES-XTS key generation — reset-triggered tests
// =========================================================================

/// After a reset on `AesGenerateKey`, AES-XTS `generate_key` recovers.
#[api_test]
fn test_aes_xts_generate_key_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));

    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_xts_key_props());
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-XTS generate_key should recover after reset"
    );
}

/// Without resiliency, AES-XTS `generate_key` does not recover from a reset.
#[api_test]
fn test_aes_xts_generate_key_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();

    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));

    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let result = HsmKeyManager::generate_key(&session, &mut algo, aes_xts_key_props());
    clear_faults();

    assert!(
        result.is_err(),
        "AES-XTS generate_key without resiliency should fail after reset"
    );
}

/// Two consecutive resets on `AesGenerateKey` for AES-XTS are each
/// followed by a successful recovery.
#[api_test]
fn test_aes_xts_generate_key_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));
    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let result1 = HsmKeyManager::generate_key(&session, &mut algo, aes_xts_key_props());
    clear_faults();
    assert!(
        result1.is_ok(),
        "First AES-XTS generate_key should recover after reset"
    );

    inject_fault(FaultRule::reset_on_next(DdiOp::AesGenerateKey, 1));
    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let result2 = HsmKeyManager::generate_key(&session, &mut algo, aes_xts_key_props());
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second AES-XTS generate_key should recover after reset"
    );
}

// =========================================================================
// ECC key pair generation — missing test patterns
// =========================================================================

/// ECC `generate_key_pair` fails when all retries are exhausted.
#[api_test]
fn test_ecc_generate_key_pair_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        inject_fault(FaultRule::fail_next(
            DdiOp::EccGenerateKeyPair,
            MAX_RETRIES + 1,
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
            result.is_err(),
            "ECC generate_key_pair should fail after exhausting retries \
             with {error:?}"
        );
    }
}

/// ECC `generate_key_pair` recovers from compound fault on
/// EccGenerateKeyPair + InitBk3.
#[api_test]
fn test_ecc_generate_key_pair_recovers_from_compound_fault() {
    if use_tpm() {
        return;
    }
    let (_part, session, _ctx) = init_with_resiliency_and_session();

    inject_fault(FaultRule::fail_next(
        DdiOp::EccGenerateKeyPair,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::InitBk3,
        1,
        FaultError::Driver(DriverError::IoAborted),
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
        "ECC generate_key_pair should recover from compound faults"
    );
}
