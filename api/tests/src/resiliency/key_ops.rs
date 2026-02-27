// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests for key operations.
//!
//! These tests exercise the `#[resiliency_key_op]` macro's
//! restore-partition + session-reopen + key-refresh recovery on
//! key operations using two complementary strategies:
//!
//! 1. Fault-injection tests — inject transient DDI faults through
//!    the resiliency mock device and verify the retry path recovers.
//! 2. NSSR-triggered tests — trigger an NVMe Subsystem Reset during
//!    a DDI operation via `FaultRule::reset_on_next` (simulating a live
//!    migration event occurring mid-operation) so the DDI returns
//!    `SessionNeedsRenegotiation` naturally, then verify that
//!    `restore_partition` + `reopen_session_if_needed` +
//!    `refresh_from_masked` recovers.
//!
//! Key operations retry only when resiliency is enabled (a
//! [`HsmResiliencyConfig`] was passed to [`HsmPartition::init`]).
//!
//! On a retryable failure the `#[resiliency_key_op]` macro:
//! 1. Applies exponential backoff for IO-abort / `PendingKeyGeneration`
//!    errors (not for `SessionNeedsRenegotiation`).
//! 2. Calls `restore_partition` to re-establish credentials.
//! 3. Calls `reopen_session_if_needed` to reopen the stale session.
//! 4. Calls `key.refresh_from_masked()` to unmask the key and obtain
//!    a fresh device handle.
//! 5. Retries the operation.
//!
//! # DDI operations under test
//!
//! | Key operation           | DDI op              |
//! |-------------------------|---------------------|
//! | AES-CBC encrypt/decrypt | `AesEncryptDecrypt` |
//! | ECC sign                | `EccSign`           |
//! | HMAC sign               | `Hmac`              |
//!
//! Note: AES-GCM and AES-XTS encrypt/decrypt use fast-path DDI methods
//! (`exec_op_fp_gcm_slice`, `exec_op_fp_xts_slice`) which bypass the
//! fault injection in the resiliency mock device. They are therefore
//! not tested here.
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

/// All error codes that trigger `resiliency_key_op` retry when resiliency is enabled.
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

// ── Key creation helpers ─────────────────────────────────────────────────

/// Generate an AES-256 session key for encryption/decryption tests.
fn generate_aes_key(session: &HsmSession) -> HsmAesKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES key props");
    let mut algo = HsmAesKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES key")
}

/// Generate an ECC P-256 key pair for signing tests.
fn generate_ecc_sign_key_pair(session: &HsmSession) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC public key props");

    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate ECC key pair")
}

/// Hash test data with SHA-256.
fn hash_data(session: &HsmSession, data: &[u8]) -> Vec<u8> {
    let mut hash_algo = HsmHashAlgo::Sha256;
    HsmHasher::hash_vec(session, &mut hash_algo, data).expect("Failed to hash data")
}

// ── AES-CBC encrypt helpers ──────────────────────────────────────────────

/// Create a fresh AES-CBC algo instance configured for PKCS#7 padding.
fn new_cbc_algo(iv: &[u8]) -> HsmAesCbcAlgo {
    HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo")
}

/// AES-CBC encrypt with output buffer.
fn cbc_encrypt(key: &HsmAesKey, iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    // Length query
    let cipher_len = {
        let mut algo = new_cbc_algo(iv);
        HsmEncrypter::encrypt(&mut algo, key, plaintext, None)?
    };

    let mut out = vec![0u8; cipher_len];
    let written = {
        let mut algo = new_cbc_algo(iv);
        HsmEncrypter::encrypt(&mut algo, key, plaintext, Some(&mut out))?
    };
    out.truncate(written);
    Ok(out)
}

// =========================================================================
// AES-CBC encrypt — single-fault recovery
// =========================================================================

/// AES-CBC `encrypt` recovers from a single transient fault on
/// `AesEncryptDecrypt`, for every retryable error code.
#[api_test]
fn test_aes_cbc_encrypt_recovers_from_single_fault() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let key = generate_aes_key(&session);
        let iv = [0u8; 16];
        let plaintext = b"test data for encryption!!!!!!!"; // 31 bytes, padding gets it to 32

        // The length query call (output == None) also calls AesEncryptDecrypt.
        // We need to fault an actual encrypt call with an output buffer.
        // Use fail_next to hit the next call that hasn't yet been made.
        inject_fault(FaultRule::fail_next(DdiOp::AesEncryptDecrypt, 1, *error));

        let result = cbc_encrypt(&key, &iv, plaintext);
        clear_faults();

        assert!(
            result.is_ok(),
            "AES-CBC encrypt should recover after a single {error:?} on AesEncryptDecrypt, got: {result:?}"
        );
    }
}

// =========================================================================
// AES-CBC encrypt — last-retry recovery
// =========================================================================

/// AES-CBC `encrypt` recovers on the last retry when
/// `AesEncryptDecrypt` fails for the first `MAX_RETRIES` attempts.
#[api_test]
fn test_aes_cbc_encrypt_recovers_on_last_retry() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let key = generate_aes_key(&session);
        let iv = [0u8; 16];
        let plaintext = b"test data for encryption!!!!!!!";

        inject_fault(FaultRule::fail_next(
            DdiOp::AesEncryptDecrypt,
            MAX_RETRIES,
            *error,
        ));

        let result = cbc_encrypt(&key, &iv, plaintext);
        clear_faults();

        assert!(
            result.is_ok(),
            "AES-CBC encrypt should recover on the last retry after {MAX_RETRIES} consecutive {error:?}, got: {result:?}"
        );
    }
}

// =========================================================================
// ECC sign — single-fault recovery
// =========================================================================

/// ECC `sign` recovers from a single transient fault on
/// `EccSign`, for every retryable error code.
#[api_test]
fn test_ecc_sign_recovers_from_single_fault() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
        let hash = hash_data(&session, b"Test data for ECC signing");

        inject_fault(FaultRule::fail_nth(DdiOp::EccSign, 1, *error));

        let mut sign_algo = HsmEccSignAlgo::default();
        let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
        clear_faults();

        assert!(
            result.is_ok(),
            "ECC sign should recover after a single {error:?} on EccSign, got: {result:?}"
        );
    }
}

// =========================================================================
// ECC sign — last-retry recovery
// =========================================================================

/// ECC `sign` recovers on the last retry when `EccSign` fails for
/// the first `MAX_RETRIES` attempts.
#[api_test]
fn test_ecc_sign_recovers_on_last_retry() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
        let hash = hash_data(&session, b"Test data for ECC signing");

        inject_fault(FaultRule::fail_next(DdiOp::EccSign, MAX_RETRIES, *error));

        let mut sign_algo = HsmEccSignAlgo::default();
        let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
        clear_faults();

        assert!(
            result.is_ok(),
            "ECC sign should recover on the last retry after {MAX_RETRIES} consecutive {error:?}, got: {result:?}"
        );
    }
}

// =========================================================================
// HMAC sign — single-fault recovery
// =========================================================================

/// HMAC `sign` recovers from a single transient fault on
/// `Hmac`, for every retryable error code.
#[api_test]
fn test_hmac_sign_recovers_from_single_fault() {
    for error in RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();

        // Generate an HMAC key via ECDH + HKDF (the standard test pattern).
        let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
        let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

        let shared_secret = ecdh_derive(&session, &priv_key_a, &pub_key_b);
        let hmac_key = hkdf_derive_hmac_key(&session, &shared_secret, HsmKeyKind::HmacSha256, 256);

        inject_fault(FaultRule::fail_nth(DdiOp::Hmac, 1, *error));

        let mut sign_algo = HsmHmacAlgo::new();
        let result = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");
        clear_faults();

        assert!(
            result.is_ok(),
            "HMAC sign should recover after a single {error:?} on Hmac, got: {result:?}"
        );
    }
}

// =========================================================================
// No retry without resiliency
// =========================================================================

/// Without resiliency, AES-CBC `encrypt` does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_aes_cbc_encrypt_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"test data for encryption!!!!!!!";

    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        DriverError::IoAborted,
    ));

    let result = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();

    assert_eq!(
        result.unwrap_err(),
        HsmError::IoAborted,
        "AES-CBC encrypt without resiliency should propagate IoAborted immediately"
    );
}

/// Without resiliency, ECC `sign` does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_ecc_sign_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    inject_fault(FaultRule::fail_nth(
        DdiOp::EccSign,
        1,
        DriverError::IoAborted,
    ));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();

    assert_eq!(
        result.unwrap_err(),
        HsmError::IoAborted,
        "ECC sign without resiliency should propagate IoAborted immediately"
    );
}

// =========================================================================
// Exhaustion — all retries fail
// =========================================================================

/// When all retry attempts are exhausted, AES-CBC `encrypt` returns
/// the last transient error.
#[api_test]
fn test_aes_cbc_encrypt_fails_after_all_retries_exhausted() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"test data for encryption!!!!!!!";

    // Fail MAX_RETRIES + 1 times → 1 initial + MAX_RETRIES retries all fail.
    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        MAX_RETRIES + 1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();

    assert_eq!(
        result.unwrap_err(),
        HsmError::IoAborted,
        "AES-CBC encrypt should return IoAborted after exhausting all retries"
    );
}

/// When all retry attempts are exhausted, ECC `sign` returns the
/// last transient error.
#[api_test]
fn test_ecc_sign_fails_after_all_retries_exhausted() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    inject_fault(FaultRule::fail_next(
        DdiOp::EccSign,
        MAX_RETRIES + 1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();

    assert_eq!(
        result.unwrap_err(),
        HsmError::IoAborted,
        "ECC sign should return IoAborted after exhausting all retries"
    );
}

// =========================================================================
// Non-retryable error propagates
// =========================================================================

/// A non-retryable error on `AesEncryptDecrypt` is not retried.
#[api_test]
fn test_aes_cbc_encrypt_non_retryable_error_propagates() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"test data for encryption!!!!!!!";

    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        FaultError::Status(DdiStatus::InvalidArg),
    ));

    let result = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-CBC encrypt should fail on a non-retryable error even with resiliency enabled"
    );
}

/// A non-retryable error on `EccSign` is not retried.
#[api_test]
fn test_ecc_sign_non_retryable_error_propagates() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    inject_fault(FaultRule::fail_nth(
        DdiOp::EccSign,
        1,
        FaultError::Status(DdiStatus::InvalidArg),
    ));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();

    assert!(
        result.is_err(),
        "ECC sign should fail on a non-retryable error even with resiliency enabled"
    );
}

// =========================================================================
// restore_partition + key refresh verification
// =========================================================================

/// When AES-CBC `encrypt` retries, `restore_partition` re-establishes
/// credentials (calls `InitBk3`) and `refresh_from_masked` unmasks
/// the key (calls `UnmaskKey`).
#[api_test]
fn test_restore_and_refresh_on_aes_cbc_encrypt_retry() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"test data for encryption!!!!!!!";

    let bk3_before = op_call_count(DdiOp::InitBk3);
    let unmask_before = op_call_count(DdiOp::UnmaskKey);

    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = cbc_encrypt(&key, &iv, plaintext);

    let bk3_after = op_call_count(DdiOp::InitBk3);
    let unmask_after = op_call_count(DdiOp::UnmaskKey);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-CBC encrypt should recover after restore + key refresh"
    );
    assert!(
        bk3_after > bk3_before,
        "InitBk3 should have been called during restore_partition \
         (before: {bk3_before}, after: {bk3_after})"
    );
    assert!(
        unmask_after > unmask_before,
        "UnmaskKey should have been called during refresh_from_masked \
         (before: {unmask_before}, after: {unmask_after})"
    );
}

/// When ECC `sign` retries, `restore_partition` re-establishes
/// credentials and `refresh_from_masked` unmasks the key.
#[api_test]
fn test_restore_and_refresh_on_ecc_sign_retry() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    let bk3_before = op_call_count(DdiOp::InitBk3);
    let unmask_before = op_call_count(DdiOp::UnmaskKey);

    inject_fault(FaultRule::fail_nth(
        DdiOp::EccSign,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);

    let bk3_after = op_call_count(DdiOp::InitBk3);
    let unmask_after = op_call_count(DdiOp::UnmaskKey);
    clear_faults();

    assert!(
        result.is_ok(),
        "ECC sign should recover after restore + key refresh"
    );
    assert!(
        bk3_after > bk3_before,
        "InitBk3 should have been called during restore_partition \
         (before: {bk3_before}, after: {bk3_after})"
    );
    assert!(
        unmask_after > unmask_before,
        "UnmaskKey should have been called during refresh_from_masked \
         (before: {unmask_before}, after: {unmask_after})"
    );
}

// =========================================================================
// NSSR-triggered tests — AES-CBC encrypt
// =========================================================================

/// After an NSSR on `AesEncryptDecrypt`, AES-CBC `encrypt` triggers
/// `restore_partition` + `reopen_session_if_needed` +
/// `refresh_from_masked` and recovers.
#[api_test]
fn test_aes_cbc_encrypt_recovers_after_nssr() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"test data for encryption!!!!!!!";

    let bk3_before = op_call_count(DdiOp::InitBk3);

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));

    let result = cbc_encrypt(&key, &iv, plaintext);

    let bk3_after = op_call_count(DdiOp::InitBk3);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-CBC encrypt should recover after NSSR via restore + reopen + refresh, got: {result:?}"
    );
    assert!(
        bk3_after > bk3_before,
        "InitBk3 should have been called during restore_partition after NSSR \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, AES-CBC `encrypt` does not recover from
/// an NSSR — the error propagates immediately.
#[api_test]
fn test_aes_cbc_encrypt_fails_after_nssr_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"test data for encryption!!!!!!!";

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));

    let result = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-CBC encrypt without resiliency should fail after NSSR, got: {result:?}"
    );
}

/// Two consecutive NSSRs on `AesEncryptDecrypt` are each followed by a
/// successful recovery.
#[api_test]
fn test_aes_cbc_encrypt_recovers_after_consecutive_nssr() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"test data for encryption!!!!!!!";

    // First NSSR → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));
    let result1 = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First AES-CBC encrypt should recover after NSSR"
    );

    // Second NSSR → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));
    let result2 = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second AES-CBC encrypt should recover after NSSR"
    );
}

// =========================================================================
// NSSR-triggered tests — ECC sign
// =========================================================================

/// After an NSSR on `EccSign`, ECC `sign` triggers
/// `restore_partition` + `reopen_session_if_needed` +
/// `refresh_from_masked` and recovers.
#[api_test]
fn test_ecc_sign_recovers_after_nssr() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    let bk3_before = op_call_count(DdiOp::InitBk3);

    inject_fault(FaultRule::reset_on_next(DdiOp::EccSign, 1));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);

    let bk3_after = op_call_count(DdiOp::InitBk3);
    clear_faults();

    assert!(
        result.is_ok(),
        "ECC sign should recover after NSSR via restore + reopen + refresh, got: {result:?}"
    );
    assert!(
        bk3_after > bk3_before,
        "InitBk3 should have been called during restore_partition after NSSR \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, ECC `sign` does not recover from an NSSR.
#[api_test]
fn test_ecc_sign_fails_after_nssr_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    inject_fault(FaultRule::reset_on_next(DdiOp::EccSign, 1));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();

    assert!(
        result.is_err(),
        "ECC sign without resiliency should fail after NSSR, got: {result:?}"
    );
}

/// Two consecutive NSSRs on `EccSign` are each followed by a successful
/// recovery.
#[api_test]
fn test_ecc_sign_recovers_after_consecutive_nssr() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    // First NSSR → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::EccSign, 1));
    let mut sign_algo = HsmEccSignAlgo::default();
    let result1 = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();
    assert!(result1.is_ok(), "First ECC sign should recover after NSSR");

    // Second NSSR → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::EccSign, 1));
    let mut sign_algo = HsmEccSignAlgo::default();
    let result2 = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();
    assert!(result2.is_ok(), "Second ECC sign should recover after NSSR");
}

// =========================================================================
// Compound fault: key op + restore's init_part
// =========================================================================

/// When AES-CBC `encrypt` retries and `restore_partition`'s inner
/// `init_part` also hits a transient fault on `InitBk3`, both
/// retry mechanisms recover and the encrypt ultimately succeeds.
#[api_test]
fn test_aes_cbc_encrypt_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"test data for encryption!!!!!!!";

    // AesEncryptDecrypt → IoAborted → triggers retry path.
    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    // During restore, init_part's InitBk3 also fails transiently.
    inject_fault(FaultRule::fail_next(
        DdiOp::InitBk3,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-CBC encrypt should recover from compound faults on AesEncryptDecrypt + InitBk3, got: {result:?}"
    );
}

/// When ECC `sign` retries and `restore_partition`'s inner
/// `init_part` also hits a transient fault, both recover.
#[api_test]
fn test_ecc_sign_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    // EccSign → IoAborted → triggers retry path.
    inject_fault(FaultRule::fail_nth(
        DdiOp::EccSign,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    // During restore, init_part's EstablishCredential also fails transiently.
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();

    assert!(
        result.is_ok(),
        "ECC sign should recover from compound faults on EccSign + EstablishCredential, got: {result:?}"
    );
}

// ── HMAC helpers ─────────────────────────────────────────────────────────

/// Generate an ECC P-256 key pair with derive capability for ECDH.
fn generate_ecc_derive_key_pair(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC public key props");

    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate ECC key pair for ECDH")
}

/// Perform ECDH key derivation.
fn ecdh_derive(
    session: &HsmSession,
    priv_key: &HsmEccPrivateKey,
    peer_pub_key: &HsmEccPublicKey,
) -> HsmGenericSecretKey {
    let pub_key_der = peer_pub_key
        .pub_key_der_vec()
        .expect("Failed to get peer public key DER");
    let mut algo = EcdhAlgo::new(&pub_key_der);
    let bits = priv_key
        .ecc_curve()
        .expect("ECC curve missing")
        .key_size_bits() as u32;
    let secret_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(bits)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build secret key props");
    HsmKeyManager::derive_key(session, &mut algo, priv_key, secret_props)
        .expect("Failed to derive ECDH shared secret")
}

/// Derive an HMAC key from a shared secret via HKDF.
fn hkdf_derive_hmac_key(
    session: &HsmSession,
    shared_secret: &HsmGenericSecretKey,
    key_kind: HsmKeyKind,
    bits: u32,
) -> HsmHmacKey {
    let hash_algo = match key_kind {
        HsmKeyKind::HmacSha256 => HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha384 => HsmHashAlgo::Sha384,
        HsmKeyKind::HmacSha512 => HsmHashAlgo::Sha512,
        _ => panic!("Expected HMAC key kind"),
    };

    let hmac_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(key_kind)
        .bits(bits)
        .can_sign(true)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build HMAC key props");

    let mut hkdf_algo = HsmHkdfAlgo::new(hash_algo, Some(b"test_salt"), Some(b"test_info"))
        .expect("Failed to create HKDF algo");

    let derived_key =
        HsmKeyManager::derive_key(session, &mut hkdf_algo, shared_secret, hmac_key_props)
            .expect("Failed to derive HMAC key via HKDF");

    derived_key
        .try_into()
        .expect("Failed to convert derived key to HsmHmacKey")
}
