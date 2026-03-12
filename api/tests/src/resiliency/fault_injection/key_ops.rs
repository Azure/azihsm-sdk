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
//! 2. Reset-triggered tests — trigger an NVMe Subsystem Reset during
//!    a DDI operation via `FaultRule::reset_on_next` (simulating a live
//!    migration event occurring mid-operation) so the DDI returns
//!    `SessionNeedsRenegotiation` naturally, then verify that
//!    `restore_partition` + `reopen_session_if_needed` +
//!    `restore_from_masked` recovers.
//!
//! Key operations retry only when resiliency is enabled (a
//! [`HsmResiliencyConfig`] was passed to [`HsmPartition::init`]).
//!
//! On a retryable failure the `#[resiliency_key_op]` macro:
//! 1. Applies exponential backoff for IO-abort / `PendingKeyGeneration`
//!    errors (not for `SessionNeedsRenegotiation`).
//! 2. Calls `restore_partition` to re-establish credentials.
//! 3. Calls `reopen_session_if_needed` to reopen the stale session.
//! 4. Calls `key.restore_from_masked()` to unmask the key and obtain
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
//! | HMAC verify             | `Hmac`              |
//! | RSA sign                | `RsaModExp`         |
//! | RSA decrypt             | `RsaModExp`         |
//! | ECDH derive             | `EcdhKeyExchange`   |
//! | HKDF derive             | `HkdfDerive`        |
//! | AES key unwrap          | `RsaUnwrap`         |
//! | ECC key pair unwrap     | `RsaUnwrap`         |
//! | AES-XTS key unwrap      | `RsaUnwrap`         |
//! | ECC key attestation     | `AttestKey`         |
//! | Key deletion            | `DeleteKey`         |
//!
//! Note: AES-GCM and AES-XTS encrypt/decrypt use fast-path DDI methods
//! (`exec_op_fp_gcm_slice`, `exec_op_fp_xts_slice`) which bypass the
//! fault injection in the resiliency mock device. They are therefore
//! not tested here.
//!
//! # Adding a new retryable error
//!
//! Append the new [`FaultError`] variant to [`RETRYABLE_ERRORS`]
//! (and to [`super::ALL_RETRYABLE_ERRORS`] if it's new globally).
//! All loop-based tests will automatically cover it. To add a
//! non-retryable error, append to [`super::NON_RETRYABLE_ERRORS`].

use azihsm_crypto as crypto;
use azihsm_res_test_dev::DdiOp;
use azihsm_res_test_dev::DdiStatus;
use azihsm_res_test_dev::DriverError;
use azihsm_res_test_dev::FaultError;
use azihsm_res_test_dev::FaultRule;
use azihsm_res_test_dev::clear_faults;
use azihsm_res_test_dev::inject_fault;
use azihsm_res_test_dev::op_call_count;

use super::super::helpers::*;
use crate::utils::aes_xts::build_xts_wrapped_blob;
use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

// Retryable errors & helpers

/// Returns `true` when `error` is one of the key-op-retryable error codes.
fn is_key_op_retryable(error: &FaultError) -> bool {
    super::is_retryable(error, super::KEY_OP_RETRYABLE_ERRORS)
}

/// Expected number of times the faulted DDI op is invoked in a
/// fault-injection test.
///
/// * Retryable errors: `min(injected_faults + 1, MAX_RETRIES + 1)`.
///   The `+1` accounts for the successful call after all faults are
///   consumed, capped by the maximum number of attempts.
/// * Non-retryable errors: 1 (single failed call, no retry).
fn expected_op_calls(error: &FaultError, injected_faults: u32) -> u32 {
    super::expected_op_calls_for(error, injected_faults, super::KEY_OP_RETRYABLE_ERRORS)
}

// Session helpers

// Key creation & crypto helpers imported from `crate::utils::key_helpers`.

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

/// Generate an HMAC-SHA256 key via ECDH + HKDF.
fn generate_hmac_key(session: &HsmSession) -> HsmHmacKey {
    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(session, HsmEccCurve::P256);

    let shared_secret =
        ecdh_derive(session, &priv_key_a, &pub_key_b).expect("ECDH derivation failed");
    hkdf_derive_hmac_key(session, &shared_secret, HsmKeyKind::HmacSha256, 256)
}

// Key attestation helpers

/// Generate key report for an ECC private key (two-call pattern: size → fill).
fn generate_ecc_key_report(key: &HsmEccPrivateKey) -> HsmResult<Vec<u8>> {
    let report_data = [0x42u8; 128];

    let report_size = HsmKeyManager::generate_key_report(key, &report_data, None)?;
    let mut report_buffer = vec![0u8; report_size];
    let actual_size =
        HsmKeyManager::generate_key_report(key, &report_data, Some(&mut report_buffer))?;
    report_buffer.truncate(actual_size);
    Ok(report_buffer)
}

// RSA key helpers (unwrap-based import for sign / decrypt tests)

/// Generate an RSA 2048 unwrapping key pair.
fn generate_rsa_unwrapping_key_pair(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build RSA unwrapping private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build RSA unwrapping public key props");

    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate RSA unwrapping key pair")
}

/// Import an RSA 2048 key pair via wrap/unwrap for signing tests.
fn import_rsa_sign_key(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    use crypto::*;
    let sw_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate software RSA key");
    let der = sw_key.to_vec().expect("Failed to export RSA key DER");
    let (unwrap_priv, unwrap_pub) = generate_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der)
        .expect("Failed to wrap RSA key");

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build RSA sign private key props");
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build RSA sign public key props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .expect("Failed to unwrap RSA sign key pair")
}

/// Import an RSA 2048 key pair via wrap/unwrap for encrypt/decrypt tests.
fn import_rsa_enc_key(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    use crypto::*;
    let sw_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate software RSA key");
    let der = sw_key.to_vec().expect("Failed to export RSA key DER");
    let (unwrap_priv, unwrap_pub) = generate_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der)
        .expect("Failed to wrap RSA key");

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build RSA decrypt private key props");
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build RSA encrypt public key props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .expect("Failed to unwrap RSA enc key pair")
}

/// RSA sign helper: hash data and sign with PKCS#1 padding.
fn rsa_sign(key: &HsmRsaPrivateKey, session: &HsmSession, data: &[u8]) -> HsmResult<Vec<u8>> {
    let hash = hash_data(session, data);
    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    HsmSigner::sign_vec(&mut algo, key, &hash)
}

// HMAC verify helper

/// HMAC verify helper: sign first (no faults), return the signature for verify.
fn hmac_sign_for_verify(key: &HsmHmacKey, data: &[u8]) -> Vec<u8> {
    let mut algo = HsmHmacAlgo::new();
    HsmSigner::sign_vec(&mut algo, key, data).expect("HMAC sign (setup) failed")
}

/// HMAC verify: verify a pre-computed signature.
fn hmac_verify(key: &HsmHmacKey, data: &[u8], signature: &[u8]) -> HsmResult<bool> {
    let mut algo = HsmHmacAlgo::new();
    HsmVerifier::verify(&mut algo, key, data, signature)
}

// ECDH derive helper

// HKDF derive helper

/// Derive an AES-256 key from a shared secret via HKDF.
fn hkdf_derive_aes_key(
    session: &HsmSession,
    shared_secret: &HsmGenericSecretKey,
) -> HsmResult<HsmAesKey> {
    let aes_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES key props for HKDF");

    let mut hkdf_algo = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(b"salt"), Some(b"info"))
        .expect("Failed to create HKDF algo");

    let derived = HsmKeyManager::derive_key(session, &mut hkdf_algo, shared_secret, aes_props)?;
    derived.try_into().map_err(|_| HsmError::InternalError)
}

/// Set up a shared secret for HKDF tests (ECDH without faults).
fn setup_shared_secret(session: &HsmSession) -> HsmGenericSecretKey {
    let (priv_a, _pub_a) = generate_ecc_derive_key_pair(session, HsmEccCurve::P256);
    let (_priv_b, pub_b) = generate_ecc_derive_key_pair(session, HsmEccCurve::P256);
    ecdh_derive(session, &priv_a, &pub_b).expect("ECDH derivation failed")
}

// AES key unwrap helpers

/// Prepare wrapped AES-256 key bytes for unwrap tests.
fn prepare_wrapped_aes_key(session: &HsmSession) -> (HsmRsaPrivateKey, Vec<u8>) {
    let (unwrap_priv, unwrap_pub) = generate_rsa_unwrapping_key_pair(session);
    let aes_key_data = vec![0x42u8; 32]; // 256-bit AES key
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &aes_key_data)
        .expect("Failed to wrap AES key");
    (unwrap_priv, wrapped)
}

/// Unwrap an AES-256 key from wrapped bytes.
fn unwrap_aes_key(unwrapping_key: &HsmRsaPrivateKey, wrapped: &[u8]) -> HsmResult<HsmAesKey> {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES key props for unwrap");

    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    HsmKeyManager::unwrap_key(&mut unwrap_algo, unwrapping_key, wrapped, key_props)
}

// ECC key pair unwrap helpers

/// Prepare wrapped ECC P-256 key bytes for unwrap tests.
fn prepare_wrapped_ecc_key(session: &HsmSession) -> (HsmRsaPrivateKey, Vec<u8>) {
    use crypto::*;
    let sw_key =
        crypto::EccPrivateKey::from_curve(EccCurve::P256).expect("Failed to create ECC key");
    let der = sw_key.to_vec().expect("Failed to export ECC key DER");
    let (unwrap_priv, unwrap_pub) = generate_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der)
        .expect("Failed to wrap ECC key");
    (unwrap_priv, wrapped)
}

/// Unwrap an ECC P-256 key pair from wrapped bytes.
fn unwrap_ecc_key_pair(
    unwrapping_key: &HsmRsaPrivateKey,
    wrapped: &[u8],
) -> HsmResult<(HsmEccPrivateKey, HsmEccPublicKey)> {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC private key props for unwrap");
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC public key props for unwrap");

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        unwrapping_key,
        wrapped,
        priv_props,
        pub_props,
    )
}

// =========================================================================
// AES-CBC encrypt — fault-injection tests
// =========================================================================

/// AES-CBC `encrypt` recovers from a single transient fault on
/// `AesEncryptDecrypt` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_aes_cbc_encrypt_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let key = generate_aes_key(&session);
        let iv = crypto::Rng::rand_vec(16).expect("IV");
        let plaintext = b"test data for encryption!!!!!!!"; // 31 bytes

        let before = op_call_count(DdiOp::AesEncryptDecrypt);

        inject_fault(FaultRule::fail_next(DdiOp::AesEncryptDecrypt, 1, *error));

        let result = cbc_encrypt(&key, &iv, plaintext);
        let after = op_call_count(DdiOp::AesEncryptDecrypt);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "single fault on AesEncryptDecrypt",
        );

        let expected = expected_op_calls(error, 1);
        // AES-CBC uses a two-call pattern (length query + actual encrypt),
        // so the observed count may exceed the theoretical single-op count.
        assert!(
            after - before >= expected,
            "single fault on AesEncryptDecrypt: expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// AES-CBC `encrypt` recovers on the last retry when
/// `AesEncryptDecrypt` fails for the first `MAX_RETRIES` attempts
/// (retryable errors), or fails immediately on the first attempt
/// (non-retryable errors).
#[api_test]
fn test_aes_cbc_encrypt_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let key = generate_aes_key(&session);
        let iv = crypto::Rng::rand_vec(16).expect("IV");
        let plaintext = b"test data for encryption!!!!!!!";

        let before = op_call_count(DdiOp::AesEncryptDecrypt);

        inject_fault(FaultRule::fail_next(
            DdiOp::AesEncryptDecrypt,
            MAX_RETRIES,
            *error,
        ));

        let result = cbc_encrypt(&key, &iv, plaintext);
        let after = op_call_count(DdiOp::AesEncryptDecrypt);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "last retry on AesEncryptDecrypt",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert!(
            after - before >= expected,
            "last retry on AesEncryptDecrypt: expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// AES-CBC `encrypt` fails when `AesEncryptDecrypt` returns a retryable
/// error for `MAX_RETRIES + 1` consecutive calls, for every retryable
/// error code.
#[api_test]
fn test_aes_cbc_encrypt_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let key = generate_aes_key(&session);
        let iv = crypto::Rng::rand_vec(16).expect("IV");
        let plaintext = b"test data for encryption!!!!!!!";

        inject_fault(FaultRule::fail_next(
            DdiOp::AesEncryptDecrypt,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = cbc_encrypt(&key, &iv, plaintext);
        clear_faults();

        assert!(
            result.is_err(),
            "AES-CBC encrypt should fail after exhausting all {MAX_RETRIES} \
             retries with {error:?}, got: {result:?}"
        );
    }
}

/// Without resiliency, AES-CBC `encrypt` does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_aes_cbc_encrypt_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"test data for encryption!!!!!!!";

    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        DriverError::IoAborted,
    ));

    let result = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-CBC encrypt without resiliency should fail on IoAborted, \
         got: {result:?}"
    );
}

/// When AES-CBC `encrypt` retries and `restore_partition`'s inner
/// `init_part` also hits a transient fault on `InitBk3`, both
/// retry mechanisms recover and the encrypt ultimately succeeds.
///
/// Caller-source only — skipped when `AZIHSM_USE_TPM` is set
/// (TPM path uses `GetSealedBk3`, not `InitBk3`).
#[api_test]
fn test_aes_cbc_encrypt_recovers_from_compound_fault() {
    if use_tpm() {
        return;
    }
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
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
        "AES-CBC encrypt should recover from compound faults on \
         AesEncryptDecrypt + InitBk3, got: {result:?}"
    );
}

// =========================================================================
// AES-CBC encrypt — reset-triggered tests
// =========================================================================

/// After a reset on `AesEncryptDecrypt`, AES-CBC `encrypt` triggers
/// `restore_partition` + `reopen_session_if_needed` +
/// `restore_from_masked` and recovers.
#[api_test]
fn test_aes_cbc_encrypt_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"test data for encryption!!!!!!!";

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));

    let result = cbc_encrypt(&key, &iv, plaintext);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-CBC encrypt should recover after reset via restore + reopen + \
         refresh, got: {result:?}"
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, AES-CBC `encrypt` does not recover from a reset.
#[api_test]
fn test_aes_cbc_encrypt_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"test data for encryption!!!!!!!";

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));

    let result = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-CBC encrypt without resiliency should fail after reset, \
         got: {result:?}"
    );
}

/// Two consecutive resets on `AesEncryptDecrypt` are each followed by a
/// successful recovery.
#[api_test]
fn test_aes_cbc_encrypt_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"test data for encryption!!!!!!!";

    // First reset → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));
    let result1 = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First AES-CBC encrypt should recover after reset"
    );

    // Second reset → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));
    let result2 = cbc_encrypt(&key, &iv, plaintext);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second AES-CBC encrypt should recover after reset"
    );
}

// =========================================================================
// ECC sign — fault-injection tests
// =========================================================================

/// ECC `sign` recovers from a single transient fault on
/// `EccSign` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_ecc_sign_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
        let hash = hash_data(&session, b"Test data for ECC signing");

        let before = op_call_count(DdiOp::EccSign);

        inject_fault(FaultRule::fail_nth(DdiOp::EccSign, 1, *error));

        let mut sign_algo = HsmEccSignAlgo::default();
        let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
        let after = op_call_count(DdiOp::EccSign);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "single fault on EccSign",
        );

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on EccSign: expected {expected} calls for {error:?}, \
             got {}",
            after - before,
        );
    }
}

/// ECC `sign` recovers on the last retry when `EccSign` fails for
/// the first `MAX_RETRIES` attempts (retryable errors), or fails
/// immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_ecc_sign_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
        let hash = hash_data(&session, b"Test data for ECC signing");

        let before = op_call_count(DdiOp::EccSign);

        inject_fault(FaultRule::fail_next(DdiOp::EccSign, MAX_RETRIES, *error));

        let mut sign_algo = HsmEccSignAlgo::default();
        let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
        let after = op_call_count(DdiOp::EccSign);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "last retry on EccSign",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on EccSign: expected {expected} calls for {error:?}, \
             got {}",
            after - before,
        );
    }
}

/// ECC `sign` fails when `EccSign` returns a retryable error for
/// `MAX_RETRIES + 1` consecutive calls, for every retryable error code.
#[api_test]
fn test_ecc_sign_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
        let hash = hash_data(&session, b"Test data for ECC signing");

        inject_fault(FaultRule::fail_next(
            DdiOp::EccSign,
            MAX_RETRIES + 1,
            *error,
        ));

        let mut sign_algo = HsmEccSignAlgo::default();
        let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
        clear_faults();

        assert!(
            result.is_err(),
            "ECC sign should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}, got: {result:?}"
        );
    }
}

/// Without resiliency, ECC `sign` does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_ecc_sign_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    let before = op_call_count(DdiOp::EccSign);

    inject_fault(FaultRule::fail_nth(
        DdiOp::EccSign,
        1,
        DriverError::IoAborted,
    ));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    let after = op_call_count(DdiOp::EccSign);
    clear_faults();

    assert!(
        result.is_err(),
        "ECC sign without resiliency should fail on IoAborted, \
         got: {result:?}"
    );

    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 EccSign call, got {}",
        after - before,
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
        "ECC sign should recover from compound faults on \
         EccSign + EstablishCredential, got: {result:?}"
    );
}

// =========================================================================
// ECC sign — reset-triggered tests
// =========================================================================

/// After a reset on `EccSign`, ECC `sign` triggers
/// `restore_partition` + `reopen_session_if_needed` +
/// `restore_from_masked` and recovers.
#[api_test]
fn test_ecc_sign_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::EccSign, 1));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "ECC sign should recover after reset via restore + reopen + refresh, \
         got: {result:?}"
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, ECC `sign` does not recover from a reset.
#[api_test]
fn test_ecc_sign_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    inject_fault(FaultRule::reset_on_next(DdiOp::EccSign, 1));

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();

    assert!(
        result.is_err(),
        "ECC sign without resiliency should fail after reset, got: {result:?}"
    );
}

/// Two consecutive resets on `EccSign` are each followed by a successful
/// recovery.
#[api_test]
fn test_ecc_sign_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"Test data for ECC signing");

    // First reset → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::EccSign, 1));
    let mut sign_algo = HsmEccSignAlgo::default();
    let result1 = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();
    assert!(result1.is_ok(), "First ECC sign should recover after reset");

    // Second reset → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::EccSign, 1));
    let mut sign_algo = HsmEccSignAlgo::default();
    let result2 = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second ECC sign should recover after reset"
    );
}

// =========================================================================
// HMAC sign — fault-injection tests
// =========================================================================

/// HMAC `sign` recovers from a single transient fault on
/// `Hmac` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_hmac_sign_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let hmac_key = generate_hmac_key(&session);

        let before = op_call_count(DdiOp::Hmac);

        inject_fault(FaultRule::fail_nth(DdiOp::Hmac, 1, *error));

        let mut sign_algo = HsmHmacAlgo::new();
        let result = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");
        let after = op_call_count(DdiOp::Hmac);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "single fault on Hmac",
        );

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on Hmac: expected {expected} calls for {error:?}, \
             got {}",
            after - before,
        );
    }
}

/// HMAC `sign` recovers on the last retry when `Hmac` fails for
/// the first `MAX_RETRIES` attempts (retryable errors), or fails
/// immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_hmac_sign_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let hmac_key = generate_hmac_key(&session);

        let before = op_call_count(DdiOp::Hmac);

        inject_fault(FaultRule::fail_next(DdiOp::Hmac, MAX_RETRIES, *error));

        let mut sign_algo = HsmHmacAlgo::new();
        let result = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");
        let after = op_call_count(DdiOp::Hmac);
        clear_faults();

        super::assert_retryable_outcome(&result, error, is_key_op_retryable, "last retry on Hmac");

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on Hmac: expected {expected} calls for {error:?}, \
             got {}",
            after - before,
        );
    }
}

/// HMAC `sign` fails when `Hmac` returns a retryable error for
/// `MAX_RETRIES + 1` consecutive calls, for every retryable error code.
#[api_test]
fn test_hmac_sign_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let hmac_key = generate_hmac_key(&session);

        inject_fault(FaultRule::fail_next(DdiOp::Hmac, MAX_RETRIES + 1, *error));

        let mut sign_algo = HsmHmacAlgo::new();
        let result = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");
        clear_faults();

        assert!(
            result.is_err(),
            "HMAC sign should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}, got: {result:?}"
        );
    }
}

/// Without resiliency, HMAC `sign` does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_hmac_sign_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);

    let before = op_call_count(DdiOp::Hmac);

    inject_fault(FaultRule::fail_nth(DdiOp::Hmac, 1, DriverError::IoAborted));

    let mut sign_algo = HsmHmacAlgo::new();
    let result = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");
    let after = op_call_count(DdiOp::Hmac);
    clear_faults();

    assert!(
        result.is_err(),
        "HMAC sign without resiliency should fail on IoAborted, \
         got: {result:?}"
    );

    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 Hmac call, got {}",
        after - before,
    );
}

/// When HMAC `sign` retries and `restore_partition`'s inner
/// `init_part` also hits a transient fault, both recover.
#[api_test]
fn test_hmac_sign_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);

    // Hmac → IoAborted → triggers retry path.
    inject_fault(FaultRule::fail_nth(
        DdiOp::Hmac,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    // During restore, init_part's EstablishCredential also fails transiently.
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut sign_algo = HsmHmacAlgo::new();
    let result = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");
    clear_faults();

    assert!(
        result.is_ok(),
        "HMAC sign should recover from compound faults on \
         Hmac + EstablishCredential, got: {result:?}"
    );
}

// =========================================================================
// HMAC sign — reset-triggered tests
// =========================================================================

/// After a reset on `Hmac`, HMAC `sign` triggers `restore_partition` +
/// `reopen_session_if_needed` + `restore_from_masked` and recovers.
#[api_test]
fn test_hmac_sign_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::Hmac, 1));

    let mut sign_algo = HsmHmacAlgo::new();
    let result = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "HMAC sign should recover after reset via restore + reopen + refresh, \
         got: {result:?}"
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, HMAC `sign` does not recover from a reset.
#[api_test]
fn test_hmac_sign_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::Hmac, 1));

    let mut sign_algo = HsmHmacAlgo::new();
    let result = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");
    clear_faults();

    assert!(
        result.is_err(),
        "HMAC sign without resiliency should fail after reset, got: {result:?}"
    );
}

/// Two consecutive resets on `Hmac` are each followed by a successful
/// recovery.
#[api_test]
fn test_hmac_sign_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);

    // First reset → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::Hmac, 1));
    let mut sign_algo = HsmHmacAlgo::new();
    let result1 = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");
    clear_faults();
    assert!(
        result1.is_ok(),
        "First HMAC sign should recover after reset"
    );

    // Second reset → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::Hmac, 1));
    let mut sign_algo = HsmHmacAlgo::new();
    let result2 = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, b"test message");
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second HMAC sign should recover after reset"
    );
}

// =========================================================================
// Key attestation (generate_key_report) — fault-injection tests
// =========================================================================

/// ECC key attestation recovers from a single transient fault on
/// `AttestKey` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_ecc_key_report_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

        let before = op_call_count(DdiOp::AttestKey);

        inject_fault(FaultRule::fail_next(DdiOp::AttestKey, 1, *error));

        let result = generate_ecc_key_report(&priv_key);
        let after = op_call_count(DdiOp::AttestKey);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "single fault on AttestKey",
        );

        let expected = expected_op_calls(error, 1);
        // generate_key_report uses a two-call pattern (size query + fill),
        // so the observed count may exceed the theoretical single-op count.
        assert!(
            after - before >= expected,
            "single fault on AttestKey: expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// ECC key attestation recovers on the last retry when `AttestKey`
/// fails for the first `MAX_RETRIES` attempts (retryable errors),
/// or fails immediately on the first attempt (non-retryable errors).
#[api_test]
fn test_ecc_key_report_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

        let before = op_call_count(DdiOp::AttestKey);

        inject_fault(FaultRule::fail_next(DdiOp::AttestKey, MAX_RETRIES, *error));

        let result = generate_ecc_key_report(&priv_key);
        let after = op_call_count(DdiOp::AttestKey);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "last retry on AttestKey",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert!(
            after - before >= expected,
            "last retry on AttestKey: expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// ECC key attestation fails when `AttestKey` returns a retryable error
/// for `MAX_RETRIES + 1` consecutive calls, for every retryable error
/// code.
#[api_test]
fn test_ecc_key_report_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

        inject_fault(FaultRule::fail_next(
            DdiOp::AttestKey,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = generate_ecc_key_report(&priv_key);
        clear_faults();

        assert!(
            result.is_err(),
            "generate_key_report should fail after exhausting all retries"
        );
    }
}

/// Without resiliency, ECC key attestation does not retry —
/// `IoAborted` propagates immediately.
#[api_test]
fn test_ecc_key_report_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

    inject_fault(FaultRule::fail_next(
        DdiOp::AttestKey,
        1,
        DriverError::IoAborted,
    ));

    let result = generate_ecc_key_report(&priv_key);
    clear_faults();

    assert!(
        result.is_err(),
        "generate_key_report without resiliency should fail on IoAborted"
    );
}

/// When `generate_key_report` retries and `restore_partition`'s inner
/// `init_part` also hits a transient fault, both recover.
#[api_test]
fn test_ecc_key_report_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

    // AttestKey → SessionNeedsRenegotiation → triggers retry path.
    inject_fault(FaultRule::fail_next(
        DdiOp::AttestKey,
        1,
        FaultError::Status(DdiStatus::SessionNeedsRenegotiation),
    ));

    // During restore, init_part's EstablishCredential also fails transiently.
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = generate_ecc_key_report(&priv_key);
    clear_faults();

    assert!(
        result.is_ok(),
        "generate_key_report should recover from compound faults on \
         AttestKey + EstablishCredential, got: {result:?}"
    );
}

// =========================================================================
// Key attestation — reset-triggered tests
// =========================================================================

/// After a reset on `AttestKey`, `generate_key_report` triggers
/// `restore_partition` + `reopen_session_if_needed` +
/// `restore_from_masked` and recovers.
#[api_test]
fn test_ecc_key_report_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::AttestKey, 1));

    let result = generate_ecc_key_report(&priv_key);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "generate_key_report should recover after reset, got: {result:?}"
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, key attestation does not recover from a reset.
#[api_test]
fn test_ecc_key_report_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::AttestKey, 1));
    let result = generate_ecc_key_report(&priv_key);
    clear_faults();

    assert!(
        result.is_err(),
        "generate_key_report without resiliency should fail after reset, \
         got: {result:?}"
    );
}

/// Two consecutive resets on `AttestKey` are each followed by a
/// successful recovery.
#[api_test]
fn test_ecc_key_report_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

    // First reset → recover.
    inject_fault(FaultRule::reset_on_next(DdiOp::AttestKey, 1));
    let result1 = generate_ecc_key_report(&priv_key);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First generate_key_report should recover after reset"
    );

    // Second reset → recover again.
    inject_fault(FaultRule::reset_on_next(DdiOp::AttestKey, 1));
    let result2 = generate_ecc_key_report(&priv_key);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second generate_key_report should recover after reset"
    );
}

// =========================================================================
// Key deletion — epoch-aware deletion after reset
// =========================================================================

/// After a reset, explicit `delete_key` succeeds because the retryable
/// DDI error is suppressed (the device key table was wiped by reset).
#[api_test]
fn test_delete_key_succeeds_after_reset() {
    let (part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);

    // Trigger reset to wipe the device key table.
    part.reset().expect("reset failed");

    // Explicit delete should succeed — retryable DDI errors are
    // suppressed when resiliency is enabled.
    let result = HsmKeyManager::delete_key(key);
    assert!(
        result.is_ok(),
        "delete_key should succeed after reset, got: {result:?}"
    );
}

/// After a reset, explicit `delete_key` on an ECC key pair succeeds.
#[api_test]
fn test_delete_key_pair_succeeds_after_reset() {
    let (part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, pub_key) = generate_ecc_sign_key_pair(&session);

    part.reset().expect("reset failed");

    let result_priv = HsmKeyManager::delete_key(priv_key);
    assert!(
        result_priv.is_ok(),
        "delete_key (private) should succeed after reset, got: {result_priv:?}"
    );

    // Public key delete is always a no-op (software-only object).
    let result_pub = HsmKeyManager::delete_key(pub_key);
    assert!(
        result_pub.is_ok(),
        "delete_key (public) should succeed, got: {result_pub:?}"
    );
}

/// After a reset, explicit `delete_key` on a non-session (token) ECC key pair succeeds.
#[api_test]
fn test_delete_non_session_key_pair_succeeds_after_reset() {
    let (part, session, _ctx) = init_with_resiliency_and_session();

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(false)
        .build()
        .expect("Failed to build ECC private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(false)
        .build()
        .expect("Failed to build ECC public key props");

    let mut algo = HsmEccKeyGenAlgo::default();
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate non-session ECC key pair");

    part.reset().expect("reset failed");

    let result_priv = HsmKeyManager::delete_key(priv_key);
    assert!(
        result_priv.is_ok(),
        "delete_key (private, non-session) should succeed after reset, got: {result_priv:?}"
    );

    let result_pub = HsmKeyManager::delete_key(pub_key);
    assert!(
        result_pub.is_ok(),
        "delete_key (public, non-session) should succeed, got: {result_pub:?}"
    );
}

/// Drop after a reset does not panic. The best-effort DDI delete may
/// still be attempted (the epoch only becomes stale once another
/// operation triggers `restore_partition`), but any retryable error is
/// silently ignored so no ABA problem can occur.
#[api_test]
fn test_drop_after_reset_is_safe() {
    let (part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);

    part.reset().expect("reset failed");

    // Drop the key — the DDI delete call will fail because the
    // session is invalid after reset. Drop ignores errors.
    drop(key);
    // Test passes if no panic occurred.
}

/// When another operation has already triggered `restore_partition`
/// (incrementing the epoch), Drop on a stale-epoch key skips the DDI
/// call entirely.
#[api_test]
fn test_drop_skips_ddi_when_epoch_is_stale() {
    let (part, session, _ctx) = init_with_resiliency_and_session();
    let key_to_drop = generate_aes_key(&session);
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

    // reset — both keys become stale.
    part.reset().expect("reset failed");

    // A sign on priv_key triggers restore_partition + refresh.
    // This bumps the partition's restore_epoch.
    let hash = hash_data(&session, b"epoch trigger");
    let mut sign_algo = HsmEccSignAlgo::default();
    HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash).expect("sign should recover after reset");

    // key_to_drop was NOT refreshed → its epoch < partition epoch.
    // Drop should skip the DDI call.
    let delete_before = op_call_count(DdiOp::DeleteKey);
    drop(key_to_drop);
    let delete_after = op_call_count(DdiOp::DeleteKey);

    assert_eq!(
        delete_before, delete_after,
        "Drop should skip DDI when key epoch is stale \
         (before: {delete_before}, after: {delete_after})"
    );
}

/// Normal deletion (no reset) calls the DDI `DeleteKey` operation.
#[api_test]
fn test_delete_key_calls_ddi_without_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);

    let delete_before = op_call_count(DdiOp::DeleteKey);
    let result = HsmKeyManager::delete_key(key);
    let delete_after = op_call_count(DdiOp::DeleteKey);

    assert!(result.is_ok(), "delete_key should succeed, got: {result:?}");
    assert!(
        delete_after > delete_before,
        "DeleteKey DDI op should have been called \
         (before: {delete_before}, after: {delete_after})"
    );
}

/// Normal drop (no reset) calls the DDI `DeleteKey` operation.
#[api_test]
fn test_drop_calls_ddi_without_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);

    let delete_before = op_call_count(DdiOp::DeleteKey);
    drop(key);
    let delete_after = op_call_count(DdiOp::DeleteKey);

    assert!(
        delete_after > delete_before,
        "Drop should call DeleteKey when no reset occurred \
         (before: {delete_before}, after: {delete_after})"
    );
}

/// After reset + key refresh (triggered by a sign operation), deletion
/// calls DDI because the handle is current again.
#[api_test]
fn test_delete_key_after_refresh_calls_ddi() {
    let (part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

    // reset wipes the device key table.
    part.reset().expect("reset failed");

    // A sign operation triggers the resiliency retry loop which does
    // restore_partition + reopen_session + restore_from_masked.
    // After this, the key handle is current (epoch matches).
    let hash = hash_data(&session, b"refresh trigger");
    let mut sign_algo = HsmEccSignAlgo::default();
    let sign_result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
    assert!(
        sign_result.is_ok(),
        "sign should recover after reset: {sign_result:?}"
    );

    let delete_before = op_call_count(DdiOp::DeleteKey);
    let result = HsmKeyManager::delete_key(priv_key);
    let delete_after = op_call_count(DdiOp::DeleteKey);

    assert!(
        result.is_ok(),
        "delete_key after refresh should succeed, got: {result:?}"
    );
    assert!(
        delete_after > delete_before,
        "DeleteKey DDI op should be called after refresh \
         (before: {delete_before}, after: {delete_after})"
    );
}

// =========================================================================
// RSA sign — fault-injection tests
// =========================================================================

/// RSA `sign` recovers from a single transient fault on `RsaModExp`
/// for retryable error codes, and fails immediately for non-retryable ones.
#[api_test]
fn test_rsa_sign_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = import_rsa_sign_key(&session);

        let before = op_call_count(DdiOp::RsaModExp);

        inject_fault(FaultRule::fail_nth(DdiOp::RsaModExp, 1, *error));

        let result = rsa_sign(&priv_key, &session, b"test data for RSA signing");
        let after = op_call_count(DdiOp::RsaModExp);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "single fault on RsaModExp (sign)",
        );

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on RsaModExp (sign): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// RSA `sign` recovers on the last retry when `RsaModExp` fails for
/// the first `MAX_RETRIES` attempts.
#[api_test]
fn test_rsa_sign_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = import_rsa_sign_key(&session);

        let before = op_call_count(DdiOp::RsaModExp);

        inject_fault(FaultRule::fail_next(DdiOp::RsaModExp, MAX_RETRIES, *error));

        let result = rsa_sign(&priv_key, &session, b"test data for RSA signing");
        let after = op_call_count(DdiOp::RsaModExp);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "last retry on RsaModExp (sign)",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on RsaModExp (sign): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// RSA `sign` fails when `RsaModExp` returns a retryable error for
/// `MAX_RETRIES + 1` consecutive calls.
#[api_test]
fn test_rsa_sign_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = import_rsa_sign_key(&session);

        inject_fault(FaultRule::fail_next(
            DdiOp::RsaModExp,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = rsa_sign(&priv_key, &session, b"test data for RSA signing");
        clear_faults();

        assert!(
            result.is_err(),
            "RSA sign should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}, got: {result:?}"
        );
    }
}

/// Without resiliency, RSA `sign` does not retry.
#[api_test]
fn test_rsa_sign_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    let before = op_call_count(DdiOp::RsaModExp);

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaModExp,
        1,
        DriverError::IoAborted,
    ));

    let result = rsa_sign(&priv_key, &session, b"test data for RSA signing");
    let after = op_call_count(DdiOp::RsaModExp);
    clear_faults();

    assert!(
        result.is_err(),
        "RSA sign without resiliency should fail on IoAborted, got: {result:?}"
    );
    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 RsaModExp call, got {}",
        after - before,
    );
}

/// RSA `sign` recovers from compound faults.
#[api_test]
fn test_rsa_sign_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaModExp,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = rsa_sign(&priv_key, &session, b"test data for RSA signing");
    clear_faults();

    assert!(
        result.is_ok(),
        "RSA sign should recover from compound faults on \
         RsaModExp + EstablishCredential, got: {result:?}"
    );
}

// =========================================================================
// RSA sign — reset-triggered tests
// =========================================================================

/// After a reset on `RsaModExp`, RSA `sign` recovers.
#[api_test]
fn test_rsa_sign_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaModExp, 1));

    let result = rsa_sign(&priv_key, &session, b"test data for RSA signing");

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "RSA sign should recover after reset, got: {result:?}"
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, RSA `sign` does not recover from a reset.
#[api_test]
fn test_rsa_sign_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaModExp, 1));

    let result = rsa_sign(&priv_key, &session, b"test data for RSA signing");
    clear_faults();

    assert!(
        result.is_err(),
        "RSA sign without resiliency should fail after reset, got: {result:?}"
    );
}

/// Two consecutive resets on `RsaModExp` are each followed by recovery.
#[api_test]
fn test_rsa_sign_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaModExp, 1));
    let result1 = rsa_sign(&priv_key, &session, b"test data for RSA signing");
    clear_faults();
    assert!(result1.is_ok(), "First RSA sign should recover after reset");

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaModExp, 1));
    let result2 = rsa_sign(&priv_key, &session, b"test data for RSA signing");
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second RSA sign should recover after reset"
    );
}

// =========================================================================
// RSA decrypt — fault-injection tests
// =========================================================================

/// RSA `decrypt` recovers from a single transient fault on `RsaModExp`
/// for retryable error codes, and fails immediately for non-retryable ones.
#[api_test]
fn test_rsa_decrypt_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, pub_key) = import_rsa_enc_key(&session);

        // Encrypt without faults (uses public key — no DDI).
        let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
        let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, b"RSA decrypt test")
            .expect("RSA encrypt setup failed");

        let before = op_call_count(DdiOp::RsaModExp);

        inject_fault(FaultRule::fail_nth(DdiOp::RsaModExp, 1, *error));

        let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
        let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);
        let after = op_call_count(DdiOp::RsaModExp);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "single fault on RsaModExp (decrypt)",
        );

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on RsaModExp (decrypt): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// RSA `decrypt` recovers on the last retry when `RsaModExp` fails for
/// the first `MAX_RETRIES` attempts.
#[api_test]
fn test_rsa_decrypt_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, pub_key) = import_rsa_enc_key(&session);

        let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
        let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, b"RSA decrypt test")
            .expect("RSA encrypt setup failed");

        let before = op_call_count(DdiOp::RsaModExp);

        inject_fault(FaultRule::fail_next(DdiOp::RsaModExp, MAX_RETRIES, *error));

        let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
        let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);
        let after = op_call_count(DdiOp::RsaModExp);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "last retry on RsaModExp (decrypt)",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on RsaModExp (decrypt): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// RSA `decrypt` fails when `RsaModExp` returns a retryable error for
/// `MAX_RETRIES + 1` consecutive calls.
#[api_test]
fn test_rsa_decrypt_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, pub_key) = import_rsa_enc_key(&session);

        let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
        let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, b"RSA decrypt test")
            .expect("RSA encrypt setup failed");

        inject_fault(FaultRule::fail_next(
            DdiOp::RsaModExp,
            MAX_RETRIES + 1,
            *error,
        ));

        let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
        let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);
        clear_faults();

        assert!(
            result.is_err(),
            "RSA decrypt should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}, got: {result:?}"
        );
    }
}

/// Without resiliency, RSA `decrypt` does not retry.
#[api_test]
fn test_rsa_decrypt_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, pub_key) = import_rsa_enc_key(&session);

    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, b"RSA decrypt test")
        .expect("RSA encrypt setup failed");

    let before = op_call_count(DdiOp::RsaModExp);

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaModExp,
        1,
        DriverError::IoAborted,
    ));

    let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);
    let after = op_call_count(DdiOp::RsaModExp);
    clear_faults();

    assert!(
        result.is_err(),
        "RSA decrypt without resiliency should fail on IoAborted, got: {result:?}"
    );
    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 RsaModExp call, got {}",
        after - before,
    );
}

/// RSA `decrypt` recovers from compound faults.
#[api_test]
fn test_rsa_decrypt_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, pub_key) = import_rsa_enc_key(&session);

    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, b"RSA decrypt test")
        .expect("RSA encrypt setup failed");

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaModExp,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);
    clear_faults();

    assert!(
        result.is_ok(),
        "RSA decrypt should recover from compound faults on \
         RsaModExp + EstablishCredential, got: {result:?}"
    );
}

// =========================================================================
// RSA decrypt — reset-triggered tests
// =========================================================================

/// After a reset on `RsaModExp`, RSA `decrypt` recovers.
#[api_test]
fn test_rsa_decrypt_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, pub_key) = import_rsa_enc_key(&session);

    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, b"RSA decrypt test")
        .expect("RSA encrypt setup failed");

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaModExp, 1));

    let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "RSA decrypt should recover after reset, got: {result:?}"
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, RSA `decrypt` does not recover from a reset.
#[api_test]
fn test_rsa_decrypt_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, pub_key) = import_rsa_enc_key(&session);

    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, b"RSA decrypt test")
        .expect("RSA encrypt setup failed");

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaModExp, 1));

    let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);
    clear_faults();

    assert!(
        result.is_err(),
        "RSA decrypt without resiliency should fail after reset, got: {result:?}"
    );
}

/// Two consecutive resets on `RsaModExp` are each followed by recovery.
#[api_test]
fn test_rsa_decrypt_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, pub_key) = import_rsa_enc_key(&session);

    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ct1 = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, b"RSA decrypt test 1")
        .expect("RSA encrypt setup failed");

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaModExp, 1));
    let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let result1 = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ct1);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First RSA decrypt should recover after reset"
    );

    let mut enc_algo2 = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ct2 = HsmEncrypter::encrypt_vec(&mut enc_algo2, &pub_key, b"RSA decrypt test 2")
        .expect("RSA encrypt setup failed");

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaModExp, 1));
    let mut dec_algo2 = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let result2 = HsmDecrypter::decrypt_vec(&mut dec_algo2, &priv_key, &ct2);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second RSA decrypt should recover after reset"
    );
}

// =========================================================================
// HMAC verify — fault-injection tests
// =========================================================================

/// HMAC `verify` recovers from a single transient fault on `Hmac`
/// for retryable error codes, and fails immediately for non-retryable ones.
#[api_test]
fn test_hmac_verify_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let hmac_key = generate_hmac_key(&session);
        let data = b"test message for HMAC verify";
        let signature = hmac_sign_for_verify(&hmac_key, data);

        let before = op_call_count(DdiOp::Hmac);

        inject_fault(FaultRule::fail_next(DdiOp::Hmac, 1, *error));

        let result = hmac_verify(&hmac_key, data, &signature);
        let after = op_call_count(DdiOp::Hmac);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "single fault on Hmac (verify)",
        );

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on Hmac (verify): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// HMAC `verify` recovers on the last retry when `Hmac` fails for
/// the first `MAX_RETRIES` attempts.
#[api_test]
fn test_hmac_verify_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let hmac_key = generate_hmac_key(&session);
        let data = b"test message for HMAC verify";
        let signature = hmac_sign_for_verify(&hmac_key, data);

        let before = op_call_count(DdiOp::Hmac);

        inject_fault(FaultRule::fail_next(DdiOp::Hmac, MAX_RETRIES, *error));

        let result = hmac_verify(&hmac_key, data, &signature);
        let after = op_call_count(DdiOp::Hmac);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "last retry on Hmac (verify)",
        );

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on Hmac (verify): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// HMAC `verify` fails when `Hmac` returns a retryable error for
/// `MAX_RETRIES + 1` consecutive calls.
#[api_test]
fn test_hmac_verify_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let hmac_key = generate_hmac_key(&session);
        let data = b"test message for HMAC verify";
        let signature = hmac_sign_for_verify(&hmac_key, data);

        inject_fault(FaultRule::fail_next(DdiOp::Hmac, MAX_RETRIES + 1, *error));

        let result = hmac_verify(&hmac_key, data, &signature);
        clear_faults();

        assert!(
            result.is_err(),
            "HMAC verify should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}, got: {result:?}"
        );
    }
}

/// Without resiliency, HMAC `verify` does not retry.
#[api_test]
fn test_hmac_verify_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);
    let data = b"test message for HMAC verify";
    let signature = hmac_sign_for_verify(&hmac_key, data);

    let before = op_call_count(DdiOp::Hmac);

    inject_fault(FaultRule::fail_next(DdiOp::Hmac, 1, DriverError::IoAborted));

    let result = hmac_verify(&hmac_key, data, &signature);
    let after = op_call_count(DdiOp::Hmac);
    clear_faults();

    assert!(
        result.is_err(),
        "HMAC verify without resiliency should fail on IoAborted, got: {result:?}"
    );
    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 Hmac call, got {}",
        after - before,
    );
}

/// HMAC `verify` recovers from compound faults.
#[api_test]
fn test_hmac_verify_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);
    let data = b"test message for HMAC verify";
    let signature = hmac_sign_for_verify(&hmac_key, data);

    inject_fault(FaultRule::fail_nth(
        DdiOp::Hmac,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = hmac_verify(&hmac_key, data, &signature);
    clear_faults();

    assert!(
        result.is_ok(),
        "HMAC verify should recover from compound faults on \
         Hmac + EstablishCredential, got: {result:?}"
    );
}

// =========================================================================
// HMAC verify — reset-triggered tests
// =========================================================================

/// After a reset on `Hmac`, HMAC `verify` recovers.
#[api_test]
fn test_hmac_verify_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);
    let data = b"test message for HMAC verify";
    let signature = hmac_sign_for_verify(&hmac_key, data);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::Hmac, 1));

    let result = hmac_verify(&hmac_key, data, &signature);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "HMAC verify should recover after reset, got: {result:?}"
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, HMAC `verify` does not recover from a reset.
#[api_test]
fn test_hmac_verify_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);
    let data = b"test message for HMAC verify";
    let signature = hmac_sign_for_verify(&hmac_key, data);

    inject_fault(FaultRule::reset_on_next(DdiOp::Hmac, 1));

    let result = hmac_verify(&hmac_key, data, &signature);
    clear_faults();

    assert!(
        result.is_err(),
        "HMAC verify without resiliency should fail after reset, got: {result:?}"
    );
}

/// Two consecutive resets on `Hmac` are each followed by recovery.
#[api_test]
fn test_hmac_verify_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let hmac_key = generate_hmac_key(&session);
    let data = b"test message for HMAC verify";
    let signature = hmac_sign_for_verify(&hmac_key, data);

    inject_fault(FaultRule::reset_on_next(DdiOp::Hmac, 1));
    let result1 = hmac_verify(&hmac_key, data, &signature);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First HMAC verify should recover after reset"
    );

    inject_fault(FaultRule::reset_on_next(DdiOp::Hmac, 1));
    let result2 = hmac_verify(&hmac_key, data, &signature);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second HMAC verify should recover after reset"
    );
}

// =========================================================================
// ECDH derive — fault-injection tests
// =========================================================================

/// ECDH `derive_key` recovers from a single transient fault on
/// `EcdhKeyExchange` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_ecdh_derive_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
        let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

        let before = op_call_count(DdiOp::EcdhKeyExchange);

        inject_fault(FaultRule::fail_nth(DdiOp::EcdhKeyExchange, 1, *error));

        let result = ecdh_derive(&session, &priv_key, &pub_key_b);
        let after = op_call_count(DdiOp::EcdhKeyExchange);
        clear_faults();

        if is_key_op_retryable(error) {
            assert!(
                result.is_ok(),
                "single fault on EcdhKeyExchange: expected Ok for retryable {error:?}, \
                 got err: {:?}",
                result.as_ref().err(),
            );
        } else {
            assert!(
                result.is_err(),
                "single fault on EcdhKeyExchange: expected Err for non-retryable {error:?}",
            );
        }

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on EcdhKeyExchange: expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// ECDH `derive_key` recovers on the last retry when `EcdhKeyExchange`
/// fails for the first `MAX_RETRIES` attempts.
#[api_test]
fn test_ecdh_derive_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
        let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

        let before = op_call_count(DdiOp::EcdhKeyExchange);

        inject_fault(FaultRule::fail_next(
            DdiOp::EcdhKeyExchange,
            MAX_RETRIES,
            *error,
        ));

        let result = ecdh_derive(&session, &priv_key, &pub_key_b);
        let after = op_call_count(DdiOp::EcdhKeyExchange);
        clear_faults();

        if is_key_op_retryable(error) {
            assert!(
                result.is_ok(),
                "last retry on EcdhKeyExchange: expected Ok for retryable {error:?}, \
                 got err: {:?}",
                result.as_ref().err(),
            );
        } else {
            assert!(
                result.is_err(),
                "last retry on EcdhKeyExchange: expected Err for non-retryable {error:?}",
            );
        }

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on EcdhKeyExchange: expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// ECDH `derive_key` fails when `EcdhKeyExchange` returns a retryable
/// error for `MAX_RETRIES + 1` consecutive calls.
#[api_test]
fn test_ecdh_derive_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
        let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

        inject_fault(FaultRule::fail_next(
            DdiOp::EcdhKeyExchange,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = ecdh_derive(&session, &priv_key, &pub_key_b);
        clear_faults();

        assert!(
            result.is_err(),
            "ECDH derive should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}"
        );
    }
}

/// Without resiliency, ECDH `derive_key` does not retry.
#[api_test]
fn test_ecdh_derive_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

    let before = op_call_count(DdiOp::EcdhKeyExchange);

    inject_fault(FaultRule::fail_nth(
        DdiOp::EcdhKeyExchange,
        1,
        DriverError::IoAborted,
    ));

    let result = ecdh_derive(&session, &priv_key, &pub_key_b);
    let after = op_call_count(DdiOp::EcdhKeyExchange);
    clear_faults();

    assert!(
        result.is_err(),
        "ECDH derive without resiliency should fail on IoAborted"
    );
    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 EcdhKeyExchange call, got {}",
        after - before,
    );
}

/// ECDH `derive_key` recovers from compound faults.
#[api_test]
fn test_ecdh_derive_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

    inject_fault(FaultRule::fail_nth(
        DdiOp::EcdhKeyExchange,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = ecdh_derive(&session, &priv_key, &pub_key_b);
    clear_faults();

    assert!(
        result.is_ok(),
        "ECDH derive should recover from compound faults on \
         EcdhKeyExchange + EstablishCredential, got err: {:?}",
        result.as_ref().err(),
    );
}

// =========================================================================
// ECDH derive — reset-triggered tests
// =========================================================================

/// After a reset on `EcdhKeyExchange`, ECDH `derive_key` recovers.
#[api_test]
fn test_ecdh_derive_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::EcdhKeyExchange, 1));

    let result = ecdh_derive(&session, &priv_key, &pub_key_b);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "ECDH derive should recover after reset, got err: {:?}",
        result.as_ref().err(),
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, ECDH `derive_key` does not recover from a reset.
#[api_test]
fn test_ecdh_derive_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

    inject_fault(FaultRule::reset_on_next(DdiOp::EcdhKeyExchange, 1));

    let result = ecdh_derive(&session, &priv_key, &pub_key_b);
    clear_faults();

    assert!(
        result.is_err(),
        "ECDH derive without resiliency should fail after reset"
    );
}

/// Two consecutive resets on `EcdhKeyExchange` are each followed by recovery.
#[api_test]
fn test_ecdh_derive_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

    inject_fault(FaultRule::reset_on_next(DdiOp::EcdhKeyExchange, 1));
    let result1 = ecdh_derive(&session, &priv_key, &pub_key_b);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First ECDH derive should recover after reset"
    );

    inject_fault(FaultRule::reset_on_next(DdiOp::EcdhKeyExchange, 1));
    let result2 = ecdh_derive(&session, &priv_key, &pub_key_b);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second ECDH derive should recover after reset"
    );
}

// =========================================================================
// HKDF derive — fault-injection tests
// =========================================================================

/// HKDF `derive_key` recovers from a single transient fault on
/// `HkdfDerive` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_hkdf_derive_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let shared_secret = setup_shared_secret(&session);

        let before = op_call_count(DdiOp::HkdfDerive);

        inject_fault(FaultRule::fail_nth(DdiOp::HkdfDerive, 1, *error));

        let result = hkdf_derive_aes_key(&session, &shared_secret);
        let after = op_call_count(DdiOp::HkdfDerive);
        clear_faults();

        if is_key_op_retryable(error) {
            assert!(
                result.is_ok(),
                "single fault on HkdfDerive: expected Ok for retryable {error:?}, \
                 got err: {:?}",
                result.as_ref().err(),
            );
        } else {
            assert!(
                result.is_err(),
                "single fault on HkdfDerive: expected Err for non-retryable {error:?}",
            );
        }

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on HkdfDerive: expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// HKDF `derive_key` recovers on the last retry when `HkdfDerive`
/// fails for the first `MAX_RETRIES` attempts.
#[api_test]
fn test_hkdf_derive_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let shared_secret = setup_shared_secret(&session);

        let before = op_call_count(DdiOp::HkdfDerive);

        inject_fault(FaultRule::fail_next(DdiOp::HkdfDerive, MAX_RETRIES, *error));

        let result = hkdf_derive_aes_key(&session, &shared_secret);
        let after = op_call_count(DdiOp::HkdfDerive);
        clear_faults();

        if is_key_op_retryable(error) {
            assert!(
                result.is_ok(),
                "last retry on HkdfDerive: expected Ok for retryable {error:?}, \
                 got err: {:?}",
                result.as_ref().err(),
            );
        } else {
            assert!(
                result.is_err(),
                "last retry on HkdfDerive: expected Err for non-retryable {error:?}",
            );
        }

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on HkdfDerive: expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// HKDF `derive_key` fails when `HkdfDerive` returns a retryable error
/// for `MAX_RETRIES + 1` consecutive calls.
#[api_test]
fn test_hkdf_derive_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let shared_secret = setup_shared_secret(&session);

        inject_fault(FaultRule::fail_next(
            DdiOp::HkdfDerive,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = hkdf_derive_aes_key(&session, &shared_secret);
        clear_faults();

        assert!(
            result.is_err(),
            "HKDF derive should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}"
        );
    }
}

/// Without resiliency, HKDF `derive_key` does not retry.
#[api_test]
fn test_hkdf_derive_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let shared_secret = setup_shared_secret(&session);

    let before = op_call_count(DdiOp::HkdfDerive);

    inject_fault(FaultRule::fail_nth(
        DdiOp::HkdfDerive,
        1,
        DriverError::IoAborted,
    ));

    let result = hkdf_derive_aes_key(&session, &shared_secret);
    let after = op_call_count(DdiOp::HkdfDerive);
    clear_faults();

    assert!(
        result.is_err(),
        "HKDF derive without resiliency should fail on IoAborted"
    );
    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 HkdfDerive call, got {}",
        after - before,
    );
}

/// HKDF `derive_key` recovers from compound faults.
#[api_test]
fn test_hkdf_derive_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let shared_secret = setup_shared_secret(&session);

    inject_fault(FaultRule::fail_nth(
        DdiOp::HkdfDerive,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = hkdf_derive_aes_key(&session, &shared_secret);
    clear_faults();

    assert!(
        result.is_ok(),
        "HKDF derive should recover from compound faults on \
         HkdfDerive + EstablishCredential, got err: {:?}",
        result.as_ref().err(),
    );
}

// =========================================================================
// HKDF derive — reset-triggered tests
// =========================================================================

/// After a reset on `HkdfDerive`, HKDF `derive_key` recovers.
#[api_test]
fn test_hkdf_derive_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let shared_secret = setup_shared_secret(&session);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::HkdfDerive, 1));

    let result = hkdf_derive_aes_key(&session, &shared_secret);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "HKDF derive should recover after reset, got err: {:?}",
        result.as_ref().err(),
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, HKDF `derive_key` does not recover from a reset.
#[api_test]
fn test_hkdf_derive_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let shared_secret = setup_shared_secret(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::HkdfDerive, 1));

    let result = hkdf_derive_aes_key(&session, &shared_secret);
    clear_faults();

    assert!(
        result.is_err(),
        "HKDF derive without resiliency should fail after reset"
    );
}

/// Two consecutive resets on `HkdfDerive` are each followed by recovery.
#[api_test]
fn test_hkdf_derive_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let shared_secret = setup_shared_secret(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::HkdfDerive, 1));
    let result1 = hkdf_derive_aes_key(&session, &shared_secret);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First HKDF derive should recover after reset"
    );

    inject_fault(FaultRule::reset_on_next(DdiOp::HkdfDerive, 1));
    let result2 = hkdf_derive_aes_key(&session, &shared_secret);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second HKDF derive should recover after reset"
    );
}

// =========================================================================
// AES key unwrap — fault-injection tests
// =========================================================================

/// AES `unwrap_key` recovers from a single transient fault on
/// `RsaUnwrap` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_aes_unwrap_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (unwrap_key, wrapped) = prepare_wrapped_aes_key(&session);

        let before = op_call_count(DdiOp::RsaUnwrap);

        inject_fault(FaultRule::fail_nth(DdiOp::RsaUnwrap, 1, *error));

        let result = unwrap_aes_key(&unwrap_key, &wrapped);
        let after = op_call_count(DdiOp::RsaUnwrap);
        clear_faults();

        if is_key_op_retryable(error) {
            assert!(
                result.is_ok(),
                "single fault on RsaUnwrap (AES): expected Ok for retryable {error:?}, \
                 got err: {:?}",
                result.as_ref().err(),
            );
        } else {
            assert!(
                result.is_err(),
                "single fault on RsaUnwrap (AES): expected Err for non-retryable {error:?}",
            );
        }

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on RsaUnwrap (AES): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// AES `unwrap_key` recovers on the last retry when `RsaUnwrap`
/// fails for the first `MAX_RETRIES` attempts.
#[api_test]
fn test_aes_unwrap_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (unwrap_key, wrapped) = prepare_wrapped_aes_key(&session);

        let before = op_call_count(DdiOp::RsaUnwrap);

        inject_fault(FaultRule::fail_next(DdiOp::RsaUnwrap, MAX_RETRIES, *error));

        let result = unwrap_aes_key(&unwrap_key, &wrapped);
        let after = op_call_count(DdiOp::RsaUnwrap);
        clear_faults();

        if is_key_op_retryable(error) {
            assert!(
                result.is_ok(),
                "last retry on RsaUnwrap (AES): expected Ok for retryable {error:?}, \
                 got err: {:?}",
                result.as_ref().err(),
            );
        } else {
            assert!(
                result.is_err(),
                "last retry on RsaUnwrap (AES): expected Err for non-retryable {error:?}",
            );
        }

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on RsaUnwrap (AES): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// AES `unwrap_key` fails when `RsaUnwrap` returns a retryable error
/// for `MAX_RETRIES + 1` consecutive calls.
#[api_test]
fn test_aes_unwrap_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (unwrap_key, wrapped) = prepare_wrapped_aes_key(&session);

        inject_fault(FaultRule::fail_next(
            DdiOp::RsaUnwrap,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = unwrap_aes_key(&unwrap_key, &wrapped);
        clear_faults();

        assert!(
            result.is_err(),
            "AES unwrap should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}"
        );
    }
}

/// Without resiliency, AES `unwrap_key` does not retry.
#[api_test]
fn test_aes_unwrap_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_aes_key(&session);

    let before = op_call_count(DdiOp::RsaUnwrap);

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaUnwrap,
        1,
        DriverError::IoAborted,
    ));

    let result = unwrap_aes_key(&unwrap_key, &wrapped);
    let after = op_call_count(DdiOp::RsaUnwrap);
    clear_faults();

    assert!(
        result.is_err(),
        "AES unwrap without resiliency should fail on IoAborted"
    );
    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 RsaUnwrap call, got {}",
        after - before,
    );
}

/// AES `unwrap_key` recovers from compound faults.
#[api_test]
fn test_aes_unwrap_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_aes_key(&session);

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaUnwrap,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = unwrap_aes_key(&unwrap_key, &wrapped);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES unwrap should recover from compound faults on \
         RsaUnwrap + EstablishCredential, got err: {:?}",
        result.as_ref().err(),
    );
}

// =========================================================================
// AES key unwrap — reset-triggered tests
// =========================================================================

/// After a reset on `RsaUnwrap`, AES `unwrap_key` recovers.
#[api_test]
fn test_aes_unwrap_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_aes_key(&session);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));

    let result = unwrap_aes_key(&unwrap_key, &wrapped);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES unwrap should recover after reset, got err: {:?}",
        result.as_ref().err(),
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, AES `unwrap_key` does not recover from a reset.
#[api_test]
fn test_aes_unwrap_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_aes_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));

    let result = unwrap_aes_key(&unwrap_key, &wrapped);
    clear_faults();

    assert!(
        result.is_err(),
        "AES unwrap without resiliency should fail after reset"
    );
}

/// Two consecutive resets on `RsaUnwrap` are each followed by recovery.
#[api_test]
fn test_aes_unwrap_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_aes_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));
    let result1 = unwrap_aes_key(&unwrap_key, &wrapped);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First AES unwrap should recover after reset"
    );

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));
    let result2 = unwrap_aes_key(&unwrap_key, &wrapped);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second AES unwrap should recover after reset"
    );
}

// =========================================================================
// ECC key pair unwrap — fault-injection tests
// =========================================================================

/// ECC `unwrap_key_pair` recovers from a single transient fault on
/// `RsaUnwrap` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_ecc_unwrap_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (unwrap_key, wrapped) = prepare_wrapped_ecc_key(&session);

        let before = op_call_count(DdiOp::RsaUnwrap);

        inject_fault(FaultRule::fail_nth(DdiOp::RsaUnwrap, 1, *error));

        let result = unwrap_ecc_key_pair(&unwrap_key, &wrapped);
        let after = op_call_count(DdiOp::RsaUnwrap);
        clear_faults();

        if is_key_op_retryable(error) {
            assert!(
                result.is_ok(),
                "single fault on RsaUnwrap (ECC): expected Ok for retryable {error:?}"
            );
        } else {
            assert!(
                result.is_err(),
                "single fault on RsaUnwrap (ECC): expected Err for non-retryable {error:?}"
            );
        }

        let expected = expected_op_calls(error, 1);
        assert_eq!(
            after - before,
            expected,
            "single fault on RsaUnwrap (ECC): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// ECC `unwrap_key_pair` recovers on the last retry when `RsaUnwrap`
/// fails for the first `MAX_RETRIES` attempts.
#[api_test]
fn test_ecc_unwrap_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (unwrap_key, wrapped) = prepare_wrapped_ecc_key(&session);

        let before = op_call_count(DdiOp::RsaUnwrap);

        inject_fault(FaultRule::fail_next(DdiOp::RsaUnwrap, MAX_RETRIES, *error));

        let result = unwrap_ecc_key_pair(&unwrap_key, &wrapped);
        let after = op_call_count(DdiOp::RsaUnwrap);
        clear_faults();

        if is_key_op_retryable(error) {
            assert!(
                result.is_ok(),
                "last retry on RsaUnwrap (ECC): expected Ok for retryable {error:?}"
            );
        } else {
            assert!(
                result.is_err(),
                "last retry on RsaUnwrap (ECC): expected Err for non-retryable {error:?}"
            );
        }

        let expected = expected_op_calls(error, MAX_RETRIES);
        assert_eq!(
            after - before,
            expected,
            "last retry on RsaUnwrap (ECC): expected {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// ECC `unwrap_key_pair` fails when `RsaUnwrap` returns a retryable
/// error for `MAX_RETRIES + 1` consecutive calls.
#[api_test]
fn test_ecc_unwrap_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (unwrap_key, wrapped) = prepare_wrapped_ecc_key(&session);

        inject_fault(FaultRule::fail_next(
            DdiOp::RsaUnwrap,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = unwrap_ecc_key_pair(&unwrap_key, &wrapped);
        clear_faults();

        assert!(
            result.is_err(),
            "ECC unwrap should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}"
        );
    }
}

/// Without resiliency, ECC `unwrap_key_pair` does not retry.
#[api_test]
fn test_ecc_unwrap_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_ecc_key(&session);

    let before = op_call_count(DdiOp::RsaUnwrap);

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaUnwrap,
        1,
        DriverError::IoAborted,
    ));

    let result = unwrap_ecc_key_pair(&unwrap_key, &wrapped);
    let after = op_call_count(DdiOp::RsaUnwrap);
    clear_faults();

    assert!(
        result.is_err(),
        "ECC unwrap without resiliency should fail on IoAborted"
    );
    assert_eq!(
        after - before,
        1,
        "no-retry: expected 1 RsaUnwrap call, got {}",
        after - before,
    );
}

/// ECC `unwrap_key_pair` recovers from compound faults.
#[api_test]
fn test_ecc_unwrap_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_ecc_key(&session);

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaUnwrap,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = unwrap_ecc_key_pair(&unwrap_key, &wrapped);
    clear_faults();

    assert!(
        result.is_ok(),
        "ECC unwrap should recover from compound faults on \
         RsaUnwrap + EstablishCredential"
    );
}

// =========================================================================
// ECC key pair unwrap — reset-triggered tests
// =========================================================================

/// After a reset on `RsaUnwrap`, ECC `unwrap_key_pair` recovers.
#[api_test]
fn test_ecc_unwrap_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_ecc_key(&session);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));

    let result = unwrap_ecc_key_pair(&unwrap_key, &wrapped);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(result.is_ok(), "ECC unwrap should recover after reset");
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, ECC `unwrap_key_pair` does not recover from a reset.
#[api_test]
fn test_ecc_unwrap_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_ecc_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));

    let result = unwrap_ecc_key_pair(&unwrap_key, &wrapped);
    clear_faults();

    assert!(
        result.is_err(),
        "ECC unwrap without resiliency should fail after reset"
    );
}

/// Two consecutive resets on `RsaUnwrap` are each followed by recovery.
#[api_test]
fn test_ecc_unwrap_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_ecc_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));
    let result1 = unwrap_ecc_key_pair(&unwrap_key, &wrapped);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First ECC unwrap should recover after reset"
    );

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));
    let result2 = unwrap_ecc_key_pair(&unwrap_key, &wrapped);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second ECC unwrap should recover after reset"
    );
}

// =========================================================================
// AES-XTS key unwrap helpers
// =========================================================================

/// Prepare a wrapped AES-XTS key-pair blob and RSA unwrapping key.
fn prepare_wrapped_xts_key(session: &HsmSession) -> (HsmRsaPrivateKey, Vec<u8>) {
    let (unwrap_priv, unwrap_pub) = generate_rsa_unwrapping_key_pair(session);
    let key1_plain = vec![0x11u8; 32]; // AES-256 half
    let key2_plain = vec![0x22u8; 32]; // AES-256 half
    let wrapped_blob =
        build_xts_wrapped_blob(&unwrap_pub, HsmHashAlgo::Sha256, &key1_plain, &key2_plain);
    (unwrap_priv, wrapped_blob)
}

/// Unwrap an AES-XTS key from a wrapped blob.
fn unwrap_xts_key(unwrapping_key: &HsmRsaPrivateKey, wrapped: &[u8]) -> HsmResult<HsmAesXtsKey> {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES-XTS key props for unwrap");

    let mut unwrap_algo = HsmAesXtsKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    HsmKeyManager::unwrap_key(&mut unwrap_algo, unwrapping_key, wrapped, key_props)
}

// =========================================================================
// AES-XTS key unwrap — fault-injection tests
// =========================================================================

/// AES-XTS `unwrap_key` recovers from a single transient fault on
/// `RsaUnwrap` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_aes_xts_unwrap_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (unwrap_key, wrapped) = prepare_wrapped_xts_key(&session);

        let before = op_call_count(DdiOp::RsaUnwrap);

        inject_fault(FaultRule::fail_nth(DdiOp::RsaUnwrap, 1, *error));

        let result = unwrap_xts_key(&unwrap_key, &wrapped);
        let after = op_call_count(DdiOp::RsaUnwrap);
        clear_faults();

        if is_key_op_retryable(error) {
            assert!(
                result.is_ok(),
                "single fault on RsaUnwrap (XTS): expected Ok for retryable {error:?}, \
                 got err: {:?}",
                result.as_ref().err(),
            );
        } else {
            assert!(
                result.is_err(),
                "single fault on RsaUnwrap (XTS): expected Err for non-retryable {error:?}",
            );
        }

        let expected = expected_op_calls(error, 1);
        assert!(
            after - before >= expected,
            "single fault on RsaUnwrap (XTS): expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// AES-XTS `unwrap_key` fails when `RsaUnwrap` returns a retryable
/// error for every attempt. Both the outer `aes_xts_unwrap_key` and
/// the inner `rsa_aes_unwrap_key` have `#[resiliency_key_op]` retry
/// loops, so exhausting all retries requires (MAX_RETRIES + 1)² faults.
#[api_test]
fn test_aes_xts_unwrap_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (unwrap_key, wrapped) = prepare_wrapped_xts_key(&session);

        // Nested retries: the outer function retries (MAX_RETRIES + 1)
        // times, and each outer attempt triggers a full inner retry
        // cycle of (MAX_RETRIES + 1) DDI calls before the inner
        // function reports failure.
        inject_fault(FaultRule::fail_next(
            DdiOp::RsaUnwrap,
            (MAX_RETRIES + 1) * (MAX_RETRIES + 1),
            *error,
        ));

        let result = unwrap_xts_key(&unwrap_key, &wrapped);
        clear_faults();

        assert!(
            result.is_err(),
            "AES-XTS unwrap should fail after exhausting all {MAX_RETRIES} retries \
             with {error:?}"
        );
    }
}

/// Without resiliency, AES-XTS `unwrap_key` does not retry.
#[api_test]
fn test_aes_xts_unwrap_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_xts_key(&session);

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaUnwrap,
        1,
        DriverError::IoAborted,
    ));

    let result = unwrap_xts_key(&unwrap_key, &wrapped);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-XTS unwrap without resiliency should fail on IoAborted"
    );
}

/// AES-XTS `unwrap_key` recovers from compound faults.
#[api_test]
fn test_aes_xts_unwrap_recovers_from_compound_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_xts_key(&session);

    inject_fault(FaultRule::fail_nth(
        DdiOp::RsaUnwrap,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::EstablishCredential,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = unwrap_xts_key(&unwrap_key, &wrapped);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-XTS unwrap should recover from compound faults on \
         RsaUnwrap + EstablishCredential, got err: {:?}",
        result.as_ref().err(),
    );
}

// =========================================================================
// AES-XTS key unwrap — reset-triggered tests
// =========================================================================

/// After a reset on `RsaUnwrap`, AES-XTS `unwrap_key` recovers.
#[api_test]
fn test_aes_xts_unwrap_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_xts_key(&session);

    let op = bk3_op();
    let bk3_before = op_call_count(op);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));

    let result = unwrap_xts_key(&unwrap_key, &wrapped);

    let bk3_after = op_call_count(op);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-XTS unwrap should recover after reset, got err: {:?}",
        result.as_ref().err(),
    );
    assert!(
        bk3_after > bk3_before,
        "{op:?} should have been called during restore_partition after reset \
         (before: {bk3_before}, after: {bk3_after})"
    );
}

/// Without resiliency, AES-XTS `unwrap_key` does not recover from a reset.
#[api_test]
fn test_aes_xts_unwrap_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_xts_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));

    let result = unwrap_xts_key(&unwrap_key, &wrapped);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-XTS unwrap without resiliency should fail after reset"
    );
}

/// Two consecutive resets on `RsaUnwrap` are each followed by recovery.
#[api_test]
fn test_aes_xts_unwrap_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (unwrap_key, wrapped) = prepare_wrapped_xts_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));
    let result1 = unwrap_xts_key(&unwrap_key, &wrapped);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First AES-XTS unwrap should recover after reset"
    );

    inject_fault(FaultRule::reset_on_next(DdiOp::RsaUnwrap, 1));
    let result2 = unwrap_xts_key(&unwrap_key, &wrapped);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second AES-XTS unwrap should recover after reset"
    );
}

// =========================================================================
// AES-CBC decrypt — fault-injection tests
// =========================================================================

/// AES-CBC `decrypt` recovers from a single transient fault on
/// `AesEncryptDecrypt` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_aes_cbc_decrypt_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let key = generate_aes_key(&session);
        let iv = crypto::Rng::rand_vec(16).expect("IV");
        let plaintext = b"test data for encryption!!!!!!!";
        let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

        let before = op_call_count(DdiOp::AesEncryptDecrypt);

        inject_fault(FaultRule::fail_next(DdiOp::AesEncryptDecrypt, 1, *error));

        let result = cbc_decrypt(&key, &iv, &ciphertext);
        let after = op_call_count(DdiOp::AesEncryptDecrypt);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "single fault on AesEncryptDecrypt (decrypt)",
        );

        let expected = expected_op_calls(error, 1);
        assert!(
            after - before >= expected,
            "single fault on AesEncryptDecrypt (decrypt): expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// AES-CBC `decrypt` recovers on the last retry.
#[api_test]
fn test_aes_cbc_decrypt_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let key = generate_aes_key(&session);
        let iv = crypto::Rng::rand_vec(16).expect("IV");
        let plaintext = b"test data for encryption!!!!!!!";
        let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

        inject_fault(FaultRule::fail_next(
            DdiOp::AesEncryptDecrypt,
            MAX_RETRIES,
            *error,
        ));

        let result = cbc_decrypt(&key, &iv, &ciphertext);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "last retry on AesEncryptDecrypt (decrypt)",
        );
    }
}

/// AES-CBC `decrypt` fails when all retries are exhausted.
#[api_test]
fn test_aes_cbc_decrypt_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let key = generate_aes_key(&session);
        let iv = crypto::Rng::rand_vec(16).expect("IV");
        let plaintext = b"test data for encryption!!!!!!!";
        let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

        inject_fault(FaultRule::fail_next(
            DdiOp::AesEncryptDecrypt,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = cbc_decrypt(&key, &iv, &ciphertext);
        clear_faults();

        assert!(
            result.is_err(),
            "AES-CBC decrypt should fail after exhausting all {MAX_RETRIES} \
             retries with {error:?}, got: {result:?}"
        );
    }
}

/// Without resiliency, AES-CBC `decrypt` does not retry.
#[api_test]
fn test_aes_cbc_decrypt_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"test data for encryption!!!!!!!";
    let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        DriverError::IoAborted,
    ));

    let result = cbc_decrypt(&key, &iv, &ciphertext);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-CBC decrypt without resiliency should fail on IoAborted, \
         got: {result:?}"
    );
}

/// AES-CBC `decrypt` recovers from compound fault on
/// AesEncryptDecrypt + InitBk3.
#[api_test]
fn test_aes_cbc_decrypt_recovers_from_compound_fault() {
    if use_tpm() {
        return;
    }
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"test data for encryption!!!!!!!";
    let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::InitBk3,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = cbc_decrypt(&key, &iv, &ciphertext);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-CBC decrypt should recover from compound faults on \
         AesEncryptDecrypt + InitBk3, got: {result:?}"
    );
}

// =========================================================================
// AES-CBC decrypt — reset-triggered tests
// =========================================================================

/// After a reset on `AesEncryptDecrypt`, AES-CBC `decrypt` recovers.
#[api_test]
fn test_aes_cbc_decrypt_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"test data for encryption!!!!!!!";
    let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));

    let result = cbc_decrypt(&key, &iv, &ciphertext);
    clear_faults();

    assert!(
        result.is_ok(),
        "AES-CBC decrypt should recover after reset, got: {result:?}"
    );
}

/// Without resiliency, AES-CBC `decrypt` does not recover from a reset.
#[api_test]
fn test_aes_cbc_decrypt_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"test data for encryption!!!!!!!";
    let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));

    let result = cbc_decrypt(&key, &iv, &ciphertext);
    clear_faults();

    assert!(
        result.is_err(),
        "AES-CBC decrypt without resiliency should fail after reset, \
         got: {result:?}"
    );
}

/// Two consecutive resets on `AesEncryptDecrypt` during decrypt
/// are each followed by a successful recovery.
#[api_test]
fn test_aes_cbc_decrypt_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"test data for encryption!!!!!!!";
    let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));
    let result1 = cbc_decrypt(&key, &iv, &ciphertext);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First AES-CBC decrypt should recover after reset"
    );

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));
    let result2 = cbc_decrypt(&key, &iv, &ciphertext);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second AES-CBC decrypt should recover after reset"
    );
}

// =========================================================================
// RSA key attestation — fault-injection tests
// =========================================================================

/// Helper to generate an RSA key report (attestation).
fn generate_rsa_key_report(key: &HsmRsaPrivateKey) -> HsmResult<Vec<u8>> {
    let report_data = [0u8; 128];
    let report_size = HsmKeyManager::generate_key_report(key, &report_data, None)?;
    let mut report_buffer = vec![0u8; report_size];
    let actual_size =
        HsmKeyManager::generate_key_report(key, &report_data, Some(&mut report_buffer))?;
    report_buffer.truncate(actual_size);
    Ok(report_buffer)
}

/// RSA key attestation recovers from a single transient fault on
/// `AttestKey` for retryable error codes, and fails immediately
/// for non-retryable ones.
#[api_test]
fn test_rsa_key_report_recovers_from_single_fault() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = import_rsa_sign_key(&session);

        let before = op_call_count(DdiOp::AttestKey);

        inject_fault(FaultRule::fail_next(DdiOp::AttestKey, 1, *error));

        let result = generate_rsa_key_report(&priv_key);
        let after = op_call_count(DdiOp::AttestKey);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "single fault on AttestKey (RSA)",
        );

        let expected = expected_op_calls(error, 1);
        assert!(
            after - before >= expected,
            "single fault on AttestKey (RSA): expected >= {expected} calls \
             for {error:?}, got {}",
            after - before,
        );
    }
}

/// RSA key attestation recovers on the last retry.
#[api_test]
fn test_rsa_key_report_recovers_on_last_retry() {
    for error in &super::all_test_errors() {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = import_rsa_sign_key(&session);

        inject_fault(FaultRule::fail_next(DdiOp::AttestKey, MAX_RETRIES, *error));

        let result = generate_rsa_key_report(&priv_key);
        clear_faults();

        super::assert_retryable_outcome(
            &result,
            error,
            is_key_op_retryable,
            "last retry on AttestKey (RSA)",
        );
    }
}

/// RSA key attestation fails when all retries are exhausted.
#[api_test]
fn test_rsa_key_report_fails_after_all_retries_exhausted() {
    for error in super::KEY_OP_RETRYABLE_ERRORS {
        let (_part, session, _ctx) = init_with_resiliency_and_session();
        let (priv_key, _pub_key) = import_rsa_sign_key(&session);

        inject_fault(FaultRule::fail_next(
            DdiOp::AttestKey,
            MAX_RETRIES + 1,
            *error,
        ));

        let result = generate_rsa_key_report(&priv_key);
        clear_faults();

        assert!(
            result.is_err(),
            "RSA key attestation should fail after exhausting retries \
             with {error:?}, got: {result:?}"
        );
    }
}

/// Without resiliency, RSA key attestation does not retry.
#[api_test]
fn test_rsa_key_report_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    inject_fault(FaultRule::fail_next(
        DdiOp::AttestKey,
        1,
        DriverError::IoAborted,
    ));

    let result = generate_rsa_key_report(&priv_key);
    clear_faults();

    assert!(
        result.is_err(),
        "RSA key attestation without resiliency should fail on IoAborted, \
         got: {result:?}"
    );
}

/// RSA key attestation recovers from compound fault on
/// AttestKey + InitBk3.
#[api_test]
fn test_rsa_key_report_recovers_from_compound_fault() {
    if use_tpm() {
        return;
    }
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    inject_fault(FaultRule::fail_next(
        DdiOp::AttestKey,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));
    inject_fault(FaultRule::fail_next(
        DdiOp::InitBk3,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = generate_rsa_key_report(&priv_key);
    clear_faults();

    assert!(
        result.is_ok(),
        "RSA key attestation should recover from compound faults, got: {result:?}"
    );
}

// =========================================================================
// RSA key attestation — reset-triggered tests
// =========================================================================

/// After a reset, RSA key attestation recovers.
#[api_test]
fn test_rsa_key_report_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::AttestKey, 1));

    let result = generate_rsa_key_report(&priv_key);
    clear_faults();

    assert!(
        result.is_ok(),
        "RSA key attestation should recover after reset, got: {result:?}"
    );
}

/// Without resiliency, RSA key attestation does not recover from a reset.
#[api_test]
fn test_rsa_key_report_fails_after_reset_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::AttestKey, 1));

    let result = generate_rsa_key_report(&priv_key);
    clear_faults();

    assert!(
        result.is_err(),
        "RSA key attestation without resiliency should fail after reset, \
         got: {result:?}"
    );
}

/// Two consecutive resets on `AttestKey` for RSA key are each
/// followed by a successful recovery.
#[api_test]
fn test_rsa_key_report_recovers_after_consecutive_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let (priv_key, _pub_key) = import_rsa_sign_key(&session);

    inject_fault(FaultRule::reset_on_next(DdiOp::AttestKey, 1));
    let result1 = generate_rsa_key_report(&priv_key);
    clear_faults();
    assert!(
        result1.is_ok(),
        "First RSA key attestation should recover after reset"
    );

    inject_fault(FaultRule::reset_on_next(DdiOp::AttestKey, 1));
    let result2 = generate_rsa_key_report(&priv_key);
    clear_faults();
    assert!(
        result2.is_ok(),
        "Second RSA key attestation should recover after reset"
    );
}

// =========================================================================
// AES-CBC streaming encrypt — fault-injection tests
// =========================================================================

/// AES-CBC streaming encrypt recovers from a single transient fault
/// on `AesEncryptDecrypt` during a multi-chunk operation.
#[api_test]
fn test_aes_cbc_streaming_encrypt_recovers_from_single_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    // Two 16-byte chunks → each triggers a separate DDI call.
    let chunks: &[&[u8]] = &[b"chunk one 16byte", b"chunk two 16byte"];

    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = cbc_streaming_encrypt(&key, &iv, chunks);
    clear_faults();

    assert!(
        result.is_ok(),
        "Streaming AES-CBC encrypt should recover from single fault, \
         got: {result:?}"
    );
}

/// AES-CBC streaming encrypt recovers after a reset during a
/// multi-chunk operation.
#[api_test]
fn test_aes_cbc_streaming_encrypt_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let chunks: &[&[u8]] = &[b"chunk one 16byte", b"chunk two 16byte"];

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));

    let result = cbc_streaming_encrypt(&key, &iv, chunks);
    clear_faults();

    assert!(
        result.is_ok(),
        "Streaming AES-CBC encrypt should recover after reset, \
         got: {result:?}"
    );
}

/// Without resiliency, streaming AES-CBC encrypt does not retry.
#[api_test]
fn test_aes_cbc_streaming_encrypt_no_retry_without_resiliency() {
    let (_part, session) = init_without_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let chunks: &[&[u8]] = &[b"chunk one 16byte", b"chunk two 16byte"];

    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        DriverError::IoAborted,
    ));

    let result = cbc_streaming_encrypt(&key, &iv, chunks);
    clear_faults();

    assert!(
        result.is_err(),
        "Streaming AES-CBC encrypt without resiliency should fail, \
         got: {result:?}"
    );
}

// =========================================================================
// AES-CBC streaming decrypt — fault-injection tests
// =========================================================================

/// AES-CBC streaming decrypt recovers from a single transient fault.
#[api_test]
fn test_aes_cbc_streaming_decrypt_recovers_from_single_fault() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"chunk one 16bytechunk two 16byte";
    let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

    // Split ciphertext into 16-byte chunks for streaming decrypt.
    let mid = 16;
    let chunks: &[&[u8]] = &[&ciphertext[..mid], &ciphertext[mid..]];

    inject_fault(FaultRule::fail_next(
        DdiOp::AesEncryptDecrypt,
        1,
        FaultError::Driver(DriverError::IoAborted),
    ));

    let result = cbc_streaming_decrypt(&key, &iv, chunks);
    clear_faults();

    assert!(
        result.is_ok(),
        "Streaming AES-CBC decrypt should recover from single fault, \
         got: {result:?}"
    );
}

/// AES-CBC streaming decrypt recovers after a reset.
#[api_test]
fn test_aes_cbc_streaming_decrypt_recovers_after_reset() {
    let (_part, session, _ctx) = init_with_resiliency_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"chunk one 16bytechunk two 16byte";
    let ciphertext = cbc_encrypt(&key, &iv, plaintext).expect("encrypt failed");

    let mid = 16;
    let chunks: &[&[u8]] = &[&ciphertext[..mid], &ciphertext[mid..]];

    inject_fault(FaultRule::reset_on_next(DdiOp::AesEncryptDecrypt, 1));

    let result = cbc_streaming_decrypt(&key, &iv, chunks);
    clear_faults();

    assert!(
        result.is_ok(),
        "Streaming AES-CBC decrypt should recover after reset, \
         got: {result:?}"
    );
}
