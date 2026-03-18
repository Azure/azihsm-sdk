// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Multi-threaded stress tests for key-operation resiliency.
//!
//! These tests exercise the resiliency retry path (proc macros
//! `#[resiliency_key_gen]` and `#[resiliency_key_op]`) under concurrent Reset
//! pressure. Unlike the fault-injection tests in `resiliency/`, these
//! tests use the mock device directly and trigger real simulated
//! Resets via [`HsmPartition::reset`].
//!
//! # Architecture
//!
//! Each test follows this pattern:
//!
//! 1. Initialize a partition with resiliency enabled.
//! 2. Open a session and generate keys.
//! 3. Spawn N worker threads that repeatedly perform key operations.
//! 4. Spawn 1 Reset thread that continuously calls
//!    `partition.reset()`.
//! 5. All threads synchronize at a [`Barrier`] and run for a fixed
//!    number of iterations.
//! 6. Workers assert that every operation eventually succeeds (the
//!    retry macros recover from transient Reset failures).
//!
//! # Feature gate
//!
//! This module does not require the `res-test` feature.
//! It does not depend on `azihsm_res_test_dev` (no fault
//! injection); Resets are triggered directly via `partition.reset()`.
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use azihsm_crypto as crypto;
use tracing::*;

use super::super::helpers::*;
use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

// Constants

/// Number of worker threads per test.
const NUM_WORKERS: usize = 8;

/// Number of iterations each worker performs.
const ITERATIONS_PER_WORKER: usize = 500;

/// Delay between Reset triggers (ms).
///
/// Mock: the retry backoff base is 8 ms (see `BACKOFF_BASE_MS` in
/// `resiliency.rs` under `cfg(feature = "mock")`), and
/// `SessionNeedsRenegotiation` retries without backoff.
/// With 4 workers all serializing through `restore_partition`,
/// recovery completes quickly. 1 second is high enough for
/// recovery to finish, but low enough that workers encounter
/// multiple Resets during their run.
///
/// Real hardware: `BACKOFF_BASE_MS` is 400 ms, and Reset may take
/// up to ~5 seconds to complete. The interval must be longer than
/// that to avoid spurious `IOAbortInProgress` errors.
#[cfg(feature = "mock")]
const RESET_INTERVAL_MS: u64 = 1000;
#[cfg(not(feature = "mock"))]
const RESET_INTERVAL_MS: u64 = 7000;

/// Small inter-iteration sleep (ms) so that the worker loop
/// runs long enough to span several Reset cycles.
const WORKER_ITER_SLEEP_MS: u64 = 10;

// Setup helpers

/// Initialize a partition with resiliency enabled and open a session.
///
/// Returns the partition, credentials, session, and the RAII context
/// that owns the resiliency temp directory.
fn init_partition_and_session() -> (HsmPartition, HsmCredentials, HsmSession, ResiliencyTestCtx) {
    let (part, session, ctx) = init_with_resiliency_and_session();
    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    (part, creds, session, ctx)
}

// Key-generation and crypto-operation helpers imported from
// `crate::utils::key_helpers`.

/// Derive an HMAC-SHA256 key from a shared secret via HKDF.
fn hkdf_derive_hmac_key(session: &HsmSession, shared_secret: &HsmGenericSecretKey) -> HsmHmacKey {
    let hmac_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build HMAC key props");

    let mut hkdf_algo = HsmHkdfAlgo::new(
        HsmHashAlgo::Sha256,
        Some(b"stress_salt"),
        Some(b"stress_info"),
    )
    .expect("Failed to create HKDF algo");

    let derived_key =
        HsmKeyManager::derive_key(session, &mut hkdf_algo, shared_secret, hmac_key_props)
            .expect("Failed to derive HMAC key via HKDF");

    derived_key
        .try_into()
        .expect("Failed to convert derived key to HsmHmacKey")
}

// Reset thread

/// Spawn a background thread that continuously triggers Reset until the
/// stop flag is set.
///
/// Opens a separate `HsmPartition` handle from the given `path` so
/// that `reset()`'s partition WRITE lock does not contend with the
/// workers' READ locks on the shared `RwLock`. The reset still affects
/// the underlying device, which is what the workers need to recover from.
fn spawn_reset_thread(
    path: String,
    stop: Arc<AtomicBool>,
    barrier: Arc<Barrier>,
) -> thread::JoinHandle<u32> {
    thread::spawn(move || {
        let partition = HsmPartitionManager::open_partition(&path)
            .expect("Failed to open partition for reset thread");
        barrier.wait();
        let tid = std::thread::current().id();
        let mut count = 0u32;
        while !stop.load(Ordering::Relaxed) {
            info!("[Reset tid={tid:?}] firing reset #{}", count + 1);
            let result = partition.reset();
            info!("[Reset tid={tid:?}] reset #{} result={result:?}", count + 1);
            if result.is_ok() {
                count += 1;
            }
            thread::sleep(Duration::from_millis(RESET_INTERVAL_MS));
        }
        info!("[Reset tid={tid:?}] exiting, total Resets={count}");
        count
    })
}

// =========================================================================
// Test: AES-CBC encrypt under continuous Reset
// =========================================================================

/// Multiple threads perform AES-CBC encrypt while a dedicated thread
/// fires Resets continuously. Every operation must eventually succeed
/// via the retry path.
#[api_test]
fn test_stress_aes_cbc_encrypt_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"stress test data!!!!!!!!!!!!!!!!"; // 32 bytes

    let stop = Arc::new(AtomicBool::new(false));
    // +1 for the Reset thread.
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    // Spawn Reset thread.
    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    // Spawn worker threads.
    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let key = key.clone();
            let barrier = barrier.clone();
            let plaintext = plaintext.to_vec();
            let iv = iv.clone();
            thread::spawn(move || {
                barrier.wait();
                let mut successes = 0u32;
                for i in 0..ITERATIONS_PER_WORKER {
                    let result = cbc_encrypt(&key, &iv, &plaintext);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: AES-CBC encrypt error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: AES-CBC encrypt failed: {:?}",
                        result.unwrap_err()
                    );
                    successes += 1;
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
                successes
            })
        })
        .collect();

    // Wait for workers to finish, then stop the Reset thread.
    let mut total_successes = 0u32;
    for w in workers {
        total_successes += w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");

    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total_successes, expected,
        "Expected {expected} total successes, got {total_successes}"
    );
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: AES-CBC encrypt + decrypt round-trip under Reset
// =========================================================================

/// Workers encrypt then decrypt under continuous Reset, verifying
/// round-trip correctness.
#[api_test]
fn test_stress_aes_cbc_round_trip_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let key = key.clone();
            let barrier = barrier.clone();
            let iv = iv.clone();
            thread::spawn(move || {
                barrier.wait();
                let mut successes = 0u32;
                for i in 0..ITERATIONS_PER_WORKER {
                    let plaintext = format!("worker {id} iteration {i} data!!");
                    let plaintext_bytes = plaintext.as_bytes();

                    let ciphertext = match cbc_encrypt(&key, &iv, plaintext_bytes) {
                        Ok(ct) => ct,
                        Err(e) => panic!("Worker {id} iteration {i}: encrypt failed: {e:?}"),
                    };

                    match cbc_decrypt(&key, &iv, &ciphertext) {
                        Ok(decrypted) => {
                            assert_eq!(
                                decrypted, plaintext_bytes,
                                "Worker {id} iteration {i}: round-trip mismatch"
                            );
                            successes += 1;
                        }
                        Err(e) => panic!("Worker {id} iteration {i}: decrypt failed: {e:?}"),
                    }
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
                successes
            })
        })
        .collect();

    let mut total = 0u32;
    for w in workers {
        total += w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: ECC sign under continuous Reset
// =========================================================================

/// Multiple threads perform ECC sign while Resets fire continuously.
#[api_test]
fn test_stress_ecc_sign_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"stress test data for ECC signing");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let priv_key = priv_key.clone();
            let hash = hash.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut sign_algo = HsmEccSignAlgo::default();
                    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: ECC sign error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: ECC sign failed: {:?}",
                        result.unwrap_err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: HMAC sign under continuous Reset
// =========================================================================

/// Multiple threads perform HMAC sign while Resets fire continuously.
#[api_test]
fn test_stress_hmac_sign_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate HMAC key via ECDH + HKDF.
    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let shared_secret =
        ecdh_derive(&session, &priv_key_a, &pub_key_b).expect("ECDH derivation failed");
    let hmac_key = hkdf_derive_hmac_key(&session, &shared_secret);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let hmac_key = hmac_key.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let msg = format!("worker {id} iteration {i} hmac msg");
                    let mut sign_algo = HsmHmacAlgo::new();
                    let result = HsmSigner::sign_vec(&mut sign_algo, &hmac_key, msg.as_bytes());
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: HMAC sign error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: HMAC sign failed: {:?}",
                        result.unwrap_err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: Mixed operations under continuous Reset
// =========================================================================

/// Workers perform different key operations (AES-CBC encrypt, ECC sign,
/// HMAC sign, RSA hash-sign) concurrently while Resets fire continuously.
#[api_test]
fn test_stress_mixed_ops_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate all key types up front.
    let aes_key = generate_aes_key(&session);
    let (ecc_priv, _ecc_pub) = generate_ecc_sign_key_pair(&session);
    let ecc_hash = hash_data(&session, b"mixed test ECC data");

    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let shared_secret =
        ecdh_derive(&session, &priv_key_a, &pub_key_b).expect("ECDH derivation failed");
    let hmac_key = hkdf_derive_hmac_key(&session, &shared_secret);
    let (rsa_priv, _rsa_pub) = generate_rsa_sign_key_pair(&session);

    let stop = Arc::new(AtomicBool::new(false));
    // 4 worker threads (one per op type) + 1 Reset thread.
    let barrier = Arc::new(Barrier::new(5));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    // Worker 0: AES-CBC encrypt
    let aes_barrier = barrier.clone();
    let aes_key_c = aes_key.clone();
    let aes_worker = thread::spawn(move || {
        aes_barrier.wait();
        let iv = crypto::Rng::rand_vec(16).expect("IV");
        let plaintext = b"mixed test aes data!!!!!!!!!!!!!"; // 32 bytes
        let mut successes = 0u32;
        for _i in 0..ITERATIONS_PER_WORKER {
            match cbc_encrypt(&aes_key_c, &iv, plaintext) {
                Ok(_) => successes += 1,
                Err(e) => panic!("AES worker unexpected error: {e:?}"),
            }
            thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
        }
        successes
    });

    // Worker 1: ECC sign
    let ecc_barrier = barrier.clone();
    let ecc_priv_c = ecc_priv.clone();
    let ecc_hash_c = ecc_hash.clone();
    let ecc_worker = thread::spawn(move || {
        ecc_barrier.wait();
        let mut successes = 0u32;
        for _i in 0..ITERATIONS_PER_WORKER {
            let mut sign_algo = HsmEccSignAlgo::default();
            match HsmSigner::sign_vec(&mut sign_algo, &ecc_priv_c, &ecc_hash_c) {
                Ok(_) => successes += 1,
                Err(e) => panic!("ECC worker unexpected error: {e:?}"),
            }
            thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
        }
        successes
    });

    // Worker 2: HMAC sign
    let hmac_barrier = barrier.clone();
    let hmac_key_c = hmac_key.clone();
    let hmac_worker = thread::spawn(move || {
        hmac_barrier.wait();
        let mut successes = 0u32;
        for _i in 0..ITERATIONS_PER_WORKER {
            let mut sign_algo = HsmHmacAlgo::new();
            match HsmSigner::sign_vec(&mut sign_algo, &hmac_key_c, b"mixed test hmac data") {
                Ok(_) => successes += 1,
                Err(e) => panic!("HMAC worker unexpected error: {e:?}"),
            }
            thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
        }
        successes
    });

    // Worker 3: RSA hash-sign
    let rsa_barrier = barrier.clone();
    let rsa_priv_c = rsa_priv.clone();
    let rsa_worker = thread::spawn(move || {
        rsa_barrier.wait();
        let message = b"mixed test rsa data!!!!!!!!!!!!!";
        let mut successes = 0u32;
        for _i in 0..ITERATIONS_PER_WORKER {
            let mut sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
            match HsmSigner::sign_vec(&mut sign_algo, &rsa_priv_c, message) {
                Ok(_) => successes += 1,
                Err(e) => panic!("RSA worker unexpected error: {e:?}"),
            }
            thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
        }
        successes
    });

    let aes_ok = aes_worker.join().expect("AES worker panicked");
    let ecc_ok = ecc_worker.join().expect("ECC worker panicked");
    let hmac_ok = hmac_worker.join().expect("HMAC worker panicked");
    let rsa_ok = rsa_worker.join().expect("RSA worker panicked");

    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );

    // Each worker must complete all iterations successfully.
    let expected = ITERATIONS_PER_WORKER as u32;
    assert_eq!(
        aes_ok, expected,
        "AES worker succeeded {aes_ok}/{ITERATIONS_PER_WORKER}, expected {expected}"
    );
    assert_eq!(
        ecc_ok, expected,
        "ECC worker succeeded {ecc_ok}/{ITERATIONS_PER_WORKER}, expected {expected}"
    );
    assert_eq!(
        hmac_ok, expected,
        "HMAC worker succeeded {hmac_ok}/{ITERATIONS_PER_WORKER}, expected {expected}"
    );
    assert_eq!(
        rsa_ok, expected,
        "RSA worker succeeded {rsa_ok}/{ITERATIONS_PER_WORKER}, expected {expected}"
    );
}

// =========================================================================
// Test: Key generation under continuous Reset
// =========================================================================

/// Workers repeatedly generate AES keys while Resets fire, verifying
/// that `#[resiliency_key_gen]` recovers.
#[api_test]
fn test_stress_key_gen_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
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
                    let result: HsmResult<HsmAesKey> =
                        HsmKeyManager::generate_key(&session, &mut algo, props);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: key gen error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: key gen failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: Rapid Reset bursts between operations
// =========================================================================

/// A single worker alternates between performing an AES-CBC encrypt and
/// triggering an Reset, validating recovery after every single reset.
#[api_test]
fn test_stress_rapid_reset_between_ops() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");
    let plaintext = b"rapid reset test data!!!!!!!!!!!!"; // 32 bytes

    const RAPID_RESET_ITERATIONS: usize = 10;
    for i in 0..RAPID_RESET_ITERATIONS {
        // Fire an Reset.
        part.reset()
            .unwrap_or_else(|e| panic!("Reset {i} failed: {e:?}"));

        // Wait for the device to settle before attempting recovery,
        // using the same interval as the multi-threaded stress tests.
        thread::sleep(Duration::from_millis(RESET_INTERVAL_MS));

        // The next encrypt must recover via the retry path.
        let result = cbc_encrypt(&key, &iv, plaintext);
        assert!(
            result.is_ok(),
            "Iteration {i}: AES-CBC encrypt after Reset failed: {:?}",
            result.unwrap_err()
        );
    }
}

// =========================================================================
// Test: AES-GCM round-trip under continuous Reset
// =========================================================================

/// Generate an AES-GCM-256 session key.
#[cfg(feature = "mock")]
fn generate_aes_gcm_key(session: &HsmSession) -> HsmAesGcmKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES-GCM key props");
    let mut algo = HsmAesGcmKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES-GCM key")
}

/// AES-GCM encrypt (returns ciphertext + tag).
#[cfg(feature = "mock")]
fn gcm_encrypt(
    key: &HsmAesGcmKey,
    iv: &[u8],
    aad: Option<&[u8]>,
    plaintext: &[u8],
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let ct_len = {
        let mut algo = HsmAesGcmAlgo::new_for_encryption(iv.to_vec(), aad.map(|a| a.to_vec()))
            .expect("Failed to create AES-GCM algo");
        HsmEncrypter::encrypt(&mut algo, key, plaintext, None)?
    };

    let mut out = vec![0u8; ct_len];
    let mut algo = HsmAesGcmAlgo::new_for_encryption(iv.to_vec(), aad.map(|a| a.to_vec()))
        .expect("Failed to create AES-GCM algo");
    let written = HsmEncrypter::encrypt(&mut algo, key, plaintext, Some(&mut out))?;
    out.truncate(written);
    let tag = algo.tag().expect("GCM tag missing after encrypt").to_vec();
    Ok((out, tag))
}

/// AES-GCM decrypt.
#[cfg(feature = "mock")]
fn gcm_decrypt(
    key: &HsmAesGcmKey,
    iv: &[u8],
    tag: &[u8],
    aad: Option<&[u8]>,
    ciphertext: &[u8],
) -> HsmResult<Vec<u8>> {
    let pt_len = {
        let mut algo =
            HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), tag.to_vec(), aad.map(|a| a.to_vec()))
                .expect("Failed to create AES-GCM decrypt algo");
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?
    };

    let mut out = vec![0u8; pt_len];
    let mut algo =
        HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), tag.to_vec(), aad.map(|a| a.to_vec()))
            .expect("Failed to create AES-GCM decrypt algo");
    let written = HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut out))?;
    out.truncate(written);
    Ok(out)
}

/// Workers encrypt then decrypt with AES-GCM under continuous Reset,
/// verifying round-trip correctness including authenticated data.
#[cfg(feature = "mock")]
#[api_test]
fn test_stress_aes_gcm_round_trip_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_gcm_key(&session);
    let iv = [0u8; 12]; // GCM uses 12-byte IV
    let aad = b"stress test additional data";

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let key = key.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let mut successes = 0u32;
                for i in 0..ITERATIONS_PER_WORKER {
                    let plaintext = format!("gcm worker {id} iteration {i} data");
                    let pt_bytes = plaintext.as_bytes();

                    let (ciphertext, tag) = match gcm_encrypt(&key, &iv, Some(aad), pt_bytes) {
                        Ok(pair) => pair,
                        Err(e) => panic!("Worker {id} iteration {i}: GCM encrypt failed: {e:?}"),
                    };

                    match gcm_decrypt(&key, &iv, &tag, Some(aad), &ciphertext) {
                        Ok(decrypted) => {
                            assert_eq!(
                                decrypted, pt_bytes,
                                "Worker {id} iteration {i}: GCM round-trip mismatch"
                            );
                            successes += 1;
                        }
                        Err(e) => panic!("Worker {id} iteration {i}: GCM decrypt failed: {e:?}"),
                    }
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
                successes
            })
        })
        .collect();

    let mut total = 0u32;
    for w in workers {
        total += w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: AES-XTS round-trip under continuous Reset
// =========================================================================

/// Generate an AES-XTS-512 session key.
#[cfg(feature = "mock")]
fn generate_aes_xts_key(session: &HsmSession) -> HsmAesXtsKey {
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
    HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES-XTS key")
}

/// AES-XTS encrypt.
#[cfg(feature = "mock")]
fn xts_encrypt(
    key: &HsmAesXtsKey,
    tweak: &[u8],
    dul: usize,
    plaintext: &[u8],
) -> HsmResult<Vec<u8>> {
    let ct_len = {
        let mut algo = HsmAesXtsAlgo::new(tweak, dul).expect("Failed to create AES-XTS algo");
        HsmEncrypter::encrypt(&mut algo, key, plaintext, None)?
    };

    let mut out = vec![0u8; ct_len];
    let written = {
        let mut algo = HsmAesXtsAlgo::new(tweak, dul).expect("Failed to create AES-XTS algo");
        HsmEncrypter::encrypt(&mut algo, key, plaintext, Some(&mut out))?
    };
    out.truncate(written);
    Ok(out)
}

/// AES-XTS decrypt.
#[cfg(feature = "mock")]
fn xts_decrypt(
    key: &HsmAesXtsKey,
    tweak: &[u8],
    dul: usize,
    ciphertext: &[u8],
) -> HsmResult<Vec<u8>> {
    let pt_len = {
        let mut algo = HsmAesXtsAlgo::new(tweak, dul).expect("Failed to create AES-XTS algo");
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?
    };

    let mut out = vec![0u8; pt_len];
    let written = {
        let mut algo = HsmAesXtsAlgo::new(tweak, dul).expect("Failed to create AES-XTS algo");
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut out))?
    };
    out.truncate(written);
    Ok(out)
}

/// Workers encrypt then decrypt with AES-XTS under continuous Reset,
/// verifying round-trip correctness.
#[cfg(feature = "mock")]
#[api_test]
fn test_stress_aes_xts_round_trip_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_xts_key(&session);
    let tweak = [0u8; 16]; // 16-byte tweak
    let dul: usize = 512; // data unit length: multiple of 16, max 8192
    // Plaintext must be a multiple of DUL.
    let plaintext = vec![0xABu8; dul];

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let key = key.clone();
            let barrier = barrier.clone();
            let plaintext = plaintext.clone();
            thread::spawn(move || {
                barrier.wait();
                let mut successes = 0u32;
                for i in 0..ITERATIONS_PER_WORKER {
                    let ciphertext = match xts_encrypt(&key, &tweak, dul, &plaintext) {
                        Ok(ct) => ct,
                        Err(e) => {
                            panic!("Worker {id} iteration {i}: XTS encrypt failed: {e:?}")
                        }
                    };

                    match xts_decrypt(&key, &tweak, dul, &ciphertext) {
                        Ok(decrypted) => {
                            assert_eq!(
                                decrypted, plaintext,
                                "Worker {id} iteration {i}: XTS round-trip mismatch"
                            );
                            successes += 1;
                        }
                        Err(e) => {
                            panic!("Worker {id} iteration {i}: XTS decrypt failed: {e:?}")
                        }
                    }
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
                successes
            })
        })
        .collect();

    let mut total = 0u32;
    for w in workers {
        total += w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: ECC sign + verify under continuous Reset
// =========================================================================

/// Workers sign with the private key and verify with the public key
/// under continuous Reset, ensuring both operations recover.
#[api_test]
fn test_stress_ecc_sign_verify_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let (priv_key, pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"stress test data for ECC sign+verify");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let priv_key = priv_key.clone();
            let pub_key = pub_key.clone();
            let hash = hash.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let mut successes = 0u32;
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut sign_algo = HsmEccSignAlgo::default();
                    let signature = match HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash) {
                        Ok(sig) => sig,
                        Err(e) => {
                            panic!("Worker {id} iteration {i}: ECC sign failed: {e:?}")
                        }
                    };

                    let mut verify_algo = HsmEccSignAlgo::default();
                    match HsmVerifier::verify(&mut verify_algo, &pub_key, &hash, &signature) {
                        Ok(valid) => {
                            assert!(
                                valid,
                                "Worker {id} iteration {i}: ECC verify returned false"
                            );
                            successes += 1;
                        }
                        Err(e) => {
                            panic!("Worker {id} iteration {i}: ECC verify failed: {e:?}")
                        }
                    }
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
                successes
            })
        })
        .collect();

    let mut total = 0u32;
    for w in workers {
        total += w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: HMAC sign + verify under continuous Reset
// =========================================================================

/// Workers sign and verify HMAC tags under continuous Reset.
#[api_test]
fn test_stress_hmac_sign_verify_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate HMAC key via ECDH + HKDF.
    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let shared_secret =
        ecdh_derive(&session, &priv_key_a, &pub_key_b).expect("ECDH derivation failed");
    let hmac_key = hkdf_derive_hmac_key(&session, &shared_secret);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let hmac_key = hmac_key.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let mut successes = 0u32;
                for i in 0..ITERATIONS_PER_WORKER {
                    let msg = format!("worker {id} iteration {i} hmac verify");
                    let msg_bytes = msg.as_bytes();

                    let mut sign_algo = HsmHmacAlgo::new();
                    let tag = match HsmSigner::sign_vec(&mut sign_algo, &hmac_key, msg_bytes) {
                        Ok(t) => t,
                        Err(e) => {
                            panic!("Worker {id} iteration {i}: HMAC sign failed: {e:?}")
                        }
                    };

                    let mut verify_algo = HsmHmacAlgo::new();
                    match HsmVerifier::verify(&mut verify_algo, &hmac_key, msg_bytes, &tag) {
                        Ok(valid) => {
                            assert!(
                                valid,
                                "Worker {id} iteration {i}: HMAC verify returned false"
                            );
                            successes += 1;
                        }
                        Err(e) => {
                            panic!("Worker {id} iteration {i}: HMAC verify failed: {e:?}")
                        }
                    }
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
                successes
            })
        })
        .collect();

    let mut total = 0u32;
    for w in workers {
        total += w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: ECC key-pair generation under continuous Reset
// =========================================================================

/// Workers repeatedly generate ECC P-256 key pairs while Resets fire,
/// verifying that `#[resiliency_key_gen]` recovers.
#[api_test]
fn test_stress_ecc_key_gen_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let priv_props = HsmKeyPropsBuilder::default()
                        .class(HsmKeyClass::Private)
                        .key_kind(HsmKeyKind::Ecc)
                        .ecc_curve(HsmEccCurve::P256)
                        .can_sign(true)
                        .is_session(true)
                        .build()
                        .expect("Failed to build ECC private key props");

                    let pub_props = HsmKeyPropsBuilder::default()
                        .class(HsmKeyClass::Public)
                        .key_kind(HsmKeyKind::Ecc)
                        .ecc_curve(HsmEccCurve::P256)
                        .can_verify(true)
                        .is_session(true)
                        .build()
                        .expect("Failed to build ECC public key props");

                    let mut algo = HsmEccKeyGenAlgo::default();
                    let result: HsmResult<(HsmEccPrivateKey, HsmEccPublicKey)> =
                        HsmKeyManager::generate_key_pair(
                            &session, &mut algo, priv_props, pub_props,
                        );
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: ECC key gen failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: AES-GCM key generation under continuous Reset
// =========================================================================

/// Workers repeatedly generate AES-GCM keys while Resets fire.
#[cfg(feature = "mock")]
#[api_test]
fn test_stress_aes_gcm_key_gen_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let props = HsmKeyPropsBuilder::default()
                        .class(HsmKeyClass::Secret)
                        .key_kind(HsmKeyKind::AesGcm)
                        .bits(256)
                        .can_encrypt(true)
                        .can_decrypt(true)
                        .is_session(true)
                        .build()
                        .expect("Failed to build AES-GCM key props");
                    let mut algo = HsmAesGcmKeyGenAlgo::default();
                    let result: HsmResult<HsmAesGcmKey> =
                        HsmKeyManager::generate_key(&session, &mut algo, props);
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: AES-GCM key gen failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: ECDH derivation under continuous Reset
// =========================================================================

/// Workers repeatedly perform ECDH key derivation while Resets fire.
#[api_test]
fn test_stress_ecdh_derive_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate two ECC key pairs for ECDH.
    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);

    let peer_pub_key_der = pub_key_b
        .pub_key_der_vec()
        .expect("Failed to get peer public key DER");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let priv_key = priv_key_a.clone();
            let peer_der = peer_pub_key_der.clone();
            let session = session.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
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
                    let mut algo = EcdhAlgo::new(&peer_der);
                    let result: HsmResult<HsmGenericSecretKey> =
                        HsmKeyManager::derive_key(&session, &mut algo, &priv_key, secret_props);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: ECDH derive error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: ECDH derive failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: HKDF derivation under continuous Reset
// =========================================================================

/// Workers repeatedly perform HKDF key derivation while Resets fire.
#[api_test]
fn test_stress_hkdf_derive_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Pre-derive a shared secret for HKDF base key.
    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let shared_secret =
        ecdh_derive(&session, &priv_key_a, &pub_key_b).expect("ECDH derivation failed");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let base_key = shared_secret.clone();
            let session = session.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let aes_key_props = HsmKeyPropsBuilder::default()
                        .class(HsmKeyClass::Secret)
                        .key_kind(HsmKeyKind::Aes)
                        .bits(256)
                        .can_encrypt(true)
                        .can_decrypt(true)
                        .is_session(true)
                        .build()
                        .expect("Failed to build AES key props");
                    let mut hkdf_algo = HsmHkdfAlgo::new(
                        HsmHashAlgo::Sha256,
                        Some(b"stress_salt"),
                        Some(b"stress_info"),
                    )
                    .expect("Failed to create HKDF algo");
                    let result: HsmResult<HsmGenericSecretKey> = HsmKeyManager::derive_key(
                        &session,
                        &mut hkdf_algo,
                        &base_key,
                        aes_key_props,
                    );
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: HKDF derive error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: HKDF derive failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: RSA hash-sign under continuous Reset
// =========================================================================

/// Generate an RSA sign key pair by importing a software-generated
/// key through the wrap/unwrap path.
fn generate_rsa_sign_key_pair(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    use crypto::*;

    // 1. Generate RSA key in software.
    let sw_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let der = sw_key.to_vec().expect("Failed to export RSA key DER");

    // 2. Generate an HSM unwrapping key pair.
    let unwrap_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build unwrapping key props");
    let unwrap_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build wrapping key props");
    let mut gen_algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    let (unwrap_priv, unwrap_pub) = HsmKeyManager::generate_key_pair(
        session,
        &mut gen_algo,
        unwrap_priv_props,
        unwrap_pub_props,
    )
    .expect("Failed to generate RSA unwrapping key pair");

    // 3. Wrap the software key with the HSM public key.
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha384, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der)
        .expect("Failed to wrap RSA key");

    // 4. Unwrap into the HSM as a sign-capable key.
    let sign_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_sign(true)
        .build()
        .expect("Failed to build RSA sign private key props");
    let verify_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_verify(true)
        .build()
        .expect("Failed to build RSA verify public key props");
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha384);
    let (priv_key, pub_key) = unwrap_algo
        .unwrap_key_pair(&unwrap_priv, &wrapped, sign_priv_props, verify_pub_props)
        .expect("Failed to unwrap RSA sign key pair");

    (priv_key, pub_key)
}

/// Workers repeatedly perform RSA hash-sign while Resets fire.
#[api_test]
fn test_stress_rsa_hash_sign_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let (priv_key, pub_key) = generate_rsa_sign_key_pair(&session);
    let message = b"stress test data for RSA signing!";

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let priv_key = priv_key.clone();
            let pub_key = pub_key.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    // Sign
                    let mut sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
                    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, message);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: RSA sign error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: RSA sign failed: {:?}",
                        result.unwrap_err()
                    );
                    let signature = result.unwrap();

                    // Verify
                    let mut verify_algo =
                        HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
                    let valid =
                        HsmVerifier::verify(&mut verify_algo, &pub_key, message, &signature);
                    assert!(
                        valid.is_ok() && valid.unwrap(),
                        "Worker {id} iteration {i}: RSA verify failed"
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: RSA key-pair unwrap under continuous Reset
// =========================================================================

/// Workers repeatedly unwrap an RSA key pair using the HSM unwrapping key
/// while Resets fire.
///
/// This exercises the `#[resiliency_key_op(key = "unwrapping_key")]`
/// recovery path, which requires MUK persistence.  After Reset, the
/// device needs the MUK (persisted by `generate_key_pair`) to
/// reconstruct the unwrapping key state, then `restore_from_masked`
/// restores the device handle so the next `unwrap_key_pair` succeeds.
#[api_test]
fn test_stress_rsa_unwrap_under_reset() {
    use crypto::*;

    let (part, _creds, session, _ctx) = init_partition_and_session();

    // 1. Generate an HSM RSA unwrapping key pair.
    let unwrap_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build unwrapping key props");
    let unwrap_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build wrapping key props");
    let mut gen_algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    let (unwrap_priv, unwrap_pub) = HsmKeyManager::generate_key_pair(
        &session,
        &mut gen_algo,
        unwrap_priv_props,
        unwrap_pub_props,
    )
    .expect("Failed to generate RSA unwrapping key pair");

    // 2. Generate a software RSA key and wrap it with the HSM public key.
    let sw_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let sw_key_der = sw_key.to_vec().expect("Failed to export RSA key DER");
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha384, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &sw_key_der)
        .expect("Failed to wrap RSA key");

    // Target key properties for each unwrap.
    let sign_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_sign(true)
        .build()
        .expect("Failed to build RSA sign private key props");
    let verify_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_verify(true)
        .build()
        .expect("Failed to build RSA verify public key props");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let unwrap_priv = unwrap_priv.clone();
            let wrapped = wrapped.clone();
            let sign_priv_props = sign_priv_props.clone();
            let verify_pub_props = verify_pub_props.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha384);
                    let result = unwrap_algo.unwrap_key_pair(
                        &unwrap_priv,
                        &wrapped,
                        sign_priv_props.clone(),
                        verify_pub_props.clone(),
                    );
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: RSA unwrap error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: RSA unwrap failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: ECC key-pair unmask under continuous Reset
// =========================================================================

/// Workers repeatedly unmask an ECC key pair from a masked blob while
/// Resets fire.
#[api_test]
fn test_stress_ecc_unmask_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate an ECC sign key pair and grab its masked blob.
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let masked_blob = priv_key
        .masked_key_vec()
        .expect("Failed to get masked ECC key pair");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let blob = masked_blob.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut unmask_algo = HsmEccKeyUnmaskAlgo::default();
                    let result: HsmResult<(HsmEccPrivateKey, HsmEccPublicKey)> =
                        HsmKeyManager::unmask_key_pair(&session, &mut unmask_algo, &blob);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: ECC unmask error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: ECC unmask failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: Generic secret unmask under continuous Reset
// =========================================================================

/// Workers repeatedly unmask a shared secret (from ECDH) while Resets fire.
#[api_test]
fn test_stress_generic_secret_unmask_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Derive a shared secret and grab its masked blob.
    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let shared_secret =
        ecdh_derive(&session, &priv_key_a, &pub_key_b).expect("ECDH derivation failed");
    let masked_blob = shared_secret
        .masked_key_vec()
        .expect("Failed to get masked shared secret");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let blob = masked_blob.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut unmask_algo = HsmGenericSecretKeyUnmaskAlgo::default();
                    let result: HsmResult<HsmGenericSecretKey> =
                        HsmKeyManager::unmask_key(&session, &mut unmask_algo, &blob);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: generic secret unmask error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: generic secret unmask failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: ECC key attestation under continuous Reset
// =========================================================================

/// Workers repeatedly perform ECC key attestation while Resets fire.
#[api_test]
fn test_stress_ecc_key_report_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let mut priv_key = priv_key.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let report_data = [0x42u8; 128];
                    let result =
                        HsmKeyManager::generate_key_report_vec(&mut priv_key, &report_data);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: ECC key report error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: ECC key report failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: Key deletion after Reset (epoch-aware)
// =========================================================================

/// Workers generate keys and delete them while Resets fire. The epoch
/// check in `delete_key` ensures stale handles are not sent to the
/// device.
#[api_test]
fn test_stress_delete_key_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    // Generate a session AES key.
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
                    let key_result = HsmKeyManager::generate_key(&session, &mut algo, props);
                    if let Err(ref e) = key_result {
                        warn!("Worker {id} iteration {i}: AES key gen error: {e:?}");
                    }
                    assert!(
                        key_result.is_ok(),
                        "Worker {id} iteration {i}: AES key gen failed: {:?}",
                        key_result.err()
                    );
                    let key = key_result.unwrap();

                    // Explicit delete — should succeed even after Reset
                    // (epoch check skips the DDI call for stale handles).
                    let del_result = HsmKeyManager::delete_key(key);
                    if let Err(ref e) = del_result {
                        warn!("Worker {id} iteration {i}: delete_key error: {e:?}");
                    }
                    assert!(
                        del_result.is_ok(),
                        "Worker {id} iteration {i}: delete_key failed: {:?}",
                        del_result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: cert_chain under continuous Reset
// =========================================================================

/// Workers repeatedly call `cert_chain(0)` while a dedicated thread
/// fires Resets. Every `cert_chain` call must eventually succeed
/// via the retry path.
#[api_test]
fn test_stress_cert_chain_under_reset() {
    let (part, _creds, _session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let part = part.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let mut successes = 0u32;
                for i in 0..ITERATIONS_PER_WORKER {
                    let result = part.cert_chain(0);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: cert_chain error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: cert_chain failed: {:?}",
                        result.err()
                    );
                    successes += 1;
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
                successes
            })
        })
        .collect();

    let mut total_successes = 0u32;
    for w in workers {
        total_successes += w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");

    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total_successes, expected,
        "Expected {expected} total successes, got {total_successes}"
    );
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: concurrent init_part under continuous Reset
// =========================================================================

/// Multiple threads repeatedly call `init()` with resiliency enabled
/// while a dedicated thread fires Resets. Every `init()` call must
/// eventually succeed via the `#[resiliency_init_part]` retry path.
///
/// This exercises the cross-process resiliency lock serialization,
/// `try_establish_credential`'s `MaskedKeyDecodeFailed` retry, and
/// POTA re-endorsement — all under concurrent Reset pressure.
#[api_test]
fn test_stress_init_part_under_reset() {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    let path = list[0].path.clone();

    // Initial setup: open, reset, init once to establish baseline.
    let part = HsmPartitionManager::open_partition(&path).expect("Failed to open partition");
    part.reset().expect("Partition reset failed");

    // Create a shared resiliency context so all workers use the same
    // lock file and storage directory — just as real callers would.
    let shared_ctx = ResiliencyTestCtx::new();
    let shared_dir: Arc<std::path::PathBuf> = Arc::new(shared_ctx.dir().to_path_buf());

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);
    let resiliency_config = make_resiliency_config_in(&shared_dir, &part);
    part.init(
        creds,
        None,
        None,
        obk_info,
        pota_endorsement,
        Some(resiliency_config),
    )
    .expect("Initial partition init failed");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    // Spawn Reset thread.
    let reset_handle = spawn_reset_thread(path.clone(), stop.clone(), barrier.clone());

    // Spawn worker threads that each repeatedly call init.
    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let barrier = barrier.clone();
            let part = part.clone();
            let dir = shared_dir.clone();
            thread::spawn(move || {
                barrier.wait();
                let mut successes = 0u32;
                for i in 0..ITERATIONS_PER_WORKER {
                    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
                    let (obk_info, pota_endorsement) = make_init_params(&part);
                    let resiliency_config = make_resiliency_config_in(&dir, &part);

                    let result = part.init(
                        creds,
                        None,
                        None,
                        obk_info,
                        pota_endorsement,
                        Some(resiliency_config),
                    );
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: init failed: {:?}",
                        result.unwrap_err()
                    );
                    successes += 1;
                }
                successes
            })
        })
        .collect();

    let total: u32 = workers
        .into_iter()
        .map(|w| w.join().expect("Worker thread panicked"))
        .sum();
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");

    info!("init_part stress: {total} total inits, {reset_count} resets");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
    assert_eq!(
        total,
        (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32,
        "All init operations should have succeeded"
    );
}

// =========================================================================
// Test: AES-XTS key generation under continuous Reset
// =========================================================================

/// Workers repeatedly generate AES-XTS keys while Resets fire.
#[cfg(feature = "mock")]
#[api_test]
fn test_stress_aes_xts_key_gen_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
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
                    let result = HsmKeyManager::generate_key(&session, &mut algo, props);
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: AES-XTS key gen failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: RSA key report under continuous Reset
// =========================================================================

/// Workers repeatedly perform RSA key attestation while Resets fire.
#[api_test]
fn test_stress_rsa_key_report_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let (priv_key, _pub_key) = generate_rsa_sign_key_pair(&session);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let mut priv_key = priv_key.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let report_data = [0x42u8; 128];
                    let result =
                        HsmKeyManager::generate_key_report_vec(&mut priv_key, &report_data);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: RSA key report error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: RSA key report failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: RSA decrypt under continuous Reset
// =========================================================================

/// Workers repeatedly perform RSA decryption while Resets fire.
#[api_test]
fn test_stress_rsa_decrypt_under_reset() {
    use crypto::*;

    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Import an RSA key pair via wrap/unwrap for encryption/decryption.
    let sw_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let der = sw_key.to_vec().expect("Failed to export RSA key DER");

    let unwrap_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("unwrap priv props");
    let unwrap_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("unwrap pub props");
    let mut gen_algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    let (unwrap_priv, unwrap_pub) = HsmKeyManager::generate_key_pair(
        &session,
        &mut gen_algo,
        unwrap_priv_props,
        unwrap_pub_props,
    )
    .expect("generate unwrapping key pair");

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha384, 32);
    let wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).expect("wrap RSA key");

    let dec_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("dec priv props");
    let enc_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .expect("enc pub props");
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha384);
    let (dec_priv, enc_pub) = unwrap_algo
        .unwrap_key_pair(&unwrap_priv, &wrapped, dec_priv_props, enc_pub_props)
        .expect("unwrap RSA enc/dec key pair");

    // Pre-encrypt data with the public key.
    let plaintext = b"stress test RSA decrypt data!!!!";
    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut enc_algo, &enc_pub, plaintext).expect("RSA pre-encrypt");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let dec_priv = dec_priv.clone();
            let ciphertext = ciphertext.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
                    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &dec_priv, &ciphertext);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: RSA decrypt error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: RSA decrypt failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: AES key unmask under continuous Reset
// =========================================================================

/// Workers repeatedly unmask an AES key from a masked blob while Resets fire.
#[api_test]
fn test_stress_aes_unmask_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let key = generate_aes_key(&session);
    let masked_blob = key.masked_key_vec().expect("Failed to get masked AES key");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let blob = masked_blob.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut unmask_algo = HsmAesKeyUnmaskAlgo::default();
                    let result: HsmResult<HsmAesKey> =
                        HsmKeyManager::unmask_key(&session, &mut unmask_algo, &blob);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: AES unmask error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: AES unmask failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: AES-XTS key unmask under continuous Reset
// =========================================================================

/// Workers repeatedly unmask an AES-XTS key from a masked blob while Resets fire.
#[cfg(feature = "mock")]
#[api_test]
fn test_stress_xts_unmask_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let key = generate_aes_xts_key(&session);
    let masked_blob = key.masked_key_vec().expect("Failed to get masked XTS key");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let blob = masked_blob.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut unmask_algo = HsmAesXtsKeyUnmaskAlgo::default();
                    let result: HsmResult<HsmAesXtsKey> =
                        HsmKeyManager::unmask_key(&session, &mut unmask_algo, &blob);
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: XTS unmask error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: XTS unmask failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: AES key unwrap (RSA-AES) under continuous Reset
// =========================================================================

/// Workers repeatedly unwrap an AES key using RSA-AES while Resets fire.
#[api_test]
fn test_stress_aes_unwrap_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate an RSA unwrapping key pair.
    let unwrap_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("unwrap priv props");
    let unwrap_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("unwrap pub props");
    let mut gen_algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    let (unwrap_priv, unwrap_pub) = HsmKeyManager::generate_key_pair(
        &session,
        &mut gen_algo,
        unwrap_priv_props,
        unwrap_pub_props,
    )
    .expect("generate unwrapping key pair");

    // Generate a software AES key, wrap it.
    let sw_aes_key = [0xABu8; 32];
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha384, 32);
    let wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &sw_aes_key).expect("wrap AES key");

    let aes_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("AES key props");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let unwrap_priv = unwrap_priv.clone();
            let wrapped = wrapped.clone();
            let aes_props = aes_props.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha384);
                    let result = unwrap_algo.unwrap_key(&unwrap_priv, &wrapped, aes_props.clone());
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: AES unwrap error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: AES unwrap failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: ECC key pair unwrap (RSA-AES) under continuous Reset
// =========================================================================

/// Workers repeatedly unwrap an ECC key pair using RSA-AES while Resets fire.
#[api_test]
fn test_stress_ecc_unwrap_under_reset() {
    use crypto::*;

    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate an RSA unwrapping key pair.
    let unwrap_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("unwrap priv props");
    let unwrap_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("unwrap pub props");
    let mut gen_algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    let (unwrap_priv, unwrap_pub) = HsmKeyManager::generate_key_pair(
        &session,
        &mut gen_algo,
        unwrap_priv_props,
        unwrap_pub_props,
    )
    .expect("generate unwrapping key pair");

    // Generate an ECC P-256 key in software and wrap it.
    let sw_ecc = crypto::EccPrivateKey::from_curve(crypto::EccCurve::P256)
        .expect("Failed to generate ECC key");
    let sw_ecc_der = sw_ecc.to_vec().expect("Failed to export ECC key DER");
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha384, 32);
    let wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &sw_ecc_der).expect("wrap ECC key");

    let sign_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("ECC sign priv props");
    let verify_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("ECC verify pub props");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let unwrap_priv = unwrap_priv.clone();
            let wrapped = wrapped.clone();
            let sign_priv_props = sign_priv_props.clone();
            let verify_pub_props = verify_pub_props.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha384);
                    let result = unwrap_algo.unwrap_key_pair(
                        &unwrap_priv,
                        &wrapped,
                        sign_priv_props.clone(),
                        verify_pub_props.clone(),
                    );
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: ECC unwrap error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: ECC unwrap failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: AES-XTS key unwrap (RSA-AES) under continuous Reset
// =========================================================================

/// Workers repeatedly unwrap an AES-XTS key using RSA-AES while Resets fire.
#[cfg(feature = "mock")]
#[api_test]
fn test_stress_xts_unwrap_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate an RSA unwrapping key pair.
    let unwrap_priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("unwrap priv props");
    let unwrap_pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("unwrap pub props");
    let mut gen_algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    let (unwrap_priv, unwrap_pub) = HsmKeyManager::generate_key_pair(
        &session,
        &mut gen_algo,
        unwrap_priv_props,
        unwrap_pub_props,
    )
    .expect("generate unwrapping key pair");

    // Create an XTS wrap blob using the special two-key format.
    let key1 = [0x11u8; 32];
    let key2 = [0x22u8; 32];
    let wrapped = {
        const WRAP_BLOB_MAGIC: u64 = 0x5354_584D_5348_5A41;
        const WRAP_BLOB_VERSION: u16 = 1;

        let mut wrap1 = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
        let key1_wrapped =
            HsmEncrypter::encrypt_vec(&mut wrap1, &unwrap_pub, &key1).expect("XTS key1 wrap");
        let mut wrap2 = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
        let key2_wrapped =
            HsmEncrypter::encrypt_vec(&mut wrap2, &unwrap_pub, &key2).expect("XTS key2 wrap");

        let key1_len = key1_wrapped.len() as u16;
        let key2_len = key2_wrapped.len() as u16;

        let mut hdr = [0u8; 16];
        hdr[0..8].copy_from_slice(&WRAP_BLOB_MAGIC.to_le_bytes());
        hdr[8..10].copy_from_slice(&WRAP_BLOB_VERSION.to_le_bytes());
        hdr[10..12].copy_from_slice(&key1_len.to_le_bytes());
        hdr[12..14].copy_from_slice(&key2_len.to_le_bytes());

        let mut blob = Vec::new();
        blob.extend_from_slice(&hdr);
        blob.extend_from_slice(&key1_wrapped);
        blob.extend_from_slice(&key2_wrapped);
        blob
    };

    let xts_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("XTS key props");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let unwrap_priv = unwrap_priv.clone();
            let wrapped = wrapped.clone();
            let xts_props = xts_props.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let mut unwrap_algo = HsmAesXtsKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
                    let result = unwrap_algo.unwrap_key(&unwrap_priv, &wrapped, xts_props.clone());
                    if let Err(ref e) = result {
                        warn!("Worker {id} iteration {i}: XTS unwrap error: {e:?}");
                    }
                    assert!(
                        result.is_ok(),
                        "Worker {id} iteration {i}: XTS unwrap failed: {:?}",
                        result.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// Test: Keygen + immediate delete under continuous Reset
// =========================================================================

/// Workers repeatedly generate AES keys and immediately delete them while
/// Resets fire, exercising the keygen + epoch-aware delete path.
#[api_test]
fn test_stress_keygen_delete_under_reset() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let session = session.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERATIONS_PER_WORKER {
                    let props = HsmKeyPropsBuilder::default()
                        .class(HsmKeyClass::Secret)
                        .key_kind(HsmKeyKind::Aes)
                        .bits(256)
                        .can_encrypt(true)
                        .can_decrypt(true)
                        .is_session(true)
                        .build()
                        .expect("AES key props");
                    let mut algo = HsmAesKeyGenAlgo::default();
                    let key = HsmKeyManager::generate_key(&session, &mut algo, props);
                    assert!(
                        key.is_ok(),
                        "Worker {id} iteration {i}: keygen failed: {:?}",
                        key.err()
                    );
                    let del = HsmKeyManager::delete_key(key.unwrap());
                    assert!(
                        del.is_ok(),
                        "Worker {id} iteration {i}: delete failed: {:?}",
                        del.err()
                    );
                    thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
}

// =========================================================================
// ABA safety tests — verify key handle isolation across resets
// =========================================================================

/// Concurrent key generation and key operations under resets must never
/// cross-contaminate key material.
///
/// Thread A repeatedly generates AES keys and encrypts known plaintext.
/// Thread B holds a pre-created ECC key and repeatedly signs data.
/// A Reset thread fires resets continuously.
///
/// After reset recovery, Thread A's newly generated key must produce
/// ciphertext that only that key can decrypt. Thread B's ECC signatures
/// must verify with Thread B's public key, not with any of Thread A's
/// keys. If an ABA handle collision occurred, one thread's operation
/// would silently use another thread's key material, producing output
/// that doesn't match.
#[api_test]
fn test_concurrent_key_gen_and_key_op_no_aba() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Pre-create an ECC sign key for Thread B.
    let (ecc_priv, ecc_pub) = generate_ecc_sign_key_pair(&session);

    let stop = Arc::new(AtomicBool::new(false));
    // 2 workers + 1 reset thread.
    let barrier = Arc::new(Barrier::new(3));

    let reset_handle = spawn_reset_thread(part.path(), stop.clone(), barrier.clone());

    // Thread A: generate AES keys and verify encrypt/decrypt round-trip.
    let session_a = session.clone();
    let barrier_a = barrier.clone();
    let handle_a = thread::spawn(move || {
        barrier_a.wait();
        let mut successes = 0u32;
        for i in 0..ITERATIONS_PER_WORKER {
            // Generate a fresh AES key.
            let props = HsmKeyPropsBuilder::default()
                .class(HsmKeyClass::Secret)
                .key_kind(HsmKeyKind::Aes)
                .bits(256)
                .can_encrypt(true)
                .can_decrypt(true)
                .is_session(true)
                .build()
                .expect("AES key props");
            let mut algo = HsmAesKeyGenAlgo::default();
            let key = match HsmKeyManager::generate_key(&session_a, &mut algo, props) {
                Ok(k) => k,
                Err(e) => {
                    panic!("Thread A iteration {i}: key gen failed: {e:?}");
                }
            };

            // Encrypt and decrypt — verify the round-trip produces the
            // original plaintext. If an ABA collision occurred, the key
            // behind this handle would be wrong and decryption would
            // produce garbage or fail.
            let iv = crypto::Rng::rand_vec(16).expect("IV");
            let plaintext = format!("aba-test-A-iter-{i}!!!!!!!!!!!!!!!");
            let plaintext_bytes = &plaintext.as_bytes()[..32];

            let ct = match cbc_encrypt(&key, &iv, plaintext_bytes) {
                Ok(ct) => ct,
                Err(e) => {
                    warn!("Thread A iteration {i}: encrypt failed: {e:?}");
                    continue; // retry error during reset — acceptable
                }
            };

            let pt = match cbc_decrypt(&key, &iv, &ct) {
                Ok(pt) => pt,
                Err(e) => {
                    warn!("Thread A iteration {i}: decrypt failed: {e:?}");
                    continue; // retry error during reset — acceptable
                }
            };

            assert_eq!(
                pt, plaintext_bytes,
                "Thread A iteration {i}: ABA detected! Decrypted plaintext \
                 does not match original — key handle may have been reused \
                 for a different key."
            );
            successes += 1;
            thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
        }
        successes
    });

    // Thread B: sign with ECC key and verify the signature.
    let session_b = session.clone();
    let barrier_b = barrier.clone();
    let handle_b = thread::spawn(move || {
        barrier_b.wait();
        let mut successes = 0u32;
        for i in 0..ITERATIONS_PER_WORKER {
            let data = format!("aba-test-B-iter-{i}");
            let hash = {
                let mut hash_algo = HsmHashAlgo::Sha256;
                match HsmHasher::hash_vec(&session_b, &mut hash_algo, data.as_bytes()) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("Thread B iteration {i}: hash failed: {e:?}");
                        continue;
                    }
                }
            };

            let mut sign_algo = HsmEccSignAlgo::default();
            let sig = match HsmSigner::sign_vec(&mut sign_algo, &ecc_priv, &hash) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Thread B iteration {i}: sign failed: {e:?}");
                    continue;
                }
            };

            // Verify with the original public key. If an ABA collision
            // occurred, the signature would have been produced with a
            // different key and verification would fail.
            let mut verify_algo = HsmEccSignAlgo::default();
            let valid = match HsmVerifier::verify(&mut verify_algo, &ecc_pub, &hash, &sig) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Thread B iteration {i}: verify failed: {e:?}");
                    continue;
                }
            };

            assert!(
                valid,
                "Thread B iteration {i}: ABA detected! Signature produced by \
                 ECC sign does not verify with the original public key — key \
                 handle may have been reused for a different key."
            );
            successes += 1;
            thread::sleep(Duration::from_millis(WORKER_ITER_SLEEP_MS));
        }
        successes
    });

    let successes_a = handle_a.join().expect("Thread A panicked");
    let successes_b = handle_b.join().expect("Thread B panicked");
    stop.store(true, Ordering::Relaxed);
    let reset_count = reset_handle.join().expect("Reset thread panicked");

    info!(
        "ABA test: Thread A {successes_a} key-gen round-trips, \
         Thread B {successes_b} sign-verify round-trips, \
         {reset_count} resets"
    );
    assert!(
        reset_count > 0,
        "Reset thread should have triggered at least one Reset"
    );
    assert!(
        successes_a > 0,
        "Thread A should have completed at least one round-trip"
    );
    assert!(
        successes_b > 0,
        "Thread B should have completed at least one round-trip"
    );
}

/// After a reset, a restored key's handle must not collide with a
/// concurrently generated key's handle.
///
/// This test verifies the fix to `execute_key_gen_with_retry` that
/// uses a write lock during retry to prevent ABA collisions.
///
/// 1. Generate two AES keys (key_encrypt, key_sign_source).
/// 2. Reset the device.
/// 3. On one thread, trigger recovery on key_encrypt (via encrypt).
///    This calls restore_from_masked → unmask → gets a new handle.
/// 4. On another thread, generate a new AES key.
///    This calls AesGenerateKey → gets a new handle.
/// 5. Verify both keys work independently: key_encrypt decrypts its
///    own ciphertext, and the new key decrypts its own ciphertext.
///    If handles collided, one key's decrypt would fail or produce
///    wrong plaintext.
#[api_test]
fn test_key_gen_during_restore_no_handle_collision() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key_a = generate_aes_key(&session);
    let iv = crypto::Rng::rand_vec(16).expect("IV");

    // Encrypt with key_a before any reset.
    let plaintext_a = b"key-A-plaintext-for-roundtrip!!!";
    let ct_a = cbc_encrypt(&key_a, &iv, plaintext_a).expect("pre-reset encrypt failed");

    const ITERATIONS: usize = 10;
    for i in 0..ITERATIONS {
        // Reset — invalidates all handles.
        part.reset()
            .unwrap_or_else(|e| panic!("Reset {i} failed: {e:?}"));
        thread::sleep(Duration::from_millis(RESET_INTERVAL_MS));

        // Recover key_a by using it (triggers restore_from_masked).
        let pt_a = cbc_decrypt(&key_a, &iv, &ct_a);
        assert!(
            pt_a.is_ok(),
            "Iteration {i}: key_a decrypt after reset failed: {:?}",
            pt_a.err()
        );
        assert_eq!(
            pt_a.unwrap(),
            plaintext_a.as_slice(),
            "Iteration {i}: key_a decrypted wrong plaintext after restore"
        );

        // Generate a new key and verify it works independently.
        let key_b = generate_aes_key(&session);
        let plaintext_b = [0x42u8; 32];

        let ct_b = cbc_encrypt(&key_b, &iv, &plaintext_b)
            .unwrap_or_else(|e| panic!("Iteration {i}: key_b encrypt failed: {e:?}"));
        let pt_b = cbc_decrypt(&key_b, &iv, &ct_b)
            .unwrap_or_else(|e| panic!("Iteration {i}: key_b decrypt failed: {e:?}"));
        assert_eq!(
            pt_b.as_slice(),
            &plaintext_b[..],
            "Iteration {i}: key_b decrypted wrong plaintext — possible ABA collision"
        );

        // Verify key_a still works after key_b was generated.
        let pt_a2 = cbc_decrypt(&key_a, &iv, &ct_a)
            .unwrap_or_else(|e| panic!("Iteration {i}: key_a re-decrypt failed: {e:?}"));
        assert_eq!(
            pt_a2,
            plaintext_a.as_slice(),
            "Iteration {i}: key_a re-decrypt produced wrong plaintext after key_b gen"
        );
    }
}
