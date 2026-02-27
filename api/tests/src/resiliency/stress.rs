// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Multi-threaded stress tests for key-operation resiliency.
//!
//! These tests exercise the resiliency retry path (proc macros
//! `#[resiliency_key_gen]` and `#[resiliency_key_op]`) under concurrent NSSR
//! pressure. Unlike the fault-injection tests in `resiliency/`, these
//! tests use the **mock** device directly and trigger real simulated
//! NSSRs via [`HsmPartition::reset`].
//!
//! # Architecture
//!
//! Each test follows this pattern:
//!
//! 1. Initialize a partition with resiliency enabled.
//! 2. Open a session and generate keys.
//! 3. Spawn **N** worker threads that repeatedly perform key operations.
//! 4. Spawn **1** NSSR thread that continuously calls
//!    `partition.reset()`.
//! 5. All threads synchronize at a [`Barrier`] and run for a fixed
//!    number of iterations.
//! 6. Workers assert that every operation eventually succeeds (the
//!    retry macros recover from transient NSSR failures).
//!
//! # Feature gate
//!
//! This module is compiled only under `#[cfg(feature = "mock")]`.
//! It does **not** depend on `azihsm_ddi_resiliency_mock` (no fault
//! injection); NSSR is triggered directly on the mock device.

use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use crate::utils::partition::*;
use crate::utils::resiliency::*;
use crate::*;

// ── Constants ────────────────────────────────────────────────────────────

/// Number of worker threads per test.
const NUM_WORKERS: usize = 4;

/// Number of iterations each worker performs.
const ITERATIONS_PER_WORKER: usize = 100;

/// Delay between NSSR triggers (ms).
/// Under `mock` the retry backoff base is 400 ms, and
/// `SessionNeedsRenegotiation` retries without backoff.
/// With 4 workers all serializing through `restore_partition`
/// recovery takes up to ~500 ms. Set the interval high enough
/// that recovery always completes before the next NSSR, but
/// low enough that workers encounter multiple NSSRs during
/// their run (~6 seconds).
const NSSR_INTERVAL_MS: u64 = 3000;

/// Small inter-iteration sleep (ms) so that the worker loop
/// runs long enough to span several NSSR cycles.
const WORKER_ITER_SLEEP_MS: u64 = 50;

// ── Setup helpers ────────────────────────────────────────────────────────

/// Initialize a partition with resiliency enabled and open a session.
///
/// Returns the partition, credentials, session, and the RAII context
/// that owns the resiliency temp directory.
fn init_partition_and_session() -> (HsmPartition, HsmCredentials, HsmSession, ResiliencyTestCtx) {
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

    (part, creds, session, ctx)
}

// ── Key-generation helpers ───────────────────────────────────────────────

/// Generate an AES-256 session key.
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

/// Generate an ECC P-256 sign key pair.
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

/// Generate an ECC key pair with derive capability for ECDH.
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

// ── Operation helpers ────────────────────────────────────────────────────

/// AES-CBC encrypt (length query + actual encrypt).
fn cbc_encrypt(key: &HsmAesKey, iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    let cipher_len = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmEncrypter::encrypt(&mut algo, key, plaintext, None)?
    };

    let mut out = vec![0u8; cipher_len];
    let written = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmEncrypter::encrypt(&mut algo, key, plaintext, Some(&mut out))?
    };
    out.truncate(written);
    Ok(out)
}

/// AES-CBC decrypt.
fn cbc_decrypt(key: &HsmAesKey, iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
    let plain_len = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?
    };

    let mut out = vec![0u8; plain_len];
    let written = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut out))?
    };
    out.truncate(written);
    Ok(out)
}

/// Hash data with SHA-256.
fn hash_data(session: &HsmSession, data: &[u8]) -> Vec<u8> {
    let mut hash_algo = HsmHashAlgo::Sha256;
    HsmHasher::hash_vec(session, &mut hash_algo, data).expect("Failed to hash data")
}

// ── NSSR thread ──────────────────────────────────────────────────────────

/// Spawn a background thread that continuously triggers NSSR until the
/// stop flag is set.
fn spawn_nssr_thread(
    partition: HsmPartition,
    stop: Arc<AtomicBool>,
    barrier: Arc<Barrier>,
) -> thread::JoinHandle<u32> {
    thread::spawn(move || {
        barrier.wait();
        let mut count = 0u32;
        while !stop.load(Ordering::Relaxed) {
            if partition.reset().is_ok() {
                count += 1;
            }
            thread::sleep(Duration::from_millis(NSSR_INTERVAL_MS));
        }
        count
    })
}

// =========================================================================
// Test: AES-CBC encrypt under continuous NSSR
// =========================================================================

/// Multiple threads perform AES-CBC encrypt while a dedicated thread
/// fires NSSRs continuously. Every operation must eventually succeed
/// via the retry path.
#[api_test]
fn test_stress_aes_cbc_encrypt_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"stress test data!!!!!!!!!!!!!!!!"; // 32 bytes

    let stop = Arc::new(AtomicBool::new(false));
    // +1 for the NSSR thread.
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    // Spawn NSSR thread.
    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

    // Spawn worker threads.
    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let key = key.clone();
            let barrier = barrier.clone();
            let iv = iv;
            let plaintext = plaintext.to_vec();
            thread::spawn(move || {
                barrier.wait();
                let mut successes = 0u32;
                for i in 0..ITERATIONS_PER_WORKER {
                    let result = cbc_encrypt(&key, &iv, &plaintext);
                    if let Err(ref e) = result {
                        eprintln!("Worker {id} iteration {i}: AES-CBC encrypt error: {e:?}");
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

    // Wait for workers to finish, then stop the NSSR thread.
    let mut total_successes = 0u32;
    for w in workers {
        total_successes += w.join().expect("Worker thread panicked");
    }
    stop.store(true, Ordering::Relaxed);
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");

    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total_successes, expected,
        "Expected {expected} total successes, got {total_successes}"
    );
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
}

// =========================================================================
// Test: AES-CBC encrypt + decrypt round-trip under NSSR
// =========================================================================

/// Workers encrypt then decrypt under continuous NSSR, verifying
/// round-trip correctness.
#[api_test]
fn test_stress_aes_cbc_round_trip_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

    let workers: Vec<_> = (0..NUM_WORKERS)
        .map(|id| {
            let key = key.clone();
            let barrier = barrier.clone();
            let iv = iv;
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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: ECC sign under continuous NSSR
// =========================================================================

/// Multiple threads perform ECC sign while NSSRs fire continuously.
#[api_test]
fn test_stress_ecc_sign_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let (priv_key, _pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"stress test data for ECC signing");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

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
                        eprintln!("Worker {id} iteration {i}: ECC sign error: {e:?}");
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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
}

// =========================================================================
// Test: HMAC sign under continuous NSSR
// =========================================================================

/// Multiple threads perform HMAC sign while NSSRs fire continuously.
#[api_test]
fn test_stress_hmac_sign_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate HMAC key via ECDH + HKDF.
    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let shared_secret = ecdh_derive(&session, &priv_key_a, &pub_key_b);
    let hmac_key = hkdf_derive_hmac_key(&session, &shared_secret);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

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
                        eprintln!("Worker {id} iteration {i}: HMAC sign error: {e:?}");
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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
}

// =========================================================================
// Test: Mixed operations under continuous NSSR
// =========================================================================

/// Workers perform different key operations (AES-CBC encrypt, ECC sign,
/// HMAC sign) concurrently while NSSRs fire continuously.
#[api_test]
fn test_stress_mixed_ops_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate all key types up front.
    let aes_key = generate_aes_key(&session);
    let (ecc_priv, _ecc_pub) = generate_ecc_sign_key_pair(&session);
    let ecc_hash = hash_data(&session, b"mixed test ECC data");

    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let shared_secret = ecdh_derive(&session, &priv_key_a, &pub_key_b);
    let hmac_key = hkdf_derive_hmac_key(&session, &shared_secret);

    let stop = Arc::new(AtomicBool::new(false));
    // 3 worker threads (one per op type) + 1 NSSR thread.
    let barrier = Arc::new(Barrier::new(4));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

    // Worker 0: AES-CBC encrypt
    let aes_barrier = barrier.clone();
    let aes_key_c = aes_key.clone();
    let aes_worker = thread::spawn(move || {
        aes_barrier.wait();
        let iv = [0u8; 16];
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

    let aes_ok = aes_worker.join().expect("AES worker panicked");
    let ecc_ok = ecc_worker.join().expect("ECC worker panicked");
    let hmac_ok = hmac_worker.join().expect("HMAC worker panicked");

    stop.store(true, Ordering::Relaxed);
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
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
}

// =========================================================================
// Test: Key generation under continuous NSSR
// =========================================================================

/// Workers repeatedly generate AES keys while NSSRs fire, verifying
/// that `#[resiliency_key_gen]` recovers.
#[api_test]
fn test_stress_key_gen_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

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
                        eprintln!("Worker {id} iteration {i}: key gen error: {e:?}");
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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
}

// =========================================================================
// Test: Rapid NSSR bursts between operations
// =========================================================================

/// A single worker alternates between performing an AES-CBC encrypt and
/// triggering an NSSR, validating recovery after every single reset.
#[api_test]
fn test_stress_rapid_nssr_between_ops() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_key(&session);
    let iv = [0u8; 16];
    let plaintext = b"rapid nssr test data!!!!!!!!!!!!"; // 32 bytes

    for i in 0..ITERATIONS_PER_WORKER * 2 {
        // Fire an NSSR.
        part.reset()
            .unwrap_or_else(|e| panic!("NSSR {i} failed: {e:?}"));

        // The next encrypt must recover via the retry path.
        let result = cbc_encrypt(&key, &iv, plaintext);
        assert!(
            result.is_ok(),
            "Iteration {i}: AES-CBC encrypt after NSSR failed: {:?}",
            result.unwrap_err()
        );
    }
}

// =========================================================================
// Test: AES-GCM round-trip under continuous NSSR
// =========================================================================

/// Generate an AES-GCM-256 session key.
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

/// Workers encrypt then decrypt with AES-GCM under continuous NSSR,
/// verifying round-trip correctness including authenticated data.
#[api_test]
fn test_stress_aes_gcm_round_trip_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_gcm_key(&session);
    let iv = [0u8; 12]; // GCM uses 12-byte IV
    let aad = b"stress test additional data";

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: AES-XTS round-trip under continuous NSSR
// =========================================================================

/// Generate an AES-XTS-512 session key.
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

/// Workers encrypt then decrypt with AES-XTS under continuous NSSR,
/// verifying round-trip correctness.
#[api_test]
fn test_stress_aes_xts_round_trip_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let key = generate_aes_xts_key(&session);
    let tweak = [0u8; 16]; // 16-byte tweak
    let dul: usize = 512; // data unit length: multiple of 16, max 8192
    // Plaintext must be a multiple of DUL.
    let plaintext = vec![0xABu8; dul];

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: ECC sign + verify under continuous NSSR
// =========================================================================

/// Workers sign with the private key and verify with the public key
/// under continuous NSSR, ensuring both operations recover.
#[api_test]
fn test_stress_ecc_sign_verify_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();
    let (priv_key, pub_key) = generate_ecc_sign_key_pair(&session);
    let hash = hash_data(&session, b"stress test data for ECC sign+verify");

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: HMAC sign + verify under continuous NSSR
// =========================================================================

/// Workers sign and verify HMAC tags under continuous NSSR.
#[api_test]
fn test_stress_hmac_sign_verify_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    // Generate HMAC key via ECDH + HKDF.
    let (priv_key_a, _pub_key_a) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let (_priv_key_b, pub_key_b) = generate_ecc_derive_key_pair(&session, HsmEccCurve::P256);
    let shared_secret = ecdh_derive(&session, &priv_key_a, &pub_key_b);
    let hmac_key = hkdf_derive_hmac_key(&session, &shared_secret);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
    let expected = (NUM_WORKERS * ITERATIONS_PER_WORKER) as u32;
    assert_eq!(
        total, expected,
        "Expected {expected} total successes, got {total}"
    );
}

// =========================================================================
// Test: ECC key-pair generation under continuous NSSR
// =========================================================================

/// Workers repeatedly generate ECC P-256 key pairs while NSSRs fire,
/// verifying that `#[resiliency_key_gen]` recovers.
#[api_test]
fn test_stress_ecc_key_gen_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
}

// =========================================================================
// Test: AES-GCM key generation under continuous NSSR
// =========================================================================

/// Workers repeatedly generate AES-GCM keys while NSSRs fire.
#[api_test]
fn test_stress_aes_gcm_key_gen_under_nssr() {
    let (part, _creds, session, _ctx) = init_partition_and_session();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));

    let nssr_handle = spawn_nssr_thread(part.clone(), stop.clone(), barrier.clone());

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
    let nssr_count = nssr_handle.join().expect("NSSR thread panicked");
    assert!(
        nssr_count > 0,
        "NSSR thread should have triggered at least one NSSR"
    );
}
