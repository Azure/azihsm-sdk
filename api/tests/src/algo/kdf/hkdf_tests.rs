// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;
use azihsm_crypto::Rng;

use crate::algo::ecc::*;

// ================================
// Helper functions
// ================================

/// Generates a random IV of the given size
pub fn test_iv(size: usize) -> Vec<u8> {
    Rng::rand_vec(size).expect("RNG failure generating IV")
}

/// Returns the set of HKDF hash algorithms supported for testing
fn supported_hkdf_hash_algos() -> &'static [HsmHashAlgo] {
    &[
        HsmHashAlgo::Sha1,
        HsmHashAlgo::Sha256,
        HsmHashAlgo::Sha384,
        HsmHashAlgo::Sha512,
    ]
}

/// Generates two ECDH keypairs and derives matching shared secrets for both parties
fn derive_ecdh_shared_secrets(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmGenericSecretKey, HsmGenericSecretKey) {
    let (priv_key_a, pub_key_a) = generate_ecc_keypair_with_derive(session.clone(), curve, true)
        .expect("Failed to generate key pair for party A");

    let (priv_key_b, pub_key_b) = generate_ecc_keypair_with_derive(session.clone(), curve, true)
        .expect("Failed to generate key pair for party B");

    let shared_secret_a = ecdh_derive_shared_secret(session, &priv_key_a, &pub_key_b)
        .expect("Failed to derive shared secret for party A");
    let shared_secret_b = ecdh_derive_shared_secret(session, &priv_key_b, &pub_key_a)
        .expect("Failed to derive shared secret for party B");

    (shared_secret_a, shared_secret_b)
}

/// Derives an AES key from a shared secret using HKDF with the given parameters
fn derive_aes_key_from_shared_secret(
    session: &HsmSession,
    hkdf_algo: &mut HsmHkdfAlgo,
    shared_secret: &HsmGenericSecretKey,
    bits: u32,
) -> HsmAesKey {
    let aes_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build AES key props");

    let derived_key = HsmKeyManager::derive_key(session, hkdf_algo, shared_secret, aes_key_props)
        .expect("Failed to derive AES key");

    assert_eq!(derived_key.kind(), HsmKeyKind::Aes);
    assert_eq!(derived_key.bits(), bits);
    derived_key
        .try_into()
        .expect("Derived key was not an AES key")
}

/// Verifies AES-CBC encryption and decryption roundtrip correctness
fn assert_aes_cbc_roundtrip(enc_key: &HsmAesKey, dec_key: &HsmAesKey, plaintext: &[u8]) {
    let iv = test_iv(16);

    let mut enc =
        HsmAesCbcAlgo::with_padding(iv.clone()).expect("AES-CBC algo creation failed (enc)");

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut enc, enc_key, plaintext).expect("AES-CBC encryption failed");

    let mut dec = HsmAesCbcAlgo::with_padding(iv).expect("AES-CBC algo creation failed (dec)");

    let decrypted = HsmDecrypter::decrypt_vec(&mut dec, dec_key, &ciphertext)
        .expect("AES-CBC decryption failed");

    assert_eq!(decrypted, plaintext, "AES-CBC roundtrip mismatch");
}

/// Runs full HKDF matrix tests across hash algorithms and AES key sizes for a curve
fn run_hkdf_matrix_for_curve(session: &HsmSession, curve: HsmEccCurve) {
    let (shared_secret_a, shared_secret_b) = derive_ecdh_shared_secrets(session, curve);

    for &hash_algo in supported_hkdf_hash_algos() {
        for &bits in &[128u32, 192u32, 256u32] {
            let mut hkdf_algo =
                HsmHkdfAlgo::new(hash_algo, None, None).expect("Failed HKDF algo creation");

            let derived_aes_key_a =
                derive_aes_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_a, bits);
            let derived_aes_key_b =
                derive_aes_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_b, bits);

            let plaintext =
                format!("HKDF curve={curve:?} hash={hash_algo:?} aes_bits={bits}").into_bytes();
            assert_aes_cbc_roundtrip(&derived_aes_key_a, &derived_aes_key_b, &plaintext);
        }
    }

    // Salt + info should also work.
    let salt = b"hkdf-salt";
    let info = b"hkdf-info";
    let mut hkdf_algo = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), Some(info))
        .expect("Failed HKDF algo creation");

    let derived_aes_key_a =
        derive_aes_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_a, 256);
    let derived_aes_key_b =
        derive_aes_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_b, 256);
    assert_aes_cbc_roundtrip(
        &derived_aes_key_a,
        &derived_aes_key_b,
        b"HKDF with salt+info derived key roundtrip",
    );

    // If info differs between parties, the derived keys should not match.
    let info_a = b"hkdf-info-a";
    let info_b = b"hkdf-info-b";
    let mut hkdf_algo_a = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), Some(info_a))
        .expect("Failed HKDF algo creation");
    let mut hkdf_algo_b = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), Some(info_b))
        .expect("Failed HKDF algo creation");

    let derived_aes_key_a =
        derive_aes_key_from_shared_secret(session, &mut hkdf_algo_a, &shared_secret_a, 256);
    let derived_aes_key_b =
        derive_aes_key_from_shared_secret(session, &mut hkdf_algo_b, &shared_secret_b, 256);

    let iv = [0u8; 16];
    let mut aes_algo_enc =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES CBC algo creation failed");
    let ciphertext = HsmEncrypter::encrypt_vec(
        &mut aes_algo_enc,
        &derived_aes_key_a,
        b"HKDF salt/info mismatch should fail",
    )
    .expect("Encryption failed");

    let mut aes_algo_dec =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES CBC algo creation failed");
    if let Ok(plaintext) =
        HsmDecrypter::decrypt_vec(&mut aes_algo_dec, &derived_aes_key_b, &ciphertext)
    {
        assert_ne!(plaintext, b"HKDF salt/info mismatch should fail");
    }
}

/// Verifies empty salt and info behave correctly
fn run_hkdf_empty_salt_info_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(b""), Some(b"")).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"empty salt info");
}

/// Verifies derived keys work with large plaintext inputs
fn run_hkdf_large_plaintext_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_b, 256);

    let large = vec![0x55; 32 * 1024];

    assert_aes_cbc_roundtrip(&key_a, &key_b, &large);
}

/// Verifies secrets from different curves cannot interoperate
fn run_hkdf_cross_curve_negative(session: &HsmSession) {
    let (secret_p256, _) = derive_ecdh_shared_secrets(session, HsmEccCurve::P256);
    let (secret_p384, _) = derive_ecdh_shared_secrets(session, HsmEccCurve::P384);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_p256, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_p384, 256);

    let iv = [0u8; 16];
    let mut enc = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc, &key_a, b"cross curve").unwrap();

    let mut dec = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    match HsmDecrypter::decrypt_vec(&mut dec, &key_b, &ciphertext) {
        Ok(pt) => assert_ne!(pt, b"cross curve"),

        Err(e) => {
            assert!(
                matches!(
                    e,
                    HsmError::InvalidKey | HsmError::InternalError | HsmError::DdiCmdFailure
                ),
                "unexpected error: {:?}",
                e
            );
        }
    }
}

/// Verifies each HKDF hash algorithm works independently
fn run_hkdf_hash_algo_test(session: &HsmSession, curve: HsmEccCurve, hash: HsmHashAlgo) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf = HsmHkdfAlgo::new(hash, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_b, 256);

    let msg = format!("hash={hash:?}").into_bytes();
    assert_aes_cbc_roundtrip(&key_a, &key_b, &msg);
}

/// Verifies encryption/decryption of empty plaintext
fn run_hkdf_empty_plaintext_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"");
}

/// Verifies encryption of 1-byte plaintext (padding edge)
fn run_hkdf_single_byte_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"A");
}

/// Verifies deriving multiple key sizes from same HKDF instance
fn run_hkdf_multi_key_size_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    for bits in [128u32, 192u32, 256u32] {
        let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, bits);
        let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_b, bits);

        assert_aes_cbc_roundtrip(&key_a, &key_b, b"multi size");
    }
}

/// Verifies HKDF handles moderately large salt and info inputs
fn run_hkdf_long_salt_info_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let salt = vec![0x11; 128];
    let info = vec![0x22; 128];

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(&salt), Some(&info)).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"long salt info");
}

/// Verifies ECDH shared secret derivation is stable across repeated derivations
fn run_ecdh_shared_secret_stability(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_a, _pub_a) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();
    let (_priv_b, pub_b) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    // Derive shared secret twice using same inputs
    let s1 = ecdh_derive_shared_secret(session, &priv_a, &pub_b).unwrap();
    let s2 = ecdh_derive_shared_secret(session, &priv_a, &pub_b).unwrap();

    // Derive AES keys from both secrets
    let mut hkdf1 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();
    let mut hkdf2 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key1 = derive_aes_key_from_shared_secret(session, &mut hkdf1, &s1, 256);
    let key2 = derive_aes_key_from_shared_secret(session, &mut hkdf2, &s2, 256);

    // Validate equivalence via encryption/decryption
    assert_aes_cbc_roundtrip(&key1, &key2, b"ecdh stability");
}

/// Verifies different HKDF hash algorithms produce non-interoperable keys
fn run_hkdf_cross_hash_mismatch_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf_sha256 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();
    let mut hkdf_sha384 = HsmHkdfAlgo::new(HsmHashAlgo::Sha384, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf_sha256, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf_sha384, &secret_b, 256);

    let iv = [0u8; 16];
    let mut enc = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    let ct = HsmEncrypter::encrypt_vec(&mut enc, &key_a, b"hash mismatch").unwrap();

    let mut dec = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    if let Ok(pt) = HsmDecrypter::decrypt_vec(&mut dec, &key_b, &ct) {
        assert_ne!(pt, b"hash mismatch");
    }
}

/// Verifies different salts produce different derived keys
fn run_hkdf_salt_sensitivity_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf_a = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(b"saltA"), None).unwrap();
    let mut hkdf_b = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(b"saltB"), None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf_b, &secret_b, 256);

    let iv = [0u8; 16];
    let mut enc = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    let ct = HsmEncrypter::encrypt_vec(&mut enc, &key_a, b"salt mismatch").unwrap();

    let mut dec = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    if let Ok(pt) = HsmDecrypter::decrypt_vec(&mut dec, &key_b, &ct) {
        assert_ne!(pt, b"salt mismatch");
    }
}

/// Verifies info parameter impacts key derivation
fn run_hkdf_info_sensitivity_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf_a = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, Some(b"infoA")).unwrap();
    let mut hkdf_b = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, Some(b"infoB")).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf_b, &secret_b, 256);

    let iv = [0u8; 16];
    let mut enc = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    let ct = HsmEncrypter::encrypt_vec(&mut enc, &key_a, b"info mismatch").unwrap();

    let mut dec = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    if let Ok(pt) = HsmDecrypter::decrypt_vec(&mut dec, &key_b, &ct) {
        assert_ne!(pt, b"info mismatch");
    }
}

/// Verifies same HKDF params across different curves produce non-interoperable keys
fn run_hkdf_same_params_cross_curve_mismatch(session: &HsmSession) {
    let (secret_p256_a, _secret_p256_b) = derive_ecdh_shared_secrets(session, HsmEccCurve::P256);
    let (_secret_p384_a, secret_p384_b) = derive_ecdh_shared_secrets(session, HsmEccCurve::P384);

    let salt = b"same-salt";
    let info = b"same-info";

    let mut hkdf_p256 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), Some(info)).unwrap();
    let mut hkdf_p384 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), Some(info)).unwrap();

    let key_p256 = derive_aes_key_from_shared_secret(session, &mut hkdf_p256, &secret_p256_a, 256);
    let key_p384 = derive_aes_key_from_shared_secret(session, &mut hkdf_p384, &secret_p384_b, 256);

    let iv = [0u8; 16];
    let mut enc = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut enc, &key_p256, b"cross curve same params").unwrap();

    let mut dec = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();

    if let Ok(pt) = HsmDecrypter::decrypt_vec(&mut dec, &key_p384, &ciphertext) {
        assert_ne!(pt, b"cross curve same params");
    }
}

/// Verifies HKDF derive rejects invalid AES key size
fn run_hkdf_invalid_aes_key_size_test(session: &HsmSession, curve: HsmEccCurve) {
    // Generate valid shared secret input via ECDH
    let (secret, _) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    // Build AES key props with intentionally invalid size
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(true)
        .can_decrypt(true)
        .bits(4096) // invalid for AES
        .build()
        .unwrap();

    let result = HsmKeyManager::derive_key(session, &mut hkdf, &secret, props);

    match result {
        Err(e) => {
            assert!(
                matches!(e, HsmError::InvalidArgument),
                "unexpected error: {:?}",
                e
            );
        }
        Ok(_) => panic!("expected HKDF derive to fail due to invalid AES key size"),
    }
}

/// Verifies HKDF-derived keys from unrelated shared secrets cannot interoperate
fn run_hkdf_unrelated_secret_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, _) = derive_ecdh_shared_secrets(session, curve);
    let (secret_b, _) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_b, 256);

    let iv = [0u8; 16];

    let mut enc = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    let ct = HsmEncrypter::encrypt_vec(&mut enc, &key_a, b"unrelated secret").unwrap();

    let mut dec = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();

    if let Ok(pt) = HsmDecrypter::decrypt_vec(&mut dec, &key_b, &ct) {
        assert_ne!(pt, b"unrelated secret");
    }
}

/// Verifies HKDF operates correctly with minimal valid parameters (weakest hash + smallest AES key)
fn run_hkdf_min_input_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha1, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, 128);
    let key_b = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_b, 128);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"min input");
}

/// Verifies ECDH shared secret derivation fails when derive capability is disabled
fn run_ecdh_missing_derive_flag_test(session: &HsmSession) {
    let (priv_a, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, false).unwrap();

    let (_, pub_b) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let result = ecdh_derive_shared_secret(session, &priv_a, &pub_b);
    assert!(result.is_err());
}

/// Verifies ECDH shared secret derivation fails for mismatched elliptic curves
fn run_ecdh_cross_curve_fail_test(session: &HsmSession) {
    let (priv_a, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let (_, pub_b) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P384, true).unwrap();

    let result = ecdh_derive_shared_secret(session, &priv_a, &pub_b);
    assert!(result.is_err());
}

/// Verifies HKDF determinism using behavioral equivalence (identical ciphertext outputs)
fn run_hkdf_strong_determinism_test(session: &HsmSession, curve: HsmEccCurve) {
    let (secret, _) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf1 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();
    let mut hkdf2 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key1 = derive_aes_key_from_shared_secret(session, &mut hkdf1, &secret, 256);
    let key2 = derive_aes_key_from_shared_secret(session, &mut hkdf2, &secret, 256);

    let iv = [0u8; 16];

    let mut enc1 = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    let mut enc2 = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();

    let msg = b"determinism-check";

    let ct1 = HsmEncrypter::encrypt_vec(&mut enc1, &key1, msg).unwrap();
    let ct2 = HsmEncrypter::encrypt_vec(&mut enc2, &key2, msg).unwrap();

    assert_eq!(ct1, ct2);
}

/// Verifies AES-CBC decryption fails on deterministically corrupted padding
fn run_aes_cbc_padding_tamper_test(session: &HsmSession) {
    let (secret_a, _) = derive_ecdh_shared_secrets(session, HsmEccCurve::P256);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key = derive_aes_key_from_shared_secret(session, &mut hkdf, &secret_a, 256);

    let iv = [0u8; 16];
    let mut enc = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();

    let mut ct = HsmEncrypter::encrypt_vec(&mut enc, &key, b"padding test").unwrap();

    // Corrupt previous block to reliably break padding
    let len = ct.len();
    // Corrupt previous block if possible (best for breaking padding deterministically)
    let idx = if len >= 32 { len - 16 } else { len / 2 };
    ct[idx] ^= 0xFF;

    let mut dec = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();

    let result = HsmDecrypter::decrypt_vec(&mut dec, &key, &ct);

    assert!(
        result.is_err(),
        "tampered ciphertext should fail padding validation"
    );
}

// ============================================================
// test case section
// ============================================================

/// Verifies HKDF matrix coverage for P256 across hashes, key sizes, and salt/info cases
#[session_test]
fn test_hkdf_matrix_p256(session: HsmSession) {
    run_hkdf_matrix_for_curve(&session, HsmEccCurve::P256);
}

/// Verifies HKDF matrix coverage for P384 across hashes, key sizes, and salt/info cases
#[session_test]
fn test_hkdf_matrix_p384(session: HsmSession) {
    run_hkdf_matrix_for_curve(&session, HsmEccCurve::P384);
}

/// Verifies HKDF matrix coverage for P521 across hashes, key sizes, and salt/info cases
#[session_test]
fn test_hkdf_matrix_p521(session: HsmSession) {
    run_hkdf_matrix_for_curve(&session, HsmEccCurve::P521);
}

/// Verifies HKDF derivation works correctly when only salt is provided
#[session_test]
fn test_hkdf_with_only_salt(session: HsmSession) {
    let (shared_secret_a, shared_secret_b) =
        derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let salt = b"hkdf-salt-only";
    for &bits in &[128u32, 192u32, 256u32] {
        let mut hkdf_algo = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), None)
            .expect("Failed HKDF algo creation");

        let derived_aes_key_a =
            derive_aes_key_from_shared_secret(&session, &mut hkdf_algo, &shared_secret_a, bits);
        let derived_aes_key_b =
            derive_aes_key_from_shared_secret(&session, &mut hkdf_algo, &shared_secret_b, bits);

        let plaintext = format!("HKDF salt-only AES-{bits} roundtrip").into_bytes();
        assert_aes_cbc_roundtrip(&derived_aes_key_a, &derived_aes_key_b, &plaintext);
    }
}

/// Verifies HKDF derivation works correctly when only info is provided
#[session_test]
fn test_hkdf_with_only_info(session: HsmSession) {
    let (shared_secret_a, shared_secret_b) =
        derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let info = b"hkdf-info-only";
    for &bits in &[128u32, 192u32, 256u32] {
        let mut hkdf_algo = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, Some(info))
            .expect("Failed HKDF algo creation");

        let derived_aes_key_a =
            derive_aes_key_from_shared_secret(&session, &mut hkdf_algo, &shared_secret_a, bits);
        let derived_aes_key_b =
            derive_aes_key_from_shared_secret(&session, &mut hkdf_algo, &shared_secret_b, bits);

        let plaintext = format!("HKDF info-only AES-{bits} roundtrip").into_bytes();
        assert_aes_cbc_roundtrip(&derived_aes_key_a, &derived_aes_key_b, &plaintext);
    }
}

/// Verifies HKDF rejects invalid AES key sizes
#[session_test]
fn test_hkdf_invalid_aes_key_size_fails(session: HsmSession) {
    let (shared_secret_a, _) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);
    let mut hkdf_algo =
        HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).expect("Failed HKDF Algo creation");

    let aes_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(42)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build AES key props");

    let result =
        HsmKeyManager::derive_key(&session, &mut hkdf_algo, &shared_secret_a, aes_key_props);
    let err = match result {
        Ok(_) => panic!("HKDF derive should fail for invalid AES key size"),
        Err(err) => err,
    };
    assert_eq!(err, HsmError::InvalidArgument);
}

/// Verifies HKDF rejects unsupported derived key kinds
#[session_test]
fn test_hkdf_unsupported_derived_key_kind_fails(session: HsmSession) {
    let (shared_secret_a, _) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);
    let mut hkdf_algo =
        HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).expect("Failed HKDF Algo creation");

    let unsupported_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build()
        .expect("Failed to build ECC key props");

    let result = HsmKeyManager::derive_key(
        &session,
        &mut hkdf_algo,
        &shared_secret_a,
        unsupported_props,
    );
    let err = match result {
        Ok(_) => panic!("HKDF derive should fail for unsupported derived key kind"),
        Err(err) => err,
    };
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies cross-curve mismatch behavior globally
#[session_test]
fn test_hkdf_cross_curve_negative_case(session: HsmSession) {
    run_hkdf_cross_curve_negative(&session);
}

/// Verifies empty salt/info for P256
#[session_test]
fn test_hkdf_empty_salt_info_p256(session: HsmSession) {
    run_hkdf_empty_salt_info_test(&session, HsmEccCurve::P256);
}

/// Verifies empty salt/info for P384
#[session_test]
fn test_hkdf_empty_salt_info_p384(session: HsmSession) {
    run_hkdf_empty_salt_info_test(&session, HsmEccCurve::P384);
}

/// Verifies empty salt/info for P521
#[session_test]
fn test_hkdf_empty_salt_info_p521(session: HsmSession) {
    run_hkdf_empty_salt_info_test(&session, HsmEccCurve::P521);
}

/// Verifies large plaintext handling for P256
#[session_test]
fn test_hkdf_large_plaintext_p256(session: HsmSession) {
    run_hkdf_large_plaintext_test(&session, HsmEccCurve::P256);
}

/// Verifies large plaintext handling for P384
#[session_test]
fn test_hkdf_large_plaintext_p384(session: HsmSession) {
    run_hkdf_large_plaintext_test(&session, HsmEccCurve::P384);
}

/// Verifies large plaintext handling for P521
#[session_test]
fn test_hkdf_large_plaintext_p521(session: HsmSession) {
    run_hkdf_large_plaintext_test(&session, HsmEccCurve::P521);
}

/// Verifies HKDF hash algos for P256
#[session_test]
fn test_hkdf_hash_algos_p256(session: HsmSession) {
    for &h in supported_hkdf_hash_algos() {
        run_hkdf_hash_algo_test(&session, HsmEccCurve::P256, h);
    }
}

/// Verifies HKDF hash algos for P384
#[session_test]
fn test_hkdf_hash_algos_p384(session: HsmSession) {
    for &h in supported_hkdf_hash_algos() {
        run_hkdf_hash_algo_test(&session, HsmEccCurve::P384, h);
    }
}

/// Verifies HKDF hash algos for P521
#[session_test]
fn test_hkdf_hash_algos_p521(session: HsmSession) {
    for &h in supported_hkdf_hash_algos() {
        run_hkdf_hash_algo_test(&session, HsmEccCurve::P521, h);
    }
}

/// Verifies empty plaintext for P256
#[session_test]
fn test_hkdf_empty_plaintext_p256(session: HsmSession) {
    run_hkdf_empty_plaintext_test(&session, HsmEccCurve::P256);
}

/// Verifies empty plaintext for P384
#[session_test]
fn test_hkdf_empty_plaintext_p384(session: HsmSession) {
    run_hkdf_empty_plaintext_test(&session, HsmEccCurve::P384);
}

/// Verifies empty plaintext for P521
#[session_test]
fn test_hkdf_empty_plaintext_p521(session: HsmSession) {
    run_hkdf_empty_plaintext_test(&session, HsmEccCurve::P521);
}

/// Verifies single-byte plaintext for P256
#[session_test]
fn test_hkdf_single_byte_p256(session: HsmSession) {
    run_hkdf_single_byte_test(&session, HsmEccCurve::P256);
}

/// Verifies single-byte plaintext for P384
#[session_test]
fn test_hkdf_single_byte_p384(session: HsmSession) {
    run_hkdf_single_byte_test(&session, HsmEccCurve::P384);
}

/// Verifies single-byte plaintext for P521
#[session_test]
fn test_hkdf_single_byte_p521(session: HsmSession) {
    run_hkdf_single_byte_test(&session, HsmEccCurve::P521);
}

/// Verifies multi key size derivation for P256
#[session_test]
fn test_hkdf_multi_key_size_p256(session: HsmSession) {
    run_hkdf_multi_key_size_test(&session, HsmEccCurve::P256);
}

/// Verifies multi key size derivation for P384
#[session_test]
fn test_hkdf_multi_key_size_p384(session: HsmSession) {
    run_hkdf_multi_key_size_test(&session, HsmEccCurve::P384);
}

/// Verifies multi key size derivation for P521
#[session_test]
fn test_hkdf_multi_key_size_p521(session: HsmSession) {
    run_hkdf_multi_key_size_test(&session, HsmEccCurve::P521);
}

/// Verifies long salt/info handling for P256
#[session_test]
fn test_hkdf_long_salt_info_p256(session: HsmSession) {
    run_hkdf_long_salt_info_test(&session, HsmEccCurve::P256);
}

/// Verifies long salt/info handling for P384
#[session_test]
fn test_hkdf_long_salt_info_p384(session: HsmSession) {
    run_hkdf_long_salt_info_test(&session, HsmEccCurve::P384);
}

/// Verifies long salt/info handling for P521
#[session_test]
fn test_hkdf_long_salt_info_p521(session: HsmSession) {
    run_hkdf_long_salt_info_test(&session, HsmEccCurve::P521);
}

/// Verifies shared secret stability for P256
#[session_test]
fn test_ecdh_shared_secret_stability_p256(session: HsmSession) {
    run_ecdh_shared_secret_stability(&session, HsmEccCurve::P256);
}

/// Verifies shared secret stability for P384
#[session_test]
fn test_ecdh_shared_secret_stability_p384(session: HsmSession) {
    run_ecdh_shared_secret_stability(&session, HsmEccCurve::P384);
}

/// Verifies shared secret stability for P521
#[session_test]
fn test_ecdh_shared_secret_stability_p521(session: HsmSession) {
    run_ecdh_shared_secret_stability(&session, HsmEccCurve::P521);
}

/// Verifies invalid key usage flags are rejected at derive time
#[session_test]
fn test_hkdf_invalid_key_usage_flags_fail(session: HsmSession) {
    let (secret, _) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(false) // invalid combination
        .can_decrypt(true)
        .build()
        .unwrap();

    let result = HsmKeyManager::derive_key(&session, &mut hkdf, &secret, props);

    let err = match result {
        Ok(_) => panic!("Expected derive to fail due to invalid key usage flags"),
        Err(e) => e,
    };

    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies different HKDF hash algorithms do not interoperate for P256
#[session_test]
fn test_hkdf_cross_hash_p256(session: HsmSession) {
    run_hkdf_cross_hash_mismatch_test(&session, HsmEccCurve::P256);
}

/// Verifies different HKDF hash algorithms do not interoperate for P384
#[session_test]
fn test_hkdf_cross_hash_p384(session: HsmSession) {
    run_hkdf_cross_hash_mismatch_test(&session, HsmEccCurve::P384);
}

/// Verifies different HKDF hash algorithms do not interoperate for P521
#[session_test]
fn test_hkdf_cross_hash_p521(session: HsmSession) {
    run_hkdf_cross_hash_mismatch_test(&session, HsmEccCurve::P521);
}

/// Verifies IV impacts ciphertext
#[session_test]
fn test_aes_cbc_iv_sensitivity(session: HsmSession) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(&session, &mut hkdf, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(&session, &mut hkdf, &secret_b, 256);

    let iv1 = [0u8; 16];
    let iv2 = [1u8; 16];

    let mut enc1 = HsmAesCbcAlgo::with_padding(iv1.to_vec()).unwrap();
    let mut enc2 = HsmAesCbcAlgo::with_padding(iv2.to_vec()).unwrap();

    let ct1 = HsmEncrypter::encrypt_vec(&mut enc1, &key_a, b"iv test").unwrap();
    let ct2 = HsmEncrypter::encrypt_vec(&mut enc2, &key_a, b"iv test").unwrap();

    assert_ne!(ct1, ct2);

    let mut dec = HsmAesCbcAlgo::with_padding(iv1.to_vec()).unwrap();
    let pt = HsmDecrypter::decrypt_vec(&mut dec, &key_b, &ct1).unwrap();

    assert_eq!(pt, b"iv test");
}

/// Verifies tampered ciphertext does not decrypt correctly
#[session_test]
fn test_aes_cbc_ciphertext_tamper(session: HsmSession) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(&session, &mut hkdf, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(&session, &mut hkdf, &secret_b, 256);

    let iv = [0u8; 16];
    let mut enc = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    let mut ct = HsmEncrypter::encrypt_vec(&mut enc, &key_a, b"tamper").unwrap();

    ct[0] ^= 0xFF;

    let mut dec = HsmAesCbcAlgo::with_padding(iv.to_vec()).unwrap();
    if let Ok(pt) = HsmDecrypter::decrypt_vec(&mut dec, &key_b, &ct) {
        assert_ne!(pt, b"tamper");
    }
}

/// Verifies salt sensitivity for P256
#[session_test]
fn test_hkdf_salt_sensitivity_p256(session: HsmSession) {
    run_hkdf_salt_sensitivity_test(&session, HsmEccCurve::P256);
}

/// Verifies salt sensitivity for P384
#[session_test]
fn test_hkdf_salt_sensitivity_p384(session: HsmSession) {
    run_hkdf_salt_sensitivity_test(&session, HsmEccCurve::P384);
}

/// Verifies salt sensitivity for P521
#[session_test]
fn test_hkdf_salt_sensitivity_p521(session: HsmSession) {
    run_hkdf_salt_sensitivity_test(&session, HsmEccCurve::P521);
}

/// Verifies info sensitivity for P256
#[session_test]
fn test_hkdf_info_sensitivity_p256(session: HsmSession) {
    run_hkdf_info_sensitivity_test(&session, HsmEccCurve::P256);
}

/// Verifies info sensitivity for P384
#[session_test]
fn test_hkdf_info_sensitivity_p384(session: HsmSession) {
    run_hkdf_info_sensitivity_test(&session, HsmEccCurve::P384);
}

/// Verifies info sensitivity for P521
#[session_test]
fn test_hkdf_info_sensitivity_p521(session: HsmSession) {
    run_hkdf_info_sensitivity_test(&session, HsmEccCurve::P521);
}

/// Verifies independent HKDF instances produce equivalent results
#[session_test]
fn test_hkdf_instance_equivalence(session: HsmSession) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf1 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(b"s"), Some(b"i")).unwrap();
    let mut hkdf2 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(b"s"), Some(b"i")).unwrap();

    let key1 = derive_aes_key_from_shared_secret(&session, &mut hkdf1, &secret_a, 256);
    let key2 = derive_aes_key_from_shared_secret(&session, &mut hkdf2, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key1, &key2, b"instance eq");
}

/// Verifies minimum AES key size (128-bit) works correctly
#[session_test]
fn test_hkdf_min_aes_size(session: HsmSession) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key_a = derive_aes_key_from_shared_secret(&session, &mut hkdf, &secret_a, 128);
    let key_b = derive_aes_key_from_shared_secret(&session, &mut hkdf, &secret_b, 128);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"128-bit key");
}

/// Verifies HKDF fails when using unsupported key class
#[session_test]
fn test_hkdf_invalid_key_class_fail(session: HsmSession) {
    let (secret, _) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public) // invalid for HKDF
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .build()
        .unwrap();

    let result = HsmKeyManager::derive_key(&session, &mut hkdf, &secret, props);

    assert!(result.is_err());
}

/// Verifies same HKDF params across curves do not interoperate
#[session_test]
fn test_hkdf_same_params_cross_curve_mismatch(session: HsmSession) {
    run_hkdf_same_params_cross_curve_mismatch(&session);
}

/// Verifies HKDF output size limits are enforced
#[session_test]
fn test_hkdf_invalid_aes_key_size_p256(session: HsmSession) {
    run_hkdf_invalid_aes_key_size_test(&session, HsmEccCurve::P256);
}

/// Verifies HKDF rejects oversized output for P384
#[session_test]
fn test_hkdf_invalid_aes_key_size_p384(session: HsmSession) {
    run_hkdf_invalid_aes_key_size_test(&session, HsmEccCurve::P384);
}

/// Verifies HKDF rejects oversized output for P521
#[session_test]
fn test_hkdf_invalid_aes_key_size_p521(session: HsmSession) {
    run_hkdf_invalid_aes_key_size_test(&session, HsmEccCurve::P521);
}

/// Verifies ECDH fails without derive permission
#[session_test]
fn test_ecdh_missing_derive_flag(session: HsmSession) {
    run_ecdh_missing_derive_flag_test(&session);
}

/// Verifies ECDH fails for cross-curve inputs
#[session_test]
fn test_ecdh_cross_curve_fail(session: HsmSession) {
    run_ecdh_cross_curve_fail_test(&session);
}

/// Verifies strong HKDF determinism for P256
#[session_test]
fn test_hkdf_strong_determinism_p256(session: HsmSession) {
    run_hkdf_strong_determinism_test(&session, HsmEccCurve::P256);
}

/// Verifies strong HKDF determinism for P384
#[session_test]
fn test_hkdf_strong_determinism_p384(session: HsmSession) {
    run_hkdf_strong_determinism_test(&session, HsmEccCurve::P384);
}

/// Verifies strong HKDF determinism for P521
#[session_test]
fn test_hkdf_strong_determinism_p521(session: HsmSession) {
    run_hkdf_strong_determinism_test(&session, HsmEccCurve::P521);
}

/// Verifies AES-CBC padding tampering is detected
#[session_test]
fn test_aes_cbc_padding_tamper(session: HsmSession) {
    run_aes_cbc_padding_tamper_test(&session);
}

/// Verifies unrelated shared secrets do not interoperate for P256
#[session_test]
fn test_hkdf_unrelated_secret_p256(session: HsmSession) {
    run_hkdf_unrelated_secret_test(&session, HsmEccCurve::P256);
}

/// Verifies unrelated shared secrets do not interoperate for P384
#[session_test]
fn test_hkdf_unrelated_secret_p384(session: HsmSession) {
    run_hkdf_unrelated_secret_test(&session, HsmEccCurve::P384);
}

/// Verifies unrelated shared secrets do not interoperate for P521
#[session_test]
fn test_hkdf_unrelated_secret_p521(session: HsmSession) {
    run_hkdf_unrelated_secret_test(&session, HsmEccCurve::P521);
}

/// Verifies HKDF works with minimal valid parameters for P256
#[session_test]
fn test_hkdf_min_input_p256(session: HsmSession) {
    run_hkdf_min_input_test(&session, HsmEccCurve::P256);
}

/// Verifies HKDF works with minimal valid parameters for P384
#[session_test]
fn test_hkdf_min_input_p384(session: HsmSession) {
    run_hkdf_min_input_test(&session, HsmEccCurve::P384);
}

/// Verifies HKDF works with minimal valid parameters for P521
#[session_test]
fn test_hkdf_min_input_p521(session: HsmSession) {
    run_hkdf_min_input_test(&session, HsmEccCurve::P521);
}

/// Verifies ECDH rejects creating a shared secret without can_derive flag
#[session_test]
fn test_ecdh_rejects_non_derivable_shared_secret(session: HsmSession) {
    // Generate ECC keypair WITHOUT derive capability
    let (priv_a, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();
    let (_, pub_b) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    // Attempt ECDH → should fail due to can_derive = false
    let non_derivable_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        // intentionally omit .can_derive(true)
        .build()
        .expect("Failed to build non-derivable shared secret props");

    let result =
        ecdh_derive_shared_secret_with_props(&session, &priv_a, &pub_b, non_derivable_props);

    assert!(
        matches!(result, Err(HsmError::DdiCmdFailure)),
        "ECDH should reject creating a shared secret without can_derive flag"
    );
}
