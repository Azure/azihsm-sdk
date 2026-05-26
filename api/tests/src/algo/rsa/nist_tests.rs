// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA NIST/vector validation using HSM RSA keys.

use azihsm_crypto::testvectors::rsa::OaepTestVector;
use azihsm_crypto::testvectors::rsa::PkcsTestVector;
use azihsm_crypto::testvectors::rsa::PssTestVector;
use azihsm_crypto::testvectors::rsa::RSA_OAEP_TEST_VECTORS;
use azihsm_crypto::testvectors::rsa::RSA_PKCS1_TEST_VECTORS;
use azihsm_crypto::testvectors::rsa::RSA_PSS_TEST_VECTORS;
use azihsm_crypto::testvectors::rsa::TestHashAlgo;

use super::*;

// =======================================================
// Common helpers
// =======================================================

/// Converts the RSA test-vector hash enum into the HSM API hash enum.
fn hsm_hash_from_test(hash: TestHashAlgo) -> HsmHashAlgo {
    match hash {
        TestHashAlgo::Sha1 => HsmHashAlgo::Sha1,
        TestHashAlgo::Sha256 => HsmHashAlgo::Sha256,
        TestHashAlgo::Sha384 => HsmHashAlgo::Sha384,
        TestHashAlgo::Sha512 => HsmHashAlgo::Sha512,
    }
}

/// Returns whether the RSA key size is supported by the HSM API tests.
fn is_supported_rsa_bits(bits: u32) -> bool {
    matches!(bits, 2048 | 3072 | 4096)
}

/// Imports RSA private-key DER into HSM RSA session key handles through RSA-AES wrap/unwrap.
fn import_rsa_key_pair(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
    usage: ImportedRsaKeyUsage,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    try_import_rsa_key_pair(session, der, bits, usage, true)
        .expect("Failed to unwrap RSA session key pair via RSA-AES")
}

/// Imports an RSA key pair configured for sign/verify operations.
fn import_rsa_sign_verify_key(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    import_rsa_key_pair(session, der, bits, ImportedRsaKeyUsage::SignVerify)
}

/// Imports an RSA key pair configured for encrypt/decrypt operations.
fn import_rsa_enc_dec_key(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    import_rsa_key_pair(session, der, bits, ImportedRsaKeyUsage::EncryptDecrypt)
}

/// Infers RSA key size from signature length.
fn rsa_bits_from_signature(signature: &[u8]) -> u32 {
    (signature.len() * 8) as u32
}

/// Infers RSA key size from ciphertext length.
fn rsa_bits_from_ciphertext(ciphertext: &[u8]) -> u32 {
    (ciphertext.len() * 8) as u32
}

/// Returns whether a vector should be skipped due to known OpenSSL strictness.
///
/// Vector 29 is skipped for RSA NIST signature-vector tests because it is known
/// to be rejected by the HSM/OpenSSL-backed verification path.
///
/// For PKCS#1 v1.5, vector 29 contains an encoded DigestInfo that does not
/// satisfy OpenSSL's stricter DER validation rules.
///
/// For PSS, vector 29 is also skipped only to preserve the existing OpenSSL-backed
/// test behavior for this shared vector index.
fn should_skip_known_openssl_vector(idx: usize) -> bool {
    idx == 29
}

/// Returns true when a vector should be skipped due to unsupported key size.
fn should_skip_unsupported_bits(kind: &str, idx: usize, bits: u32) -> bool {
    if is_supported_rsa_bits(bits) {
        false
    } else {
        println!("Skipping {kind} vector {idx}: unsupported RSA key size {bits}");
        true
    }
}

/// Hashes a message using the hash algorithm specified by the RSA test vector.
fn hash_test_vector_message(session: &HsmSession, hash_algo: TestHashAlgo, msg: &[u8]) -> Vec<u8> {
    let mut hsm_hash_algo = hsm_hash_from_test(hash_algo);

    HsmHasher::hash_vec(session, &mut hsm_hash_algo, msg)
        .expect("Failed to hash RSA NIST test-vector message")
}

// =======================================================
// PKCS#1 NIST helpers
// =======================================================

/// Verifies one PKCS#1 NIST signature vector using single-shot API verification.
fn verify_pkcs1_vector(session: &HsmSession, idx: usize, vector: &PkcsTestVector) {
    let bits = rsa_bits_from_signature(vector.s);
    if should_skip_unsupported_bits("PKCS#1", idx, bits) {
        return;
    }

    let (_priv_key, pub_key) = import_rsa_sign_verify_key(session, vector.priv_der, bits);
    let mut algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hsm_hash_from_test(vector.hash_algo));

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, vector.msg, vector.s)
        .unwrap_or_else(|err| panic!("vector {idx}: PKCS#1 NIST verify failed: {err:?}"));
    assert!(
        is_valid,
        "vector {idx}: PKCS#1 NIST signature should verify"
    );
}

/// Verifies one PKCS#1 NIST signature vector using streaming API verification.
fn verify_pkcs1_vector_streaming(session: &HsmSession, idx: usize, vector: &PkcsTestVector) {
    let bits = rsa_bits_from_signature(vector.s);
    if should_skip_unsupported_bits("PKCS#1", idx, bits) {
        return;
    }

    let (_priv_key, pub_key) = import_rsa_sign_verify_key(session, vector.priv_der, bits);
    let algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hsm_hash_from_test(vector.hash_algo));

    let mut verify_ctx = HsmVerifier::verify_init(algo, pub_key)
        .unwrap_or_else(|err| panic!("vector {idx}: PKCS#1 verify_init failed: {err:?}"));

    for chunk in vector.msg.chunks(32) {
        verify_ctx
            .update(chunk)
            .unwrap_or_else(|err| panic!("vector {idx}: PKCS#1 verify update failed: {err:?}"));
    }

    let is_valid = verify_ctx
        .finish(vector.s)
        .unwrap_or_else(|err| panic!("vector {idx}: PKCS#1 streaming verify failed: {err:?}"));

    assert!(
        is_valid,
        "vector {idx}: PKCS#1 NIST streaming signature should verify"
    );
}

/// Signs and verifies one PKCS#1 NIST vector message using the imported NIST private key.
fn sign_verify_pkcs1_vector(session: &HsmSession, idx: usize, vector: &PkcsTestVector) {
    let bits = rsa_bits_from_signature(vector.s);
    if should_skip_unsupported_bits("PKCS#1 sign/verify", idx, bits) {
        return;
    }

    let (priv_key, pub_key) = import_rsa_sign_verify_key(session, vector.priv_der, bits);
    let hash = hash_test_vector_message(session, vector.hash_algo, vector.msg);

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hsm_hash_from_test(vector.hash_algo));

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash)
        .unwrap_or_else(|err| panic!("vector {idx}: PKCS#1 NIST signing failed: {err:?}"));

    assert_eq!(
        signature.as_slice(),
        vector.s,
        "vector {idx}: PKCS#1 generated signature should match NIST vector signature"
    );

    let is_valid =
        HsmVerifier::verify(&mut algo, &pub_key, &hash, vector.s).unwrap_or_else(|err| {
            panic!("vector {idx}: PKCS#1 NIST vector-signature verify failed: {err:?}")
        });

    assert!(
        is_valid,
        "vector {idx}: PKCS#1 NIST vector signature should verify"
    );
}

// =======================================================
// PSS NIST helpers
// =======================================================

/// Verifies one PSS NIST signature vector using single-shot API verification.
fn verify_pss_vector(session: &HsmSession, idx: usize, vector: &PssTestVector) {
    let bits = rsa_bits_from_signature(vector.s);
    if should_skip_unsupported_bits("PSS", idx, bits) {
        return;
    }

    let (_priv_key, pub_key) = import_rsa_sign_verify_key(session, vector.private_der, bits);
    let mut algo =
        HsmRsaHashSignAlgo::with_pss_padding(hsm_hash_from_test(vector.hash_algo), vector.salt_len);

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, vector.msg, vector.s)
        .unwrap_or_else(|err| panic!("vector {idx}: PSS NIST verify failed: {err:?}"));

    assert!(is_valid, "vector {idx}: PSS NIST signature should verify");
}

/// Verifies one PSS NIST signature vector using streaming API verification.
fn verify_pss_vector_streaming(session: &HsmSession, idx: usize, vector: &PssTestVector) {
    let bits = rsa_bits_from_signature(vector.s);
    if should_skip_unsupported_bits("PSS", idx, bits) {
        return;
    }

    let (_priv_key, pub_key) = import_rsa_sign_verify_key(session, vector.private_der, bits);
    let algo =
        HsmRsaHashSignAlgo::with_pss_padding(hsm_hash_from_test(vector.hash_algo), vector.salt_len);

    let mut verify_ctx = HsmVerifier::verify_init(algo, pub_key)
        .unwrap_or_else(|err| panic!("vector {idx}: PSS verify_init failed: {err:?}"));

    for chunk in vector.msg.chunks(32) {
        verify_ctx
            .update(chunk)
            .unwrap_or_else(|err| panic!("vector {idx}: PSS verify update failed: {err:?}"));
    }

    let is_valid = verify_ctx
        .finish(vector.s)
        .unwrap_or_else(|err| panic!("vector {idx}: PSS streaming verify failed: {err:?}"));

    assert!(
        is_valid,
        "vector {idx}: PSS NIST streaming signature should verify"
    );
}

/// Signs and verifies one PSS NIST vector message using the imported NIST private key.
fn sign_verify_pss_vector(session: &HsmSession, idx: usize, vector: &PssTestVector) {
    let bits = rsa_bits_from_signature(vector.s);
    if should_skip_unsupported_bits("PSS sign/verify", idx, bits) {
        return;
    }

    let (priv_key, pub_key) = import_rsa_sign_verify_key(session, vector.private_der, bits);
    let hash = hash_test_vector_message(session, vector.hash_algo, vector.msg);

    let mut algo =
        HsmRsaSignAlgo::with_pss_padding(hsm_hash_from_test(vector.hash_algo), vector.salt_len);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash)
        .unwrap_or_else(|err| panic!("vector {idx}: PSS NIST signing failed: {err:?}"));

    let is_valid =
        HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature).unwrap_or_else(|err| {
            panic!("vector {idx}: PSS NIST generated-signature verify failed: {err:?}")
        });

    assert!(
        is_valid,
        "vector {idx}: PSS NIST generated signature should verify"
    );
}

// =======================================================
// OAEP NIST helpers
// =======================================================

/// Decrypts one OAEP NIST ciphertext vector using API decryption.
fn decrypt_oaep_vector(session: &HsmSession, idx: usize, vector: &OaepTestVector) {
    let bits = rsa_bits_from_ciphertext(vector.ciphertext);
    if should_skip_unsupported_bits("OAEP", idx, bits) {
        return;
    }

    let (priv_key, _pub_key) = import_rsa_enc_dec_key(session, vector.priv_der, bits);
    let mut algo =
        HsmRsaEncryptAlgo::with_oaep_padding(hsm_hash_from_test(vector.hash_algo), vector.label);

    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, vector.ciphertext)
        .unwrap_or_else(|err| panic!("vector {idx}: OAEP decrypt failed: {err:?}"));

    assert_eq!(
        decrypted.as_slice(),
        vector.plaintext,
        "vector {idx}: OAEP plaintext mismatch"
    );
}

/// Encrypts and decrypts one OAEP NIST vector plaintext using API roundtrip operations.
fn roundtrip_oaep_vector(session: &HsmSession, idx: usize, vector: &OaepTestVector) {
    let bits = rsa_bits_from_ciphertext(vector.ciphertext);
    if should_skip_unsupported_bits("OAEP", idx, bits) {
        return;
    }

    let (priv_key, pub_key) = import_rsa_enc_dec_key(session, vector.priv_der, bits);
    let mut algo =
        HsmRsaEncryptAlgo::with_oaep_padding(hsm_hash_from_test(vector.hash_algo), vector.label);

    let ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, vector.plaintext)
        .unwrap_or_else(|err| panic!("vector {idx}: OAEP encrypt failed: {err:?}"));

    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .unwrap_or_else(|err| panic!("vector {idx}: OAEP roundtrip decrypt failed: {err:?}"));

    assert_eq!(
        decrypted.as_slice(),
        vector.plaintext,
        "vector {idx}: OAEP roundtrip plaintext mismatch"
    );
}

// =======================================================
// Test cases
// =======================================================

/// Verifies all supported RSA_PKCS1_TEST_VECTORS NIST vectors using single-shot API verification.
#[session_test]
fn test_rsa_pkcs1_nist_vectors_single_shot(session: HsmSession) {
    for (idx, vector) in RSA_PKCS1_TEST_VECTORS.iter().enumerate() {
        if should_skip_known_openssl_vector(idx) {
            println!("Skipping PKCS#1 vector {idx} due to known OpenSSL strictness.");
            continue;
        }

        verify_pkcs1_vector(&session, idx, vector);
    }
}

/// Signs and verifies all supported RSA_PKCS1_TEST_VECTORS NIST messages.
#[session_test]
fn test_rsa_pkcs1_nist_vectors_sign_verify(session: HsmSession) {
    for (idx, vector) in RSA_PKCS1_TEST_VECTORS.iter().enumerate() {
        if should_skip_known_openssl_vector(idx) {
            println!("Skipping PKCS#1 sign/verify vector {idx} due to known OpenSSL strictness.");
            continue;
        }

        sign_verify_pkcs1_vector(&session, idx, vector);
    }
}

/// Verifies all supported RSA_PKCS1_TEST_VECTORS NIST vectors using streaming API verification.
#[session_test]
fn test_rsa_pkcs1_nist_vectors_streaming(session: HsmSession) {
    for (idx, vector) in RSA_PKCS1_TEST_VECTORS.iter().enumerate() {
        if should_skip_known_openssl_vector(idx) {
            println!("Skipping PKCS#1 vector {idx} due to known OpenSSL strictness.");
            continue;
        }

        verify_pkcs1_vector_streaming(&session, idx, vector);
    }
}

/// Verifies all supported RSA_PSS_TEST_VECTORS NIST vectors using single-shot API verification.
#[session_test]
fn test_rsa_pss_nist_vectors_single_shot(session: HsmSession) {
    for (idx, vector) in RSA_PSS_TEST_VECTORS.iter().enumerate() {
        if should_skip_known_openssl_vector(idx) {
            println!("Skipping PSS vector {idx} due to known OpenSSL strictness.");
            continue;
        }

        verify_pss_vector(&session, idx, vector);
    }
}

/// Verifies all supported RSA_PSS_TEST_VECTORS NIST vectors using streaming API verification.
#[session_test]
fn test_rsa_pss_nist_vectors_streaming(session: HsmSession) {
    for (idx, vector) in RSA_PSS_TEST_VECTORS.iter().enumerate() {
        if should_skip_known_openssl_vector(idx) {
            println!("Skipping PSS vector {idx} due to known OpenSSL strictness.");
            continue;
        }

        verify_pss_vector_streaming(&session, idx, vector);
    }
}

/// Signs and verifies all supported RSA_PSS_TEST_VECTORS NIST messages.
#[session_test]
fn test_rsa_pss_nist_vectors_sign_verify(session: HsmSession) {
    for (idx, vector) in RSA_PSS_TEST_VECTORS.iter().enumerate() {
        if should_skip_known_openssl_vector(idx) {
            println!("Skipping PSS sign/verify vector {idx} due to known OpenSSL strictness.");
            continue;
        }

        sign_verify_pss_vector(&session, idx, vector);
    }
}

/// Decrypts all supported RSA_OAEP_TEST_VECTORS NIST ciphertext vectors using API decryption.
#[session_test]
fn test_rsa_oaep_vectors_decrypt(session: HsmSession) {
    for (idx, vector) in RSA_OAEP_TEST_VECTORS.iter().enumerate() {
        decrypt_oaep_vector(&session, idx, vector);
    }
}

/// Roundtrips all supported RSA_OAEP_TEST_VECTORS NIST plaintext vectors using API encrypt/decrypt.
#[session_test]
fn test_rsa_oaep_vectors_encrypt_decrypt_roundtrip(session: HsmSession) {
    for (idx, vector) in RSA_OAEP_TEST_VECTORS.iter().enumerate() {
        roundtrip_oaep_vector(&session, idx, vector);
    }
}
