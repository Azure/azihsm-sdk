// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::HsmAesKeyRsaAesKeyUnwrapAlgo;
use azihsm_api::HsmKeyClass;
use azihsm_api::HsmKeyKind;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmKeyPropsBuilder;
use azihsm_api::HsmRsaAesWrapAlgo;
use azihsm_api::HsmRsaPrivateKey;
use azihsm_api::HsmRsaPublicKey;
use azihsm_crypto::testvectors::aes::AES_CBC_128_GFSBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_128_MCT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_128_MMT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_128_SBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_128_VAR_KEY_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_128_VAR_TXT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_GFSBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_MCT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_MMT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_SBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_VAR_KEY_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_VAR_TXT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_GFSBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_MCT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_MMT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_SBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_VAR_KEY_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_VAR_TXT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AesCbcTestVector;

use super::common::*;
use super::*;

fn generate_rsa_keypair(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
        .expect("RSA key generation failed")
}

fn wrap_aes_key_rsa(rsa_pub: &HsmRsaPublicKey, key_bytes: &[u8]) -> Vec<u8> {
    let kek_size = match key_bytes.len() {
        16 | 24 | 32 => key_bytes.len(),
        _ => panic!("Invalid AES key size: {}", key_bytes.len()),
    };

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, kek_size);
    let size = wrap_algo
        .encrypt(rsa_pub, key_bytes, None)
        .expect("wrap size failed");

    let mut wrapped = vec![0u8; size];

    wrap_algo
        .encrypt(rsa_pub, key_bytes, Some(&mut wrapped))
        .expect("wrap failed");

    wrapped
}

fn run_cbc_mct_encrypt(key: &HsmAesKey, iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    assert_eq!(plaintext.len(), 16);

    let initial_iv = iv.to_vec();
    let mut chaining_iv = initial_iv.clone();
    let mut input_block = plaintext.to_vec();
    let mut previous_output = vec![0u8; 16];
    let mut current_output = vec![0u8; 16];

    // NIST MCT encrypt pseudocode (single-block CBC):
    // For j = 0..999
    //   CT[j] = AES_CBC_ENC(Key, IV, PT[j])
    //   PT[j+1] = (j == 0 ? IV[i] : CT[j-1])
    // Output is CT[999].
    for j in 0..1000 {
        let out = cbc_encrypt(key, false, &chaining_iv, &input_block).expect("encrypt failed");
        current_output.copy_from_slice(&out);

        if j == 0 {
            input_block.copy_from_slice(&initial_iv);
        } else {
            input_block.copy_from_slice(&previous_output);
        }

        previous_output.copy_from_slice(&current_output);
        // For single-block CBC encrypt, next IV = ciphertext output
        chaining_iv.copy_from_slice(&current_output);
    }

    current_output
}

fn run_cbc_mct_decrypt(key: &HsmAesKey, iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    assert_eq!(ciphertext.len(), 16);

    let initial_iv = iv.to_vec();
    let mut chaining_iv = initial_iv.clone();
    let mut input_block = ciphertext.to_vec();
    let mut previous_output = vec![0u8; 16];
    let mut current_output = vec![0u8; 16];

    // NIST MCT decrypt pseudocode (single-block CBC):
    // For j = 0..999
    //   PT[j] = AES_CBC_DEC(Key, IV, CT[j])
    //   CT[j+1] = (j == 0 ? IV[i] : PT[j-1])
    // Output is PT[999].
    for j in 0..1000 {
        let out = cbc_decrypt(key, false, &chaining_iv, &input_block).expect("decrypt failed");
        current_output.copy_from_slice(&out);

        // Save input before overwriting (CBC decrypt: next IV = ciphertext just decrypted)
        let prev_input = input_block.clone();

        if j == 0 {
            input_block.copy_from_slice(&initial_iv);
        } else {
            input_block.copy_from_slice(&previous_output);
        }

        previous_output.copy_from_slice(&current_output);
        // For single-block CBC decrypt, next IV = the ciphertext block that was decrypted
        chaining_iv.copy_from_slice(&prev_input);
    }

    current_output
}

fn assert_encrypt_match(actual: &[u8], vector: &AesCbcTestVector, dataset: &str, key_bits: usize) {
    assert_eq!(
        actual,
        vector.ciphertext,
        "\n[ENCRYPT FAIL] {dataset} ({key_bits}-bit) vector {id}\n\
         key: {key:02x?}\n  iv: {iv:02x?}\n  plaintext: {pt:02x?}\n\
         expected: {exp:02x?}\n  actual: {act:02x?}\n",
        id = vector.test_count_id,
        key = vector.key,
        iv = vector.iv,
        pt = vector.plaintext,
        exp = vector.ciphertext,
        act = actual,
    );
}

fn assert_decrypt_match(actual: &[u8], vector: &AesCbcTestVector, dataset: &str, key_bits: usize) {
    assert_eq!(
        actual,
        vector.plaintext,
        "\n[DECRYPT FAIL] {dataset} ({key_bits}-bit) vector {id}\n\
         key: {key:02x?}\n  iv: {iv:02x?}\n  ciphertext: {ct:02x?}\n\
         expected: {exp:02x?}\n  actual: {act:02x?}\n",
        id = vector.test_count_id,
        key = vector.key,
        iv = vector.iv,
        ct = vector.ciphertext,
        exp = vector.plaintext,
        act = actual,
    );
}

fn run_cbc_vectors(
    vectors: &[AesCbcTestVector],
    key_bits: usize,
    dataset: &str,
    rsa_priv: &HsmRsaPrivateKey,
    rsa_pub: &HsmRsaPublicKey,
) {
    for vector in vectors {
        assert_eq!(
            vector.key.len() * 8,
            key_bits,
            "Key size mismatch in vector {}",
            vector.test_count_id
        );

        println!(
            "Running {} ({}-bit) vector {}",
            dataset, key_bits, vector.test_count_id
        );

        let is_mct = dataset.contains("MCT");

        let wrapped_key = wrap_aes_key_rsa(rsa_pub, vector.key);

        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Aes)
            .bits(key_bits as u32)
            .can_encrypt(true)
            .can_decrypt(true)
            .is_session(true)
            .build()
            .unwrap();

        let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

        let key = HsmKeyManager::unwrap_key(&mut unwrap_algo, rsa_priv, &wrapped_key, props)
            .expect("unwrap failed");

        assert!(
            vector.plaintext.len() % 16 == 0,
            "plaintext not block aligned for vector {}",
            vector.test_count_id
        );

        // MCT vectors are one-directional: each vector is either encrypt or
        // decrypt, not both. The MCT loops use different chaining rules so
        // they are not inverses of each other.
        if is_mct {
            if vector.encrypt {
                let ct = run_cbc_mct_encrypt(&key, vector.iv, vector.plaintext);
                assert_encrypt_match(&ct, vector, dataset, key_bits);
            } else {
                let pt = run_cbc_mct_decrypt(&key, vector.iv, vector.ciphertext);
                assert_decrypt_match(&pt, vector, dataset, key_bits);
            }
        } else {
            let ct = cbc_encrypt(&key, false, vector.iv, vector.plaintext).unwrap();
            assert_encrypt_match(&ct, vector, dataset, key_bits);

            let pt = cbc_decrypt(&key, false, vector.iv, vector.ciphertext).unwrap();
            assert_decrypt_match(&pt, vector, dataset, key_bits);
        }

        HsmKeyManager::delete_key(key).unwrap();
    }
}

#[session_test]
fn cbc_128_gfsbox(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_128_GFSBOX_TEST_VECTORS,
        128,
        "CBC_128_GFSBOX",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_128_mmt(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_128_MMT_TEST_VECTORS,
        128,
        "CBC_128_MMT",
        &rsa_priv,
        &rsa_pub,
    );
}

#[ignore]
#[session_test]
fn cbc_128_mct(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_128_MCT_TEST_VECTORS,
        128,
        "CBC_128_MCT",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_128_sbox(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_128_SBOX_TEST_VECTORS,
        128,
        "CBC_128_SBOX",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_128_varkey(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_128_VAR_KEY_TEST_VECTORS,
        128,
        "CBC_128_VAR_KEY",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_128_vartxt(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_128_VAR_TXT_TEST_VECTORS,
        128,
        "CBC_128_VAR_TXT",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_192_gfsbox(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_192_GFSBOX_TEST_VECTORS,
        192,
        "CBC_192_GFSBOX",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_192_mmt(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_192_MMT_TEST_VECTORS,
        192,
        "CBC_192_MMT",
        &rsa_priv,
        &rsa_pub,
    );
}

#[ignore]
#[session_test]
fn cbc_192_mct(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_192_MCT_TEST_VECTORS,
        192,
        "CBC_192_MCT",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_192_sbox(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_192_SBOX_TEST_VECTORS,
        192,
        "CBC_192_SBOX",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_192_varkey(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_192_VAR_KEY_TEST_VECTORS,
        192,
        "CBC_192_VAR_KEY",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_192_vartxt(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_192_VAR_TXT_TEST_VECTORS,
        192,
        "CBC_192_VAR_TXT",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_256_gfsbox(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_256_GFSBOX_TEST_VECTORS,
        256,
        "CBC_256_GFSBOX",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_256_mmt(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_256_MMT_TEST_VECTORS,
        256,
        "CBC_256_MMT",
        &rsa_priv,
        &rsa_pub,
    );
}

#[ignore]
#[session_test]
fn cbc_256_mct(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_256_MCT_TEST_VECTORS,
        256,
        "CBC_256_MCT",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_256_sbox(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_256_SBOX_TEST_VECTORS,
        256,
        "CBC_256_SBOX",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_256_varkey(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_256_VAR_KEY_TEST_VECTORS,
        256,
        "CBC_256_VAR_KEY",
        &rsa_priv,
        &rsa_pub,
    );
}

#[session_test]
fn cbc_256_vartxt(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);
    run_cbc_vectors(
        AES_CBC_256_VAR_TXT_TEST_VECTORS,
        256,
        "CBC_256_VAR_TXT",
        &rsa_priv,
        &rsa_pub,
    );
}
