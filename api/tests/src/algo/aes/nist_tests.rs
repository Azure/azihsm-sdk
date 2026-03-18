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
use azihsm_crypto::testvectors::aes::AES_CBC_128_MMT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_128_SBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_128_VAR_KEY_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_128_VAR_TXT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_GFSBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_MMT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_SBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_VAR_KEY_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_192_VAR_TXT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_GFSBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_MMT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_SBOX_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_VAR_KEY_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AES_CBC_256_VAR_TXT_TEST_VECTORS;
use azihsm_crypto::testvectors::aes::AesCbcTestVector;

use super::common::*;
use super::*;

const CBC_128_VECTORS: &[(&str, &[AesCbcTestVector])] = &[
    ("CBC_128_GFSBOX", AES_CBC_128_GFSBOX_TEST_VECTORS),
    ("CBC_128_MMT", AES_CBC_128_MMT_TEST_VECTORS),
    ("CBC_128_SBOX", AES_CBC_128_SBOX_TEST_VECTORS),
    ("CBC_128_VAR_KEY", AES_CBC_128_VAR_KEY_TEST_VECTORS),
    ("CBC_128_VAR_TXT", AES_CBC_128_VAR_TXT_TEST_VECTORS),
];

const CBC_192_VECTORS: &[(&str, &[AesCbcTestVector])] = &[
    ("CBC_192_GFSBOX", AES_CBC_192_GFSBOX_TEST_VECTORS),
    ("CBC_192_MMT", AES_CBC_192_MMT_TEST_VECTORS),
    ("CBC_192_SBOX", AES_CBC_192_SBOX_TEST_VECTORS),
    ("CBC_192_VAR_KEY", AES_CBC_192_VAR_KEY_TEST_VECTORS),
    ("CBC_192_VAR_TXT", AES_CBC_192_VAR_TXT_TEST_VECTORS),
];

const CBC_256_VECTORS: &[(&str, &[AesCbcTestVector])] = &[
    ("CBC_256_GFSBOX", AES_CBC_256_GFSBOX_TEST_VECTORS),
    ("CBC_256_MMT", AES_CBC_256_MMT_TEST_VECTORS),
    ("CBC_256_SBOX", AES_CBC_256_SBOX_TEST_VECTORS),
    ("CBC_256_VAR_KEY", AES_CBC_256_VAR_KEY_TEST_VECTORS),
    ("CBC_256_VAR_TXT", AES_CBC_256_VAR_TXT_TEST_VECTORS),
];

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

fn xor_block(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn run_cbc_mct_encrypt(key: &HsmAesKey, iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    assert_eq!(plaintext.len(), 16);

    let mut chaining_iv = iv.to_vec();
    let mut input_block = plaintext.to_vec();
    let mut current_output = vec![0u8; 16];

    for _ in 0..1000 {
        //  manual XOR
        let x = xor_block(&input_block, &chaining_iv);

        //  encrypt single block (ECB-style)
        let iv = test_iv();
        let out = cbc_encrypt(key, false, &iv, &x).expect("encrypt failed");

        current_output.copy_from_slice(&out);

        // update
        input_block.copy_from_slice(&current_output);
        chaining_iv.copy_from_slice(&current_output);
    }

    current_output
}

fn run_cbc_mct_decrypt(key: &HsmAesKey, iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    assert_eq!(ciphertext.len(), 16);

    let mut chaining_iv = iv.to_vec();
    let mut input_block = ciphertext.to_vec();
    let mut current_output = vec![0u8; 16];

    for _ in 0..1000 {
        // decrypt block
        let iv = test_iv();
        let out = cbc_decrypt(key, false, &iv, &input_block).expect("decrypt failed");

        // XOR after decrypt
        let x = xor_block(&out, &chaining_iv);

        current_output.copy_from_slice(&x);

        chaining_iv.copy_from_slice(&input_block);
        input_block.copy_from_slice(&current_output);
    }

    current_output
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

        // ----------------------------
        // Wrap AES key
        // ----------------------------
        let wrapped_key = wrap_aes_key_rsa(rsa_pub, vector.key);

        // ----------------------------
        // Unwrap AES key
        // ----------------------------
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

        // ----------------------------
        // Encrypt
        // ----------------------------

        assert!(
            vector.plaintext.len() % 16 == 0,
            "plaintext not block aligned for vector {}",
            vector.test_count_id
        );

        let ciphertext = if is_mct {
            run_cbc_mct_encrypt(&key, vector.iv, vector.plaintext)
        } else {
            cbc_encrypt(&key, false, vector.iv, vector.plaintext).unwrap()
        };

        assert_eq!(
            ciphertext,
            vector.ciphertext,
            "\n[ENCRYPT FAIL]\n\
     dataset: {}\n\
     key_bits: {}\n\
     vector_id: {}\n\
     key: {:02x?}\n\
     iv: {:02x?}\n\
     plaintext: {:02x?}\n\
     expected_ciphertext: {:02x?}\n\
     actual_ciphertext: {:02x?}\n",
            dataset,
            key_bits,
            vector.test_count_id,
            vector.key,
            vector.iv,
            vector.plaintext,
            vector.ciphertext,
            ciphertext,
        );

        // ----------------------------
        // Decrypt
        // ----------------------------

        let plaintext = if is_mct {
            run_cbc_mct_decrypt(&key, vector.iv, vector.ciphertext)
        } else {
            cbc_decrypt(&key, false, vector.iv, vector.ciphertext).unwrap()
        };

        assert_eq!(
            plaintext,
            vector.plaintext,
            "\n[DECRYPT FAIL]\n\
     dataset: {}\n\
     key_bits: {}\n\
     vector_id: {}\n\
     key: {:02x?}\n\
     iv: {:02x?}\n\
     ciphertext: {:02x?}\n\
     expected_plaintext: {:02x?}\n\
     actual_plaintext: {:02x?}\n",
            dataset,
            key_bits,
            vector.test_count_id,
            vector.key,
            vector.iv,
            vector.ciphertext,
            vector.plaintext,
            plaintext,
        );

        HsmKeyManager::delete_key(key).unwrap();
    }
}

#[session_test]
fn test_cbc_all_vectors(session: HsmSession) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(&session);

    for (groups, bits) in [
        (CBC_128_VECTORS, 128),
        (CBC_192_VECTORS, 192),
        (CBC_256_VECTORS, 256),
    ] {
        for (name, group) in groups {
            run_cbc_vectors(group, bits, name, &rsa_priv, &rsa_pub);
        }
    }
}
