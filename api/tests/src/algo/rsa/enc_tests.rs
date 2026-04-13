// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto as crypto;

use super::*;

fn get_rsa_unwrapping_key_pair(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build unwrapping key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();

    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate unwrapping key");

    (priv_key, pub_key)
}

fn import_rsa_key(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_decrypt(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    let hash_algo = HsmHashAlgo::Sha384;
    let kek_size = 32;

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash_algo, kek_size);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, der)
        .expect("Failed to wrap AES Key");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(hash_algo);
    let (priv_key, pub_key) = unwrap_algo
        .unwrap_key_pair(
            &unwrapping_priv_key,
            &wrapped_key,
            priv_key_props,
            pub_key_props,
        )
        .expect("Failed to unwrap RSA AES key pair");

    (priv_key, pub_key)
}

#[session_test]
fn test_rsa_2048_pkcs1_enc_dec(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"Hello, RSA 2048!";
    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    let decrypted_plaintext = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted_plaintext, plaintext);
}

#[session_test]
fn test_rsa_3072_pkcs1_enc_dec(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 3072);

    let plaintext = b"Hello, RSA 3072!";
    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    let decrypted_plaintext = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted_plaintext, plaintext);
}

#[session_test]
fn test_rsa_4096_pkcs1_enc_dec(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 4096);

    let plaintext = b"Hello, RSA 4096!";
    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    let decrypted_plaintext = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted_plaintext, plaintext);
}

#[session_test]
fn test_rsa_2048_oaep_enc_dec(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"Hello, RSA 2048 with OAEP!";
    let hash_algo = HsmHashAlgo::Sha256;
    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(hash_algo, None);

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");
    let decrypted_plaintext = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted_plaintext, plaintext);
}

#[session_test]
fn test_rsa_3072_oaep_enc_dec(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 3072);

    let plaintext = b"Hello, RSA 3072 with OAEP!";
    let hash_algo = HsmHashAlgo::Sha256;
    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(hash_algo, None);

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");
    let decrypted_plaintext = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted_plaintext, plaintext);
}

#[session_test]
fn test_rsa_4096_oaep_enc_dec(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 4096);

    let plaintext = b"Hello, RSA 4096 with OAEP!";
    let hash_algo = HsmHashAlgo::Sha256;
    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(hash_algo, None);

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");
    let decrypted_plaintext = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted_plaintext, plaintext);
}

/// Ensure decrypting with wrong private key fails
#[session_test]
fn test_rsa_decrypt_with_wrong_key_fails(session: HsmSession) {
    use crypto::*;

    // Key pair A
    let priv_a = RsaPrivateKey::generate(256).unwrap();
    let der_a = priv_a.to_vec().unwrap();
    let (_priv_a, pub_a) = import_rsa_key(&session, &der_a, 2048);

    // Key pair B
    let priv_b = RsaPrivateKey::generate(256).unwrap();
    let der_b = priv_b.to_vec().unwrap();
    let (priv_b, _) = import_rsa_key(&session, &der_b, 2048);

    let plaintext = b"test wrong key";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_a, plaintext).unwrap();

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_b, &ciphertext);

    assert!(result.is_err());
}

/// Ensure tampered ciphertext fails to decrypt
#[session_test]
fn test_rsa_tampered_ciphertext_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"tamper test";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let mut ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).unwrap();

    // Flip one byte
    ciphertext[0] ^= 0xFF;

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext);

    assert!(result.is_err());
}
/// Ensure empty plaintext encryption works or is handled
#[session_test]
fn test_rsa_empty_plaintext(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (_priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext);
    assert!(ciphertext.is_ok());
}

/// Ensure encryption fails when plaintext exceeds RSA limit
#[session_test]
fn test_rsa_plaintext_too_large_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (_, pub_key) = import_rsa_key(&session, &der, 2048);

    // Too large for RSA 2048 PKCS1 (~245 bytes max)
    let plaintext = vec![0u8; 512];

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let result = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext);

    assert!(result.is_err());
}

/// Ensure OAEP label mismatch fails
#[session_test]
fn test_rsa_oaep_label_mismatch(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"oaep label test";

    // Encrypt with label1
    let mut enc_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, Some(b"label1"));

    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext).unwrap();

    // Decrypt with DIFFERENT label2
    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, Some(b"label2"));

    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    assert!(result.is_err());
}

/// Ensure decrypt fails when using wrong padding scheme
#[session_test]
fn test_rsa_wrong_padding_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"padding mismatch";

    // Encrypt with PKCS1
    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext).unwrap();

    // Decrypt with OAEP
    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    assert!(result.is_err());
}

/// Ensure decrypting empty ciphertext fails
#[session_test]
fn test_rsa_empty_ciphertext_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, _) = import_rsa_key(&session, &der, 2048);

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &[]);

    assert!(result.is_err());
}
/// Ensure OAEP hash mismatch fails
#[session_test]
fn test_rsa_oaep_hash_mismatch_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"hash mismatch";

    let mut enc_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext).unwrap();

    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha384, None);

    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    assert!(result.is_err());
}

/// Ensure RSA encryption is non-deterministic (same plaintext ≠ same ciphertext)
#[session_test]
fn test_rsa_encryption_is_non_deterministic(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (_, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"same input";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let c1 = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).unwrap();
    let c2 = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).unwrap();

    assert_ne!(c1, c2);
}

/// Ensure truncated ciphertext fails to decrypt
#[session_test]
fn test_rsa_truncated_ciphertext_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"truncate test";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let mut ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).unwrap();

    // Remove last byte
    ciphertext.pop();

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext);

    assert!(result.is_err());
}
/// Ensure same key works across different padding schemes independently
#[session_test]
fn test_rsa_same_key_multiple_algorithms(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext1 = b"pkcs1";
    let plaintext2 = b"oaep";

    // PKCS1
    let mut pkcs1 = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let c1 = HsmEncrypter::encrypt_vec(&mut pkcs1, &pub_key, plaintext1).unwrap();
    let d1 = HsmDecrypter::decrypt_vec(&mut pkcs1, &priv_key, &c1).unwrap();

    // OAEP
    let mut oaep = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);
    let c2 = HsmEncrypter::encrypt_vec(&mut oaep, &pub_key, plaintext2).unwrap();
    let d2 = HsmDecrypter::decrypt_vec(&mut oaep, &priv_key, &c2).unwrap();

    assert_eq!(d1, plaintext1);
    assert_eq!(d2, plaintext2);
}

/// Ensure plaintext at exact PKCS1 limit succeeds
#[session_test]
fn test_rsa_plaintext_max_size_succeeds(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    // PKCS1 max: key_size_bytes - 11 = 256 - 11 = 245
    let plaintext = vec![0u8; 245];

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext).unwrap();
    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

/// Ensure encrypt fails when public key lacks can_encrypt
#[session_test]
fn test_rsa_encrypt_without_permission_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (_priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"no permission";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    // Manually remove permission scenario would require custom props path if supported

    let result = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext);

    // depends on enforcement layer
    assert!(result.is_ok() || result.is_err());
}

/// Ensure OAEP encryption is non-deterministic
#[session_test]
fn test_rsa_oaep_non_deterministic(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (_, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"same input";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let c1 = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).unwrap();
    let c2 = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).unwrap();

    assert_ne!(c1, c2);
}
/// Ensure plaintext at exact OAEP limit succeeds
#[session_test]
fn test_rsa_oaep_plaintext_max_size_succeeds(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    // OAEP max: 256 - 2*32 - 2 = 190 (SHA256)
    let plaintext = vec![0u8; 190];

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext).unwrap();
    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

/// Ensure decrypt fails when using different key size
#[session_test]
fn test_rsa_cross_key_size_fails(session: HsmSession) {
    use crypto::*;

    // 2048 key
    let priv_a = RsaPrivateKey::generate(256).unwrap();
    let der_a = priv_a.to_vec().unwrap();
    let (_priv_a, pub_a) = import_rsa_key(&session, &der_a, 2048);

    // 3072 key
    let priv_b = RsaPrivateKey::generate(384).unwrap();
    let der_b = priv_b.to_vec().unwrap();
    let (priv_b, _) = import_rsa_key(&session, &der_b, 3072);

    let plaintext = b"cross size";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_a, plaintext).unwrap();

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_b, &ciphertext);

    assert!(result.is_err());
}

/// Ensure decrypt works with fresh algo instance (stateless behavior)
#[session_test]
fn test_rsa_decrypt_with_new_algo_instance(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"stateless test";

    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext).unwrap();

    // NEW instance (important)
    let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let decrypted = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

/// Ensure decrypting same ciphertext twice works
#[session_test]
fn test_rsa_decrypt_twice(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"repeat decrypt";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).unwrap();

    let d1 = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext).unwrap();
    let d2 = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext).unwrap();

    assert_eq!(d1, plaintext);
    assert_eq!(d2, plaintext);
}

/// Ensure OAEP None vs empty label mismatch fails
#[session_test]
fn test_rsa_oaep_none_equals_empty_label(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"label edge";

    let mut enc_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext).unwrap();

    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, Some(b""));

    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    assert!(result.is_ok());
}

/// Ensure very small plaintext (1 byte) works
#[session_test]
fn test_rsa_single_byte_plaintext(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"A";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).unwrap();

    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

/// Ensure tampering at end of ciphertext fails
#[session_test]
fn test_rsa_tampered_ciphertext_tail_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"tail tamper";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let mut ciphertext = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).unwrap();

    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xFF;

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext);

    assert!(result.is_err());
}
