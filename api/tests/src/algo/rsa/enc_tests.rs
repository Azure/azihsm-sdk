// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto as crypto;
use crypto::*;

use super::*;

/// Import an external RSA private key DER blob into the HSM by wrapping and unwrapping it.
fn import_rsa_key(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    try_import_rsa_key_pair(
        session,
        der,
        bits,
        ImportedRsaKeyUsage::EncryptDecrypt,
        false,
    )
    .expect("Failed to import RSA encrypt/decrypt key pair")
}

/// Ensure RSA-2048 PKCS1 encryption and decryption round-trips successfully.
#[session_test]
fn test_rsa_2048_pkcs1_enc_dec(session: HsmSession) {
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

/// Ensure RSA-3072 PKCS1 encryption and decryption round-trips successfully.
#[session_test]
fn test_rsa_3072_pkcs1_enc_dec(session: HsmSession) {
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

/// Ensure RSA-4096 PKCS1 encryption and decryption round-trips successfully.
#[session_test]
fn test_rsa_4096_pkcs1_enc_dec(session: HsmSession) {
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

/// Ensure RSA-2048 OAEP encryption and decryption round-trips successfully.
#[session_test]
fn test_rsa_2048_oaep_enc_dec(session: HsmSession) {
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

/// Ensure RSA-3072 OAEP encryption and decryption round-trips successfully.
#[session_test]
fn test_rsa_3072_oaep_enc_dec(session: HsmSession) {
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

/// Ensure RSA-4096 OAEP encryption and decryption round-trips successfully.
#[session_test]
fn test_rsa_4096_oaep_enc_dec(session: HsmSession) {
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
    // Key pair A
    let priv_a = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der_a = priv_a.to_vec().expect("Failed to export RSA Key");
    let (_priv_a, pub_a) = import_rsa_key(&session, &der_a, 2048);

    // Key pair B
    let priv_b = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der_b = priv_b.to_vec().expect("Failed to export RSA Key");
    let (priv_b, _) = import_rsa_key(&session, &der_b, 2048);

    let plaintext = b"test wrong key";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_a, plaintext).expect("Failed to encrypt data");

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_b, &ciphertext);

    assert!(matches!(
        result,
        Err(HsmError::DdiCmdFailure | HsmError::InternalError)
    ));
}

/// Ensure tampered ciphertext fails to decrypt
#[session_test]
fn test_rsa_tampered_ciphertext_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"tamper test";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let mut ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    // Flip one byte
    ciphertext[0] ^= 0xFF;

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext);

    assert!(matches!(
        result,
        Err(HsmError::DdiCmdFailure | HsmError::InternalError)
    ));
}

/// Ensure empty plaintext encryption works or is handled
#[session_test]
fn test_rsa_empty_plaintext(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("encrypt empty plaintext");

    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("decrypt empty plaintext");

    assert_eq!(decrypted, plaintext);
}

/// Ensure encryption fails when plaintext exceeds RSA limit
#[session_test]
fn test_rsa_plaintext_too_large_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (_, pub_key) = import_rsa_key(&session, &der, 2048);

    // Too large for RSA 2048 PKCS1 (~245 bytes max)
    let plaintext = vec![0u8; 512];

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let result = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Ensure OAEP label mismatch fails
#[session_test]
fn test_rsa_oaep_label_mismatch(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"oaep label test";

    // Encrypt with label1
    let mut enc_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, Some(b"label1"));

    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext)
        .expect("Failed to encrypt data");

    // Decrypt with DIFFERENT label2
    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, Some(b"label2"));

    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Ensure decrypt fails when using wrong padding scheme
#[session_test]
fn test_rsa_wrong_padding_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"padding mismatch";

    // Encrypt with PKCS1
    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext)
        .expect("Failed to encrypt data");

    // Decrypt with OAEP
    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Ensure decrypting empty ciphertext fails
#[session_test]
fn test_rsa_empty_ciphertext_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, _) = import_rsa_key(&session, &der, 2048);

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &[]);

    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// Ensure OAEP hash mismatch fails
#[session_test]
fn test_rsa_oaep_hash_mismatch_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"hash mismatch";

    let mut enc_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext)
        .expect("Failed to encrypt data");

    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha384, None);

    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Ensure RSA encryption is non-deterministic (same plaintext ≠ same ciphertext)
#[session_test]
fn test_rsa_encryption_is_non_deterministic(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (_, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"same input";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let c1 =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");
    let c2 =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    assert_ne!(c1, c2);
}

/// Ensure truncated ciphertext fails to decrypt
#[session_test]
fn test_rsa_truncated_ciphertext_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"truncate test";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let mut ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    // Remove last byte
    ciphertext.pop();

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext);

    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// Ensure same key works across different padding schemes independently
#[session_test]
fn test_rsa_same_key_multiple_algorithms(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext1 = b"pkcs1";
    let plaintext2 = b"oaep";

    // PKCS1
    let mut pkcs1 = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let c1 = HsmEncrypter::encrypt_vec(&mut pkcs1, &pub_key, plaintext1)
        .expect("Failed to encrypt data");
    let d1 = HsmDecrypter::decrypt_vec(&mut pkcs1, &priv_key, &c1).expect("Failed to decrypt data");

    // OAEP
    let mut oaep = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);
    let c2 =
        HsmEncrypter::encrypt_vec(&mut oaep, &pub_key, plaintext2).expect("Failed to encrypt data");
    let d2 = HsmDecrypter::decrypt_vec(&mut oaep, &priv_key, &c2).expect("Failed to decrypt data");

    assert_eq!(d1, plaintext1);
    assert_eq!(d2, plaintext2);
}

/// Ensure plaintext at exact PKCS1 limit succeeds
#[session_test]
fn test_rsa_plaintext_max_size_succeeds(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    // PKCS1 max: key_size_bytes - 11 = 256 - 11 = 245
    let plaintext = vec![0u8; 245];

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext).expect("Failed to encrypt data");
    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted, plaintext);
}

/// Ensure unwrap fails when public key lacks can_encrypt permission
#[session_test]
fn test_rsa_unwrap_without_encrypt_permission_fails(session: HsmSession) {
    // Generate external RSA key
    let priv_key = RsaPrivateKey::generate(256).expect("gen rsa key");
    let der = priv_key.to_vec().expect("export rsa key");

    // Unwrapping key pair
    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    // Valid private props
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("build private props");

    //  Invalid public props (missing can_encrypt)
    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .expect("build public props");

    // Wrap
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha384, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).expect("wrap key");

    //  Expect unwrap to fail
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha384);

    let result = unwrap_algo.unwrap_key_pair(&unwrap_priv, &wrapped, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Ensure OAEP encryption is non-deterministic
#[session_test]
fn test_rsa_oaep_non_deterministic(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (_, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"same input";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let c1 =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");
    let c2 =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    assert_ne!(c1, c2);
}

/// Ensure plaintext at exact OAEP limit succeeds
#[session_test]
fn test_rsa_oaep_plaintext_max_size_succeeds(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    // OAEP max: 256 - 2*32 - 2 = 190 (SHA256)
    let plaintext = vec![0u8; 190];

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext).expect("Failed to encrypt data");
    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted, plaintext);
}

/// Ensure decrypt fails when using different key size
#[session_test]
fn test_rsa_cross_key_size_fails(session: HsmSession) {
    // 2048 key
    let priv_a = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der_a = priv_a.to_vec().expect("Failed to export RSA Key");
    let (_priv_a, pub_a) = import_rsa_key(&session, &der_a, 2048);

    // 3072 key
    let priv_b = RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der_b = priv_b.to_vec().expect("Failed to export RSA Key");
    let (priv_b, _) = import_rsa_key(&session, &der_b, 3072);

    let plaintext = b"cross size";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_a, plaintext).expect("Failed to encrypt data");

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_b, &ciphertext);

    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// Ensure decrypt works with fresh algo instance (stateless behavior)
#[session_test]
fn test_rsa_decrypt_with_new_algo_instance(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"stateless test";

    let mut enc_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext)
        .expect("Failed to encrypt data");

    // NEW instance (important)
    let mut dec_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let decrypted = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted, plaintext);
}

/// Ensure decrypting same ciphertext twice works
#[session_test]
fn test_rsa_decrypt_twice(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"repeat decrypt";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    let d1 = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");
    let d2 = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(d1, plaintext);
    assert_eq!(d2, plaintext);
}

/// Ensure OAEP None and empty label are treated equivalently
#[session_test]
fn test_rsa_oaep_none_equals_empty_label(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"label edge";

    let mut enc_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext)
        .expect("Failed to encrypt data");

    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, Some(b""));

    let decrypted = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt OAEP ciphertext with empty label");

    assert_eq!(decrypted, plaintext);
}

/// Ensure very small plaintext (1 byte) works
#[session_test]
fn test_rsa_single_byte_plaintext(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"A";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted, plaintext);
}

/// Ensure tampering at end of ciphertext fails
#[session_test]
fn test_rsa_tampered_ciphertext_tail_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"tail tamper";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let mut ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xFF;

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Ensure RSA decryption fails when ciphertext is decrypted with a private key of a different size.
#[session_test]
fn test_rsa_decrypt_with_wrong_key_size_fails(session: HsmSession) {
    // Encrypt with RSA-2048 public key.
    let priv_a = RsaPrivateKey::generate(256).expect("Failed to generate RSA-2048 key");
    let der_a = priv_a.to_vec().expect("Failed to export RSA-2048 key");
    let (_, pub_a) = import_rsa_key(&session, &der_a, 2048);

    // Attempt to decrypt with RSA-3072 private key.
    let priv_b = RsaPrivateKey::generate(384).expect("Failed to generate RSA-3072 key");
    let der_b = priv_b.to_vec().expect("Failed to export RSA-3072 key");
    let (priv_b, _) = import_rsa_key(&session, &der_b, 3072);

    let plaintext = b"wrong key size";

    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_a, plaintext).expect("Failed to encrypt data");

    let result = HsmDecrypter::decrypt_vec(&mut algo, &priv_b, &ciphertext);

    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// Ensure RSA OAEP round-trips successfully with SHA1.
#[session_test]
fn test_rsa_oaep_sha1_enc_dec(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"oaep sha1";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha1, None);

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted, plaintext);
}

/// Ensure RSA OAEP round-trips successfully with SHA512.
#[session_test]
fn test_rsa_oaep_sha512_enc_dec(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"oaep sha512";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha512, None);

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Failed to encrypt data");

    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted, plaintext);
}

/// Ensure RSA OAEP decryption fails when encrypted with SHA1 and decrypted with SHA512.
#[session_test]
fn test_rsa_oaep_sha1_to_sha512_hash_mismatch_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"oaep sha1 sha512 mismatch";

    let mut enc_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha1, None);
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext)
        .expect("Failed to encrypt data");

    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha512, None);
    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Ensure RSA OAEP decryption fails when encrypted with SHA512 and decrypted with SHA1.
#[session_test]
fn test_rsa_oaep_sha512_to_sha1_hash_mismatch_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let plaintext = b"oaep sha512 sha1 mismatch";

    let mut enc_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha512, None);
    let ciphertext = HsmEncrypter::encrypt_vec(&mut enc_algo, &pub_key, plaintext)
        .expect("Failed to encrypt data");

    let mut dec_algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha1, None);
    let result = HsmDecrypter::decrypt_vec(&mut dec_algo, &priv_key, &ciphertext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Ensure plaintext at exact OAEP SHA1 limit succeeds.
#[session_test]
fn test_rsa_oaep_sha1_plaintext_max_size_succeeds(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    // OAEP max for RSA-2048 with SHA1: 256 - 2*20 - 2 = 214
    let plaintext = vec![0u8; 214];

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha1, None);

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext).expect("Failed to encrypt data");

    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted, plaintext);
}

/// Ensure plaintext at exact OAEP SHA512 limit succeeds.
#[session_test]
fn test_rsa_oaep_sha512_plaintext_max_size_succeeds(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    // OAEP max for RSA-2048 with SHA512: 256 - 2*64 - 2 = 126
    let plaintext = vec![0u8; 126];

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha512, None);

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext).expect("Failed to encrypt data");

    let decrypted = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext)
        .expect("Failed to decrypt data");

    assert_eq!(decrypted, plaintext);
}

/// Ensure RSA OAEP SHA512 encryption fails when plaintext exceeds the hash-dependent limit.
#[session_test]
fn test_rsa_oaep_sha512_plaintext_too_large_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (_, pub_key) = import_rsa_key(&session, &der, 2048);

    // OAEP SHA512 max for RSA-2048 is 126 bytes, so 127 should fail.
    let plaintext = vec![0u8; 127];

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha512, None);

    let result = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Ensure RSA OAEP SHA1 encryption fails when plaintext exceeds the hash-dependent limit.
#[session_test]
fn test_rsa_oaep_sha1_plaintext_too_large_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (_, pub_key) = import_rsa_key(&session, &der, 2048);

    // OAEP SHA1 max for RSA-2048 is 214 bytes, so 215 should fail.
    let plaintext = vec![0u8; 215];

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha1, None);

    let result = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Ensure RSA OAEP SHA256 encryption fails when plaintext exceeds the hash-dependent limit.
#[session_test]
fn test_rsa_oaep_sha256_plaintext_too_large_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (_, pub_key) = import_rsa_key(&session, &der, 2048);

    // OAEP SHA256 max for RSA-2048 is 190 bytes, so 191 should fail.
    let plaintext = vec![0u8; 191];

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let result = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, &plaintext);

    assert!(matches!(result, Err(HsmError::InternalError)));
}
