// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

fn rsa_oaep_roundtrip(
    key_size_bytes: usize,
    hash: &HashAlgo,
    label: Option<&'static [u8]>,
    plaintext: &'static [u8],
) {
    let private_key =
        RsaPrivateKey::generate(key_size_bytes).expect("Failed to generate RSA private key");
    let public_key = private_key
        .public_key()
        .expect("Failed to get RSA public key");

    let mut algo = RsaEncryptAlgo::with_oaep_padding(hash.clone(), label);

    let cipher_size =
        Encrypter::encrypt(&mut algo, &public_key, plaintext, None).expect("Encryption failed");
    assert_eq!(cipher_size, key_size_bytes);

    let mut ciphertext = vec![0u8; cipher_size];
    assert_eq!(
        Encrypter::encrypt(&mut algo, &public_key, plaintext, Some(&mut ciphertext)),
        Ok(cipher_size)
    );

    let plain_size =
        Decrypter::decrypt(&mut algo, &private_key, &ciphertext, None).expect("Decryption failed");
    let mut decrypted = vec![0u8; plain_size];
    let len = Decrypter::decrypt(&mut algo, &private_key, &ciphertext, Some(&mut decrypted))
        .expect("Decryption failed");
    decrypted.truncate(len);

    // Some backends may return a sized buffer and leave unused bytes as zeros.
    assert_eq!(&decrypted, plaintext);
}
fn assert_oaep_vector_ok(vector: &OaepTestVector, private_key: &RsaPrivateKey) {
    let public_key = private_key
        .public_key()
        .expect("Failed to get RSA public key");

    let hash: HashAlgo = vector.hash_algo.into();
    let mut algo = RsaEncryptAlgo::with_oaep_padding(hash.clone(), vector.label);

    // Validate decryption of known-good ciphertext.
    let plain_size = Decrypter::decrypt(&mut algo, private_key, vector.ciphertext, None)
        .unwrap_or_else(|e| panic!("vector {}: decrypt_len failed: {e:?}", vector.name));

    let mut decrypted = vec![0u8; plain_size];
    let len = Decrypter::decrypt(
        &mut algo,
        private_key,
        vector.ciphertext,
        Some(&mut decrypted),
    )
    .expect("Vector decryption failed");
    decrypted.truncate(len);

    assert_eq!(
        decrypted.as_slice(),
        vector.plaintext,
        "vector {}: plaintext mismatch",
        vector.name
    );

    // Exercise encryption path too (OAEP is randomized, so we don't compare ciphertext).
    let cipher_size = Encrypter::encrypt(&mut algo, &public_key, vector.plaintext, None)
        .unwrap_or_else(|e| panic!("vector {}: encrypt_len failed: {e:?}", vector.name));

    assert_eq!(
        cipher_size,
        vector.ciphertext.len(),
        "vector {}: ciphertext length mismatch",
        vector.name
    );

    let mut ciphertext = vec![0u8; cipher_size];
    assert_eq!(
        Encrypter::encrypt(
            &mut algo,
            &public_key,
            vector.plaintext,
            Some(&mut ciphertext)
        ),
        Ok(cipher_size),
        "vector {}: encrypt failed",
        vector.name
    );

    let roundtrip_plain_size = Decrypter::decrypt(&mut algo, private_key, &ciphertext, None)
        .expect("Roundtrip decrypt_len failed");
    let mut roundtrip_plaintext = vec![0u8; roundtrip_plain_size];

    let len = Decrypter::decrypt(
        &mut algo,
        private_key,
        &ciphertext,
        Some(&mut roundtrip_plaintext),
    )
    .expect("Decryption Failed");
    roundtrip_plaintext.truncate(len);
    assert_eq!(
        roundtrip_plaintext.as_slice(),
        vector.plaintext,
        "vector {}: roundtrip plaintext mismatch",
        vector.name
    );
}

// Validates OAEP decryption against known BoringSSL vectors, and then does an encrypt+decrypt
// roundtrip per vector (OAEP is randomized, so ciphertext is not compared).
#[test]
fn test_rsa_oaep_boringssl_testvectors() {
    for vector in RSA_OAEP_TEST_VECTORS {
        let imported = <RsaPrivateKey as ImportableKey>::from_bytes(vector.priv_der);
        match imported {
            Ok(private_key) => assert_oaep_vector_ok(vector, &private_key),
            Err(CryptoError::EccInvalidKeySize) => {
                // The crate intentionally only supports 2048/3072/4096-bit RSA keys.
                assert!(
                    !is_supported_rsa_modulus_size_bytes(vector.ciphertext.len()),
                    "vector {}: unexpected key size rejection for supported modulus size",
                    vector.name
                );
            }
            Err(e) => panic!(
                "vector {}: failed to import RSA private key: {e:?}",
                vector.name
            ),
        }
    }
}

// Exercises OAEP (SHA-256) encrypt/decrypt on a freshly generated 2048-bit key.
#[test]
fn test_rsa_2048_encrypt_decrypt_oaep_sha256() {
    // OAEP (SHA-256) max input length for 2048-bit key is 256 - 2*32 - 2 = 190 bytes.
    rsa_oaep_roundtrip(
        2048 / 8,
        &HashAlgo::sha256(),
        None,
        b"Test message for RSA OAEP(SHA-256)",
    );
}

// Exercises OAEP (SHA-384) encrypt/decrypt on a freshly generated 2048-bit key.
#[test]
fn test_rsa_2048_encrypt_decrypt_oaep_sha384() {
    // OAEP (SHA-384) max input length for 2048-bit key is 256 - 2*48 - 2 = 158 bytes.
    rsa_oaep_roundtrip(
        2048 / 8,
        &HashAlgo::sha384(),
        None,
        b"Test message for RSA OAEP(SHA-384)",
    );
}

// Exercises OAEP (SHA-1) encrypt/decrypt with a non-empty label.
#[test]
fn test_rsa_2048_encrypt_decrypt_oaep_sha1_with_label() {
    // OAEP (SHA-1) max input length for 2048-bit key is 256 - 2*20 - 2 = 214 bytes.
    rsa_oaep_roundtrip(
        2048 / 8,
        &HashAlgo::sha1(),
        Some(b"oaep-label"),
        b"Test message for RSA OAEP(SHA-1) with label",
    );
}

// Exercises OAEP (SHA-512) encrypt/decrypt with a non-empty label.
#[test]
fn test_rsa_2048_encrypt_decrypt_oaep_sha512_with_label() {
    // OAEP (SHA-512) max input length for 2048-bit key is 256 - 2*64 - 2 = 126 bytes.
    rsa_oaep_roundtrip(
        2048 / 8,
        &HashAlgo::sha512(),
        Some(b"label-sha512"),
        b"OAEP SHA-512 label test",
    );
}

// Exercises OAEP (SHA-256) encrypt/decrypt on a freshly generated 3072-bit key.
#[test]
fn test_rsa_3072_encrypt_decrypt_oaep_sha256() {
    // OAEP (SHA-256) max input length for 3072-bit key is 384 - 2*32 - 2 = 318 bytes.
    rsa_oaep_roundtrip(
        3072 / 8,
        &HashAlgo::sha256(),
        None,
        b"Test message for RSA OAEP(SHA-256) with 3072-bit key",
    );
}

// Exercises OAEP (SHA-256) encrypt/decrypt on a freshly generated 4096-bit key.
#[test]
fn test_rsa_4096_encrypt_decrypt_oaep_sha256() {
    // OAEP (SHA-256) max input length for 4096-bit key is 512 - 2*32 - 2 = 446 bytes.
    rsa_oaep_roundtrip(
        4096 / 8,
        &HashAlgo::sha256(),
        None,
        b"Test message for RSA OAEP(SHA-256) with 4096-bit key",
    );
}

// Negative test: ciphertext created with label A must not decrypt with label B.
// Uses a buffered decrypt to avoid false positives from length-only queries.
#[test]
fn test_rsa_2048_oaep_label_mismatch_fails() {
    let private_key =
        RsaPrivateKey::generate(2048 / 8).expect("Failed to generate RSA private key");
    let public_key = private_key
        .public_key()
        .expect("Failed to get RSA public key");

    let plaintext = b"OAEP label mismatch should fail";

    let hash = HashAlgo::sha256();
    // Encrypt with label "label-a"
    let mut algo_a = RsaEncryptAlgo::with_oaep_padding(hash.clone(), Some(b"label-a"));

    let cipher_size =
        Encrypter::encrypt(&mut algo_a, &public_key, plaintext, None).expect("Encryption failed");
    let mut ciphertext = vec![0u8; cipher_size];
    assert_eq!(
        Encrypter::encrypt(&mut algo_a, &public_key, plaintext, Some(&mut ciphertext)),
        Ok(cipher_size)
    );
    // Attempt to decrypt with label "label-b"
    let mut algo_b = RsaEncryptAlgo::with_oaep_padding(hash.clone(), Some(b"label-a"));
    // decrypt_len can succeed even when decrypt fails.
    let plain_size = Decrypter::decrypt(&mut algo_b, &private_key, &ciphertext, None)
        .expect("decrypt_len should succeed");
    let mut out = vec![0u8; plain_size];
    let mut algo_b = RsaEncryptAlgo::with_oaep_padding(hash.clone(), Some(b"label-b"));
    assert!(Decrypter::decrypt(&mut algo_b, &private_key, &ciphertext, Some(&mut out)).is_err());
}

// encrypt decrypt zero-length message
#[test]
fn test_rsa_2048_encrypt_decrypt_oaep_sha256_zero_length_message() {
    rsa_oaep_roundtrip(2048 / 8, &HashAlgo::sha256(), None, b"");
}
