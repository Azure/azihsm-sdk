// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::*;

fn roundtrip(key_size_bytes: usize, plaintext_prefix: &[u8]) {
    let private_key =
        RsaPrivateKey::generate(key_size_bytes).expect("Failed to generate RSA private key");
    let public_key = private_key
        .public_key()
        .expect("Failed to get RSA public key");

    let mut algo = RsaEncryptAlgo::with_no_padding();

    // With no padding, the input must be exactly the modulus size.
    // For a stable roundtrip assertion, we build an input buffer exactly key_size_bytes.
    let mut padded_plaintext = vec![0u8; key_size_bytes];
    padded_plaintext[..plaintext_prefix.len()].copy_from_slice(plaintext_prefix);

    let cipher_size = Encrypter::encrypt(&mut algo, &public_key, &padded_plaintext, None)
        .expect("Encryption failed");
    assert_eq!(cipher_size, key_size_bytes);

    let mut ciphertext = vec![0u8; cipher_size];
    assert_eq!(
        Encrypter::encrypt(
            &mut algo,
            &public_key,
            &padded_plaintext,
            Some(&mut ciphertext)
        ),
        Ok(cipher_size)
    );

    let plain_size =
        Decrypter::decrypt(&mut algo, &private_key, &ciphertext, None).expect("Decryption failed");
    assert_eq!(plain_size, key_size_bytes);

    let mut decrypted_plaintext = vec![0u8; plain_size];
    assert_eq!(
        Decrypter::decrypt(
            &mut algo,
            &private_key,
            &ciphertext,
            Some(&mut decrypted_plaintext)
        ),
        Ok(plain_size)
    );

    assert_eq!(&decrypted_plaintext, &padded_plaintext);
}

fn enc_oversize_fails(key_size_bytes: usize) {
    let private_key =
        RsaPrivateKey::generate(key_size_bytes).expect("Failed to generate RSA private key");
    let public_key = private_key
        .public_key()
        .expect("Failed to get RSA public key");

    let mut algo = RsaEncryptAlgo::with_no_padding();

    // Oversized plaintext (k+1) must not be encryptable.
    let plaintext = vec![0xA5u8; key_size_bytes + 1];

    let mut ciphertext = vec![0u8; key_size_bytes + 1];
    assert!(
        Encrypter::encrypt(&mut algo, &public_key, &plaintext, Some(&mut ciphertext)).is_err(),
        "expected encryption to fail for plaintext longer than modulus size"
    );
}

// fn dec_bad_len_fails(key_size_bytes: usize) {
//     let private_key =
//         RsaPrivateKey::generate(key_size_bytes).expect("Failed to generate RSA private key");
//     let public_key = private_key
//         .public_key()
//         .expect("Failed to get RSA public key");
//     let mut algo = RsaEncryption::new();

//     // Start from a valid ciphertext.
//     let plaintext = vec![0x3Cu8; key_size_bytes];
//     let cipher_size =
//         Encrypter::encrypt(&mut algo, &public_key, &plaintext, None).expect("encrypt_len failed");
//     assert_eq!(cipher_size, key_size_bytes);
//     let mut ciphertext = vec![0u8; cipher_size];
//     Encrypter::encrypt(&mut algo, &public_key, &plaintext, Some(&mut ciphertext))
//         .expect("encrypt failed");

//     // Truncate ciphertext by 1 byte and attempt decrypt.
//     // RSA NO-PADDING commonly accepts ciphertext shorter than modulus size.
//     let truncated = &ciphertext[..ciphertext.len() - 1];
//     let plain_size = Decrypter::decrypt(&mut algo, &private_key, truncated, None)
//         .expect("decrypt_len failed for truncated ciphertext");
//     let mut out = vec![0u8; plain_size];
//     let written = Decrypter::decrypt(&mut algo, &private_key, truncated, Some(&mut out))
//         .expect("truncated ciphertext unexpectedly failed to decrypt");
//     assert_eq!(written, plain_size);
//     assert_ne!(
//         &out[..written],
//         &plaintext[..written],
//         "truncated ciphertext unexpectedly decrypted to original plaintext"
//     );

//     // Ciphertext longer than modulus size should fail.
//     let mut long_ciphertext = ciphertext;
//     long_ciphertext.push(0);
//     let mut out2 = vec![0u8; key_size_bytes];
//     assert!(
//         Decrypter::decrypt(&mut algo, &private_key, &long_ciphertext, Some(&mut out2)).is_err(),
//         "expected decryption to fail for ciphertext longer than modulus size"
//     );
// }

// Validates a full encrypt/decrypt roundtrip with RSA no-padding for a 2048-bit key.
// The plaintext is pre-sized to the modulus to satisfy no-padding input requirements.
#[test]
fn test_rsa_2048_no_pad_roundtrip() {
    roundtrip(2048 / 8, b"Test message for RSA encryption with no padding");
}

// Ensures RSA no-padding rejects plaintext longer than the modulus (k+1 bytes).
#[test]
fn test_rsa_2048_no_pad_enc_oversize_fails() {
    enc_oversize_fails(2048 / 8);
}

// Exercises ciphertext length edge cases for RSA no-padding on 2048-bit keys.
// Shorter-than-modulus may decrypt; longer-than-modulus must fail.
// #[test]
// fn test_rsa_2048_no_pad_dec_bad_len_fails() {
//     dec_bad_len_fails(2048 / 8);
// }

// Validates a full encrypt/decrypt roundtrip with RSA no-padding for a 3072-bit key.
#[test]
fn test_rsa_3072_no_pad_roundtrip() {
    roundtrip(
        3072 / 8,
        b"Test message for RSA encryption with no padding (3072)",
    );
}

// Ensures RSA no-padding rejects oversized plaintext for a 3072-bit modulus.
#[test]
fn test_rsa_3072_no_pad_enc_oversize_fails() {
    enc_oversize_fails(3072 / 8);
}

// Exercises ciphertext length edge cases for RSA no-padding on 3072-bit keys.
// #[test]
// fn test_rsa_3072_no_pad_dec_bad_len_fails() {
//     dec_bad_len_fails(3072 / 8);
// }

// Validates a full encrypt/decrypt roundtrip with RSA no-padding for a 4096-bit key.
#[test]
fn test_rsa_4096_no_pad_roundtrip() {
    roundtrip(
        4096 / 8,
        b"Test message for RSA encryption with no padding (4096)",
    );
}

// Ensures RSA no-padding rejects oversized plaintext for a 4096-bit modulus.
#[test]
fn test_rsa_4096_no_pad_enc_oversize_fails() {
    enc_oversize_fails(4096 / 8);
}

// Exercises ciphertext length edge cases for RSA no-padding on 4096-bit keys.
// #[test]
// fn test_rsa_4096_no_pad_dec_bad_len_fails() {
//     dec_bad_len_fails(4096 / 8);
// }

// Validates RSA no-padding behavior against fixed raw RSA test vectors.
// Supported key sizes must match exactly; unsupported sizes must be rejected at import.
#[test]
fn test_rsa_no_pad_raw_testvectors() {
    for vector in RSA_NO_PADDING_TEST_VECTORS {
        let modulus_size = vector.plaintext.len();

        assert_eq!(
            vector.plaintext.len(),
            vector.ciphertext.len(),
            "vector {}: plaintext/ciphertext length mismatch",
            vector.name
        );

        match <RsaPrivateKey as ImportableKey>::from_bytes(vector.priv_der) {
            Ok(private_key) => {
                assert!(
                    is_supported_rsa_modulus_size_bytes(modulus_size),
                    "vector {} imported a key with unsupported modulus size {}",
                    vector.name,
                    modulus_size
                );

                assert_raw_rsa_vector_ok(vector, &private_key);
            }
            Err(CryptoError::EccInvalidKeySize) => {
                assert!(
                    !is_supported_rsa_modulus_size_bytes(modulus_size),
                    "vector {} has supported modulus size {} but key import rejected it",
                    vector.name,
                    modulus_size
                );
            }
            Err(err) => {
                panic!(
                    "vector {}: unexpected key import error for modulus size {}: {:?}",
                    vector.name, modulus_size, err
                );
            }
        }
    }
}

fn assert_raw_rsa_vector_ok(vector: &RsaEncTestVector, private_key: &RsaPrivateKey) {
    let public_key = private_key
        .public_key()
        .unwrap_or_else(|_| panic!("failed to derive RSA public key for vector {}", vector.name));

    let mut algo = RsaEncryptAlgo::with_no_padding();

    // Raw RSA encryption is deterministic; ciphertext should match exactly.
    let cipher_size = Encrypter::encrypt(&mut algo, &public_key, vector.plaintext, None)
        .unwrap_or_else(|_| panic!("vector {}: encrypt_len failed", vector.name));
    assert_eq!(
        cipher_size,
        vector.ciphertext.len(),
        "vector {}: unexpected ciphertext size",
        vector.name
    );

    let mut ciphertext = vec![0u8; cipher_size];
    let written = Encrypter::encrypt(
        &mut algo,
        &public_key,
        vector.plaintext,
        Some(&mut ciphertext),
    )
    .unwrap_or_else(|_| panic!("vector {}: encrypt failed", vector.name));
    assert_eq!(
        written, cipher_size,
        "vector {}: short encrypt",
        vector.name
    );
    assert_eq!(
        &ciphertext, vector.ciphertext,
        "vector {}: ciphertext mismatch",
        vector.name
    );

    // And decryption should recover the exact, key-sized plaintext.
    let plain_size = Decrypter::decrypt(&mut algo, private_key, vector.ciphertext, None)
        .unwrap_or_else(|_| panic!("vector {}: decrypt_len failed", vector.name));
    assert_eq!(
        plain_size,
        vector.plaintext.len(),
        "vector {}: unexpected plaintext size",
        vector.name
    );
    let mut plaintext = vec![0u8; plain_size];
    let written = Decrypter::decrypt(
        &mut algo,
        private_key,
        vector.ciphertext,
        Some(&mut plaintext),
    )
    .unwrap_or_else(|_| panic!("vector {}: decrypt failed", vector.name));
    assert_eq!(written, plain_size, "vector {}: short decrypt", vector.name);
    assert_eq!(
        &plaintext, vector.plaintext,
        "vector {}: plaintext mismatch",
        vector.name
    );
}
