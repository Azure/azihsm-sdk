// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn test_rsa_kw_basic_wrap_unwrap() {
    // Generate RSA key pair (256 bytes = 2048 bits)
    let private_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let public_key = private_key
        .public_key()
        .expect("Failed to derive public key");

    // Create a test AES key to wrap
    let target_key = AesKey::generate(32).expect("Failed to generate target key");

    // Create hash algorithm and wrapper
    let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), 32);

    // Query the required buffer size
    let wrapped_len = wrapper
        .wrap_key(&public_key, &target_key, None)
        .expect("Failed to get wrapped key length");

    assert!(wrapped_len > 0, "Wrapped key length should be non-zero");

    // Perform the actual wrapping
    let mut wrapped_key = vec![0u8; wrapped_len];
    let actual_wrapped_len = wrapper
        .wrap_key(&public_key, &target_key, Some(&mut wrapped_key))
        .expect("Failed to wrap key");

    assert_eq!(
        wrapped_len, actual_wrapped_len,
        "Wrapped length should match queried length"
    );

    // Unwrap the key
    let unwrapped_key: AesKey = wrapper
        .unwrap_key::<AesKey>(&private_key, &wrapped_key[..actual_wrapped_len])
        .expect("Failed to unwrap key");

    // Verify the keys match by comparing their byte representations
    let original_bytes = target_key.to_vec().expect("Failed to export original key");
    let unwrapped_bytes = unwrapped_key
        .to_vec()
        .expect("Failed to export unwrapped key");

    assert_eq!(
        original_bytes, unwrapped_bytes,
        "Unwrapped key should match original key"
    );
}

#[test]
fn test_rsa_kw_different_aes_key_sizes() {
    let private_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let public_key = private_key
        .public_key()
        .expect("Failed to derive public key");
    let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), 32);
    // Test with different AES key sizes (128, 192, 256 bits)
    for key_size in [16, 24, 32] {
        let target_key = AesKey::generate(key_size).expect("Failed to generate target key");

        let wrapped_len = wrapper
            .wrap_key(&public_key, &target_key, None)
            .expect("Failed to get wrapped key length");

        let mut wrapped_key = vec![0u8; wrapped_len];
        let actual_wrapped_len = wrapper
            .wrap_key(&public_key, &target_key, Some(&mut wrapped_key))
            .expect("Failed to wrap key");

        let unwrapped_key: AesKey = wrapper
            .unwrap_key::<AesKey>(&private_key, &wrapped_key[..actual_wrapped_len])
            .expect("Failed to unwrap key");

        let original_bytes = target_key.to_vec().expect("Failed to export original key");
        let unwrapped_bytes = unwrapped_key
            .to_vec()
            .expect("Failed to export unwrapped key");

        assert_eq!(
            original_bytes, unwrapped_bytes,
            "Unwrapped key should match original for size {}",
            key_size
        );
    }
}

#[test]
fn test_rsa_kw_different_kek_sizes() {
    let private_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let public_key = private_key
        .public_key()
        .expect("Failed to derive public key");
    let target_key = AesKey::generate(32).expect("Failed to generate target key");
    // Test with different KEK sizes (128, 192, 256 bits)
    for kek_size in [16, 24, 32] {
        let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), kek_size);

        let wrapped_len = wrapper
            .wrap_key(&public_key, &target_key, None)
            .expect("Failed to get wrapped key length");

        let mut wrapped_key = vec![0u8; wrapped_len];
        let actual_wrapped_len = wrapper
            .wrap_key(&public_key, &target_key, Some(&mut wrapped_key))
            .expect("Failed to wrap key");

        let unwrapped_key: AesKey = wrapper
            .unwrap_key::<AesKey>(&private_key, &wrapped_key[..actual_wrapped_len])
            .expect("Failed to unwrap key");

        let original_bytes = target_key.to_vec().expect("Failed to export original key");
        let unwrapped_bytes = unwrapped_key
            .to_vec()
            .expect("Failed to export unwrapped key");

        assert_eq!(
            original_bytes, unwrapped_bytes,
            "Unwrapped key should match original for KEK size {}",
            kek_size
        );
    }
}

#[test]
fn test_rsa_kw_different_hash_algorithms() {
    let private_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let public_key = private_key
        .public_key()
        .expect("Failed to derive public key");
    let target_key = AesKey::generate(32).expect("Failed to generate target key");

    // Test with different hash algorithms
    for hash_algo in [HashAlgo::sha256(), HashAlgo::sha384(), HashAlgo::sha512()] {
        let mut wrapper = RsaAesKeyWrap::new(hash_algo.clone(), 32);

        let wrapped_len = wrapper
            .wrap_key(&public_key, &target_key, None)
            .expect("Failed to get wrapped key length");

        let mut wrapped_key = vec![0u8; wrapped_len];
        let actual_wrapped_len = wrapper
            .wrap_key(&public_key, &target_key, Some(&mut wrapped_key))
            .expect("Failed to wrap key");

        let unwrapped_key: AesKey = wrapper
            .unwrap_key::<AesKey>(&private_key, &wrapped_key[..actual_wrapped_len])
            .expect("Failed to unwrap key");

        let original_bytes = target_key.to_vec().expect("Failed to export original key");
        let unwrapped_bytes = unwrapped_key
            .to_vec()
            .expect("Failed to export unwrapped key");

        assert_eq!(
            original_bytes,
            unwrapped_bytes,
            "Unwrapped key should match original for hash algorithm {:?}",
            hash_algo.size()
        );
    }
}

#[test]
fn test_rsa_kw_different_rsa_key_sizes() {
    let target_key = AesKey::generate(32).expect("Failed to generate target key");
    let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), 32);
    // Test with different RSA key sizes (2048, 3072, 4096 bits)
    for rsa_size in [256, 384, 512] {
        let private_key = RsaPrivateKey::generate(rsa_size).expect("Failed to generate RSA key");
        let public_key = private_key
            .public_key()
            .expect("Failed to derive public key");

        let wrapped_len = wrapper
            .wrap_key(&public_key, &target_key, None)
            .expect("Failed to get wrapped key length");

        let mut wrapped_key = vec![0u8; wrapped_len];
        let actual_wrapped_len = wrapper
            .wrap_key(&public_key, &target_key, Some(&mut wrapped_key))
            .expect("Failed to wrap key");

        let unwrapped_key: AesKey = wrapper
            .unwrap_key::<AesKey>(&private_key, &wrapped_key[..actual_wrapped_len])
            .expect("Failed to unwrap key");

        let original_bytes = target_key.to_vec().expect("Failed to export original key");
        let unwrapped_bytes = unwrapped_key
            .to_vec()
            .expect("Failed to export unwrapped key");

        assert_eq!(
            original_bytes, unwrapped_bytes,
            "Unwrapped key should match original for RSA size {}",
            rsa_size
        );
    }
}

#[test]
fn test_rsa_kw_corrupted_data_fails() {
    let private_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let public_key = private_key
        .public_key()
        .expect("Failed to derive public key");
    let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), 32);
    let target_key = AesKey::generate(32).expect("Failed to generate target key");

    let wrapped_len = wrapper
        .wrap_key(&public_key, &target_key, None)
        .expect("Failed to get wrapped key length");

    let mut wrapped_key = vec![0u8; wrapped_len];
    let actual_wrapped_len = wrapper
        .wrap_key(&public_key, &target_key, Some(&mut wrapped_key))
        .expect("Failed to wrap key");

    // Corrupt the wrapped key data (flip a byte in the middle)
    wrapped_key[actual_wrapped_len / 2] ^= 0xFF;

    // Attempt to unwrap should fail
    let result = wrapper.unwrap_key::<AesKey>(&private_key, &wrapped_key[..actual_wrapped_len]);

    assert!(result.is_err(), "Unwrapping corrupted data should fail");
}

#[test]
fn test_rsa_kw_wrong_private_key_fails() {
    let private_key1 = RsaPrivateKey::generate(256).expect("Failed to generate RSA key 1");
    let public_key1 = private_key1
        .public_key()
        .expect("Failed to derive public key 1");

    let private_key2 = RsaPrivateKey::generate(256).expect("Failed to generate RSA key 2");

    let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), 32);
    let target_key = AesKey::generate(32).expect("Failed to generate target key");

    let wrapped_len = wrapper
        .wrap_key(&public_key1, &target_key, None)
        .expect("Failed to get wrapped key length");

    let mut wrapped_key = vec![0u8; wrapped_len];
    let actual_wrapped_len = wrapper
        .wrap_key(&public_key1, &target_key, Some(&mut wrapped_key))
        .expect("Failed to wrap key");

    // Try to unwrap with wrong private key
    let result = wrapper.unwrap_key::<AesKey>(&private_key2, &wrapped_key[..actual_wrapped_len]);

    assert!(
        result.is_err(),
        "Unwrapping with wrong private key should fail"
    );
}

#[test]
fn test_rsa_kw_truncated_data_fails() {
    let private_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let public_key = private_key
        .public_key()
        .expect("Failed to derive public key");
    let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), 32);
    let target_key = AesKey::generate(32).expect("Failed to generate target key");

    let wrapped_len = wrapper
        .wrap_key(&public_key, &target_key, None)
        .expect("Failed to get wrapped key length");

    let mut wrapped_key = vec![0u8; wrapped_len];
    let actual_wrapped_len = wrapper
        .wrap_key(&public_key, &target_key, Some(&mut wrapped_key))
        .expect("Failed to wrap key");

    // Try to unwrap with truncated data
    let truncated_len = actual_wrapped_len / 2;
    let result = wrapper.unwrap_key::<AesKey>(&private_key, &wrapped_key[..truncated_len]);

    assert!(result.is_err(), "Unwrapping truncated data should fail");
}

#[test]
fn test_rsa_kw_buffer_too_small_fails() {
    let private_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let public_key = private_key
        .public_key()
        .expect("Failed to derive public key");
    let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), 32);
    let target_key = AesKey::generate(32).expect("Failed to generate target key");

    let wrapped_len = wrapper
        .wrap_key(&public_key, &target_key, None)
        .expect("Failed to get wrapped key length");

    // Try to wrap with buffer that's too small
    let mut small_buffer = vec![0u8; wrapped_len / 2];
    let result = wrapper.wrap_key(&public_key, &target_key, Some(&mut small_buffer));

    assert!(result.is_err(), "Wrapping with small buffer should fail");
}
