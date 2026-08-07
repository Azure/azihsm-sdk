// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto as crypto;
use crypto::*;

use super::*;
// ================================
// Helper functions
// ================================

// Private RSA representation requested for the imported key.
// The public half of both key-pair forms remains `HsmKeyKind::Rsa`.
#[derive(Clone, Copy, Debug)]
enum RsaPrivateKeyKind {
    Rsa,
    RsaCrt,
}

impl RsaPrivateKeyKind {
    fn hsm_kind(self) -> HsmKeyKind {
        match self {
            Self::Rsa => HsmKeyKind::Rsa,
            Self::RsaCrt => HsmKeyKind::RsaCrt,
        }
    }
}

/// Helper to unwrap RSA key and validate properties for a given key size
fn test_unwrap_rsa_key_for_bits(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    // Generate RSA key using azihsm_crypto
    let priv_key =
        crypto::RsaPrivateKey::generate(key_size_bytes).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    // Get unwrapping key pair
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    // Wrap the generated key
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA Key");

    // Define properties for the unwrapped key
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(bits)
        .can_decrypt(true)
        .build()
        .expect("Failed to build unwrapping key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    // Unwrap the key pair
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap requested RSA key form");

    // Verify private key properties
    assert_eq!(
        priv_key.class(),
        HsmKeyClass::Private,
        "Private key class mismatch"
    );
    assert_eq!(
        priv_key.kind(),
        private_kind.hsm_kind(),
        "Private key kind mismatch"
    );
    assert_eq!(priv_key.bits(), bits, "Private key bits mismatch");
    assert!(
        !priv_key.is_local(),
        "Unwrapped private key should not be local"
    );
    assert!(
        !priv_key.is_session(),
        "Unwrapped private key should not be a session key"
    );
    assert!(
        priv_key.is_sensitive(),
        "Unwrapped RSA private key should be sensitive"
    );
    assert!(
        priv_key.is_extractable(),
        "Unwrapped RSA keys should be extractable"
    );
    assert!(
        priv_key.can_decrypt(),
        "Private key should support decryption"
    );
    assert!(
        !priv_key.can_sign(),
        "Private key should not support signing"
    );
    assert!(
        !priv_key.can_unwrap(),
        "Private key should not support unwrapping"
    );
    assert!(
        priv_key.ecc_curve().is_none(),
        "RSA key should not have ECC curve"
    );

    // Verify public key properties
    assert_eq!(
        pub_key.class(),
        HsmKeyClass::Public,
        "Public key class mismatch"
    );
    assert_eq!(pub_key.kind(), HsmKeyKind::Rsa, "Public key kind mismatch");
    assert_eq!(pub_key.bits(), bits, "Public key bits mismatch");
    assert!(
        !pub_key.is_local(),
        "Unwrapped public key should not be local"
    );
    assert!(
        !pub_key.is_session(),
        "Unwrapped public key should not be a session key"
    );
    assert!(
        !pub_key.is_sensitive(),
        "Public key should not be sensitive"
    );
    assert!(pub_key.is_extractable(), "Keys are always extractable");
    assert!(
        pub_key.can_encrypt(),
        "Public key should support encryption"
    );
    assert!(
        !pub_key.can_verify(),
        "Public key should not support verification"
    );
    assert!(
        !pub_key.can_wrap(),
        "Public key should not support wrapping"
    );
    assert!(
        pub_key.ecc_curve().is_none(),
        "RSA key should not have ECC curve"
    );

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete RSA private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete RSA public key");
}

/// Helper to compare all private key properties between original and unmasked keys
fn compare_rsa_private_key_properties(original: &HsmRsaPrivateKey, unmasked: &HsmRsaPrivateKey) {
    assert_eq!(
        original.class(),
        unmasked.class(),
        "Private key class mismatch"
    );
    assert_eq!(
        original.kind(),
        unmasked.kind(),
        "Private key kind mismatch"
    );
    assert_eq!(
        original.bits(),
        unmasked.bits(),
        "Private key bits mismatch"
    );
    assert_eq!(
        original.can_sign(),
        unmasked.can_sign(),
        "Private key sign capability mismatch"
    );
    assert_eq!(
        original.can_verify(),
        unmasked.can_verify(),
        "Private key verify capability mismatch"
    );
    assert_eq!(
        original.can_encrypt(),
        unmasked.can_encrypt(),
        "Private key encrypt capability mismatch"
    );
    assert_eq!(
        original.can_decrypt(),
        unmasked.can_decrypt(),
        "Private key decrypt capability mismatch"
    );
    assert_eq!(
        original.can_wrap(),
        unmasked.can_wrap(),
        "Private key wrap capability mismatch"
    );
    assert_eq!(
        original.can_unwrap(),
        unmasked.can_unwrap(),
        "Private key unwrap capability mismatch"
    );
    assert_eq!(
        original.can_derive(),
        unmasked.can_derive(),
        "Private key derive capability mismatch"
    );
    assert_eq!(
        original.is_session(),
        unmasked.is_session(),
        "Private key session flag mismatch"
    );
    assert_eq!(
        original.is_local(),
        unmasked.is_local(),
        "Private key local flag mismatch"
    );
    assert_eq!(
        original.is_sensitive(),
        unmasked.is_sensitive(),
        "Private key sensitive flag mismatch"
    );
    assert_eq!(
        original.is_extractable(),
        unmasked.is_extractable(),
        "Private key extractable flag mismatch"
    );
}

/// Helper to compare all public key properties between original and unmasked keys
fn compare_rsa_public_key_properties(original: &HsmRsaPublicKey, unmasked: &HsmRsaPublicKey) {
    assert_eq!(
        original.class(),
        unmasked.class(),
        "Public key class mismatch"
    );
    assert_eq!(original.kind(), unmasked.kind(), "Public key kind mismatch");
    assert_eq!(original.bits(), unmasked.bits(), "Public key bits mismatch");
    assert_eq!(
        original.can_sign(),
        unmasked.can_sign(),
        "Public key sign capability mismatch"
    );
    assert_eq!(
        original.can_verify(),
        unmasked.can_verify(),
        "Public key verify capability mismatch"
    );
    assert_eq!(
        original.can_encrypt(),
        unmasked.can_encrypt(),
        "Public key encrypt capability mismatch"
    );
    assert_eq!(
        original.can_decrypt(),
        unmasked.can_decrypt(),
        "Public key decrypt capability mismatch"
    );
    assert_eq!(
        original.can_wrap(),
        unmasked.can_wrap(),
        "Public key wrap capability mismatch"
    );
    assert_eq!(
        original.can_unwrap(),
        unmasked.can_unwrap(),
        "Public key unwrap capability mismatch"
    );
    assert_eq!(
        original.can_derive(),
        unmasked.can_derive(),
        "Public key derive capability mismatch"
    );
    assert_eq!(
        original.is_session(),
        unmasked.is_session(),
        "Public key session flag mismatch"
    );
    assert_eq!(
        original.is_local(),
        unmasked.is_local(),
        "Public key local flag mismatch"
    );
    assert_eq!(
        original.is_sensitive(),
        unmasked.is_sensitive(),
        "Public key sensitive flag mismatch"
    );
    assert_eq!(
        original.is_extractable(),
        unmasked.is_extractable(),
        "Public key extractable flag mismatch"
    );
}

/// Helper function to test RSA key pair unmasking.
/// Since the device only supports generating unwrapping keys for RSA, this test:
/// 1. Generates a crypto RSA key and unwraps it into the HSM
/// 2. Extracts the masked_key_vec from the unwrapped key
/// 3. Unmasks it using unmask_key_pair
/// 4. Verifies all properties match between the unwrapped and unmasked keys
fn test_rsa_key_unmask_for_bits(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    // Generate RSA key using azihsm_crypto
    let crypto_priv_key =
        crypto::RsaPrivateKey::generate(key_size_bytes).expect("Failed to generate RSA Key");
    let der = crypto_priv_key.to_vec().expect("Failed to export RSA Key");

    // Get unwrapping key pair for wrapping/unwrapping
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    // Wrap the generated key
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA Key");

    // Define properties for the unwrapped key
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(bits)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    // Unwrap the key pair into HSM
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (original_priv_key, original_pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap requested RSA key form");

    // Get the masked key from the unwrapped private key
    let masked_key_pair = original_priv_key
        .masked_key_vec()
        .expect("Failed to get masked private key");

    // Unmask the key pair
    let mut unmask_algo = HsmRsaKeyUnmaskAlgo::default();
    let (unmasked_priv_key, unmasked_pub_key) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, &masked_key_pair)
            .expect("Failed to unmask RSA key pair");

    // Verify all properties match between original (unwrapped) and unmasked keys
    compare_rsa_private_key_properties(&original_priv_key, &unmasked_priv_key);
    compare_rsa_public_key_properties(&original_pub_key, &unmasked_pub_key);

    HsmKeyManager::delete_key(original_priv_key).expect("Failed to delete original private key");
    HsmKeyManager::delete_key(original_pub_key).expect("Failed to delete original public key");
    HsmKeyManager::delete_key(unmasked_priv_key).expect("Failed to delete unmasked private key");
    HsmKeyManager::delete_key(unmasked_pub_key).expect("Failed to delete unmasked public key");
}

/// Helper to validate RSA unwrap functional correctness via encrypt/decrypt roundtrip
fn run_rsa_functional_test(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    let crypto_priv_key = RsaPrivateKey::generate(key_size_bytes).unwrap();
    let der = crypto_priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(bits)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .unwrap();

    let msg = b"rsa functional";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let ct = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, msg).unwrap();
    let pt = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ct).unwrap();

    assert_eq!(pt, msg);

    HsmKeyManager::delete_key(priv_key).unwrap();
    HsmKeyManager::delete_key(pub_key).unwrap();
}

/// Helper to verify repeated unwrap produces usable (not necessarily identical) keys
fn run_rsa_repeatability_test(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    let crypto_priv_key = RsaPrivateKey::generate(key_size_bytes).unwrap();
    let der = crypto_priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(bits)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let (k1_priv, k1_pub) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props.clone(),
        pub_props.clone(),
    )
    .unwrap();

    let (k2_priv, k2_pub) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .unwrap();

    let msg = b"repeatability";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let ct1 = HsmEncrypter::encrypt_vec(&mut algo, &k1_pub, msg).unwrap();
    let pt1 = HsmDecrypter::decrypt_vec(&mut algo, &k1_priv, &ct1).unwrap();

    let ct2 = HsmEncrypter::encrypt_vec(&mut algo, &k2_pub, msg).unwrap();
    let pt2 = HsmDecrypter::decrypt_vec(&mut algo, &k2_priv, &ct2).unwrap();

    assert_eq!(pt1, msg);
    assert_eq!(pt2, msg);

    HsmKeyManager::delete_key(k1_priv).unwrap();
    HsmKeyManager::delete_key(k1_pub).unwrap();
    HsmKeyManager::delete_key(k2_priv).unwrap();
    HsmKeyManager::delete_key(k2_pub).unwrap();
}

/// Helper to verify truncated wrapped key fails during unwrap
fn run_rsa_truncated_ciphertext_test(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    let priv_key = RsaPrivateKey::generate(key_size_bytes).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    wrapped.truncate(wrapped.len() / 2);

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(bits)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(
        matches!(result, Err(HsmError::DdiCmdFailure)),
        "Truncated ciphertext should fail"
    );
}

/// Generates DER-encoded RSA private key of given byte size.
fn generate_rsa_der(bytes: usize) -> Vec<u8> {
    let key = crypto::RsaPrivateKey::generate(bytes).expect("Failed to generate RSA key");
    key.to_vec().expect("Failed to export RSA key")
}

/// Wraps a DER-encoded RSA key using a freshly generated unwrapping key pair.
fn wrap_rsa_key(session: &HsmSession, der: &[u8], salt_len: usize) -> (HsmRsaPrivateKey, Vec<u8>) {
    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, der)
        .expect("Failed to wrap RSA key");

    (unwrap_priv, wrapped)
}

/// Generate an RSA key, wrap/unwrap it into the HSM, and return its masked private key blob
fn get_rsa_masked_blob(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
) -> (Vec<u8>, HsmRsaPrivateKey) {
    // Step 1: generate external RSA key
    let crypto_priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let der = crypto_priv_key.to_vec().expect("Failed to export RSA key");

    // Step 2: get unwrapping key pair
    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);

    // Step 3: wrap
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der)
        .expect("Failed to wrap RSA key");

    // Step 4: session key props (important!)
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(2048)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    // Step 5: unwrap
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, _) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .expect("Failed to unwrap RSA key");

    // Step 6: extract masked blob
    let masked = priv_key.masked_key_vec().expect("Failed to get masked key");

    (masked, priv_key)
}

/// Verify roundtrip works between original and unmasked key pair
fn run_rsa_unmask_roundtrip_test(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    // generate RSA key and wrap/unwrap
    let crypto_priv_key = RsaPrivateKey::generate(key_size_bytes).unwrap();
    let der = crypto_priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(bits)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let (orig_priv, orig_pub) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .unwrap();

    //  mask + unmask
    let masked = orig_priv.masked_key_vec().unwrap();

    let mut unmask_algo = HsmRsaKeyUnmaskAlgo::default();
    let (unmasked_priv, unmasked_pub) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, &masked).unwrap();

    // roundtrip test
    let msg = b"unmask roundtrip";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    // Encrypt with ORIGINAL pub → decrypt with UNMASKED priv
    let ct = HsmEncrypter::encrypt_vec(&mut algo, &orig_pub, msg).unwrap();
    let pt = HsmDecrypter::decrypt_vec(&mut algo, &unmasked_priv, &ct).unwrap();
    assert_eq!(pt, msg);

    // Encrypt with UNMASKED pub → decrypt with ORIGINAL priv
    let ct2 = HsmEncrypter::encrypt_vec(&mut algo, &unmasked_pub, msg).unwrap();
    let pt2 = HsmDecrypter::decrypt_vec(&mut algo, &orig_priv, &ct2).unwrap();
    assert_eq!(pt2, msg);

    // Cleanup
    HsmKeyManager::delete_key(orig_priv).unwrap();
    HsmKeyManager::delete_key(orig_pub).unwrap();
    HsmKeyManager::delete_key(unmasked_priv).unwrap();
    HsmKeyManager::delete_key(unmasked_pub).unwrap();
}

fn try_import_rsa_key(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
    private_kind: RsaPrivateKeyKind,
) -> Result<(HsmRsaPrivateKey, HsmRsaPublicKey), HsmError> {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(bits)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let hash_algo = HsmHashAlgo::Sha384;
    let salt_size = 32;

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash_algo, salt_size);

    match HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, der) {
        Ok(wrapped_key) => {
            let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(hash_algo);

            unwrap_algo.unwrap_key_pair(
                &unwrapping_priv_key,
                &wrapped_key,
                priv_key_props,
                pub_key_props,
            )
        }
        Err(err) => Err(err),
    }
}

/// Returns the signing hash used for the requested RSA modulus size.
fn rsa_sign_hash_for_bits(bits: u32) -> HsmHashAlgo {
    match bits {
        2048 => HsmHashAlgo::Sha256,
        3072 => HsmHashAlgo::Sha384,
        4096 => HsmHashAlgo::Sha512,
        _ => panic!("Unsupported RSA key size: {bits}"),
    }
}

/// Imports an RSA/RSA-CRT key pair configured for signing and verification.
fn import_rsa_signing_key(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
    bits: u32,
    key_size_bytes: usize,
    is_session: bool,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let crypto_priv_key =
        crypto::RsaPrivateKey::generate(key_size_bytes).expect("Failed to generate RSA key");
    let der = crypto_priv_key.to_vec().expect("Failed to export RSA key");

    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    let hash_algo = HsmHashAlgo::Sha256;
    let salt_len = match bits {
        2048 => 32,
        3072 => 24,
        4096 => 16,
        _ => panic!("Unsupported RSA key size: {bits}"),
    };
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash_algo, salt_len);

    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA key");

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(bits)
        .can_sign(true)
        .is_session(is_session)
        .build()
        .expect("Failed to build private key props");

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_verify(true)
        .is_session(is_session)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(hash_algo);

    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_props,
        pub_props,
    )
    .expect("Failed to import RSA signing key")
}

/// Verifies an imported RSA/RSA-CRT private key can sign and its public key can verify.
fn run_rsa_sign_verify_test(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
    bits: u32,
    key_size_bytes: usize,
) {
    let (priv_key, pub_key) =
        import_rsa_signing_key(session, private_kind, bits, key_size_bytes, false);

    assert_eq!(
        priv_key.kind(),
        private_kind.hsm_kind(),
        "Private key kind mismatch"
    );
    assert_eq!(pub_key.kind(), HsmKeyKind::Rsa, "Public key kind mismatch");
    assert!(priv_key.can_sign(), "Private key should support signing");
    assert!(
        pub_key.can_verify(),
        "Public key should support verification"
    );

    let message = b"rsa crt sign verify";
    let hash_algo = rsa_sign_hash_for_bits(bits);

    let mut algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, 32);

    let signature =
        HsmSigner::sign_vec(&mut algo, &priv_key, message).expect("Failed to sign with RSA key");

    let valid = HsmVerifier::verify(&mut algo, &pub_key, message, &signature)
        .expect("Failed to verify RSA signature");

    assert!(valid, "RSA signature verification failed");

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete public key");
}

/// Verifies an RSA/RSA-CRT signing key remains usable after mask/unmask.
fn run_rsa_unmask_sign_verify_test(
    session: &HsmSession,
    private_kind: RsaPrivateKeyKind,
    bits: u32,
    key_size_bytes: usize,
) {
    let (original_priv, original_pub) =
        import_rsa_signing_key(session, private_kind, bits, key_size_bytes, true);

    let masked = original_priv
        .masked_key_vec()
        .expect("Failed to get masked private key");

    let mut unmask_algo = HsmRsaKeyUnmaskAlgo::default();

    let (unmasked_priv, unmasked_pub) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, &masked)
            .expect("Failed to unmask RSA key pair");

    assert_eq!(
        unmasked_priv.kind(),
        private_kind.hsm_kind(),
        "Private key kind changed after unmask"
    );
    assert_eq!(
        unmasked_pub.kind(),
        HsmKeyKind::Rsa,
        "Public key kind changed after unmask"
    );

    assert!(
        unmasked_priv.can_sign(),
        "Unmasked private key lost signing capability"
    );
    assert!(
        unmasked_pub.can_verify(),
        "Unmasked public key lost verification capability"
    );

    let message = b"rsa crt unmask sign verify";
    let hash_algo = rsa_sign_hash_for_bits(bits);

    let mut algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, 32);

    // Sign using the UNMASKED CRT private key.
    let signature = HsmSigner::sign_vec(&mut algo, &unmasked_priv, message)
        .expect("Failed to sign with unmasked RSA key");

    // Verify using the ORIGINAL public key.
    let valid = HsmVerifier::verify(&mut algo, &original_pub, message, &signature)
        .expect("Failed to verify signature");

    assert!(
        valid,
        "Signature from unmasked private key should verify with original public key"
    );

    // Also sign with original private key and verify with unmasked public key.
    let signature = HsmSigner::sign_vec(&mut algo, &original_priv, message)
        .expect("Failed to sign with original RSA key");

    let valid = HsmVerifier::verify(&mut algo, &unmasked_pub, message, &signature)
        .expect("Failed to verify signature");

    assert!(
        valid,
        "Signature from original private key should verify with unmasked public key"
    );

    HsmKeyManager::delete_key(original_priv).expect("Failed to delete original private key");
    HsmKeyManager::delete_key(original_pub).expect("Failed to delete original public key");
    HsmKeyManager::delete_key(unmasked_priv).expect("Failed to delete unmasked private key");
    HsmKeyManager::delete_key(unmasked_pub).expect("Failed to delete unmasked public key");
}

// ============================================================
// test case section
// ============================================================

/// Ensure RSA unwrapping key pair is generated with correct properties
#[session_test]
fn test_generate_unwrapping_key(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    // Verify private key properties
    assert_eq!(
        priv_key.class(),
        HsmKeyClass::Private,
        "Private key class mismatch"
    );
    assert_eq!(
        priv_key.kind(),
        HsmKeyKind::Rsa,
        "Private key kind mismatch"
    );
    assert_eq!(priv_key.bits(), 2048, "Private key bits mismatch");
    assert!(
        priv_key.is_local(),
        "Generated RSA private key should be local"
    );
    assert!(
        !priv_key.is_session(),
        "Private key should not be a session key"
    );
    assert!(
        priv_key.is_sensitive(),
        "Generated RSA private key should be sensitive"
    );
    assert!(
        priv_key.is_extractable(),
        "Generated RSA keys should be extractable"
    );
    assert!(
        !priv_key.can_sign(),
        "Private key should not support signing"
    );
    assert!(
        !priv_key.can_decrypt(),
        "Private key should not support decryption"
    );
    assert!(
        priv_key.can_unwrap(),
        "Private key should support unwrapping"
    );
    assert!(
        priv_key.ecc_curve().is_none(),
        "RSA key should not have ECC curve"
    );

    // Verify public key properties
    assert_eq!(
        pub_key.class(),
        HsmKeyClass::Public,
        "Public key class mismatch"
    );
    assert_eq!(pub_key.kind(), HsmKeyKind::Rsa, "Public key kind mismatch");
    assert_eq!(pub_key.bits(), 2048, "Public key bits mismatch");
    assert!(
        pub_key.is_local(),
        "Generated RSA public key should be marked as local"
    );
    assert!(
        !pub_key.is_session(),
        "Public key should not be a session key"
    );
    assert!(
        !pub_key.is_sensitive(),
        "Public key should not be sensitive"
    );
    assert!(pub_key.is_extractable(), "Keys are always extractable");
    assert!(
        !pub_key.can_verify(),
        "Public key should not support verification"
    );
    assert!(
        !pub_key.can_encrypt(),
        "Public key should not support encryption"
    );
    assert!(pub_key.can_wrap(), "Public key should support wrapping");
    assert!(
        pub_key.ecc_curve().is_none(),
        "RSA key should not have ECC curve"
    );
}

/// Ensure RSA unwrap succeeds for 2048-bit key
#[session_test]
fn test_unwrap_rsa_2048_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, RsaPrivateKeyKind::Rsa, 2048, 256, 32);
}

/// Ensure RSA unwrap succeeds for 3072-bit key
#[session_test]
fn test_unwrap_rsa_3072_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, RsaPrivateKeyKind::Rsa, 3072, 384, 24);
}

/// Ensure RSA unwrap succeeds for 4096-bit key
#[session_test]
fn test_unwrap_rsa_4096_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, RsaPrivateKeyKind::Rsa, 4096, 512, 16);
}

/// Ensure RSA unmask works correctly for 2048-bit key
#[session_test]
fn test_rsa_2048_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, RsaPrivateKeyKind::Rsa, 2048, 256, 32);
}

/// Ensure RSA unmask works correctly for 3072-bit key
#[session_test]
fn test_rsa_3072_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, RsaPrivateKeyKind::Rsa, 3072, 384, 24);
}

/// Ensure RSA unmask works correctly for 4096-bit key
#[session_test]
fn test_rsa_4096_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, RsaPrivateKeyKind::Rsa, 4096, 512, 16);
}

/// Ensure RSA CRT unwrap succeeds for 2048-bit key.
#[session_test]
fn test_unwrap_rsa_crt_2048_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, RsaPrivateKeyKind::RsaCrt, 2048, 256, 32);
}

/// Ensure RSA CRT unwrap succeeds for 3072-bit key.
#[session_test]
fn test_unwrap_rsa_crt_3072_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, RsaPrivateKeyKind::RsaCrt, 3072, 384, 24);
}

/// Ensure RSA CRT unwrap succeeds for 4096-bit key.
#[session_test]
fn test_unwrap_rsa_crt_4096_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, RsaPrivateKeyKind::RsaCrt, 4096, 512, 16);
}

/// Ensure RSA CRT unmask preserves the private key kind for 2048-bit key.
#[session_test]
fn test_rsa_crt_2048_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, RsaPrivateKeyKind::RsaCrt, 2048, 256, 32);
}

/// Ensure RSA CRT unmask preserves the private key kind for 3072-bit key.
#[session_test]
fn test_rsa_crt_3072_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, RsaPrivateKeyKind::RsaCrt, 3072, 384, 24);
}

/// Ensure RSA CRT unmask preserves the private key kind for 4096-bit key.
#[session_test]
fn test_rsa_crt_4096_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, RsaPrivateKeyKind::RsaCrt, 4096, 512, 16);
}

/// Ensure imported 2048-bit RSA CRT keys support encrypt/decrypt roundtrip.
#[session_test]
fn test_rsa_crt_functional_2048(session: HsmSession) {
    run_rsa_functional_test(&session, RsaPrivateKeyKind::RsaCrt, 2048, 256, 32);
}

/// Ensure imported 3072-bit RSA CRT keys support encrypt/decrypt roundtrip.
#[session_test]
fn test_rsa_crt_functional_3072(session: HsmSession) {
    run_rsa_functional_test(&session, RsaPrivateKeyKind::RsaCrt, 3072, 384, 24);
}

/// Ensure imported 4096-bit RSA CRT keys support encrypt/decrypt roundtrip.
#[session_test]
fn test_rsa_crt_functional_4096(session: HsmSession) {
    run_rsa_functional_test(&session, RsaPrivateKeyKind::RsaCrt, 4096, 512, 16);
}

/// Ensure the same wrapped 2048-bit key can be imported repeatedly as RSA CRT.
#[session_test]
fn test_rsa_crt_repeatability_2048(session: HsmSession) {
    run_rsa_repeatability_test(&session, RsaPrivateKeyKind::RsaCrt, 2048, 256, 32);
}

/// Ensure the same wrapped 3072-bit key can be imported repeatedly as RSA CRT.
#[session_test]
fn test_rsa_crt_repeatability_3072(session: HsmSession) {
    run_rsa_repeatability_test(&session, RsaPrivateKeyKind::RsaCrt, 3072, 384, 24);
}

/// Ensure the same wrapped 4096-bit key can be imported repeatedly as RSA CRT.
#[session_test]
fn test_rsa_crt_repeatability_4096(session: HsmSession) {
    run_rsa_repeatability_test(&session, RsaPrivateKeyKind::RsaCrt, 4096, 512, 16);
}

/// Ensure truncated wrapped input fails RSA CRT unwrap for a 2048-bit key.
#[session_test]
fn test_rsa_crt_truncated_2048(session: HsmSession) {
    run_rsa_truncated_ciphertext_test(&session, RsaPrivateKeyKind::RsaCrt, 2048, 256, 32);
}

/// Ensure truncated wrapped input fails RSA CRT unwrap for a 3072-bit key.
#[session_test]
fn test_rsa_crt_truncated_3072(session: HsmSession) {
    run_rsa_truncated_ciphertext_test(&session, RsaPrivateKeyKind::RsaCrt, 3072, 384, 24);
}

/// Ensure truncated wrapped input fails RSA CRT unwrap for a 4096-bit key.
#[session_test]
fn test_rsa_crt_truncated_4096(session: HsmSession) {
    run_rsa_truncated_ciphertext_test(&session, RsaPrivateKeyKind::RsaCrt, 4096, 512, 16);
}

/// Ensure RSA CRT masking/unmasking preserves interoperability for 2048-bit keys.
#[session_test]
fn test_rsa_crt_unmask_roundtrip_2048(session: HsmSession) {
    run_rsa_unmask_roundtrip_test(&session, RsaPrivateKeyKind::RsaCrt, 2048, 256, 32);
}

/// Ensure RSA CRT masking/unmasking preserves interoperability for 3072-bit keys.
#[session_test]
fn test_rsa_crt_unmask_roundtrip_3072(session: HsmSession) {
    run_rsa_unmask_roundtrip_test(&session, RsaPrivateKeyKind::RsaCrt, 3072, 384, 24);
}

/// Ensure RSA CRT masking/unmasking preserves interoperability for 4096-bit keys.
#[session_test]
fn test_rsa_crt_unmask_roundtrip_4096(session: HsmSession) {
    run_rsa_unmask_roundtrip_test(&session, RsaPrivateKeyKind::RsaCrt, 4096, 512, 16);
}

/// Helper to verify key report generation for an imported RSA private-key representation.
fn run_rsa_imported_key_report_test(session: &HsmSession, private_kind: RsaPrivateKeyKind) {
    let priv_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA Key");

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(2048)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap requested RSA key form");

    assert_eq!(priv_key.kind(), private_kind.hsm_kind());
    assert_eq!(pub_key.kind(), HsmKeyKind::Rsa);

    let report_data = [0x42u8; 128];
    let report_size = HsmKeyManager::generate_key_report(&priv_key, &report_data, None)
        .expect("Failed to get key report size");
    assert!(report_size > 0, "Report size should be greater than 0");

    let mut report_buffer = vec![0u8; report_size];
    let actual_size =
        HsmKeyManager::generate_key_report(&priv_key, &report_data, Some(&mut report_buffer))
            .expect("Failed to generate key report");
    report_buffer.truncate(actual_size);

    assert!(
        report_buffer.iter().any(|&b| b != 0),
        "Report should contain non-zero data"
    );

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete RSA private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete RSA public key");
}

/// Helper to verify unwrap rejects key material whose size does not match the requested properties.
fn run_rsa_wrong_bits_test(session: &HsmSession, private_kind: RsaPrivateKeyKind) {
    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(3072)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(3072)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Unwrap should fail with InvalidKeyProps for mismatched bits"
    );
}

/// Helper to verify unwrap rejects tampered wrapped key data.
fn run_rsa_tampered_ciphertext_test(session: &HsmSession, private_kind: RsaPrivateKeyKind) {
    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();
    wrapped[0] ^= 0xFF;

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(
        matches!(result, Err(HsmError::DdiCmdFailure)),
        "Unwrap should fail for tampered data"
    );
}

/// Helper to verify unwrap rejects a private key without the required capability.
fn run_rsa_missing_private_capability_test(session: &HsmSession, private_kind: RsaPrivateKeyKind) {
    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(2048)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Unwrap should fail with InvalidKeyProps when private capability is missing"
    );
}

/// Helper to verify unwrap rejects empty wrapped input.
fn run_rsa_empty_input_test(session: &HsmSession, private_kind: RsaPrivateKeyKind) {
    let (unwrap_priv, _) = get_rsa_unwrapping_key_pair(session);

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let result =
        HsmKeyManager::unwrap_key_pair(&mut unwrap_algo, &unwrap_priv, &[], priv_props, pub_props);

    assert!(
        matches!(result, Err(HsmError::DdiCmdFailure)),
        "Empty input should fail"
    );
}

/// Helper to verify unwrap rejects an invalid public-key class combination.
fn run_rsa_wrong_class_test(session: &HsmSession, private_kind: RsaPrivateKeyKind) {
    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Unwrap should fail with InvalidKeyProps for wrong class combination"
    );
}

/// Helper to verify unwrap rejects a public key without the required capability.
fn run_rsa_missing_public_capability_test(session: &HsmSession, private_kind: RsaPrivateKeyKind) {
    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Helper to verify unwrap rejects a wrap/unwrap hash mismatch.
fn run_rsa_wrong_hash_algo_test(session: &HsmSession, private_kind: RsaPrivateKeyKind) {
    let der = generate_rsa_der(256);
    let (unwrap_priv, wrapped) = wrap_rsa_key(session, &der, 32);

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha384);
    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err());
}

/// Helper to verify unwrap rejects malformed RSA DER.
fn run_rsa_invalid_der_test(session: &HsmSession, private_kind: RsaPrivateKeyKind) {
    let mut der = generate_rsa_der(256);
    der[10] ^= 0xFF;

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(private_kind.hsm_kind())
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err());
}

/// Ensure key report generation works for imported RSA key.
#[session_test]
fn test_rsa_2048_imported_key_report(session: HsmSession) {
    run_rsa_imported_key_report_test(&session, RsaPrivateKeyKind::Rsa);
}

/// Ensure key report generation works for imported RSA CRT key.
#[session_test]
fn test_rsa_crt_2048_imported_key_report(session: HsmSession) {
    run_rsa_imported_key_report_test(&session, RsaPrivateKeyKind::RsaCrt);
}

/// Ensure RSA unwrap fails when bits do not match actual key size.
#[session_test]
fn test_unwrap_rsa_wrong_bits_fails(session: HsmSession) {
    run_rsa_wrong_bits_test(&session, RsaPrivateKeyKind::Rsa);
}

/// Ensure RSA CRT unwrap fails when bits do not match actual key size.
#[session_test]
fn test_unwrap_rsa_crt_wrong_bits_fails(session: HsmSession) {
    run_rsa_wrong_bits_test(&session, RsaPrivateKeyKind::RsaCrt);
}

/// Ensure RSA unwrap fails when wrapped key is corrupted.
#[session_test]
fn test_unwrap_rsa_tampered_ciphertext(session: HsmSession) {
    run_rsa_tampered_ciphertext_test(&session, RsaPrivateKeyKind::Rsa);
}

/// Ensure RSA CRT unwrap fails when wrapped key is corrupted.
#[session_test]
fn test_unwrap_rsa_crt_tampered_ciphertext(session: HsmSession) {
    run_rsa_tampered_ciphertext_test(&session, RsaPrivateKeyKind::RsaCrt);
}

/// Ensure RSA unwrap fails if the private decrypt capability is missing.
#[session_test]
fn test_unwrap_rsa_missing_capability(session: HsmSession) {
    run_rsa_missing_private_capability_test(&session, RsaPrivateKeyKind::Rsa);
}

/// Ensure RSA CRT unwrap fails if the private decrypt capability is missing.
#[session_test]
fn test_unwrap_rsa_crt_missing_capability(session: HsmSession) {
    run_rsa_missing_private_capability_test(&session, RsaPrivateKeyKind::RsaCrt);
}

/// Ensure RSA unwrap fails when input ciphertext is empty.
#[session_test]
fn test_unwrap_rsa_empty_input_fails(session: HsmSession) {
    run_rsa_empty_input_test(&session, RsaPrivateKeyKind::Rsa);
}

/// Ensure RSA CRT unwrap fails when input ciphertext is empty.
#[session_test]
fn test_unwrap_rsa_crt_empty_input_fails(session: HsmSession) {
    run_rsa_empty_input_test(&session, RsaPrivateKeyKind::RsaCrt);
}

/// Ensure functional RSA unwrap works for 2048-bit key
#[session_test]
fn test_rsa_functional_2048(session: HsmSession) {
    run_rsa_functional_test(&session, RsaPrivateKeyKind::Rsa, 2048, 256, 32);
}

/// Ensure functional RSA unwrap works for 3072-bit key
#[session_test]
fn test_rsa_functional_3072(session: HsmSession) {
    run_rsa_functional_test(&session, RsaPrivateKeyKind::Rsa, 3072, 384, 24);
}

/// Ensure functional RSA unwrap works for 4096-bit key
#[session_test]
fn test_rsa_functional_4096(session: HsmSession) {
    run_rsa_functional_test(&session, RsaPrivateKeyKind::Rsa, 4096, 512, 16);
}

/// Ensure unwrap repeatability for 2048-bit RSA
#[session_test]
fn test_rsa_repeatability_2048(session: HsmSession) {
    run_rsa_repeatability_test(&session, RsaPrivateKeyKind::Rsa, 2048, 256, 32);
}

/// Ensure unwrap repeatability for 3072-bit RSA
#[session_test]
fn test_rsa_repeatability_3072(session: HsmSession) {
    run_rsa_repeatability_test(&session, RsaPrivateKeyKind::Rsa, 3072, 384, 24);
}

/// Ensure unwrap repeatability for 4096-bit RSA
#[session_test]
fn test_rsa_repeatability_4096(session: HsmSession) {
    run_rsa_repeatability_test(&session, RsaPrivateKeyKind::Rsa, 4096, 512, 16);
}

/// Ensure truncated ciphertext fails unwrap for 2048-bit RSA
#[session_test]
fn test_rsa_truncated_2048(session: HsmSession) {
    run_rsa_truncated_ciphertext_test(&session, RsaPrivateKeyKind::Rsa, 2048, 256, 32);
}

/// Ensure truncated ciphertext fails unwrap for 3072-bit RSA
#[session_test]
fn test_rsa_truncated_3072(session: HsmSession) {
    run_rsa_truncated_ciphertext_test(&session, RsaPrivateKeyKind::Rsa, 3072, 384, 24);
}

/// Ensure truncated ciphertext fails unwrap for 4096-bit RSA
#[session_test]
fn test_rsa_truncated_4096(session: HsmSession) {
    run_rsa_truncated_ciphertext_test(&session, RsaPrivateKeyKind::Rsa, 4096, 512, 16);
}

/// Ensure unwrap fails when key kind is incorrect.
#[session_test]
fn test_unwrap_rsa_wrong_key_kind_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Unwrap should fail with InvalidKeyProps for wrong key kind"
    );
}

/// Ensure RSA unwrap fails when key class combination is invalid.
#[session_test]
fn test_unwrap_rsa_wrong_class_fails(session: HsmSession) {
    run_rsa_wrong_class_test(&session, RsaPrivateKeyKind::Rsa);
}

/// Ensure RSA CRT unwrap fails when key class combination is invalid.
#[session_test]
fn test_unwrap_rsa_crt_wrong_class_fails(session: HsmSession) {
    run_rsa_wrong_class_test(&session, RsaPrivateKeyKind::RsaCrt);
}

/// Ensure RSA unwrap fails when the public encrypt capability is missing.
#[session_test]
fn test_unwrap_rsa_missing_pub_capability(session: HsmSession) {
    run_rsa_missing_public_capability_test(&session, RsaPrivateKeyKind::Rsa);
}

/// Ensure RSA CRT unwrap fails when the public encrypt capability is missing.
#[session_test]
fn test_unwrap_rsa_crt_missing_pub_capability(session: HsmSession) {
    run_rsa_missing_public_capability_test(&session, RsaPrivateKeyKind::RsaCrt);
}

/// Ensures RSA unwrap fails when hash algorithm differs from wrap.
#[session_test]
fn test_unwrap_rsa_wrong_hash_algo_fails(session: HsmSession) {
    run_rsa_wrong_hash_algo_test(&session, RsaPrivateKeyKind::Rsa);
}

/// Ensures RSA CRT unwrap fails when hash algorithm differs from wrap.
#[session_test]
fn test_unwrap_rsa_crt_wrong_hash_algo_fails(session: HsmSession) {
    run_rsa_wrong_hash_algo_test(&session, RsaPrivateKeyKind::RsaCrt);
}

/// Ensures RSA unwrap fails with invalid DER structure.
#[session_test]
fn test_unwrap_rsa_invalid_der_fails(session: HsmSession) {
    run_rsa_invalid_der_test(&session, RsaPrivateKeyKind::Rsa);
}

/// Ensures RSA CRT unwrap fails with invalid DER structure.
#[session_test]
fn test_unwrap_rsa_crt_invalid_der_fails(session: HsmSession) {
    run_rsa_invalid_der_test(&session, RsaPrivateKeyKind::RsaCrt);
}

/// Ensure unmask fails when masked blob is truncated
#[session_test]
fn test_rsa_unmask_truncated_blob_fails(session: HsmSession) {
    let (mut masked, priv_key) = get_rsa_masked_blob(&session, RsaPrivateKeyKind::Rsa);

    masked.truncate(masked.len() / 2);

    let mut algo = HsmRsaKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key_pair(&session, &mut algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(priv_key).unwrap();
}

/// Ensure unmask fails when masked blob is corrupted
#[session_test]
fn test_rsa_unmask_corrupted_blob_fails(session: HsmSession) {
    let (mut masked, priv_key) = get_rsa_masked_blob(&session, RsaPrivateKeyKind::Rsa);

    masked[0] ^= 0xFF;

    let mut algo = HsmRsaKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key_pair(&session, &mut algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(priv_key).unwrap();
}

/// Ensure unmask fails when masked blob is empty
#[session_test]
fn test_rsa_unmask_empty_blob_fails(session: HsmSession) {
    let mut algo = HsmRsaKeyUnmaskAlgo::default();

    let result = HsmKeyManager::unmask_key_pair(&session, &mut algo, &[]);

    assert!(result.is_err());
}

/// Ensure unmask fails when using incorrect key pair algorithm
#[session_test]
fn test_rsa_unmask_wrong_key_kind_fails(session: HsmSession) {
    // Step 1: valid RSA masked blob
    let (masked, priv_key) = get_rsa_masked_blob(&session, RsaPrivateKeyKind::Rsa);

    // Step 2: use WRONG key-pair algo (ECC instead of RSA)
    let mut algo = HsmEccKeyUnmaskAlgo::default();

    let result = HsmKeyManager::unmask_key_pair(&session, &mut algo, &masked);

    assert!(
        result.is_err(),
        "Unmask should fail when using wrong key pair kind"
    );

    HsmKeyManager::delete_key(priv_key).unwrap();
}

/// Ensure RSA CRT unmask fails when using the ECC key-pair algorithm.
#[session_test]
fn test_rsa_crt_unmask_wrong_key_kind_fails(session: HsmSession) {
    let (masked, priv_key) = get_rsa_masked_blob(&session, RsaPrivateKeyKind::RsaCrt);

    let mut algo = HsmEccKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key_pair(&session, &mut algo, &masked);

    assert!(
        result.is_err(),
        "RSA CRT unmask should fail when using the ECC key-pair algorithm"
    );

    HsmKeyManager::delete_key(priv_key).unwrap();
}

#[session_test]
fn test_rsa_unmask_roundtrip_2048(session: HsmSession) {
    run_rsa_unmask_roundtrip_test(&session, RsaPrivateKeyKind::Rsa, 2048, 256, 32);
}

#[session_test]
fn test_rsa_unmask_roundtrip_3072(session: HsmSession) {
    run_rsa_unmask_roundtrip_test(&session, RsaPrivateKeyKind::Rsa, 3072, 384, 24);
}

#[session_test]
fn test_rsa_unmask_roundtrip_4096(session: HsmSession) {
    run_rsa_unmask_roundtrip_test(&session, RsaPrivateKeyKind::Rsa, 4096, 512, 16);
}

/// Ensure RSA CRT unmask fails when its masked blob is truncated.
#[session_test]
fn test_rsa_crt_unmask_truncated_blob_fails(session: HsmSession) {
    let (mut masked, priv_key) = get_rsa_masked_blob(&session, RsaPrivateKeyKind::RsaCrt);

    masked.truncate(masked.len() / 2);

    let mut algo = HsmRsaKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key_pair(&session, &mut algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(priv_key).unwrap();
}

/// Ensure RSA CRT unmask fails when its masked blob is corrupted.
#[session_test]
fn test_rsa_crt_unmask_corrupted_blob_fails(session: HsmSession) {
    let (mut masked, priv_key) = get_rsa_masked_blob(&session, RsaPrivateKeyKind::RsaCrt);

    masked[0] ^= 0xFF;

    let mut algo = HsmRsaKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key_pair(&session, &mut algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(priv_key).unwrap();
}

/// Verifies RSA CRT import rejects invalid DER input.
#[session_test]
fn test_import_rsa_crt_invalid_der_fails(session: HsmSession) {
    let bad_der = [0x00, 0x01, 0x02];

    let result = try_import_rsa_key(&session, &bad_der, 2048, RsaPrivateKeyKind::RsaCrt);

    let unexpected_error = match result {
        Err(HsmError::DdiCmdFailure) => None,
        Err(err) => Some(format!("{err:?}")),
        Ok((priv_key, pub_key)) => {
            let _ = HsmKeyManager::delete_key(priv_key);
            let _ = HsmKeyManager::delete_key(pub_key);
            Some("Ok((priv_key, pub_key))".to_string())
        }
    };

    assert!(
        unexpected_error.is_none(),
        "Expected RSA CRT import with invalid DER to fail with DdiCmdFailure, got {:?}",
        unexpected_error
    );
}

/// Verifies RSA CRT import rejects key material whose size mismatches the properties.
#[session_test]
fn test_import_rsa_crt_mismatched_bits_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let der = priv_key.to_vec().expect("Failed to export RSA key");

    let result = try_import_rsa_key(&session, &der, 3072, RsaPrivateKeyKind::RsaCrt);

    let unexpected_result = match result {
        Err(HsmError::InvalidKeyProps) => None,
        Err(err) => Some(format!("{err:?}")),
        Ok((priv_key, pub_key)) => {
            let _ = HsmKeyManager::delete_key(priv_key);
            let _ = HsmKeyManager::delete_key(pub_key);
            Some("Ok((priv_key, pub_key))".to_string())
        }
    };

    assert!(
        unexpected_result.is_none(),
        "Expected RSA CRT import with mismatched bits to fail with InvalidKeyProps, got {:?}",
        unexpected_result
    );
}

/// Verifies RSA import fails when the DER input is invalid.
#[session_test]
fn test_import_rsa_invalid_der_fails(session: HsmSession) {
    let bad_der = [0x00, 0x01, 0x02];

    let result = try_import_rsa_key(&session, &bad_der, 2048, RsaPrivateKeyKind::Rsa);

    let unexpected_error = match result {
        Err(HsmError::DdiCmdFailure) => None,
        Err(err) => Some(format!("{err:?}")),
        Ok((priv_key, pub_key)) => {
            let _ = HsmKeyManager::delete_key(priv_key);
            let _ = HsmKeyManager::delete_key(pub_key);
            Some("Ok((priv_key, pub_key))".to_string())
        }
    };

    assert!(
        unexpected_error.is_none(),
        "Expected RSA import with invalid DER to fail with DdiCmdFailure, got {:?}",
        unexpected_error
    );
}

/// Verifies RSA import fails when key material size does not match requested properties.
#[session_test]
fn test_import_rsa_mismatched_bits_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let der = priv_key.to_vec().expect("Failed to export RSA key");

    let result = try_import_rsa_key(&session, &der, 3072, RsaPrivateKeyKind::Rsa);

    let unexpected_result = match result {
        Err(HsmError::InvalidKeyProps) => None,
        Err(err) => Some(format!("{err:?}")),
        Ok((priv_key, pub_key)) => {
            let _ = HsmKeyManager::delete_key(priv_key);
            let _ = HsmKeyManager::delete_key(pub_key);

            Some("Ok((priv_key, pub_key))".to_string())
        }
    };

    assert!(
        unexpected_result.is_none(),
        "Expected RSA import with mismatched bits to fail with InvalidKeyProps, got {:?}",
        unexpected_result
    );
}

/// Ensure 2048-bit RSA CRT supports PSS signing and verification.
#[session_test]
fn test_rsa_crt_sign_verify_2048(session: HsmSession) {
    run_rsa_sign_verify_test(&session, RsaPrivateKeyKind::RsaCrt, 2048, 256);
}

/// Ensure 3072-bit RSA CRT supports PSS signing and verification.
#[session_test]
fn test_rsa_crt_sign_verify_3072(session: HsmSession) {
    run_rsa_sign_verify_test(&session, RsaPrivateKeyKind::RsaCrt, 3072, 384);
}

/// Ensure 4096-bit RSA CRT supports PSS signing and verification.
#[session_test]
fn test_rsa_crt_sign_verify_4096(session: HsmSession) {
    run_rsa_sign_verify_test(&session, RsaPrivateKeyKind::RsaCrt, 4096, 512);
}

/// Ensure 2048-bit RSA CRT remains usable for signing after mask/unmask.
#[session_test]
fn test_rsa_crt_unmask_sign_verify_2048(session: HsmSession) {
    run_rsa_unmask_sign_verify_test(&session, RsaPrivateKeyKind::RsaCrt, 2048, 256);
}

/// Ensure 3072-bit RSA CRT remains usable for signing after mask/unmask.
#[session_test]
fn test_rsa_crt_unmask_sign_verify_3072(session: HsmSession) {
    run_rsa_unmask_sign_verify_test(&session, RsaPrivateKeyKind::RsaCrt, 3072, 384);
}

/// Ensure 4096-bit RSA CRT remains usable for signing after mask/unmask.
#[session_test]
fn test_rsa_crt_unmask_sign_verify_4096(session: HsmSession) {
    run_rsa_unmask_sign_verify_test(&session, RsaPrivateKeyKind::RsaCrt, 4096, 512);
}
