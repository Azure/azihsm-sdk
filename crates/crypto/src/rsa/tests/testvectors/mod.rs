// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod rsa_enc_test_vectors;
mod rsa_oaep_test_vectors;
mod rsa_pkcs1_test_vectors;
mod rsa_pss_test_vectors;

pub(crate) use rsa_enc_test_vectors::RSA_NO_PADDING_TEST_VECTORS;
pub(crate) use rsa_oaep_test_vectors::RSA_OAEP_TEST_VECTORS;
pub(crate) use rsa_pkcs1_test_vectors::RSA_PKCS1_TEST_VECTORS;
pub(crate) use rsa_pss_test_vectors::RSA_PSS_TEST_VECTORS;

/// Hash algorithm enum used in test vectors.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TestHashAlgo {
    /// SHA-1
    Sha1,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}
/// Represents a single Raw RSA test vector
#[derive(Debug)]
pub struct RsaEncTestVector {
    /// Private key in PKCS#8 DER format
    pub priv_der: &'static [u8],
    /// Ciphertext (result of raw RSA encryption)
    pub ciphertext: &'static [u8],
    /// Original plaintext (zero-padded to key size)
    pub plaintext: &'static [u8],
    /// Test vector name for identification
    pub name: &'static str,
}

/// Represents a single RSA OAEP test vector
#[derive(Debug)]
pub struct OaepTestVector {
    /// Private key in PKCS#8 DER format
    pub priv_der: &'static [u8],
    /// Ciphertext input (hex decoded)
    pub ciphertext: &'static [u8],
    /// Expected plaintext output (hex decoded)
    pub plaintext: &'static [u8],
    /// Hash algorithm for OAEP (default SHA-1 if not specified)
    pub hash_algo: TestHashAlgo,
    /// Optional OAEP label
    pub label: Option<&'static [u8]>,
    /// Test vector name for identification
    pub name: &'static str,
}
#[derive(Debug)]
pub struct PkcsTestVector {
    pub priv_der: &'static [u8], // PKCS#8 DER
    pub pub_der: &'static [u8],  // PKCS#8 DER
    pub msg: &'static [u8],
    pub s: &'static [u8],
    pub hash_algo: TestHashAlgo,
}

#[derive(Debug)]
pub struct PssTestVector {
    pub private_der: &'static [u8], // PKCS#8 DER
    pub pub_der: &'static [u8],     // PKCS#8 DER
    pub msg: &'static [u8],
    pub s: &'static [u8],
    pub hash_algo: TestHashAlgo,
    pub salt_len: usize,
}
