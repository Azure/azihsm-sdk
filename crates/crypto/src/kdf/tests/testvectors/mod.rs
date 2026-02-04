// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod kbkdf_hmac_sha1_test_vectors;
mod kbkdf_hmac_sha256_test_vectors;
mod kbkdf_hmac_sha384_test_vectors;
mod kbkdf_hmac_sha512_test_vectors;
mod rfc_test_vectors;

pub(crate) use kbkdf_hmac_sha1_test_vectors::*;
pub(crate) use kbkdf_hmac_sha256_test_vectors::*;
pub(crate) use kbkdf_hmac_sha384_test_vectors::*;
pub(crate) use kbkdf_hmac_sha512_test_vectors::*;
pub(crate) use rfc_test_vectors::*;

/// Hash algorithm enum used in test vectors.
#[allow(unused)]
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

#[derive(Debug, Clone, Copy)]
pub struct HkdfTestVector {
    pub ikm: &'static [u8],      // Input Key Material
    pub salt: &'static [u8],     // Salt
    pub info: &'static [u8],     // Info
    pub length: usize,           // Output length
    pub prk: &'static [u8],      // PRK, (Extract only)
    pub expected: &'static [u8], // Expected output
    pub hash_algo: TestHashAlgo, // Hash algorithm
}

/// KBKDF test vector structure.
#[derive(Debug, Clone, Copy)]
pub struct KbkdfTestVector {
    pub vector_id: usize,
    pub hash_algo: TestHashAlgo,
    pub ki: &'static [u8],
    pub label: &'static [u8],
    pub context: &'static [u8],
    pub ko: &'static [u8],
}
