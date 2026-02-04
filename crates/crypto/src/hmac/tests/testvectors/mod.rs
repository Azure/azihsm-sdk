// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod hmac_sha1_nist_test_vectors;
mod hmac_sha256_nist_test_vectors;
mod hmac_sha384_nist_test_vectors;
mod hmac_sha512_nist_test_vectors;

pub(crate) use hmac_sha1_nist_test_vectors::HMAC_SHA1_NIST_TEST_VECTORS;
pub(crate) use hmac_sha256_nist_test_vectors::HMAC_SHA256_NIST_TEST_VECTORS;
pub(crate) use hmac_sha384_nist_test_vectors::HMAC_SHA384_NIST_TEST_VECTORS;
pub(crate) use hmac_sha512_nist_test_vectors::HMAC_SHA512_NIST_TEST_VECTORS;

#[derive(Debug, Clone)]
pub struct HmacTestVector {
    // Matches with NIST Test vector count field.
    pub vector_count_id: u32,
    pub key: &'static [u8],
    pub msg: &'static [u8],
    pub mac: &'static [u8],
}
