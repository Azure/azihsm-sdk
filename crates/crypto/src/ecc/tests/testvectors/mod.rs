// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
mod ecc_p256_test_vectors;
mod ecc_p384_test_vectors;
mod ecc_p521_test_vectors;
mod ecdh_p256_test_vectors;
mod ecdh_p384_test_vectors;
mod ecdh_p521_test_vectors;

pub(crate) use ecc_p256_test_vectors::ECC_P256_TEST_VECTORS;
pub(crate) use ecc_p384_test_vectors::ECC_P384_TEST_VECTORS;
pub(crate) use ecc_p521_test_vectors::ECC_P521_TEST_VECTORS;
pub(crate) use ecdh_p256_test_vectors::ECDH_P256_TEST_VECTORS;
pub(crate) use ecdh_p384_test_vectors::ECDH_P384_TEST_VECTORS;
pub(crate) use ecdh_p521_test_vectors::ECDH_P521_TEST_VECTORS;

#[derive(Debug, Clone)]
/// Represents a test vector for NIST-recommended elliptic curve cryptography (ECC) operations.
///
/// This struct contains all necessary components to test ECC signing and verification,
/// including the curve_bits, keys, message, digest, and signature.
pub struct EccNistTestVector {
    /// - `curve_bits`: number of curve bits.
    pub curve_bits: usize,
    /// - `public_key_der`: The DER-encoded public key bytes.
    pub public_key_der: &'static [u8],
    /// - `private_key_der`: The DER-encoded private key bytes.
    pub private_key_der: &'static [u8],
    /// - `msg`: The message to be signed or verified.
    pub msg: &'static [u8],
    /// - `_digest`: The precomputed digest of the message (may be unused in some tests).
    pub digest: &'static [u8],
    /// - `sig_der`: The DER-encoded signature for the message.
    pub sig_der: &'static [u8],
}

#[derive(Debug, Clone)]
/// Represents a test vector for ECDH primitive operations using DER-encoded keys.
pub struct EcdhNistTestVector {
    // Reference inputs (raw bytes from the .txt)
    pub _qcavs_x: &'static [u8],
    pub _qcavs_y: &'static [u8],
    pub _diut: &'static [u8],

    // Pre-encoded keys
    pub qcavs_pubkey_der: &'static [u8],
    pub diut_privkey_der: &'static [u8],
    pub _qiut_x: &'static [u8],
    pub _qiut_y: &'static [u8],
    pub ziut: &'static [u8],
}
