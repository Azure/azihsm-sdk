// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA cryptographic operations trait for the HSM PAL.
//!
//! Defines [`HsmRsaPct`] and the [`HsmRsa`] trait that PAL implementations
//! use to expose RSA key generation and modular exponentiation.
//!
//! On Cortex-M7 hardware this would delegate to the PKA (Public Key
//! Accelerator) engine. On the standard (host-native) PAL it would use
//! OpenSSL's RSA primitives.
//!
//! ## Key representation
//!
//! All key parameters are plain `&[u8]` byte slices containing the raw
//! key material. Each PAL implementation is responsible for parsing
//! them into whatever internal representation it needs.
//!
//! ## Modular exponentiation
//!
//! RSA signing and decryption are expressed as private-key modular
//! exponentiation (`mod_exp_priv`), while encryption and verification
//! use public-key modular exponentiation (`mod_exp_pub`). This matches
//! the hardware PKA register model where the engine performs a single
//! `base^exp mod n` operation regardless of the higher-level use case.
//!
//! ## Output buffer convention
//!
//! All methods take mandatory `&mut [u8]` output buffers. The caller is
//! responsible for providing buffers of the correct size (key size in
//! bytes for RSA operations).

use super::*;

/// Pairwise Consistency Test (PCT) mode for RSA key generation.
///
/// FIPS 140-3 requires a PCT after key generation to verify the key
/// pair is functional. The test mode determines which operation is
/// used for verification.
pub enum HsmRsaPct {
    /// No PCT — skip the consistency test.
    None,

    /// Sign-verify PCT: sign a test message with the private key and
    /// verify it with the public key.
    SignVerify,

    /// Encrypt-decrypt PCT: encrypt test data with the public key and
    /// verify the private key recovers the original.
    EncryptDecrypt,
}

/// Asynchronous RSA operations trait.
///
/// PAL implementations provide this to the core for RSA key generation
/// and modular exponentiation. The async signatures allow hardware-backed
/// implementations to yield while the PKA engine processes operations.
pub trait HsmRsa {
    /// Generate an RSA key pair.
    ///
    /// # Parameters
    /// - `key_size` — RSA modulus size in bits (2048, 3072, or 4096).
    /// - `priv_key` — Output buffer for the serialized private key.
    /// - `pub_key` — Output buffer for the serialized public key.
    /// - `pct` — Pairwise Consistency Test mode. When not [`HsmRsaPct::None`],
    ///   a sign/verify or encrypt/decrypt round-trip is performed to
    ///   validate the generated key pair (FIPS 140-3 requirement).
    ///
    /// # Errors
    /// Returns [`HsmError`] if key generation fails, or if the PCT
    /// verification fails.
    async fn ras_gen_keypair(
        &self,
        key_size: usize,
        priv_key: &mut [u8],
        pub_key: &mut [u8],
        pct: HsmRsaPct,
    ) -> Result<(), HsmError>;

    /// Private-key modular exponentiation: `x = y^d mod n`.
    ///
    /// Used for RSA decryption and signing.
    ///
    /// # Parameters
    /// - `key` — The RSA private key.
    /// - `y` — Input data (ciphertext for decryption, message hash for
    ///   signing). Must be exactly the key size in bytes.
    /// - `x` — Output buffer for the result. Must be exactly the key
    ///   size in bytes.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the exponentiation fails (e.g., PKA
    /// engine error, invalid key).
    async fn mod_exp_priv(&self, key: &[u8], y: &[u8], x: &mut [u8]) -> Result<(), HsmError>;

    /// Public-key modular exponentiation: `y = x^e mod n`.
    ///
    /// Used for RSA encryption and signature verification.
    ///
    /// # Parameters
    /// - `key` — The RSA public key.
    /// - `x` — Input data (plaintext for encryption, signature for
    ///   verification). Must be exactly the key size in bytes.
    /// - `y` — Output buffer for the result. Must be exactly the key
    ///   size in bytes.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the exponentiation fails (e.g., PKA
    /// engine error, invalid key).
    async fn mod_exp_pub(&self, key: &[u8], x: &[u8], y: &mut [u8]) -> Result<(), HsmError>;
}
