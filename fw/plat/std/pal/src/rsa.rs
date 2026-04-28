// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmRsa`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (DER byte slices)
//! and the [`StdRsa`](crate::drivers::rsa::StdRsa) driver (OpenSSL
//! key handles). The PAL impl is responsible for:
//!
//! 1. **Key serialization** — exporting generated handles to DER bytes
//!    (PKCS#8 for private, SPKI for public) in [`ras_gen_keypair`].
//! 2. **Key deserialization** — importing DER bytes into handles for
//!    [`mod_exp_priv`] and [`mod_exp_pub`].
//!
//! ## Key formats
//!
//! | Direction | Private key | Public key |
//! |-----------|-------------|------------|
//! | Trait → PAL (input) | PKCS#8 DER `&[u8]` | SPKI DER `&[u8]` |
//! | PAL → Trait (output) | PKCS#8 DER `&mut [u8]` | SPKI DER `&mut [u8]` |
//! | PAL → Driver (internal) | `RsaPrivateKey` handle | `RsaPublicKey` handle |
//!
//! ## Data flow (mod_exp_priv example)
//!
//! ```text
//! Core calls pal.mod_exp_priv(key_der, y, x)
//!   → RsaPrivateKey::from_bytes(key_der)      // DER → handle
//!   → self.rsa.mod_exp_priv(&handle, y, x)    // driver
//!     → WorkerPool → OpenSSL RSA raw decrypt
//!   → result written into x                   // result → caller
//! ```

use azihsm_crypto::ExportableKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::RsaPrivateKey;
use azihsm_crypto::RsaPublicKey;

use super::*;

impl HsmRsa for StdHsmPal {
    /// Generate an RSA key pair.
    ///
    /// Delegates to [`StdRsa::gen_keypair`] which returns OpenSSL handles,
    /// then exports the private key as PKCS#8 DER and the public key as
    /// SPKI DER into the caller-provided buffers.
    ///
    /// # Parameters
    /// - `key_size` — RSA modulus size in bits (2048, 3072, or 4096).
    /// - `priv_key` — Output buffer for PKCS#8 DER private key.
    /// - `pub_key` — Output buffer for SPKI DER public key.
    /// - `_pct` — Pairwise consistency test mode (currently ignored).
    ///
    /// # Errors
    /// - [`HsmError::RsaGenerateError`] — key generation failed.
    /// - [`HsmError::RsaToDerError`] — DER export failed.
    /// - [`HsmError::RsaInvalidKeyLength`] — output buffer too small.
    async fn ras_gen_keypair(
        &self,
        key_size: usize,
        priv_key: &mut [u8],
        pub_key: &mut [u8],
        _pct: HsmRsaPct,
    ) -> Result<(), HsmError> {
        let (pk, pubk) = self.rsa.gen_keypair(key_size).await?;

        // Export private key as PKCS#8 DER.
        let priv_len = pk.to_bytes(None).map_err(|_| HsmError::RsaToDerError)?;
        if priv_key.len() < priv_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }
        pk.to_bytes(Some(&mut priv_key[..priv_len]))
            .map_err(|_| HsmError::RsaToDerError)?;

        // Export public key as SPKI DER.
        let pub_len = pubk.to_bytes(None).map_err(|_| HsmError::RsaToDerError)?;
        if pub_key.len() < pub_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }
        pubk.to_bytes(Some(&mut pub_key[..pub_len]))
            .map_err(|_| HsmError::RsaToDerError)?;

        Ok(())
    }

    /// Private-key modular exponentiation: `x = y^d mod n`.
    ///
    /// Imports the private key from PKCS#8 DER, delegates the raw RSA
    /// operation to the driver.
    ///
    /// # Parameters
    /// - `key` — PKCS#8 DER private key bytes.
    /// - `y` — Input data. Must be exactly the key size in bytes.
    /// - `x` — Output buffer for the result.
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — DER import failed.
    /// - [`HsmError::RsaDecryptFailed`] — modular exponentiation failed.
    async fn mod_exp_priv(&self, key: &[u8], y: &[u8], x: &mut [u8]) -> Result<(), HsmError> {
        let priv_key = RsaPrivateKey::from_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        self.rsa.mod_exp_priv(&priv_key, y, x).await
    }

    /// Public-key modular exponentiation: `y = x^e mod n`.
    ///
    /// Imports the public key from SPKI DER, delegates the raw RSA
    /// operation to the driver.
    ///
    /// # Parameters
    /// - `key` — SPKI DER public key bytes.
    /// - `x` — Input data. Must be exactly the key size in bytes.
    /// - `y` — Output buffer for the result.
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — DER import failed.
    /// - [`HsmError::RsaEncryptFailed`] — modular exponentiation failed.
    async fn mod_exp_pub(&self, key: &[u8], x: &[u8], y: &mut [u8]) -> Result<(), HsmError> {
        let pub_key = RsaPublicKey::from_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        self.rsa.mod_exp_pub(&pub_key, x, y).await
    }
}
