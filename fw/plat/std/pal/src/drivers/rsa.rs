// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std RSA driver — performs RSA operations via OpenSSL.
//!
//! Operates on [`azihsm_crypto`] key handle types directly
//! (`RsaPrivateKey`, `RsaPublicKey`). The public API accepts
//! references and slices; owned copies for the worker thread
//! boundary are made internally via `Clone` (cheap — OpenSSL
//! key handles are reference-counted).
//!
//! ## Supported key sizes
//!
//! | Key size (bits) | Modulus bytes | Use case |
//! |-----------------|--------------|----------|
//! | 2048            | 256          | Minimum recommended for current use |
//! | 3072            | 384          | Enhanced security for long-term protection |
//! | 4096            | 512          | Maximum security for critical applications |
//!
//! ## Supported operations
//!
//! | Method | Operation | Input | Output |
//! |--------|-----------|-------|--------|
//! | [`gen_keypair`] | Key generation | key size in bits | `(RsaPrivateKey, RsaPublicKey)` |
//! | [`mod_exp_priv`] | Private-key modular exponentiation (`y^d mod n`) | `&RsaPrivateKey`, `&[u8]` | writes `&mut [u8]` |
//! | [`mod_exp_pub`] | Public-key modular exponentiation (`x^e mod n`) | `&RsaPublicKey`, `&[u8]` | writes `&mut [u8]` |
//!
//! ## Modular exponentiation
//!
//! RSA signing and decryption are expressed as private-key modular
//! exponentiation (`mod_exp_priv`: `x = y^d mod n`), while encryption
//! and verification use public-key modular exponentiation (`mod_exp_pub`:
//! `y = x^e mod n`). This matches the hardware PKA register model where
//! the engine performs a single `base^exp mod n` operation regardless of
//! the higher-level use case.
//!
//! Both operations use raw RSA (no padding) via
//! [`RsaEncryptAlgo::with_no_padding()`]. Input buffers must be exactly
//! the modulus size in bytes.
//!
//! ## Thread model
//!
//! All methods clone handles and input slices into owned buffers,
//! then dispatch to the tokio [`WorkerPool`]. The Embassy executor
//! yields while the worker runs, then copies results back.
//!
//! On real Cortex-M7 hardware, these operations would be offloaded
//! to a PKA (Public Key Accelerator) engine via DMA.

use azihsm_crypto::DecryptOp;
use azihsm_crypto::EncryptOp;
use azihsm_crypto::KeyGenerationOp;
use azihsm_crypto::PrivateKey;
use azihsm_crypto::RsaEncryptAlgo;
use azihsm_crypto::RsaPrivateKey;
use azihsm_crypto::RsaPublicKey;
use azihsm_fw_hsm_pal_traits::*;

use crate::worker::WorkerPool;

/// Std RSA driver — software RSA via OpenSSL with async worker dispatch.
///
/// Created once during PAL initialization and shared across all IO tasks.
pub struct StdRsa {
    pool: WorkerPool,
}

impl StdRsa {
    /// Create a new RSA driver backed by the given worker pool.
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    /// Generate an RSA key pair asynchronously.
    ///
    /// Converts `key_size_bits` to bytes and delegates to
    /// [`RsaPrivateKey::generate`] on the worker pool.
    ///
    /// # Parameters
    /// - `key_size_bits` — RSA modulus size in bits (2048, 3072, or 4096).
    ///
    /// # Returns
    /// The `(RsaPrivateKey, RsaPublicKey)` handle pair.
    ///
    /// # Errors
    /// - [`HsmError::RsaGenerateError`] — key generation or public key
    ///   extraction failed.
    pub async fn gen_keypair(
        &self,
        key_size_bits: usize,
    ) -> HsmResult<(RsaPrivateKey, RsaPublicKey)> {
        let size_bytes = key_size_bits / 8;
        self.pool
            .submit_with_result(async move {
                let priv_key =
                    RsaPrivateKey::generate(size_bytes).map_err(|_| HsmError::RsaGenerateError)?;
                let pub_key = priv_key
                    .public_key()
                    .map_err(|_| HsmError::RsaGenerateError)?;
                Ok((priv_key, pub_key))
            })
            .await
    }

    /// Private-key modular exponentiation: `x = y^d mod n`.
    ///
    /// Uses raw RSA (no padding) via [`RsaEncryptAlgo::with_no_padding()`]
    /// and [`DecryptOp::decrypt`] — the "decrypt" operation corresponds to
    /// the private-key exponentiation `y^d mod n`.
    ///
    /// Clones the private key handle (cheap, ref-counted), copies the
    /// input to an owned buffer, and dispatches to the worker pool.
    ///
    /// # Parameters
    /// - `priv_key` — The RSA private key handle.
    /// - `y` — Input data. Must be exactly the key size in bytes.
    /// - `x` — Output buffer for the result. Must be exactly the key
    ///   size in bytes.
    ///
    /// # Errors
    /// - [`HsmError::RsaDecryptFailed`] — the modular exponentiation failed.
    pub async fn mod_exp_priv(
        &self,
        priv_key: &RsaPrivateKey,
        y: &[u8],
        x: &mut [u8],
    ) -> HsmResult<()> {
        let key = priv_key.clone();
        let y_owned = y.to_vec();
        let out_len = x.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let mut algo = RsaEncryptAlgo::with_no_padding();
                let mut buf = vec![0u8; out_len];
                algo.decrypt(&key, &y_owned, Some(&mut buf))
                    .map_err(|_| HsmError::RsaDecryptFailed)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;

        x.copy_from_slice(&result);
        Ok(())
    }

    /// Public-key modular exponentiation: `y = x^e mod n`.
    ///
    /// Uses raw RSA (no padding) via [`RsaEncryptAlgo::with_no_padding()`]
    /// and [`EncryptOp::encrypt`] — the "encrypt" operation corresponds to
    /// the public-key exponentiation `x^e mod n`.
    ///
    /// Clones the public key handle (cheap, ref-counted), copies the
    /// input to an owned buffer, and dispatches to the worker pool.
    ///
    /// # Parameters
    /// - `pub_key` — The RSA public key handle.
    /// - `x_input` — Input data. Must be exactly the key size in bytes.
    /// - `y` — Output buffer for the result. Must be exactly the key
    ///   size in bytes.
    ///
    /// # Errors
    /// - [`HsmError::RsaEncryptFailed`] — the modular exponentiation failed.
    pub async fn mod_exp_pub(
        &self,
        pub_key: &RsaPublicKey,
        x_input: &[u8],
        y: &mut [u8],
    ) -> HsmResult<()> {
        let key = pub_key.clone();
        let x_owned = x_input.to_vec();
        let out_len = y.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let mut algo = RsaEncryptAlgo::with_no_padding();
                let mut buf = vec![0u8; out_len];
                algo.encrypt(&key, &x_owned, Some(&mut buf))
                    .map_err(|_| HsmError::RsaEncryptFailed)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;

        y.copy_from_slice(&result);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdRsa {
        StdRsa::new(WorkerPool::new(Handle::current()))
    }

    /// Build a small test message of exactly `key_size_bytes` bytes:
    /// all zeros except the last byte is `0x02`. This is a small
    /// integer (numerically < modulus) that is safe for raw RSA.
    fn small_test_message(key_size_bytes: usize) -> Vec<u8> {
        let mut msg = vec![0u8; key_size_bytes];
        msg[key_size_bytes - 1] = 0x02;
        msg
    }

    // ── Key generation ──────────────────────────────────────────

    #[tokio::test]
    async fn gen_keypair_2048() {
        let driver = make_driver();
        let (_priv_key, _pub_key) = driver.gen_keypair(2048).await.unwrap();
    }

    #[tokio::test]
    async fn gen_keypair_3072() {
        let driver = make_driver();
        let (_priv_key, _pub_key) = driver.gen_keypair(3072).await.unwrap();
    }

    #[tokio::test]
    async fn gen_keypair_4096() {
        let driver = make_driver();
        let (_priv_key, _pub_key) = driver.gen_keypair(4096).await.unwrap();
    }

    // ── Mod_exp roundtrip (encrypt with pub → decrypt with priv) ─

    async fn mod_exp_roundtrip(key_size_bits: usize) {
        let driver = make_driver();
        let key_size_bytes = key_size_bits / 8;
        let (priv_key, pub_key) = driver.gen_keypair(key_size_bits).await.unwrap();

        let plaintext = small_test_message(key_size_bytes);

        // Encrypt: y = plaintext^e mod n
        let mut ciphertext = vec![0u8; key_size_bytes];
        driver
            .mod_exp_pub(&pub_key, &plaintext, &mut ciphertext)
            .await
            .unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt: x = ciphertext^d mod n
        let mut decrypted = vec![0u8; key_size_bytes];
        driver
            .mod_exp_priv(&priv_key, &ciphertext, &mut decrypted)
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn mod_exp_roundtrip_2048() {
        mod_exp_roundtrip(2048).await;
    }

    #[tokio::test]
    async fn mod_exp_roundtrip_3072() {
        mod_exp_roundtrip(3072).await;
    }

    #[tokio::test]
    async fn mod_exp_roundtrip_4096() {
        mod_exp_roundtrip(4096).await;
    }

    // ── Identity test: pub(priv(m)) == m ─────────────────────────

    #[tokio::test]
    async fn mod_exp_priv_pub_identity_2048() {
        let driver = make_driver();
        let key_size_bytes = 256;
        let (priv_key, pub_key) = driver.gen_keypair(2048).await.unwrap();

        let plaintext = small_test_message(key_size_bytes);

        // priv(m) = m^d mod n
        let mut intermediate = vec![0u8; key_size_bytes];
        driver
            .mod_exp_priv(&priv_key, &plaintext, &mut intermediate)
            .await
            .unwrap();

        // pub(priv(m)) = (m^d)^e mod n == m
        let mut recovered = vec![0u8; key_size_bytes];
        driver
            .mod_exp_pub(&pub_key, &intermediate, &mut recovered)
            .await
            .unwrap();
        assert_eq!(recovered, plaintext);
    }
}
