// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std HMAC driver — performs HMAC operations via OpenSSL.
//!
//! Takes raw key bytes and a [`HashAlgo`] and offloads HMAC sign/verify
//! to the [`WorkerPool`]. Exposes an async API that mirrors hardware HMAC
//! engine peripherals which yield while the engine processes data.
//!
//! ## Supported algorithms
//!
//! | Hash algorithm | Key size (recommended) | Tag size |
//! |----------------|------------------------|----------|
//! | SHA-256        | 32 bytes               | 32 bytes |
//! | SHA-384        | 48 bytes               | 48 bytes |
//! | SHA-512        | 64 bytes               | 64 bytes |
//!
//! ## Thread model
//!
//! All methods copy inputs to owned buffers internally, dispatch the
//! OpenSSL HMAC operation on the tokio worker pool, then write results
//! directly into the caller's `&mut [u8]` output buffers.

use azihsm_crypto::HashAlgo;
use azihsm_crypto::HmacAlgo;
use azihsm_crypto::HmacKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::Rng;
use azihsm_crypto::SignOp;
use azihsm_crypto::VerifyOp;
use azihsm_fw_hsm_pal_traits::*;

use crate::worker::WorkerPool;

/// Std HMAC driver — software HMAC via OpenSSL with async worker dispatch.
///
/// Created once during PAL initialization and shared across all IO tasks.
pub struct StdHmac {
    pool: WorkerPool,
}

impl StdHmac {
    /// Create a new HMAC driver backed by the given worker pool.
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    /// Generate a random HMAC key asynchronously.
    ///
    /// # Parameters
    /// - `key` — Output buffer filled with random key material. Length
    ///   determines key size (e.g., 32 bytes for HMAC-SHA256).
    ///
    /// # Errors
    /// Returns [`HsmError::HmacError`] if the RNG fails.
    pub async fn gen_key(&self, key: &mut [u8]) -> HsmResult<()> {
        let len = key.len();
        let bytes = self
            .pool
            .submit_with_result(async move {
                let mut buf = vec![0u8; len];
                Rng::rand_bytes(&mut buf).map_err(|_| HsmError::HmacError)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;
        key.copy_from_slice(&bytes);
        Ok(())
    }

    /// Compute an HMAC tag (sign) asynchronously.
    ///
    /// # Parameters
    /// - `hash_algo` — The hash algorithm to use (e.g., `HashAlgo::sha256()`).
    /// - `key` — Raw HMAC key bytes.
    /// - `data` — Input message to authenticate.
    /// - `sig` — Output buffer for the MAC tag. Must be at least as large
    ///   as the hash algorithm's digest size.
    ///
    /// # Errors
    /// - [`HsmError::HmacError`] — key import or HMAC computation failed.
    pub async fn sign(
        &self,
        hash_algo: HashAlgo,
        key: &[u8],
        data: &[u8],
        sig: &mut [u8],
    ) -> HsmResult<()> {
        let key_owned = key.to_vec();
        let data_owned = data.to_vec();
        let sig_len = sig.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let hmac_key = HmacKey::from_bytes(&key_owned).map_err(|_| HsmError::HmacError)?;
                let mut algo = HmacAlgo::new(hash_algo);
                let mut buf = vec![0u8; sig_len];
                algo.sign(&hmac_key, &data_owned, Some(&mut buf))
                    .map_err(|_| HsmError::HmacError)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;

        sig.copy_from_slice(&result);
        Ok(())
    }

    /// Verify an HMAC tag asynchronously.
    ///
    /// Computes the MAC over `data` using `key` and compares it to `sig`
    /// using constant-time comparison (provided by OpenSSL).
    ///
    /// # Parameters
    /// - `hash_algo` — The hash algorithm to use (e.g., `HashAlgo::sha256()`).
    /// - `key` — Raw HMAC key bytes.
    /// - `data` — The message that was authenticated.
    /// - `sig` — The MAC tag to verify against.
    ///
    /// # Returns
    /// `true` if the tag is valid, `false` otherwise.
    ///
    /// # Errors
    /// - [`HsmError::HmacError`] — key import or HMAC computation failed.
    pub async fn verify(
        &self,
        hash_algo: HashAlgo,
        key: &[u8],
        data: &[u8],
        sig: &[u8],
    ) -> HsmResult<bool> {
        let key_owned = key.to_vec();
        let data_owned = data.to_vec();
        let sig_owned = sig.to_vec();

        self.pool
            .submit_with_result(async move {
                let hmac_key = HmacKey::from_bytes(&key_owned).map_err(|_| HsmError::HmacError)?;
                let mut algo = HmacAlgo::new(hash_algo);
                algo.verify(&hmac_key, &data_owned, &sig_owned)
                    .map_err(|_| HsmError::HmacError)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdHmac {
        StdHmac::new(WorkerPool::new(Handle::current()))
    }

    // ── Key generation ──────────────────────────────────────────

    #[tokio::test]
    async fn gen_key_32() {
        let driver = make_driver();
        let mut key = [0u8; 32];
        driver.gen_key(&mut key).await.unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    #[tokio::test]
    async fn gen_key_48() {
        let driver = make_driver();
        let mut key = [0u8; 48];
        driver.gen_key(&mut key).await.unwrap();
        assert_ne!(key, [0u8; 48]);
    }

    #[tokio::test]
    async fn gen_key_64() {
        let driver = make_driver();
        let mut key = [0u8; 64];
        driver.gen_key(&mut key).await.unwrap();
        assert_ne!(key, [0u8; 64]);
    }

    // ── Sign / verify roundtrip ─────────────────────────────────

    #[tokio::test]
    async fn sign_verify_sha256() {
        let driver = make_driver();
        let mut key = [0u8; 32];
        driver.gen_key(&mut key).await.unwrap();

        let data = b"hello world";
        let mut sig = [0u8; 32];
        driver
            .sign(HashAlgo::sha256(), &key, data, &mut sig)
            .await
            .unwrap();

        assert!(driver
            .verify(HashAlgo::sha256(), &key, data, &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn sign_verify_sha384() {
        let driver = make_driver();
        let mut key = [0u8; 48];
        driver.gen_key(&mut key).await.unwrap();

        let data = b"hello world";
        let mut sig = [0u8; 48];
        driver
            .sign(HashAlgo::sha384(), &key, data, &mut sig)
            .await
            .unwrap();

        assert!(driver
            .verify(HashAlgo::sha384(), &key, data, &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn sign_verify_sha512() {
        let driver = make_driver();
        let mut key = [0u8; 64];
        driver.gen_key(&mut key).await.unwrap();

        let data = b"hello world";
        let mut sig = [0u8; 64];
        driver
            .sign(HashAlgo::sha512(), &key, data, &mut sig)
            .await
            .unwrap();

        assert!(driver
            .verify(HashAlgo::sha512(), &key, data, &sig)
            .await
            .unwrap());
    }

    // ── Negative tests ──────────────────────────────────────────

    #[tokio::test]
    async fn verify_wrong_data() {
        let driver = make_driver();
        let mut key = [0u8; 32];
        driver.gen_key(&mut key).await.unwrap();

        let mut sig = [0u8; 32];
        driver
            .sign(HashAlgo::sha256(), &key, b"data1", &mut sig)
            .await
            .unwrap();

        assert!(!driver
            .verify(HashAlgo::sha256(), &key, b"data2", &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_wrong_key() {
        let driver = make_driver();
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        driver.gen_key(&mut key1).await.unwrap();
        driver.gen_key(&mut key2).await.unwrap();

        let data = b"hello world";
        let mut sig = [0u8; 32];
        driver
            .sign(HashAlgo::sha256(), &key1, data, &mut sig)
            .await
            .unwrap();

        assert!(!driver
            .verify(HashAlgo::sha256(), &key2, data, &sig)
            .await
            .unwrap());
    }

    // ── Known test vector ───────────────────────────────────────

    /// RFC 4231 Test Case 2 — HMAC-SHA-256.
    ///
    /// Key  = "Jefe" (4 bytes)
    /// Data = "what do ya want for nothing?"
    /// HMAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    #[tokio::test]
    async fn sign_known_vector_sha256() {
        let driver = make_driver();
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mut sig = [0u8; 32];
        driver
            .sign(HashAlgo::sha256(), key, data, &mut sig)
            .await
            .unwrap();
        assert_eq!(
            hex::encode(sig),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
