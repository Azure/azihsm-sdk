// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std hash driver — computes cryptographic digests via OpenSSL.
//!
//! Takes [`azihsm_crypto::HashAlgo`] directly and offloads computation
//! to the [`WorkerPool`]. Exposes an async API that mirrors hardware SHA
//! engine peripherals which yield while the engine processes data.
//!
//! ## Supported algorithms
//!
//! | Algorithm | Digest size |
//! |-----------|-------------|
//! | SHA-1     | 20 bytes    |
//! | SHA-256   | 32 bytes    |
//! | SHA-384   | 48 bytes    |
//! | SHA-512   | 64 bytes    |
//!
//! ## Thread model
//!
//! The caller (Embassy executor) is single-threaded. The driver copies
//! input data to an owned buffer and spawns the OpenSSL hash computation
//! on the tokio worker pool. The Embassy task yields (`Pending`) until
//! the worker completes, then copies the result into the caller's
//! digest buffer.

use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_fw_hsm_pal_traits::*;

use crate::worker::WorkerPool;

/// Std hash driver — software SHA via OpenSSL with async worker dispatch.
///
/// Created once during PAL initialization and shared across all IO tasks.
/// The inner [`WorkerPool`] handle is cheap to clone (wraps a tokio
/// `Handle`).
pub struct StdHash {
    pool: WorkerPool,
}

impl StdHash {
    /// Create a new hash driver backed by the given worker pool.
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    /// Compute a hash digest asynchronously.
    ///
    /// # Parameters
    /// - `algo` — The OpenSSL hash algorithm to use (e.g., `HashAlgo::sha256()`).
    /// - `data` — Input message bytes to hash.
    /// - `digest` — Output buffer for the resulting digest. Must be at
    ///   least as large as the algorithm's digest size.
    ///
    /// # Errors
    /// Returns [`HsmError::ShaError`] if the OpenSSL hash operation fails.
    pub async fn hash(&self, algo: HashAlgo, data: &[u8], digest: &mut [u8]) -> HsmResult<()> {
        let data_owned = data.to_vec();
        let digest_len = digest.len();

        let result: HsmResult<Vec<u8>> = self
            .pool
            .submit_with_result(async move {
                let mut out = vec![0u8; digest_len];
                let mut algo = algo;
                algo.hash(&data_owned, Some(&mut out))
                    .map_err(|_| HsmError::ShaError)?;
                Ok(out)
            })
            .await;

        digest[..digest_len].copy_from_slice(&result?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdHash {
        StdHash::new(WorkerPool::new(Handle::current()))
    }

    /// NIST FIPS 180-4 "abc" test vectors.
    #[tokio::test]
    async fn sha1_abc() {
        let driver = make_driver();
        let mut digest = [0u8; 20];
        driver
            .hash(HashAlgo::sha1(), b"abc", &mut digest)
            .await
            .unwrap();
        assert_eq!(
            hex::encode(digest),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[tokio::test]
    async fn sha256_abc() {
        let driver = make_driver();
        let mut digest = [0u8; 32];
        driver
            .hash(HashAlgo::sha256(), b"abc", &mut digest)
            .await
            .unwrap();
        assert_eq!(
            hex::encode(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn sha384_abc() {
        let driver = make_driver();
        let mut digest = [0u8; 48];
        driver
            .hash(HashAlgo::sha384(), b"abc", &mut digest)
            .await
            .unwrap();
        assert_eq!(
            hex::encode(digest),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[tokio::test]
    async fn sha512_abc() {
        let driver = make_driver();
        let mut digest = [0u8; 64];
        driver
            .hash(HashAlgo::sha512(), b"abc", &mut digest)
            .await
            .unwrap();
        assert_eq!(
            hex::encode(digest),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[tokio::test]
    async fn sha256_empty() {
        let driver = make_driver();
        let mut digest = [0u8; 32];
        driver
            .hash(HashAlgo::sha256(), b"", &mut digest)
            .await
            .unwrap();
        assert_eq!(
            hex::encode(digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
