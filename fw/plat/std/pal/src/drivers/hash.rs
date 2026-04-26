// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std hash driver — computes cryptographic digests via OpenSSL.
//!
//! Takes [`azihsm_crypto::HashAlgo`] directly and offloads computation
//! to the worker pool. Exposes an async API that mirrors hardware SHA
//! engine peripherals which yield while processing data.

use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_fw_hsm_pal_traits::*;

use crate::worker::WorkerPool;

/// Std hash driver — software SHA via OpenSSL with async worker dispatch.
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
    /// Copies input to an owned buffer, offloads the computation to the
    /// tokio worker pool, and writes the result into `digest`.
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
