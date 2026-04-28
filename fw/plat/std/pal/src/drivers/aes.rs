// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std AES driver — performs AES operations via OpenSSL.
//!
//! Takes raw key bytes and offloads AES encryption/decryption to the
//! [`WorkerPool`]. Exposes an async API that mirrors hardware AES engine
//! peripherals which yield while the engine processes data.
//!
//! ## Supported modes
//!
//! | Mode | Padding | IV required |
//! |------|---------|-------------|
//! | CBC  | None    | Yes (16 B)  |
//! | ECB  | None    | No          |
//!
//! ## Key sizes
//!
//! | Key length | Algorithm |
//! |------------|-----------|
//! | 16 bytes   | AES-128   |
//! | 24 bytes   | AES-192   |
//! | 32 bytes   | AES-256   |
//!
//! ## Thread model
//!
//! All methods copy inputs to owned buffers internally, dispatch the
//! OpenSSL cipher operation on the tokio worker pool, then write
//! results directly into the caller's `&mut [u8]` output buffers.

use azihsm_crypto::AesCbcAlgo;
use azihsm_crypto::AesEcbAlgo;
use azihsm_crypto::AesKey;
use azihsm_crypto::DecryptOp;
use azihsm_crypto::EncryptOp;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::Rng;
use azihsm_fw_hsm_pal_traits::*;

use crate::worker::WorkerPool;

/// Std AES driver — software AES via OpenSSL with async worker dispatch.
///
/// Created once during PAL initialization and shared across all IO tasks.
pub struct StdAes {
    pool: WorkerPool,
}

impl StdAes {
    /// Create a new AES driver backed by the given worker pool.
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    /// Generate a random AES key asynchronously.
    ///
    /// # Parameters
    /// - `key` — Output buffer filled with random key material. Length
    ///   determines key size (16/24/32 bytes).
    ///
    /// # Errors
    /// Returns [`HsmError::AesGenerateError`] if the RNG fails.
    pub async fn gen_key(&self, key: &mut [u8]) -> HsmResult<()> {
        let len = key.len();
        let bytes = self
            .pool
            .submit_with_result(async move {
                let mut buf = vec![0u8; len];
                Rng::rand_bytes(&mut buf).map_err(|_| HsmError::AesGenerateError)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;
        key.copy_from_slice(&bytes);
        Ok(())
    }

    /// AES-CBC encrypt or decrypt asynchronously.
    ///
    /// No PKCS#7 padding — input must be block-aligned (multiple of 16).
    ///
    /// # Parameters
    /// - `key` — Raw AES key bytes (16, 24, or 32 bytes).
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `iv` — 16-byte IV. Updated in-place to the last ciphertext
    ///   block after the operation (for CBC chaining).
    /// - `input` — Source data (must be block-aligned).
    /// - `output` — Destination buffer (must be ≥ `input.len()` bytes).
    ///
    /// # Errors
    /// - [`HsmError::AesEncryptFailed`] / [`HsmError::AesDecryptFailed`]
    /// - [`HsmError::AesInvalidKeyLength`]
    pub async fn cbc_enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        iv: &mut [u8],
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        let key_owned = key.to_vec();
        let iv_owned = iv.to_vec();
        let input_owned = input.to_vec();
        let input_len = input.len();

        let (result_data, updated_iv) = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&key_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesCbcAlgo::with_no_padding(&iv_owned);
                let mut buf = vec![0u8; input_len + 16];

                if encrypt {
                    let written = algo
                        .encrypt(&aes_key, &input_owned, Some(&mut buf))
                        .map_err(|_| HsmError::AesEncryptFailed)?;
                    buf.truncate(written);
                } else {
                    let written = algo
                        .decrypt(&aes_key, &input_owned, Some(&mut buf))
                        .map_err(|_| HsmError::AesDecryptFailed)?;
                    buf.truncate(written);
                }

                let new_iv = algo.iv().to_vec();
                Ok::<_, HsmError>((buf, new_iv))
            })
            .await?;

        output[..result_data.len()].copy_from_slice(&result_data);
        iv[..updated_iv.len()].copy_from_slice(&updated_iv);
        Ok(())
    }

    /// AES-ECB encrypt or decrypt asynchronously.
    ///
    /// No padding — input must be block-aligned (multiple of 16).
    ///
    /// # Parameters
    /// - `key` — Raw AES key bytes (16, 24, or 32 bytes).
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `input` — Source data (must be block-aligned).
    /// - `output` — Destination buffer (must be ≥ `input.len()` bytes).
    ///
    /// # Errors
    /// - [`HsmError::AesEncryptFailed`] / [`HsmError::AesDecryptFailed`]
    /// - [`HsmError::AesInvalidKeyLength`]
    pub async fn ecb_enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        let key_owned = key.to_vec();
        let input_owned = input.to_vec();
        let input_len = input.len();

        let result_data = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&key_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesEcbAlgo::default();
                let mut buf = vec![0u8; input_len + 16];

                if encrypt {
                    let written = algo
                        .encrypt(&aes_key, &input_owned, Some(&mut buf))
                        .map_err(|_| HsmError::AesEncryptFailed)?;
                    buf.truncate(written);
                } else {
                    let written = algo
                        .decrypt(&aes_key, &input_owned, Some(&mut buf))
                        .map_err(|_| HsmError::AesDecryptFailed)?;
                    buf.truncate(written);
                }

                Ok::<_, HsmError>(buf)
            })
            .await?;

        output[..result_data.len()].copy_from_slice(&result_data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdAes {
        StdAes::new(WorkerPool::new(Handle::current()))
    }

    // ── Key generation ──────────────────────────────────────────

    #[tokio::test]
    async fn gen_key_128() {
        let driver = make_driver();
        let mut key = [0u8; 16];
        driver.gen_key(&mut key).await.unwrap();
        assert_ne!(key, [0u8; 16]);
    }

    #[tokio::test]
    async fn gen_key_192() {
        let driver = make_driver();
        let mut key = [0u8; 24];
        driver.gen_key(&mut key).await.unwrap();
        assert_ne!(key, [0u8; 24]);
    }

    #[tokio::test]
    async fn gen_key_256() {
        let driver = make_driver();
        let mut key = [0u8; 32];
        driver.gen_key(&mut key).await.unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    // ── CBC roundtrip (all key sizes) ───────────────────────────

    #[tokio::test]
    async fn cbc_roundtrip_128() {
        let driver = make_driver();
        let key = [0x42u8; 16];
        let plaintext = [0xABu8; 32];
        let orig_iv = [0u8; 16];

        let mut ct = [0u8; 32];
        let mut iv = orig_iv;
        driver
            .cbc_enc_dec(&key, true, &mut iv, &plaintext, &mut ct)
            .await
            .unwrap();
        assert_ne!(ct, plaintext);

        let mut pt = [0u8; 32];
        iv = orig_iv;
        driver
            .cbc_enc_dec(&key, false, &mut iv, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn cbc_roundtrip_192() {
        let driver = make_driver();
        let key = [0x55u8; 24];
        let plaintext = [0xCDu8; 48]; // 3 blocks
        let orig_iv = [0x01u8; 16];

        let mut ct = [0u8; 48];
        let mut iv = orig_iv;
        driver
            .cbc_enc_dec(&key, true, &mut iv, &plaintext, &mut ct)
            .await
            .unwrap();

        let mut pt = [0u8; 48];
        iv = orig_iv;
        driver
            .cbc_enc_dec(&key, false, &mut iv, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn cbc_roundtrip_256() {
        let driver = make_driver();
        let key = [0x77u8; 32];
        let plaintext = [0xEFu8; 64]; // 4 blocks
        let orig_iv = [0x02u8; 16];

        let mut ct = [0u8; 64];
        let mut iv = orig_iv;
        driver
            .cbc_enc_dec(&key, true, &mut iv, &plaintext, &mut ct)
            .await
            .unwrap();

        let mut pt = [0u8; 64];
        iv = orig_iv;
        driver
            .cbc_enc_dec(&key, false, &mut iv, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    // ── CBC NIST vectors (NIST SP 800-38A) ──────────────────────

    /// NIST SP 800-38A F.2.1 — AES-128-CBC Encrypt.
    #[tokio::test]
    async fn cbc_nist_128() {
        let driver = make_driver();
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let mut iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver
            .cbc_enc_dec(&key, true, &mut iv, &pt, &mut ct)
            .await
            .unwrap();
        assert_eq!(hex::encode(ct), "7649abac8119b246cee98e9b12e9197d");
    }

    /// NIST SP 800-38A F.2.3 — AES-192-CBC Encrypt.
    #[tokio::test]
    async fn cbc_nist_192() {
        let driver = make_driver();
        let key = hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
        let mut iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver
            .cbc_enc_dec(&key, true, &mut iv, &pt, &mut ct)
            .await
            .unwrap();
        assert_eq!(hex::encode(ct), "4f021db243bc633d7178183a9fa071e8");
    }

    /// NIST SP 800-38A F.2.5 — AES-256-CBC Encrypt.
    #[tokio::test]
    async fn cbc_nist_256() {
        let driver = make_driver();
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let mut iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver
            .cbc_enc_dec(&key, true, &mut iv, &pt, &mut ct)
            .await
            .unwrap();
        assert_eq!(hex::encode(ct), "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
    }

    // ── ECB roundtrip (all key sizes) ───────────────────────────

    #[tokio::test]
    async fn ecb_roundtrip_128() {
        let driver = make_driver();
        let key = [0x33u8; 16];
        let plaintext = [0xAAu8; 16];
        let mut ct = [0u8; 16];
        driver
            .ecb_enc_dec(&key, true, &plaintext, &mut ct)
            .await
            .unwrap();
        let mut pt = [0u8; 16];
        driver.ecb_enc_dec(&key, false, &ct, &mut pt).await.unwrap();
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn ecb_roundtrip_192() {
        let driver = make_driver();
        let key = [0x44u8; 24];
        let plaintext = [0xBBu8; 32]; // 2 blocks
        let mut ct = [0u8; 32];
        driver
            .ecb_enc_dec(&key, true, &plaintext, &mut ct)
            .await
            .unwrap();
        let mut pt = [0u8; 32];
        driver.ecb_enc_dec(&key, false, &ct, &mut pt).await.unwrap();
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn ecb_roundtrip_256() {
        let driver = make_driver();
        let key = [0x66u8; 32];
        let plaintext = [0xCCu8; 48]; // 3 blocks
        let mut ct = [0u8; 48];
        driver
            .ecb_enc_dec(&key, true, &plaintext, &mut ct)
            .await
            .unwrap();
        let mut pt = [0u8; 48];
        driver.ecb_enc_dec(&key, false, &ct, &mut pt).await.unwrap();
        assert_eq!(pt, plaintext);
    }

    // ── ECB NIST vectors (NIST SP 800-38A) ──────────────────────

    /// NIST AESAVS ECBGFSbox128 — AES-128-ECB.
    #[tokio::test]
    async fn ecb_nist_128() {
        let driver = make_driver();
        let key = hex::decode("00000000000000000000000000000000").unwrap();
        let pt = hex::decode("f34481ec3cc627bacd5dc3fb08f273e6").unwrap();
        let mut ct = [0u8; 16];
        driver.ecb_enc_dec(&key, true, &pt, &mut ct).await.unwrap();
        assert_eq!(hex::encode(ct), "0336763e966d92595a567cc9ce537f5e");
    }

    /// NIST SP 800-38A F.1.3 — AES-192-ECB Encrypt.
    #[tokio::test]
    async fn ecb_nist_192() {
        let driver = make_driver();
        let key = hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver.ecb_enc_dec(&key, true, &pt, &mut ct).await.unwrap();
        assert_eq!(hex::encode(ct), "bd334f1d6e45f25ff712a214571fa5cc");
    }

    /// NIST SP 800-38A F.1.5 — AES-256-ECB Encrypt.
    #[tokio::test]
    async fn ecb_nist_256() {
        let driver = make_driver();
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver.ecb_enc_dec(&key, true, &pt, &mut ct).await.unwrap();
        assert_eq!(hex::encode(ct), "f3eed1bdb5d2a03c064b5a7e3db181f8");
    }
}
