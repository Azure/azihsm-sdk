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
use azihsm_crypto::AesGcmAlgo;
use azihsm_crypto::AesKey;
use azihsm_crypto::AesKeyWrapPadAlgo;
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

    /// AES-256-GCM encrypt asynchronously.
    ///
    /// # Parameters
    /// - `key` — Raw AES-256 key bytes (must be exactly 32 bytes).
    /// - `iv` — 12-byte nonce.
    /// - `aad` — Optional additional authenticated data.
    /// - `plaintext` — Source data (any length).
    /// - `ciphertext` — Destination buffer (must be ≥ `plaintext.len()`).
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    pub async fn gcm_encrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad: Option<&[u8]>,
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HsmResult<()> {
        if key.len() != 32 {
            return Err(HsmError::AesInvalidKeyLength);
        }

        let key_owned = key.to_vec();
        let iv_owned = *iv;
        let aad_owned = aad.map(|a| a.to_vec());
        let pt_owned = plaintext.to_vec();
        let pt_len = plaintext.len();

        let (result_data, result_tag) = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&key_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesGcmAlgo::for_encrypt(&iv_owned, aad_owned.as_deref())
                    .map_err(|_| HsmError::AesEncryptFailed)?;
                let mut buf = vec![0u8; pt_len];
                algo.encrypt(&aes_key, &pt_owned, Some(&mut buf))
                    .map_err(|_| HsmError::AesEncryptFailed)?;
                let tag_out: [u8; 16] = algo
                    .tag()
                    .try_into()
                    .map_err(|_| HsmError::AesEncryptFailed)?;
                Ok::<_, HsmError>((buf, tag_out))
            })
            .await?;

        ciphertext[..result_data.len()].copy_from_slice(&result_data);
        tag.copy_from_slice(&result_tag);
        Ok(())
    }

    /// AES-256-GCM decrypt asynchronously.
    ///
    /// # Parameters
    /// - `key` — Raw AES-256 key bytes (must be exactly 32 bytes).
    /// - `iv` — 12-byte nonce used during encryption.
    /// - `aad` — Optional additional authenticated data.
    /// - `tag` — The 16-byte authentication tag.
    /// - `ciphertext` — Source data (any length).
    /// - `plaintext` — Destination buffer (must be ≥ `ciphertext.len()`).
    pub async fn gcm_decrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad: Option<&[u8]>,
        tag: &[u8; 16],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> HsmResult<()> {
        if key.len() != 32 {
            return Err(HsmError::AesInvalidKeyLength);
        }

        let key_owned = key.to_vec();
        let iv_owned = *iv;
        let aad_owned = aad.map(|a| a.to_vec());
        let tag_owned = *tag;
        let ct_owned = ciphertext.to_vec();
        let ct_len = ciphertext.len();

        let result_data = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&key_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesGcmAlgo::for_decrypt(&iv_owned, &tag_owned, aad_owned.as_deref())
                    .map_err(|_| HsmError::AesDecryptFailed)?;
                let mut buf = vec![0u8; ct_len];
                algo.decrypt(&aes_key, &ct_owned, Some(&mut buf))
                    .map_err(|_| HsmError::AesGcmDecryptTagDoesNotMatch)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;

        plaintext[..result_data.len()].copy_from_slice(&result_data);
        Ok(())
    }

    /// AES-KWP (RFC 5649) unwrap asynchronously.
    ///
    /// Unwraps `input` with the key-encryption key `kek`, verifying the
    /// RFC 5649 AIV and padding, and writes the recovered key material
    /// into `output`.  Byte-oriented — no endianness conversion.
    ///
    /// # Parameters
    /// - `kek` — key-encryption key (16, 24, or 32 bytes).
    /// - `input` — wrapped key material (multiple of 8 bytes, `>= 16`).
    /// - `output` — destination for the unwrapped key material.
    ///
    /// # Returns
    /// - `Ok(len)` — unwrapped plaintext length; `output[..len]` valid.
    ///
    /// # Errors
    /// - [`HsmError::AesInvalidKeyLength`] — `kek` is not a valid AES
    ///   key length.
    /// - [`HsmError::InvalidArg`] — `input`/`output` size-constraint
    ///   violation (RFC 5649: `input` must be >= 16 bytes, a multiple of 8,
    ///   and <= 3080; `output` must hold at least `input.len() - 8` bytes).
    /// - [`HsmError::AesUnwrapFailed`] — AIV/padding integrity check failed
    ///   (wrong key, tampering, or corruption).
    pub async fn kwp_unwrap(
        &self,
        kek: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<usize> {
        // RFC 5649 size constraints (per the `aes_kwp_unwrap` trait
        // contract): the wrapped input is >= 16 bytes, a multiple of 8, and
        // at most 3080 (round_up_8(3072) + the 8-byte AIV); the output holds
        // at least `input.len() - 8` bytes.  Violations are `InvalidArg` —
        // distinct from an integrity failure — matching the hardware PAL.
        if input.len() < 16 || !input.len().is_multiple_of(8) || input.len() > 3080 {
            return Err(HsmError::InvalidArg);
        }
        if output.len() < input.len() - 8 {
            return Err(HsmError::InvalidArg);
        }

        let kek_owned = kek.to_vec();
        let input_owned = input.to_vec();
        let out_len = output.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&kek_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesKeyWrapPadAlgo::default();
                let mut buf = vec![0u8; out_len];
                // Size is pre-validated above, so a failure here is an
                // AIV / padding integrity failure.
                let written = algo
                    .decrypt(&aes_key, &input_owned, Some(&mut buf))
                    .map_err(|_| HsmError::AesUnwrapFailed)?;
                buf.truncate(written);
                Ok::<_, HsmError>(buf)
            })
            .await?;

        output[..result.len()].copy_from_slice(&result);
        Ok(result.len())
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

    // ── GCM roundtrip (AES-256 only) ──────────────────────────────

    #[tokio::test]
    async fn gcm_roundtrip_256() {
        let driver = make_driver();
        let key = [0x77u8; 32];
        let iv = [0x03u8; 12];
        let plaintext = [0xEFu8; 64];

        let mut ct = [0u8; 64];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, None, &plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = [0u8; 64];
        driver
            .gcm_decrypt(&key, &iv, None, &tag, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    // ── GCM rejects non-256-bit keys ──────────────────────────────

    #[tokio::test]
    async fn gcm_rejects_128_bit_key() {
        let driver = make_driver();
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        let result = driver
            .gcm_encrypt(&key, &iv, None, &[0u8; 16], &mut ct, &mut tag)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn gcm_rejects_192_bit_key() {
        let driver = make_driver();
        let key = [0x42u8; 24];
        let iv = [0x01u8; 12];
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        let result = driver
            .gcm_encrypt(&key, &iv, None, &[0u8; 16], &mut ct, &mut tag)
            .await;
        assert!(result.is_err());
    }

    // ── GCM with AAD ────────────────────────────────────────────

    #[tokio::test]
    async fn gcm_roundtrip_with_aad() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x04u8; 12];
        let aad = b"authenticated header";
        let plaintext = b"secret payload data";

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, Some(aad), plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = vec![0u8; plaintext.len()];
        driver
            .gcm_decrypt(&key, &iv, Some(aad), &tag, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(&pt, plaintext);
    }

    #[tokio::test]
    async fn gcm_wrong_aad_fails() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x05u8; 12];
        let aad = b"correct header";
        let plaintext = b"payload";

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, Some(aad), plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = vec![0u8; plaintext.len()];
        let result = driver
            .gcm_decrypt(&key, &iv, Some(b"wrong header"), &tag, &ct, &mut pt)
            .await;
        assert_eq!(result.unwrap_err(), HsmError::AesGcmDecryptTagDoesNotMatch);
    }

    // ── GCM tag tamper detection ────────────────────────────────

    #[tokio::test]
    async fn gcm_tampered_tag_fails() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x06u8; 12];
        let plaintext = b"tamper test";

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, None, plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        tag[0] ^= 0xFF; // tamper
        let mut pt = vec![0u8; plaintext.len()];
        let result = driver
            .gcm_decrypt(&key, &iv, None, &tag, &ct, &mut pt)
            .await;
        assert_eq!(result.unwrap_err(), HsmError::AesGcmDecryptTagDoesNotMatch);
    }

    #[tokio::test]
    async fn gcm_tampered_ciphertext_fails() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x07u8; 12];
        let plaintext = b"tamper ct test!!";

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, None, plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        ct[0] ^= 0xFF; // tamper
        let mut pt = vec![0u8; plaintext.len()];
        let result = driver
            .gcm_decrypt(&key, &iv, None, &tag, &ct, &mut pt)
            .await;
        assert_eq!(result.unwrap_err(), HsmError::AesGcmDecryptTagDoesNotMatch);
    }

    // ── GCM empty plaintext ─────────────────────────────────────

    #[tokio::test]
    async fn gcm_empty_plaintext() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x08u8; 12];
        let aad = b"auth only, no payload";

        let mut ct = [];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, Some(aad), &[], &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = [];
        driver
            .gcm_decrypt(&key, &iv, Some(aad), &tag, &[], &mut pt)
            .await
            .unwrap();
    }

    // ── GCM non-block-aligned data ──────────────────────────────

    #[tokio::test]
    async fn gcm_non_block_aligned() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x09u8; 12];
        let plaintext = b"7 bytes"; // not a multiple of 16

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, None, plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = vec![0u8; plaintext.len()];
        driver
            .gcm_decrypt(&key, &iv, None, &tag, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(&pt, plaintext);
    }

    // ── GCM NIST test vector ────────────────────────────────────

    /// NIST GCM test vector — AES-256-GCM (from NIST SP 800-38D).
    /// Test Case 16: key=256, pt=256, aad=256, iv=96, tag=128.
    #[tokio::test]
    async fn gcm_nist_256() {
        let driver = make_driver();
        let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .unwrap();
        let iv_vec = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let iv: [u8; 12] = iv_vec.try_into().unwrap();
        let pt = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();

        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, Some(&aad), &pt, &mut ct, &mut tag)
            .await
            .unwrap();

        let expected_ct = hex::decode(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        )
        .unwrap();
        let expected_tag = hex::decode("76fc6ece0f4e1768cddf8853bb2d551b").unwrap();

        assert_eq!(ct, expected_ct);
        assert_eq!(&tag[..], &expected_tag[..]);

        // Verify decrypt produces original plaintext
        let mut dec_pt = vec![0u8; ct.len()];
        driver
            .gcm_decrypt(&key, &iv, Some(&aad), &tag, &ct, &mut dec_pt)
            .await
            .unwrap();
        assert_eq!(dec_pt, pt);
    }

    // ── AES-KWP unwrap (RFC 5649) round-trip ────────────────────

    #[tokio::test]
    async fn kwp_unwrap_roundtrip() {
        let driver = make_driver();
        let kek = [0x42u8; 32]; // AES-256 KEK

        // Wrap a representative payload whose length is not a multiple of
        // 8 (47 bytes), so RFC 5649 pads it to the next 8-byte boundary
        // (exercising the padding / unpadding path).
        let payload: Vec<u8> = (0..47u8).collect();
        let mut wrapped = vec![0u8; payload.len() + 16];
        let wrapped_len = {
            let kek_key = AesKey::from_bytes(&kek).unwrap();
            let mut algo = AesKeyWrapPadAlgo::default();
            algo.encrypt(&kek_key, &payload, Some(&mut wrapped))
                .unwrap()
        };
        wrapped.truncate(wrapped_len);

        let mut out = vec![0u8; payload.len() + 8];
        let len = driver.kwp_unwrap(&kek, &wrapped, &mut out).await.unwrap();
        assert_eq!(&out[..len], &payload[..]);
    }

    #[tokio::test]
    async fn kwp_unwrap_tamper_fails() {
        let driver = make_driver();
        let kek = [0x42u8; 32];

        let payload: Vec<u8> = (0..32u8).collect();
        let mut wrapped = vec![0u8; payload.len() + 16];
        let wrapped_len = {
            let kek_key = AesKey::from_bytes(&kek).unwrap();
            let mut algo = AesKeyWrapPadAlgo::default();
            algo.encrypt(&kek_key, &payload, Some(&mut wrapped))
                .unwrap()
        };
        wrapped.truncate(wrapped_len);
        wrapped[0] ^= 0xff; // corrupt the AIV → integrity check must fail

        let mut out = vec![0u8; payload.len() + 8];
        let res = driver.kwp_unwrap(&kek, &wrapped, &mut out).await;
        assert_eq!(res.unwrap_err(), HsmError::AesUnwrapFailed);
    }

    #[tokio::test]
    async fn kwp_unwrap_rejects_bad_sizes() {
        let driver = make_driver();
        let kek = [0x42u8; 32];
        let mut out = vec![0u8; 4096];

        // Too short (< 16 bytes).
        let short = [0u8; 8];
        assert_eq!(
            driver.kwp_unwrap(&kek, &short, &mut out).await.unwrap_err(),
            HsmError::InvalidArg
        );

        // Not a multiple of 8.
        let unaligned = [0u8; 20];
        assert_eq!(
            driver
                .kwp_unwrap(&kek, &unaligned, &mut out)
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );

        // Larger than the 3080-byte maximum.
        let oversized = vec![0u8; 3088];
        assert_eq!(
            driver
                .kwp_unwrap(&kek, &oversized, &mut out)
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );

        // Output too small (< input.len() - 8).
        let input = [0u8; 24];
        let mut tiny = vec![0u8; 8];
        assert_eq!(
            driver
                .kwp_unwrap(&kek, &input, &mut tiny)
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );
    }
}
