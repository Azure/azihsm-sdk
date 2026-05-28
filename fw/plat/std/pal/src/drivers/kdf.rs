// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std KDF driver — performs key derivation via OpenSSL.
//!
//! Takes raw key bytes and a [`HashAlgo`] and offloads HKDF / KBKDF
//! derivation to the [`WorkerPool`]. Exposes an async API that mirrors
//! hardware key derivation engine peripherals which yield while the
//! engine processes data.
//!
//! ## Supported algorithms
//!
//! | KDF algorithm | Hash algorithms      | Reference             |
//! |---------------|----------------------|-----------------------|
//! | HKDF          | SHA-256/384/512      | RFC 5869              |
//! | KBKDF (CTR)   | SHA-256/384/512      | NIST SP 800-108       |
//!
//! ## HKDF modes
//!
//! | Mode              | Description                             |
//! |-------------------|-----------------------------------------|
//! | Extract           | Condense IKM + salt → PRK               |
//! | Expand            | Expand PRK + info → OKM                 |
//! | ExtractAndExpand  | Full HKDF (extract then expand)         |
//!
//! ## Thread model
//!
//! All methods copy inputs to owned buffers internally, dispatch the
//! OpenSSL KDF operation on the tokio worker pool, then write results
//! directly into the caller's `&mut [u8]` output buffers.

use azihsm_crypto::DeriveOp;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::GenericSecretKey;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HkdfAlgo;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::KbkdfAlgo;
use azihsm_fw_hsm_pal_traits::*;

use crate::worker::WorkerPool;

/// Std KDF driver — software HKDF/KBKDF via OpenSSL with async worker dispatch.
///
/// Created once during PAL initialization and shared across all IO tasks.
pub struct StdKdf {
    pool: WorkerPool,
}

impl StdKdf {
    /// Create a new KDF driver backed by the given worker pool.
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    /// Derive key material using HKDF (RFC 5869) asynchronously.
    ///
    /// # Parameters
    /// - `key` — Input key material (IKM) or pseudorandom key (PRK),
    ///   depending on `mode`.
    /// - `hash_algo` — The hash algorithm for the underlying HMAC
    ///   (e.g., `HashAlgo::sha256()`).
    /// - `mode` — Which HKDF phase(s) to perform.
    /// - `salt` — Optional salt value. Pass an empty slice to use the
    ///   default salt.
    /// - `info` — Context and application-specific info. Pass an empty
    ///   slice if not needed.
    /// - `output` — Buffer for the derived output key material (OKM).
    ///   The buffer length determines how many bytes are derived.
    ///
    /// # Errors
    /// Returns [`HsmError::KdfError`] if the HKDF operation fails.
    pub async fn hkdf(
        &self,
        key: &[u8],
        hash_algo: HashAlgo,
        mode: azihsm_crypto::HkdfMode,
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        let key_owned = key.to_vec();
        let salt_owned = salt.to_vec();
        let info_owned = info.to_vec();
        let derive_len = output.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let input_key =
                    GenericSecretKey::from_bytes(&key_owned).map_err(|_| HsmError::HkdfError)?;
                let salt_opt = if salt_owned.is_empty() {
                    None
                } else {
                    Some(salt_owned.as_slice())
                };
                let info_opt = if info_owned.is_empty() {
                    None
                } else {
                    Some(info_owned.as_slice())
                };
                let algo = HkdfAlgo::new(mode, &hash_algo, salt_opt, info_opt);
                let derived = algo
                    .derive(&input_key, derive_len)
                    .map_err(|_| HsmError::HkdfError)?;
                let bytes: Vec<u8> = derived.to_vec().map_err(|_| HsmError::HkdfError)?;
                Ok::<Vec<u8>, HsmError>(bytes)
            })
            .await?;

        output.copy_from_slice(&result);
        Ok(())
    }

    /// Derive key material using KBKDF in Counter Mode (NIST SP 800-108)
    /// asynchronously.
    ///
    /// # Parameters
    /// - `key` — The key-derivation key (KDK).
    /// - `hash_algo` — The HMAC hash algorithm (e.g., `HashAlgo::sha256()`).
    /// - `label` — A string identifying the purpose of the derived key.
    ///   Pass an empty slice if not needed.
    /// - `context` — Context information binding the derived key to a
    ///   specific use. Pass an empty slice if not needed.
    /// - `output` — Buffer for the derived key material. The buffer
    ///   length determines how many bytes are derived.
    ///
    /// # Errors
    /// Returns [`HsmError::KdfError`] if the KBKDF operation fails.
    pub async fn kbkdf(
        &self,
        key: &[u8],
        hash_algo: HashAlgo,
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        let key_owned = key.to_vec();
        let label_owned = label.to_vec();
        let context_owned = context.to_vec();
        let derive_len = output.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let input_key =
                    GenericSecretKey::from_bytes(&key_owned).map_err(|_| HsmError::KbkdfError)?;
                let label_opt = if label_owned.is_empty() {
                    None
                } else {
                    Some(label_owned)
                };
                let context_opt = if context_owned.is_empty() {
                    None
                } else {
                    Some(context_owned)
                };
                let algo = KbkdfAlgo::with_len(hash_algo, label_opt, context_opt);
                let derived = algo
                    .derive(&input_key, derive_len)
                    .map_err(|_| HsmError::KbkdfError)?;
                let bytes: Vec<u8> = derived.to_vec().map_err(|_| HsmError::KbkdfError)?;
                Ok::<Vec<u8>, HsmError>(bytes)
            })
            .await?;

        output.copy_from_slice(&result);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdKdf {
        StdKdf::new(WorkerPool::new(Handle::current()))
    }

    // ── HKDF tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn hkdf_extract_and_expand_sha256() {
        let driver = make_driver();
        let key = [0xaau8; 32];
        let salt = b"test-salt";
        let info = b"test-info";
        let mut output = [0u8; 32];
        driver
            .hkdf(
                &key,
                HashAlgo::sha256(),
                azihsm_crypto::HkdfMode::ExtractAndExpand,
                salt,
                info,
                &mut output,
            )
            .await
            .unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[tokio::test]
    async fn hkdf_extract_and_expand_sha384() {
        let driver = make_driver();
        let key = [0xbbu8; 48];
        let salt = b"test-salt";
        let info = b"test-info";
        let mut output = [0u8; 48];
        driver
            .hkdf(
                &key,
                HashAlgo::sha384(),
                azihsm_crypto::HkdfMode::ExtractAndExpand,
                salt,
                info,
                &mut output,
            )
            .await
            .unwrap();
        assert_ne!(output, [0u8; 48]);
    }

    #[tokio::test]
    async fn hkdf_extract_and_expand_sha512() {
        let driver = make_driver();
        let key = [0xccu8; 64];
        let salt = b"test-salt";
        let info = b"test-info";
        let mut output = [0u8; 64];
        driver
            .hkdf(
                &key,
                HashAlgo::sha512(),
                azihsm_crypto::HkdfMode::ExtractAndExpand,
                salt,
                info,
                &mut output,
            )
            .await
            .unwrap();
        assert_ne!(output, [0u8; 64]);
    }

    #[tokio::test]
    async fn hkdf_extract_only_sha256() {
        let driver = make_driver();
        let key = [0xaau8; 32];
        let salt = b"extract-salt";
        let mut prk = [0u8; 32];
        driver
            .hkdf(
                &key,
                HashAlgo::sha256(),
                azihsm_crypto::HkdfMode::Extract,
                salt,
                &[],
                &mut prk,
            )
            .await
            .unwrap();
        assert_ne!(prk, [0u8; 32]);
    }

    #[tokio::test]
    async fn hkdf_expand_only_sha256() {
        let driver = make_driver();
        let key = [0xaau8; 32];
        let salt = b"expand-salt";

        // First extract a PRK.
        let mut prk = [0u8; 32];
        driver
            .hkdf(
                &key,
                HashAlgo::sha256(),
                azihsm_crypto::HkdfMode::Extract,
                salt,
                &[],
                &mut prk,
            )
            .await
            .unwrap();

        // Then expand the PRK to 64 bytes.
        let mut okm = [0u8; 64];
        driver
            .hkdf(
                &prk,
                HashAlgo::sha256(),
                azihsm_crypto::HkdfMode::Expand,
                &[],
                b"expand-info",
                &mut okm,
            )
            .await
            .unwrap();
        assert_ne!(okm, [0u8; 64]);
    }

    /// RFC 5869 Test Case 1 — HKDF-SHA-256.
    ///
    /// IKM  = 0x0b repeated 22 times
    /// salt = 0x000102030405060708090a0b0c
    /// info = 0xf0f1f2f3f4f5f6f7f8f9
    /// L    = 42
    /// OKM  = 3cb25f25faacd57a90434f64d0362f2a
    ///        2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    ///        34007208d5b887185865
    #[tokio::test]
    async fn hkdf_known_vector_sha256() {
        let driver = make_driver();
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut okm = [0u8; 42];
        driver
            .hkdf(
                &ikm,
                HashAlgo::sha256(),
                azihsm_crypto::HkdfMode::ExtractAndExpand,
                &salt,
                &info,
                &mut okm,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    // ── KBKDF tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn kbkdf_sha256() {
        let driver = make_driver();
        let key = [0xddu8; 32];
        let label = b"kbkdf-label";
        let context = b"kbkdf-context";
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        driver
            .kbkdf(&key, HashAlgo::sha256(), label, context, &mut out1)
            .await
            .unwrap();
        driver
            .kbkdf(&key, HashAlgo::sha256(), label, context, &mut out2)
            .await
            .unwrap();
        assert_ne!(out1, [0u8; 32]);
        assert_eq!(out1, out2, "same inputs must produce same output");
    }

    #[tokio::test]
    async fn kbkdf_sha384() {
        let driver = make_driver();
        let key = [0xeeu8; 48];
        let mut output = [0u8; 48];
        driver
            .kbkdf(&key, HashAlgo::sha384(), b"label", b"ctx", &mut output)
            .await
            .unwrap();
        assert_ne!(output, [0u8; 48]);
    }

    #[tokio::test]
    async fn kbkdf_sha512() {
        let driver = make_driver();
        let key = [0xffu8; 64];
        let mut output = [0u8; 64];
        driver
            .kbkdf(&key, HashAlgo::sha512(), b"label", b"ctx", &mut output)
            .await
            .unwrap();
        assert_ne!(output, [0u8; 64]);
    }

    #[tokio::test]
    async fn kbkdf_different_label() {
        let driver = make_driver();
        let key = [0xddu8; 32];
        let context = b"same-context";
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        driver
            .kbkdf(&key, HashAlgo::sha256(), b"label-a", context, &mut out_a)
            .await
            .unwrap();
        driver
            .kbkdf(&key, HashAlgo::sha256(), b"label-b", context, &mut out_b)
            .await
            .unwrap();
        assert_ne!(
            out_a, out_b,
            "different labels must produce different output"
        );
    }

    #[tokio::test]
    async fn kbkdf_different_context() {
        let driver = make_driver();
        let key = [0xddu8; 32];
        let label = b"same-label";
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        driver
            .kbkdf(&key, HashAlgo::sha256(), label, b"ctx-a", &mut out_a)
            .await
            .unwrap();
        driver
            .kbkdf(&key, HashAlgo::sha256(), label, b"ctx-b", &mut out_b)
            .await
            .unwrap();
        assert_ne!(
            out_a, out_b,
            "different contexts must produce different output"
        );
    }
}
