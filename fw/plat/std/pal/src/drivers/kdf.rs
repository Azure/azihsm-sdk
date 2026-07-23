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

/// Copies an optional KDF input into an owned buffer for the worker
/// closure, treating a present-but-empty slice as absent (`None`).
///
/// Salt / info / label / context are all optional; a zero-length
/// slice is collapsed to `None` so the empty and omitted cases stay
/// byte-identical and OpenSSL is never handed an explicit empty input.
fn owned_nonempty(input: Option<&[u8]>) -> Option<Vec<u8>> {
    input.filter(|s| !s.is_empty()).map(<[u8]>::to_vec)
}

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
    /// - `salt` — Optional salt value. `None` selects the default
    ///   salt.
    /// - `info` — Optional context / application-specific info.
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
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output: &mut [u8],
    ) -> HsmResult<()> {
        let key_owned = key.to_vec();
        let salt_owned = owned_nonempty(salt);
        let info_owned = owned_nonempty(info);
        let derive_len = output.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let input_key =
                    GenericSecretKey::from_bytes(&key_owned).map_err(|_| HsmError::HkdfError)?;
                let algo = HkdfAlgo::new(
                    mode,
                    &hash_algo,
                    salt_owned.as_deref(),
                    info_owned.as_deref(),
                );
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
    /// - `label` — Optional string identifying the purpose of the
    ///   derived key.
    /// - `context` — Optional context information binding the derived
    ///   key to a specific use.
    /// - `output` — Buffer for the derived key material. The buffer
    ///   length determines how many bytes are derived.
    ///
    /// # Errors
    /// Returns [`HsmError::KdfError`] if the KBKDF operation fails.
    pub async fn kbkdf(
        &self,
        key: &[u8],
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        context: Option<&[u8]>,
        output: &mut [u8],
    ) -> HsmResult<()> {
        let key_owned = key.to_vec();
        let label_owned = owned_nonempty(label);
        let context_owned = owned_nonempty(context);
        let derive_len = output.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let input_key =
                    GenericSecretKey::from_bytes(&key_owned).map_err(|_| HsmError::KbkdfError)?;
                let algo = KbkdfAlgo::with_len(hash_algo, label_owned, context_owned);
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
                Some(salt),
                Some(info),
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
                Some(salt),
                Some(info),
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
                Some(salt),
                Some(info),
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
                Some(salt),
                None,
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
                Some(salt),
                None,
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
                None,
                Some(b"expand-info"),
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
                Some(&salt),
                Some(&info),
                &mut okm,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    /// RFC 5869 Test Case 1 inputs derived under SHA-384. RFC 5869
    /// publishes vectors only for SHA-256 and SHA-1; the SHA-384 output
    /// is the standard HKDF construction over the same inputs.
    #[tokio::test]
    async fn hkdf_known_vector_sha384() {
        let driver = make_driver();
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut okm = [0u8; 42];
        driver
            .hkdf(
                &ikm,
                HashAlgo::sha384(),
                azihsm_crypto::HkdfMode::ExtractAndExpand,
                Some(&salt),
                Some(&info),
                &mut okm,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f7\
             48b6457763e4f0204fc5"
        );
    }

    /// RFC 5869 Test Case 1 inputs derived under SHA-512.
    #[tokio::test]
    async fn hkdf_known_vector_sha512() {
        let driver = make_driver();
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut okm = [0u8; 42];
        driver
            .hkdf(
                &ikm,
                HashAlgo::sha512(),
                azihsm_crypto::HkdfMode::ExtractAndExpand,
                Some(&salt),
                Some(&info),
                &mut okm,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c14815793\
             38da362cb8d9f925d7cb"
        );
    }

    /// RFC 5869 Test Case 3 — HKDF-SHA-256 with empty salt and empty
    /// info. Exercises the zero-length salt (default all-zero salt) and
    /// zero-length info bounds.
    #[tokio::test]
    async fn hkdf_known_vector_empty_salt_info_sha256() {
        let driver = make_driver();
        let ikm = [0x0bu8; 22];
        let mut okm = [0u8; 42];
        driver
            .hkdf(
                &ikm,
                HashAlgo::sha256(),
                azihsm_crypto::HkdfMode::ExtractAndExpand,
                None,
                None,
                &mut okm,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        );
    }

    /// RFC 5869 Test Case 2 — HKDF-SHA-256 with longer inputs and an
    /// 82-byte output that spans multiple expand blocks (L bound).
    #[tokio::test]
    async fn hkdf_known_vector_long_output_sha256() {
        let driver = make_driver();
        let ikm: Vec<u8> = (0x00u8..0x50).collect();
        let salt: Vec<u8> = (0x60u8..0xb0).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();
        let mut okm = [0u8; 82];
        driver
            .hkdf(
                &ikm,
                HashAlgo::sha256(),
                azihsm_crypto::HkdfMode::ExtractAndExpand,
                Some(&salt),
                Some(&info),
                &mut okm,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
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
            .kbkdf(
                &key,
                HashAlgo::sha256(),
                Some(label),
                Some(context),
                &mut out1,
            )
            .await
            .unwrap();
        driver
            .kbkdf(
                &key,
                HashAlgo::sha256(),
                Some(label),
                Some(context),
                &mut out2,
            )
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
            .kbkdf(
                &key,
                HashAlgo::sha384(),
                Some(b"label"),
                Some(b"ctx"),
                &mut output,
            )
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
            .kbkdf(
                &key,
                HashAlgo::sha512(),
                Some(b"label"),
                Some(b"ctx"),
                &mut output,
            )
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
            .kbkdf(
                &key,
                HashAlgo::sha256(),
                Some(b"label-a"),
                Some(context),
                &mut out_a,
            )
            .await
            .unwrap();
        driver
            .kbkdf(
                &key,
                HashAlgo::sha256(),
                Some(b"label-b"),
                Some(context),
                &mut out_b,
            )
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
            .kbkdf(
                &key,
                HashAlgo::sha256(),
                Some(label),
                Some(b"ctx-a"),
                &mut out_a,
            )
            .await
            .unwrap();
        driver
            .kbkdf(
                &key,
                HashAlgo::sha256(),
                Some(label),
                Some(b"ctx-b"),
                &mut out_b,
            )
            .await
            .unwrap();
        assert_ne!(
            out_a, out_b,
            "different contexts must produce different output"
        );
    }

    // ── KBKDF known-answer vectors ──────────────────────────────
    //
    // NIST SP 800-108 counter mode with the fixed input
    //   [i]_32 || Label || 0x00 || Context || [L]_32
    // (counter and length big-endian, L in bits), matching the
    // `KbkdfAlgo::with_len` construction the driver uses. Expected
    // outputs are the HMAC-PRF evaluation of that input.

    /// SP 800-108 counter-mode KBKDF — HMAC-SHA-256, single block.
    #[tokio::test]
    async fn kbkdf_known_vector_sha256() {
        let driver = make_driver();
        let key = [0xddu8; 32];
        let mut out = [0u8; 32];
        driver
            .kbkdf(
                &key,
                HashAlgo::sha256(),
                Some(b"kbkdf-label"),
                Some(b"kbkdf-context"),
                &mut out,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(out),
            "e560d64c75e23eeaab02c3a97d0edd7a96ca2126ad4f1f7ec6da612f2569d7e0"
        );
    }

    /// SP 800-108 counter-mode KBKDF — HMAC-SHA-384, single block.
    #[tokio::test]
    async fn kbkdf_known_vector_sha384() {
        let driver = make_driver();
        let key = [0xeeu8; 48];
        let mut out = [0u8; 48];
        driver
            .kbkdf(
                &key,
                HashAlgo::sha384(),
                Some(b"label"),
                Some(b"ctx"),
                &mut out,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(out),
            "a47a5ef8d053aa0e681010f3bf67a198ac4d94a8b009dee22a1f6f0e445749e1\
             c0e0440d65e7b7c9d8a07a52d1b41ee1"
        );
    }

    /// SP 800-108 counter-mode KBKDF — HMAC-SHA-512, single block.
    #[tokio::test]
    async fn kbkdf_known_vector_sha512() {
        let driver = make_driver();
        let key = [0xffu8; 64];
        let mut out = [0u8; 64];
        driver
            .kbkdf(
                &key,
                HashAlgo::sha512(),
                Some(b"label"),
                Some(b"ctx"),
                &mut out,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(out),
            "854d6e6ecee15d956abf29e5ae3e4103ac8f9e639006f9b05c3f4a673f15b123\
             c6b4ffcd537479c20651c7b213caf04679aefde5cd16c9ae692b8a4b79d8aa77"
        );
    }

    /// SP 800-108 counter-mode KBKDF — HMAC-SHA-256 with a 64-byte
    /// output spanning two counter blocks, exercising the multi-round
    /// counter concatenation.
    #[tokio::test]
    async fn kbkdf_known_vector_multiblock_sha256() {
        let driver = make_driver();
        let key = [0xddu8; 32];
        let mut out = [0u8; 64];
        driver
            .kbkdf(
                &key,
                HashAlgo::sha256(),
                Some(b"kbkdf-label"),
                Some(b"kbkdf-context"),
                &mut out,
            )
            .await
            .unwrap();
        assert_eq!(
            hex::encode(out),
            "744f238545b9cf9e9f3b1040354734895c24739d2c98f464c9077b65f268cadd\
             75c760020f9aa1aec8e39779dd8e439065915349bab1081720130484ae06b81b"
        );
    }
}
