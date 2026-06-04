// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std ECC driver — performs ECC operations via OpenSSL.
//!
//! Operates on [`azihsm_crypto`] key handle types directly
//! (`EccPrivateKey`, `EccPublicKey`). The public API accepts
//! references and slices; owned copies for the worker thread
//! boundary are made internally via `Clone` (cheap — OpenSSL
//! key handles are reference-counted).
//!
//! ## Supported operations
//!
//! | Method | Operation | Input | Output |
//! |--------|-----------|-------|--------|
//! | [`gen_keypair`] | Key generation | `EccCurve` | `(EccPrivateKey, EccPublicKey)` |
//! | [`ecc_sign`] | Raw EC sign | `&EccPrivateKey`, `&[u8]` hash | `Vec<u8>` (r∥s) |
//! | [`ecc_verify`] | Raw EC verify | `&EccPublicKey`, `&[u8]` hash, `&[u8]` sig | `bool` |
//! | [`ecdh_derive`] | ECDH agreement | `&EccPrivateKey`, `&EccPublicKey` | writes `&mut [u8]` |
//!
//! ## Thread model
//!
//! All methods clone handles and input slices into owned buffers,
//! then dispatch to the tokio [`WorkerPool`]. The Embassy executor
//! yields while the worker runs, then copies results back.
//!
//! On real Cortex-M7 hardware, these operations would be offloaded
//! to a PKA (Public Key Accelerator) engine via DMA.

use azihsm_crypto::DeriveOp;
use azihsm_crypto::EccAlgo;
use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::EcdhAlgo;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::PrivateKey;
use azihsm_crypto::SignOp;
use azihsm_crypto::VerifyOp;
use azihsm_fw_hsm_pal_traits::*;

use crate::worker::WorkerPool;

// On-wire-format helpers
//
// The std PAL accepts inputs and produces outputs in the wire-LE
// convention that real PKA hardware emits natively (`x_le || y_le`
// for public keys, `r_le || s_le` for signatures, with P-521
// components padded from 66 to 68 bytes per word).  The single
// `reverse_copy` helper centralizes the BE↔LE byte reversal so the
// `_le`-suffixed driver methods can stay free of byte-shuffling
// boilerplate.

/// Reverse-copy `src` into `dst[..src.len()]`.  Used for BE↔LE
/// component swaps; the direction is symmetric.  Trailing pad bytes
/// in `dst` (e.g. the 2-byte pad after a 66-byte P-521 coordinate
/// inside a 68-byte word) are left untouched — callers that need
/// them zeroed should pre-`fill(0)` the full `dst` slot.
fn reverse_copy(dst: &mut [u8], src: &[u8]) {
    let len = src.len();
    debug_assert!(dst.len() >= len);
    for (d, s) in dst[..len].iter_mut().zip(src.iter().rev()) {
        *d = *s;
    }
}

/// Std ECC driver — software ECC via OpenSSL with async worker dispatch.
pub struct StdEcc {
    pool: WorkerPool,
}

impl StdEcc {
    /// Create a new ECC driver backed by the given worker pool.
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    /// Generate an ECC key pair asynchronously.
    ///
    /// Returns the `(EccPrivateKey, EccPublicKey)` handle pair.
    /// Used by internal-firmware callers (`cert.rs`, `part.rs`)
    /// that work directly in OpenSSL handles and BE coordinates;
    /// PAL-trait callers should use [`Self::gen_keypair_le`]
    /// instead.
    pub async fn gen_keypair(&self, curve: EccCurve) -> HsmResult<(EccPrivateKey, EccPublicKey)> {
        self.pool
            .submit_with_result(async move {
                let priv_key =
                    EccPrivateKey::from_curve(curve).map_err(|_| HsmError::EccGenerateError)?;
                let pub_key = priv_key
                    .public_key()
                    .map_err(|_| HsmError::EccGetCoordinatesError)?;
                Ok((priv_key, pub_key))
            })
            .await
    }

    /// Generate an ECC key pair, returning the private-key handle
    /// and writing the public key in wire-LE `x_le || y_le` form
    /// (with P-521 padded to 68 bytes per coordinate) into
    /// `pub_le_out`.
    ///
    /// `pub_le_out.len()` must be `wire_pub_key_len(curve)`
    /// (64 / 96 / 136 for P-256 / P-384 / P-521).
    pub async fn gen_keypair_le(
        &self,
        curve: EccCurve,
        pub_le_out: &mut [u8],
    ) -> HsmResult<EccPrivateKey> {
        let (priv_key, pub_key) = self.gen_keypair(curve).await?;
        let coord_len = priv_key_len(curve);
        let wire_coord = wire_coord_len(curve);
        if pub_le_out.len() != wire_coord * 2 {
            return Err(HsmError::EccGetCoordinatesError);
        }
        let mut x_be = [0u8; 66];
        let mut y_be = [0u8; 66];
        pub_key
            .coord(Some((&mut x_be[..coord_len], &mut y_be[..coord_len])))
            .map_err(|_| HsmError::EccGetCoordinatesError)?;

        pub_le_out.fill(0);
        let (x_dst, y_dst) = pub_le_out.split_at_mut(wire_coord);
        reverse_copy(x_dst, &x_be[..coord_len]);
        reverse_copy(y_dst, &y_be[..coord_len]);
        Ok(priv_key)
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Clones the private key handle (cheap, ref-counted), copies the
    /// hash to an owned buffer, and dispatches to the worker pool.
    ///
    /// # Parameters
    /// - `priv_key` — The signing key handle.
    /// - `hash` — Pre-computed hash digest (e.g., SHA-256 output).
    ///
    /// # Returns
    /// The raw `r ∥ s` signature as a `Vec<u8>`. Length is
    /// `2 × curve.point_size()` (64 for P-256, 96 for P-384, 132 for P-521).
    ///
    /// # Errors
    /// Returns [`HsmError::EccSignFailed`] if the OpenSSL sign operation fails.
    pub async fn ecc_sign(&self, priv_key: &EccPrivateKey, hash: &[u8]) -> HsmResult<Vec<u8>> {
        let key = priv_key.clone();
        let hash_owned = hash.to_vec();
        self.pool
            .submit_with_result(async move {
                let sig_len = EccKeyOp::curve(&key).point_size() * 2;
                let mut sig = vec![0u8; sig_len];
                let mut algo = EccAlgo::default();
                algo.sign(&key, &hash_owned, Some(&mut sig))
                    .map_err(|_| HsmError::EccSignFailed)?;
                Ok(sig)
            })
            .await
    }

    /// Sign a wire-LE digest with an [`EccPrivateKey`] handle and
    /// write the wire-LE signature (`r_le || s_le`, P-521 padded)
    /// into `sig_le_out`.
    ///
    /// `sig_le_out.len()` must be `wire_sig_len(curve)`
    /// (64 / 96 / 136 for P-256 / P-384 / P-521).  `hash_le.len()`
    /// must not exceed SHA-512 (64 bytes); longer inputs are
    /// rejected rather than silently truncated.
    pub async fn ecc_sign_le(
        &self,
        priv_key: &EccPrivateKey,
        hash_le: &[u8],
        sig_le_out: &mut [u8],
    ) -> HsmResult<()> {
        let curve = EccKeyOp::curve(priv_key);
        let coord_len = priv_key_len(curve);
        let wire_coord = wire_coord_len(curve);
        if sig_le_out.len() != wire_coord * 2 {
            return Err(HsmError::EccSignFailed);
        }
        if hash_le.len() > 64 {
            return Err(HsmError::InvalidArg);
        }

        // Reverse wire-LE digest into BE scratch for OpenSSL.
        let mut hash_be = [0u8; 64];
        reverse_copy(&mut hash_be[..hash_le.len()], hash_le);

        let sig_be = self.ecc_sign(priv_key, &hash_be[..hash_le.len()]).await?;
        if sig_be.len() < coord_len * 2 {
            return Err(HsmError::EccSignFailed);
        }

        // Reverse each component into the LE wire layout.
        sig_le_out.fill(0);
        let (r_le_dst, rest) = sig_le_out.split_at_mut(wire_coord);
        let (s_le_dst, _) = rest.split_at_mut(wire_coord);
        let (r_be, s_be) = sig_be.split_at(coord_len);
        reverse_copy(r_le_dst, r_be);
        reverse_copy(s_le_dst, s_be);
        Ok(())
    }

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    pub async fn ecc_verify(
        &self,
        pub_key: &EccPublicKey,
        hash: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        let key = pub_key.clone();
        let hash_owned = hash.to_vec();
        let sig_owned = signature.to_vec();
        self.pool
            .submit_with_result(async move {
                let mut algo = EccAlgo::default();
                algo.verify(&key, &hash_owned, &sig_owned)
                    .map_err(|_| HsmError::EccVerifyFailed)
            })
            .await
    }

    /// Verify a wire-LE signature using a public key supplied as
    /// wire-LE `x || y` coordinates.  The driver constructs the
    /// OpenSSL pub-key handle and performs BE↔LE conversion plus
    /// P-521 per-coordinate de-padding internally so the PAL doesn't
    /// have to.
    ///
    /// `hash` is passed through to OpenSSL **unmodified** — the PAL
    /// trait's verify contract says "Raw digest bytes; no endianness
    /// conversion is applied", so callers pass the BE hash they got
    /// from SHA directly.  (The asymmetry with [`Self::ecc_sign_le`]
    /// matches the upstream trait contract; both internal
    /// firmware callers of verify pass BE digests.)
    ///
    /// `pub_le.len()` must be `wire_pub_key_len(curve)`
    /// (64 / 96 / 136 for P-256 / P-384 / P-521).
    /// `sig_le.len()` must be `wire_sig_len(curve)`
    /// (64 / 96 / 136 for P-256 / P-384 / P-521).
    pub async fn ecc_verify_le(
        &self,
        curve: EccCurve,
        pub_le: &[u8],
        hash: &[u8],
        sig_le: &[u8],
    ) -> HsmResult<bool> {
        let coord_len = priv_key_len(curve);
        let wire_coord = wire_coord_len(curve);
        let wire_len = wire_coord * 2;
        if pub_le.len() < wire_len || sig_le.len() < wire_len {
            return Err(HsmError::InvalidArg);
        }

        // Reverse each wire-LE coordinate (skipping any trailing
        // padding bytes for P-521) into OpenSSL-BE form.
        let (x_wire, y_wire) = pub_le[..wire_len].split_at(wire_coord);
        let mut x_be = [0u8; 66];
        let mut y_be = [0u8; 66];
        reverse_copy(&mut x_be[..coord_len], &x_wire[..coord_len]);
        reverse_copy(&mut y_be[..coord_len], &y_wire[..coord_len]);
        let key = EccPublicKey::from_coordinates(curve, &x_be[..coord_len], &y_be[..coord_len])
            .map_err(|_| HsmError::InvalidArg)?;

        let (r_wire, s_wire) = sig_le[..wire_len].split_at(wire_coord);
        let sig_len = coord_len * 2;
        let mut sig_be = [0u8; 132];
        reverse_copy(&mut sig_be[..coord_len], &r_wire[..coord_len]);
        reverse_copy(&mut sig_be[coord_len..sig_len], &s_wire[..coord_len]);

        self.ecc_verify(&key, hash, &sig_be[..sig_len]).await
    }

    /// ECDH key agreement — derives a shared secret into `secret`.
    ///
    /// Clones both key handles, dispatches ECDH computation to the worker
    /// pool, and copies the raw shared secret (x-coordinate of the
    /// shared point) into `secret`.
    ///
    /// # Parameters
    /// - `priv_key` — The local private key handle.
    /// - `pub_key` — The remote party's public key handle.
    /// - `secret` — Output buffer. Must be ≥ `curve.point_size()` bytes
    ///   (32 for P-256, 48 for P-384, 66 for P-521).
    ///
    /// # Errors
    /// - [`HsmError::EccDeriveError`] — ECDH computation, secret export,
    ///   or output buffer too small.
    pub async fn ecdh_derive(
        &self,
        priv_key: &EccPrivateKey,
        pub_key: &EccPublicKey,
        secret: &mut [u8],
    ) -> HsmResult<()> {
        let pk = priv_key.clone();
        let pubk = pub_key.clone();
        let result: HsmResult<Vec<u8>> = self
            .pool
            .submit_with_result(async move {
                let derived_len = EccKeyOp::curve(&pk).point_size();
                let ecdh = EcdhAlgo::new(&pubk);
                let derived = ecdh
                    .derive(&pk, derived_len)
                    .map_err(|_| HsmError::EccDeriveError)?;
                derived.to_vec().map_err(|_| HsmError::EccDeriveError)
            })
            .await;
        let bytes = result?;
        if secret.len() < bytes.len() {
            return Err(HsmError::EccDeriveError);
        }
        secret[..bytes.len()].copy_from_slice(&bytes);
        Ok(())
    }

    /// ECDH key agreement using a public key supplied as wire-LE
    /// `x || y` coordinates.  The driver constructs the OpenSSL
    /// pub-key handle internally, including stripping P-521
    /// per-coordinate padding.
    ///
    /// `pub_le.len()` must be `wire_pub_key_len(curve)`
    /// (64 / 96 / 136 for P-256 / P-384 / P-521).  The shared
    /// secret is written into `secret_out` in OpenSSL's native
    /// big-endian form — the trait contract leaves the secret
    /// endianness unspecified and current callers consume it as
    /// opaque HKDF input, so no flip is applied.
    pub async fn ecdh_derive_le(
        &self,
        priv_key: &EccPrivateKey,
        curve: EccCurve,
        pub_le: &[u8],
        secret_out: &mut [u8],
    ) -> HsmResult<()> {
        let coord_len = priv_key_len(curve);
        let wire_coord = wire_coord_len(curve);
        let wire_len = wire_coord * 2;
        if pub_le.len() < wire_len {
            return Err(HsmError::InvalidArg);
        }

        let (x_wire, y_wire) = pub_le[..wire_len].split_at(wire_coord);
        let mut x_be = [0u8; 66];
        let mut y_be = [0u8; 66];
        reverse_copy(&mut x_be[..coord_len], &x_wire[..coord_len]);
        reverse_copy(&mut y_be[..coord_len], &y_wire[..coord_len]);
        let pubk = EccPublicKey::from_coordinates(curve, &x_be[..coord_len], &y_be[..coord_len])
            .map_err(|_| HsmError::InvalidArg)?;

        self.ecdh_derive(priv_key, &pubk, secret_out).await
    }
}

/// Raw private-key (and per-coordinate) length in bytes for the
/// given curve.  Mirrors `HsmEccCurve::priv_key_len` but defined
/// in driver-local terms so the driver doesn't depend on the
/// PAL-trait crate's curve enum.
fn priv_key_len(curve: EccCurve) -> usize {
    match curve {
        EccCurve::P256 => 32,
        EccCurve::P384 => 48,
        EccCurve::P521 => 66,
    }
}

/// Wire-format per-coordinate length, padded to 32-bit words.
/// P-256/P-384 are already word-aligned (32 / 48); P-521 pads from
/// 66 to 68.
fn wire_coord_len(curve: EccCurve) -> usize {
    match curve {
        EccCurve::P256 => 32,
        EccCurve::P384 => 48,
        EccCurve::P521 => 68,
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdEcc {
        StdEcc::new(WorkerPool::new(Handle::current()))
    }

    // ── Key generation ──────────────────────────────────────────

    #[tokio::test]
    async fn gen_keypair_p256() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        assert_eq!(EccKeyOp::curve(&priv_key), EccCurve::P256);
        assert_eq!(pub_key.curve(), EccCurve::P256);
    }

    #[tokio::test]
    async fn gen_keypair_p384() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        assert_eq!(EccKeyOp::curve(&priv_key), EccCurve::P384);
        assert_eq!(pub_key.curve(), EccCurve::P384);
    }

    #[tokio::test]
    async fn gen_keypair_p521() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        assert_eq!(EccKeyOp::curve(&priv_key), EccCurve::P521);
        assert_eq!(pub_key.curve(), EccCurve::P521);
    }

    // ── Sign / verify roundtrip ─────────────────────────────────

    #[tokio::test]
    async fn sign_verify_p256() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        let hash = [0xABu8; 32];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert_eq!(sig.len(), 64);
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p384() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        let hash = [0xCDu8; 48];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert_eq!(sig.len(), 96);
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p521() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        let hash = [0xEFu8; 64];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert_eq!(sig.len(), 132);
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    // ── Verify with wrong hash ──────────────────────────────────

    #[tokio::test]
    async fn verify_wrong_hash_p256() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        let sig = driver.ecc_sign(&priv_key, &[0xAAu8; 32]).await.unwrap();
        assert!(!driver
            .ecc_verify(&pub_key, &[0xBBu8; 32], &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_wrong_hash_p384() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        let sig = driver.ecc_sign(&priv_key, &[0xAAu8; 48]).await.unwrap();
        assert!(!driver
            .ecc_verify(&pub_key, &[0xBBu8; 48], &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_wrong_hash_p521() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        let sig = driver.ecc_sign(&priv_key, &[0xAAu8; 64]).await.unwrap();
        assert!(!driver
            .ecc_verify(&pub_key, &[0xBBu8; 64], &sig)
            .await
            .unwrap());
    }

    // ── ECDH shared secret ──────────────────────────────────────

    #[tokio::test]
    async fn ecdh_p256() {
        let driver = make_driver();
        let (priv_a, pub_a) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        let (priv_b, pub_b) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        let mut secret_ab = [0u8; 32];
        let mut secret_ba = [0u8; 32];
        driver
            .ecdh_derive(&priv_a, &pub_b, &mut secret_ab)
            .await
            .unwrap();
        driver
            .ecdh_derive(&priv_b, &pub_a, &mut secret_ba)
            .await
            .unwrap();
        assert_eq!(secret_ab, secret_ba);
        assert_ne!(secret_ab, [0u8; 32]);
    }

    #[tokio::test]
    async fn ecdh_p384() {
        let driver = make_driver();
        let (priv_a, pub_a) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        let (priv_b, pub_b) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        let mut secret_ab = [0u8; 48];
        let mut secret_ba = [0u8; 48];
        driver
            .ecdh_derive(&priv_a, &pub_b, &mut secret_ab)
            .await
            .unwrap();
        driver
            .ecdh_derive(&priv_b, &pub_a, &mut secret_ba)
            .await
            .unwrap();
        assert_eq!(secret_ab, secret_ba);
        assert_ne!(secret_ab, [0u8; 48]);
    }

    #[tokio::test]
    async fn ecdh_p521() {
        let driver = make_driver();
        let (priv_a, pub_a) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        let (priv_b, pub_b) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        let mut secret_ab = [0u8; 66];
        let mut secret_ba = [0u8; 66];
        driver
            .ecdh_derive(&priv_a, &pub_b, &mut secret_ab)
            .await
            .unwrap();
        driver
            .ecdh_derive(&priv_b, &pub_a, &mut secret_ba)
            .await
            .unwrap();
        assert_eq!(secret_ab, secret_ba);
        assert_ne!(secret_ab, [0u8; 66]);
    }
}
