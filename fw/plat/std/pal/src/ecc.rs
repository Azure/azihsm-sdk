// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmEcc`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (DER byte slices)
//! and the [`StdEcc`](crate::drivers::ecc::StdEcc) driver (OpenSSL
//! key handles). The PAL impl is responsible for:
//!
//! 1. **Enum mapping** — [`HsmEccCurve`] → [`azihsm_crypto::EccCurve`].
//! 2. **Key serialization** — exporting generated handles to DER bytes
//!    (PKCS#8 for private, SPKI for public) in [`ecc_gen_keypair`].
//! 3. **Key deserialization** — importing DER bytes into handles for
//!    [`ecc_sign`], [`ecc_verify`], and [`ecdh_derive`].
//!
//! ## Key formats
//!
//! | Direction | Private key | Public key |
//! |-----------|-------------|------------|
//! | Trait → PAL (input) | PKCS#8 DER `&[u8]` | SPKI DER `&[u8]` |
//! | PAL → Trait (output) | PKCS#8 DER `&mut [u8]` | SPKI DER `&mut [u8]` |
//! | PAL → Driver (internal) | `EccPrivateKey` handle | `EccPublicKey` handle |
//!
//! ## Data flow (sign example)
//!
//! ```text
//! Core calls pal.ecc_sign(curve, priv_key_der, hash, sig_buf)
//!   → EccPrivateKey::from_bytes(priv_key_der)  // DER → handle
//!   → self.ecc.ecc_sign(&handle, hash)         // driver
//!     → WorkerPool → OpenSSL ECDSA
//!   → sig_buf[..len].copy_from_slice(&sig)     // result → caller
//! ```

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::ImportableKey;

use super::*;

/// Map the PAL-level [`HsmEccCurve`] to the crypto library's
/// [`azihsm_crypto::EccCurve`].
fn to_ecc_curve(curve: HsmEccCurve) -> EccCurve {
    match curve {
        HsmEccCurve::P256 => EccCurve::P256,
        HsmEccCurve::P384 => EccCurve::P384,
        HsmEccCurve::P521 => EccCurve::P521,
    }
}

impl HsmEcc for StdHsmPal {
    /// Generate an ECC key pair on the specified curve.
    ///
    /// Delegates to [`StdEcc::gen_keypair`] which returns OpenSSL handles,
    /// then exports the private key as PKCS#8 DER and the public key as
    /// SPKI DER into the caller-provided buffers.
    ///
    /// # Parameters
    /// - `curve` — NIST curve (P-256, P-384, or P-521).
    /// - `priv_key` — Output buffer for PKCS#8 DER private key.
    /// - `pub_key` — Output buffer for SPKI DER public key.
    /// - `_pct` — Pairwise consistency test mode (currently ignored).
    ///
    /// # Errors
    /// - [`HsmError::EccGenerateError`] — key generation failed.
    /// - [`HsmError::EccToDerError`] — DER export failed.
    /// - [`HsmError::EccInvalidKeyLength`] — output buffer too small.
    async fn ecc_gen_keypair(
        &self,
        curve: HsmEccCurve,
        priv_key: &mut [u8],
        pub_key: &mut [u8],
        _pct: HsmEccPct,
    ) -> HsmResult<()> {
        let (pk, pubk) = self.ecc.gen_keypair(to_ecc_curve(curve)).await?;

        // Export private key as PKCS#8 DER.
        let priv_len = pk.to_bytes(None).map_err(|_| HsmError::EccToDerError)?;
        if priv_key.len() < priv_len {
            return Err(HsmError::EccInvalidKeyLength);
        }
        pk.to_bytes(Some(&mut priv_key[..priv_len]))
            .map_err(|_| HsmError::EccToDerError)?;

        // Export public key as SPKI DER.
        let pub_len = pubk.to_bytes(None).map_err(|_| HsmError::EccToDerError)?;
        if pub_key.len() < pub_len {
            return Err(HsmError::EccInvalidKeyLength);
        }
        pubk.to_bytes(Some(&mut pub_key[..pub_len]))
            .map_err(|_| HsmError::EccToDerError)?;

        Ok(())
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Imports the private key from PKCS#8 DER, delegates signing to
    /// the driver, and copies the raw `r ∥ s` signature into the
    /// caller's buffer.
    ///
    /// # Parameters
    /// - `_curve` — Curve hint (unused; curve is encoded in the DER key).
    /// - `priv_key` — PKCS#8 DER private key bytes.
    /// - `hash` — Pre-computed hash digest to sign.
    /// - `signature` — Output buffer (must be ≥ [`HsmEccCurve::sig_len`]).
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — DER import failed.
    /// - [`HsmError::EccSignFailed`] — signing failed or buffer too small.
    async fn ecc_sign(
        &self,
        _curve: HsmEccCurve,
        priv_key: &[u8],
        hash: &[u8],
        signature: &mut [u8],
    ) -> HsmResult<()> {
        let key = EccPrivateKey::from_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let sig = self.ecc.ecc_sign(&key, hash).await?;
        if signature.len() < sig.len() {
            return Err(HsmError::EccSignFailed);
        }
        signature[..sig.len()].copy_from_slice(&sig);
        Ok(())
    }

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// Imports the public key from SPKI DER, delegates verification
    /// to the driver.
    ///
    /// # Parameters
    /// - `_curve` — Curve hint (unused; curve is encoded in the DER key).
    /// - `pub_key` — SPKI DER public key bytes.
    /// - `hash` — Pre-computed hash digest that was signed.
    /// - `signature` — The raw `r ∥ s` signature to verify.
    ///
    /// # Returns
    /// `true` if valid, `false` otherwise.
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — DER import failed.
    /// - [`HsmError::EccVerifyFailed`] — OpenSSL verification error.
    async fn ecc_verify(
        &self,
        _curve: HsmEccCurve,
        pub_key: &[u8],
        hash: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        let key = EccPublicKey::from_bytes(pub_key).map_err(|_| HsmError::InvalidArg)?;
        self.ecc.ecc_verify(&key, hash, signature).await
    }

    /// ECDH key agreement — derives a shared secret.
    ///
    /// Imports both keys from DER, delegates ECDH to the driver, and
    /// writes the raw shared secret (x-coordinate) into `secret`.
    ///
    /// # Parameters
    /// - `_curve` — Curve hint (unused; curve is encoded in the DER keys).
    /// - `priv_key` — PKCS#8 DER local private key bytes.
    /// - `pub_key` — SPKI DER remote public key bytes.
    /// - `secret` — Output buffer (must be ≥ [`HsmEccCurve::secret_len`]).
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — DER import failed.
    /// - [`HsmError::EccDeriveError`] — ECDH computation failed or
    ///   output buffer too small.
    async fn ecdh_derive(
        &self,
        _curve: HsmEccCurve,
        priv_key: &[u8],
        pub_key: &[u8],
        secret: &mut [u8],
    ) -> HsmResult<()> {
        let pk = EccPrivateKey::from_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let pubk = EccPublicKey::from_bytes(pub_key).map_err(|_| HsmError::InvalidArg)?;
        self.ecc.ecdh_derive(&pk, &pubk, secret).await
    }
}
