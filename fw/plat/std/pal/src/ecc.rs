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
use azihsm_crypto::EccKeyOp;
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
    /// raw coordinates into the caller-provided buffer.
    async fn ecc_gen_keypair<'a>(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        key_out: &'a mut DmaBuf,
        _pct: HsmEccPct,
    ) -> HsmResult<(&'a DmaBuf, &'a DmaBuf)> {
        let (pk, pubk) = self.ecc.gen_keypair(to_ecc_curve(curve)).await?;

        // Export private key as PKCS#8 DER.
        let priv_len = pk.to_bytes(None).map_err(|_| HsmError::EccToDerError)?;
        let coord_len = curve.pub_key_len();
        if key_out.len() < priv_len + coord_len {
            return Err(HsmError::EccInvalidKeyLength);
        }

        let (priv_key, rest) = key_out.split_at_mut(priv_len);
        pk.to_bytes(Some(&mut priv_key[..priv_len]))
            .map_err(|_| HsmError::EccToDerError)?;

        // Export public key as raw coordinates (x ∥ y).
        let pub_key = &mut rest[..coord_len];
        let half = coord_len / 2;
        let (x_buf, y_buf) = pub_key.split_at_mut(half);
        pubk.coord(Some((&mut x_buf[..], &mut y_buf[..])))
            .map_err(|_| HsmError::EccToDerError)?;

        Ok((&*priv_key, &*pub_key))
    }

    /// Raw EC sign over a pre-computed hash digest.
    async fn ecc_sign(
        &self,
        _io: &impl HsmIo,
        _curve: HsmEccCurve,
        priv_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &mut DmaBuf,
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
    async fn ecc_verify(
        &self,
        _io: &impl HsmIo,
        _curve: HsmEccCurve,
        pub_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &DmaBuf,
    ) -> HsmResult<bool> {
        let key = EccPublicKey::from_bytes(pub_key).map_err(|_| HsmError::InvalidArg)?;
        self.ecc.ecc_verify(&key, hash, signature).await
    }

    /// ECDH key agreement — derives a shared secret.
    async fn ecdh_derive(
        &self,
        _io: &impl HsmIo,
        _curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pk = EccPrivateKey::from_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let pubk = EccPublicKey::from_bytes(pub_key).map_err(|_| HsmError::InvalidArg)?;
        self.ecc.ecdh_derive(&pk, &pubk, secret).await
    }
}
