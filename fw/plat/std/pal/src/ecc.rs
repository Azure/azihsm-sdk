// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmEcc`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (wire-format
//! bytes / PKCS#8 DER for private keys) and the
//! [`StdEcc`](crate::drivers::ecc::StdEcc) driver (OpenSSL key
//! handles + wire-LE byte interfaces).  Responsibilities at this
//! layer are deliberately limited to:
//!
//! 1. **Enum mapping** — [`HsmEccCurve`] → [`azihsm_crypto::EccCurve`].
//! 2. **Private-key DER round-trip** — exporting a freshly generated
//!    handle to PKCS#8 DER in [`ecc_gen_keypair`] and importing the
//!    DER blob back into a handle in [`ecc_sign`] / [`ecdh_derive`].
//! 3. **Delegation** — every wire-LE ↔ OpenSSL-BE byte flip lives
//!    inside the driver's `_le`-suffixed methods, so this layer is
//!    free of byte-shuffling boilerplate.  Real PKA hardware
//!    consumes the wire-LE format natively; the driver-side flips
//!    are an OpenSSL-backend artifact and not a host-visible
//!    firmware responsibility.
//!
//! ## Key formats at the trait boundary
//!
//! | Direction | Private key | Public key |
//! |-----------|-------------|------------|
//! | Trait → PAL (input)  | PKCS#8 DER `&DmaBuf` (variable, `≤ priv_key_der_max`) | Wire-LE `x \|\| y` `&DmaBuf` (`wire_pub_key_len` bytes, P-521 padded) |
//! | PAL → Trait (output) | PKCS#8 DER `&mut DmaBuf` (variable, `≤ priv_key_der_max`) | Wire-LE `x \|\| y` `&mut DmaBuf` (`wire_pub_key_len` bytes, P-521 padded) |
//! | PAL → Driver (internal) | `EccPrivateKey` handle | Wire-LE bytes (`_le` slices, P-521 padded) |
//! | Driver → OpenSSL (internal) | `EccPrivateKey` handle | `EccPublicKey` handle (raw BE coords) |
//!
//! The trait-level [`HsmEcc::ecc_gen_keypair`] query mode reports
//! [`HsmEccCurve::priv_key_der_max`] as the private-key upper bound
//! and [`HsmEccCurve::wire_pub_key_len`] as the public-key length;
//! the use mode returns the actual DER byte count (always
//! ≤ the query bound) and the deterministic public-key length
//! (equal to the query bound).  Real-HW PALs that emit raw scalars
//! instead report [`HsmEccCurve::priv_key_len`] in both modes; the
//! trait contract is `use ≤ query`.

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccPrivateKey;
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
    /// Generate an ECC key pair on the specified curve, query-alloc-use
    /// style.
    ///
    /// In **query mode** (`out = None`) returns the std-PAL upper
    /// bounds: PKCS#8 DER max for the private key
    /// ([`HsmEccCurve::priv_key_der_max`]) and the wire-format LE
    /// public-key length ([`HsmEccCurve::wire_pub_key_len`]).  In
    /// **use mode** (`out = Some((priv_out, pub_out))`) it asks the
    /// driver to generate a fresh keypair and write the wire-LE
    /// public key into a scoped scratch slot, then exports the
    /// private key as PKCS#8 DER into a separate scratch slot, and
    /// finally copies both into the caller's two output buffers.
    /// Returns the **actual** byte counts (DER is variable, so
    /// `priv_actual ≤ priv_max`; pub is deterministic).
    async fn ecc_gen_keypair(
        &self,
        _io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        curve: HsmEccCurve,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        let priv_max = curve.priv_key_der_max();
        let wire_pub_len = curve.wire_pub_key_len();

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_max, wire_pub_len));
        };

        if priv_out.len() < priv_max || pub_out.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }

        // Allocate the contiguous `priv || pub` scratch a real PKA
        // engine would write into.  The driver fills the pub half
        // directly in wire-LE form; we DER-serialize the priv half
        // ourselves.
        let scratch = alloc.dma_alloc(priv_max + wire_pub_len)?;
        let (scratch_priv, scratch_pub) = scratch.split_at_mut(priv_max);

        let pk = self
            .ecc
            .gen_keypair_le(to_ecc_curve(curve), scratch_pub)
            .await?;
        let priv_actual = pk
            .to_bytes(Some(&mut scratch_priv[..priv_max]))
            .map_err(|_| HsmError::EccToDerError)?;

        priv_out[..priv_actual].copy_from_slice(&scratch_priv[..priv_actual]);
        pub_out[..wire_pub_len].copy_from_slice(scratch_pub);

        Ok((priv_actual, wire_pub_len))
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Parses the PKCS#8 DER private key into an OpenSSL handle and
    /// delegates to the driver's wire-LE sign method, which performs
    /// the BE↔LE conversions internally.
    async fn ecc_sign(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &mut DmaBuf,
    ) -> HsmResult<()> {
        let wire_len = curve.wire_sig_len();
        if signature.len() < wire_len {
            return Err(HsmError::InvalidArg);
        }
        let key = EccPrivateKey::from_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        self.ecc
            .ecc_sign_le(&key, hash, &mut signature[..wire_len])
            .await
    }

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// Delegates to the driver's wire-LE verify method which
    /// constructs the OpenSSL pub-key handle from the wire-LE
    /// coordinates and performs BE↔LE conversions internally.
    async fn ecc_verify(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        pub_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &DmaBuf,
    ) -> HsmResult<bool> {
        let wire_pub_len = curve.wire_pub_key_len();
        let wire_sig_len = curve.wire_sig_len();
        if pub_key.len() < wire_pub_len || signature.len() < wire_sig_len {
            return Err(HsmError::InvalidArg);
        }
        self.ecc
            .ecc_verify_le(
                to_ecc_curve(curve),
                &pub_key[..wire_pub_len],
                hash,
                &signature[..wire_sig_len],
            )
            .await
    }

    /// ECDH key agreement — derives a shared secret.
    ///
    /// Parses the local PKCS#8 DER private into an OpenSSL handle
    /// and delegates to the driver's wire-LE ECDH method which
    /// constructs the remote pub-key handle internally from the
    /// wire-LE coordinates (stripping per-coordinate padding for
    /// P-521).
    async fn ecdh_derive(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
    ) -> HsmResult<()> {
        let wire_pub_len = curve.wire_pub_key_len();
        if pub_key.len() < wire_pub_len || secret.len() < curve.secret_len() {
            return Err(HsmError::InvalidArg);
        }
        let pk = EccPrivateKey::from_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        self.ecc
            .ecdh_derive_le(
                &pk,
                to_ecc_curve(curve),
                &pub_key[..wire_pub_len],
                &mut secret[..],
            )
            .await
    }
}
