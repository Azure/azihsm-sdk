// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmEcc`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (raw HSM
//! wire-format bytes) and the
//! [`StdEcc`](crate::drivers::ecc::StdEcc) driver (OpenSSL key
//! handles + wire-LE byte interfaces).  Responsibilities at this
//! layer are deliberately limited to:
//!
//! 1. **Enum mapping** — [`HsmEccCurve`] → [`azihsm_crypto::EccCurve`].
//! 2. **Private-key HSM round-trip** — exporting a freshly generated
//!    handle to the raw HSM scalar in [`ecc_gen_keypair`] and
//!    importing the scalar back into a handle in [`ecc_sign`] /
//!    [`ecdh_derive`].
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
//! | Trait → PAL (input)  | Raw HSM scalar `&DmaBuf` (`wire_coord_len` bytes, P-521 padded) | Wire-LE `x \|\| y` `&DmaBuf` (`wire_pub_key_len` bytes, P-521 padded) |
//! | PAL → Trait (output) | Raw HSM scalar `&mut DmaBuf` (`wire_coord_len` bytes, P-521 padded) | Wire-LE `x \|\| y` `&mut DmaBuf` (`wire_pub_key_len` bytes, P-521 padded) |
//! | PAL → Driver (internal) | `EccPrivateKey` handle | Wire-LE bytes (`_le` slices, P-521 padded) |
//! | Driver → OpenSSL (internal) | `EccPrivateKey` handle | `EccPublicKey` handle (raw BE coords) |
//!
//! The trait-level [`HsmEcc::ecc_gen_keypair`] query mode reports
//! [`HsmEccCurve::wire_coord_len`] as the private-key length and
//! [`HsmEccCurve::wire_pub_key_len`] as the public-key length; use
//! mode returns the same deterministic sizes.

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::ExportableHsmKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::PrivateKey;

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

/// Map the crypto library's [`azihsm_crypto::EccCurve`] back to the
/// PAL-level [`HsmEccCurve`].
fn from_ecc_curve(curve: EccCurve) -> HsmEccCurve {
    match curve {
        EccCurve::P256 => HsmEccCurve::P256,
        EccCurve::P384 => HsmEccCurve::P384,
        EccCurve::P521 => HsmEccCurve::P521,
    }
}

impl HsmEcc for StdHsmPal {
    /// Generate an ECC key pair on the specified curve, query-alloc-use
    /// style.
    ///
    /// In **query mode** (`out = None`) returns the std-PAL upper
    /// bounds: raw HSM scalar size for the private key
    /// ([`HsmEccCurve::wire_coord_len`]) and the wire-format LE
    /// public-key length ([`HsmEccCurve::wire_pub_key_len`]).  In
    /// **use mode** (`out = Some((priv_out, pub_out))`) it asks the
    /// driver to generate a fresh keypair and write the wire-LE
    /// public key into a scoped scratch slot, then exports the
    /// private key as raw HSM-format scalar bytes into a separate
    /// scratch slot, and finally copies both into the caller's two
    /// output buffers.  Returns the actual byte counts written
    /// (both deterministic for raw HSM bytes).
    async fn ecc_gen_keypair(
        &self,
        _io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        curve: HsmEccCurve,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        let priv_len = curve.wire_coord_len();
        let wire_pub_len = curve.wire_pub_key_len();

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, wire_pub_len));
        };

        if priv_out.len() < priv_len || pub_out.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }

        // Allocate the contiguous `priv || pub` scratch a real PKA
        // engine would write into.  The driver fills the pub half
        // directly in wire-LE form; we HSM-serialize the priv half
        // ourselves.
        let scratch = alloc.dma_alloc(priv_len + wire_pub_len)?;
        let (scratch_priv, scratch_pub) = scratch.split_at_mut(priv_len);

        let (pk, pub_key) = self.ecc.gen_keypair(to_ecc_curve(curve)).await?;
        self.ecc.pub_coords(&pub_key, false, scratch_pub).await?;
        // From here the private scalar is in `scratch_priv`; wipe it on
        // every exit (scope rewind does not clear DMA memory).
        if pk.to_hsm_bytes(&mut scratch_priv[..priv_len]).is_err() {
            scratch_priv.zeroize();
            return Err(HsmError::EccExportError);
        }

        priv_out[..priv_len].copy_from_slice(&scratch_priv[..priv_len]);
        pub_out[..wire_pub_len].copy_from_slice(scratch_pub);

        // Scrub the private-scalar half of the scratch before returning:
        // scope rewind does not clear DMA memory, so the freshly generated
        // scalar would otherwise linger in — and leak through — a later
        // per-IO allocation. (The pub half is not secret.)
        scratch_priv.zeroize();

        Ok((priv_len, wire_pub_len))
    }

    /// Deterministically derive an ECC keypair from KDF output.
    async fn ecc_gen_keypair_from_okm(
        &self,
        _io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        curve: HsmEccCurve,
        okm: &DmaBuf,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        let priv_len = curve.wire_coord_len();
        let wire_pub_len = curve.wire_pub_key_len();

        if okm.len() != curve.a2_1_okm_len() {
            return Err(HsmError::InvalidArg);
        }

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, wire_pub_len));
        };

        if priv_out.len() < priv_len || pub_out.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }

        let scratch = alloc.dma_alloc(priv_len + wire_pub_len)?;
        let (scratch_priv, scratch_pub) = scratch.split_at_mut(priv_len);

        let pk = EccPrivateKey::from_okm_a2_1(to_ecc_curve(curve), okm)
            .map_err(|_| HsmError::EccGenerateError)?;

        // Serialize the scalar into `scratch_priv`, derive the public
        // coordinates, and copy both out.  Once the scalar is in DMA
        // scratch, every exit must wipe it (scope rewind does not clear DMA
        // memory), so run the fallible tail and scrub unconditionally after.
        let fill = async {
            pk.to_hsm_bytes(&mut scratch_priv[..priv_len])
                .map_err(|_| HsmError::EccExportError)?;
            let pub_key = pk
                .public_key()
                .map_err(|_| HsmError::EccGetCoordinatesError)?;
            self.ecc.pub_coords(&pub_key, false, scratch_pub).await?;
            priv_out[..priv_len].copy_from_slice(&scratch_priv[..priv_len]);
            pub_out[..wire_pub_len].copy_from_slice(scratch_pub);
            Ok::<(), HsmError>(())
        }
        .await;
        scratch_priv.zeroize();
        fill?;

        Ok((priv_len, wire_pub_len))
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Parses the raw HSM-format private key into an OpenSSL handle
    /// and delegates to the driver's wire-LE sign method, which
    /// performs the BE↔LE conversions internally.
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
        let key = EccPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
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
        result: &mut DmaBuf,
    ) -> HsmResult<()> {
        let wire_pub_len = curve.wire_pub_key_len();
        let wire_sig_len = curve.wire_sig_len();
        if pub_key.len() < wire_pub_len || signature.len() < wire_sig_len || result.len() < 4 {
            return Err(HsmError::InvalidArg);
        }
        let valid = self
            .ecc
            .ecc_verify_le(
                to_ecc_curve(curve),
                &pub_key[..wire_pub_len],
                hash,
                &signature[..wire_sig_len],
            )
            .await?;

        result.fill(0);
        result[0] = if valid { 0 } else { 1 };
        Ok(())
    }

    /// Derive the public key from a raw private scalar (`pub = priv · G`).
    ///
    /// Delegates to the driver's `pub_from_priv_le`, which runs the
    /// OpenSSL key reconstruction and public-point derivation on the
    /// worker pool and emits the little-endian DDI wire form.
    async fn ecc_pub_from_priv(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &mut DmaBuf,
    ) -> HsmResult<()> {
        let wire_priv_len = curve.wire_priv_key_len();
        let wire_pub_len = curve.wire_pub_key_len();
        if priv_key.len() != wire_priv_len || pub_key.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }
        self.ecc
            .pub_from_priv_le(
                to_ecc_curve(curve),
                &priv_key[..wire_priv_len],
                &mut pub_key[..wire_pub_len],
            )
            .await
    }

    /// ECDH key agreement — derives a shared secret.
    ///
    /// Parses the local raw HSM-format private into an OpenSSL
    /// handle and delegates to the driver's wire-LE ECDH method
    /// which constructs the remote pub-key handle internally from
    /// the wire-LE coordinates (stripping per-coordinate padding
    /// for P-521).
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
        let pk = EccPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        self.ecc
            .ecdh_derive_le(
                &pk,
                to_ecc_curve(curve),
                &pub_key[..wire_pub_len],
                &mut secret[..],
            )
            .await
    }

    fn ecc_priv_der_to_vault(
        &self,
        _io: &impl HsmIo,
        der: &DmaBuf,
        out: Option<&mut DmaBuf>,
    ) -> HsmResult<(usize, HsmEccCurve)> {
        // std PAL vault format is raw HSM-format scalar bytes; parse the
        // recovered PKCS#8 DER and re-export in the vault representation.
        let pk = EccPrivateKey::from_bytes(der).map_err(|_| HsmError::InvalidArg)?;
        let curve = from_ecc_curve(pk.curve());
        let priv_len = curve.wire_coord_len();
        if let Some(out) = out {
            if out.len() < priv_len {
                return Err(HsmError::InvalidArg);
            }
            pk.to_hsm_bytes(&mut out[..priv_len])
                .map_err(|_| HsmError::InvalidArg)?;
        }
        Ok((priv_len, curve))
    }

    async fn ecc_priv_pub_key(
        &self,
        _io: &impl HsmIo,
        priv_key: &DmaBuf,
        pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        // Parse the vault-format (raw HSM scalar) private key and report
        // the wire public-key length; in use mode derive the public key
        // and serialize it (`x || y`, wire-LE) via the shared driver
        // helper (same chain as `ecc_gen_keypair_from_okm`).
        let pk = EccPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let wire_pub_len = from_ecc_curve(pk.curve()).wire_pub_key_len();
        if let Some(out) = pub_out {
            if out.len() < wire_pub_len {
                return Err(HsmError::InvalidArg);
            }
            let pub_key = pk
                .public_key()
                .map_err(|_| HsmError::EccGetCoordinatesError)?;
            self.ecc
                .pub_coords(&pub_key, false, &mut out[..wire_pub_len])
                .await?;
        }
        Ok(wire_pub_len)
    }
}
