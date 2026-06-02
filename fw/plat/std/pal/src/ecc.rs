// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmEcc`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (wire-format
//! bytes / PKCS#8 DER for private keys) and the
//! [`StdEcc`](crate::drivers::ecc::StdEcc) driver (OpenSSL key
//! handles).  The PAL impl is responsible for:
//!
//! 1. **Enum mapping** — [`HsmEccCurve`] → [`azihsm_crypto::EccCurve`].
//! 2. **Private-key serialization** — exporting generated handles
//!    to PKCS#8 DER in [`ecc_gen_keypair`] and re-importing DER
//!    blobs in [`ecc_sign`] / [`ecdh_derive`].
//! 3. **OpenSSL-BE ↔ wire-LE conversion** — the canonical
//!    firmware-side wire format for public-key coordinates,
//!    signature components, and the input digest is little-endian
//!    (with P-521 padded to 68 bytes per word) because that is what
//!    real PKA hardware natively consumes, so the host emits and
//!    accepts those bytes directly.  Real-HW PALs forward the wire
//!    bytes to PKA unmodified; this std PAL has to reverse them
//!    back to OpenSSL's native big-endian layout (and reverse the
//!    outputs back to wire-LE) purely because the OpenSSL backend
//!    is BE-native — not a host-visible responsibility.
//!
//! ## Key formats at the trait boundary
//!
//! | Direction | Private key | Public key |
//! |-----------|-------------|------------|
//! | Trait → PAL (input)  | PKCS#8 DER `&DmaBuf` (variable, `≤ priv_key_der_max`) | Wire-LE `x \|\| y` `&DmaBuf` (`pub_key_len` bytes) |
//! | PAL → Trait (output) | PKCS#8 DER `&mut DmaBuf` (variable, `≤ priv_key_der_max`) | Wire-LE `x \|\| y` `&mut DmaBuf` (`wire_pub_key_len` bytes, P-521 padded) |
//! | PAL → Driver (internal) | `EccPrivateKey` handle | `EccPublicKey` handle (raw BE coords) |
//!
//! The trait-level [`HsmEcc::ecc_gen_keypair`] query mode reports
//! [`HsmEccCurve::priv_key_der_max`] as the private-key upper bound
//! and [`HsmEccCurve::wire_pub_key_len`] as the public-key length;
//! the use mode returns the actual DER byte count (always
//! ≤ the query bound) and the deterministic public-key length
//! (equal to the query bound).  Real-HW PALs that emit raw scalars
//! instead report [`HsmEccCurve::priv_key_len`] in both modes; the
//! trait contract is `use ≤ query`.
//!
//! ## Data flow (sign example)
//!
//! ```text
//! Host LE-reverses digest + pads to wire bytes → DDI request.
//! Core calls pal.ecc_sign(curve, priv_key_der, hash_le, sig_buf)
//!   → EccPrivateKey::from_bytes(priv_key_der)  // DER → handle
//!   → hash_be = reverse(hash_le)               // undo host LE for OpenSSL
//!   → self.ecc.ecc_sign(&handle, hash_be)      // driver → OpenSSL ECDSA
//!   → sig_buf = reverse(sig_be) (per component) // re-encode for the wire
//! // Host parses sig_buf as wire-LE (no further conversion at the host).
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
    /// Generate an ECC key pair on the specified curve, query-alloc-use
    /// style.
    ///
    /// In **query mode** (`out = None`) returns the std-PAL upper
    /// bounds: PKCS#8 DER max for the private key
    /// ([`HsmEccCurve::priv_key_der_max`]) and the wire-format LE
    /// public-key length ([`HsmEccCurve::wire_pub_key_len`]).  In
    /// **use mode** (`out = Some((priv_out, pub_out))`) it generates
    /// a keypair via [`StdEcc::gen_keypair`], allocates a contiguous
    /// `priv_max || pub_max` scratch from `alloc`, serializes the
    /// keys into that scratch (private as PKCS#8 DER, public as
    /// LE-reversed + P-521-padded coordinates), copies into the
    /// caller's two output slots, and returns the **actual** byte
    /// counts (DER is variable, so `priv_actual ≤ priv_max`; pub is
    /// deterministic).  Public-key endianness matches the wire-native
    /// format produced by real PKA hardware — see
    /// [`HsmEcc::ecc_gen_keypair`].
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

        let (pk, pubk) = self.ecc.gen_keypair(to_ecc_curve(curve)).await?;

        // Allocate the contiguous `priv || pub` scratch (sized at the
        // PAL upper bound) a real PKA engine would write into; we then
        // perform DER serialization + BE→LE pub-key reversal in-scratch
        // before copying out.
        let scratch = alloc.dma_alloc(priv_max + wire_pub_len)?;
        let (scratch_priv, scratch_pub) = scratch.split_at_mut(priv_max);

        let priv_actual = pk
            .to_bytes(Some(&mut scratch_priv[..priv_max]))
            .map_err(|_| HsmError::EccToDerError)?;

        // Export raw BE coordinates into stack scratch, then reverse
        // each into the wire-format LE slot (leaving any P-521
        // trailing pad bytes zero).
        let coord_len = curve.priv_key_len();
        let mut x_be = [0u8; 66];
        let mut y_be = [0u8; 66];
        pubk.coord(Some((&mut x_be[..coord_len], &mut y_be[..coord_len])))
            .map_err(|_| HsmError::EccToDerError)?;

        scratch_pub.fill(0);
        let wire_coord = curve.wire_coord_len();
        let (x_dst, y_dst) = scratch_pub.split_at_mut(wire_coord);
        for (dst, src) in x_dst[..coord_len]
            .iter_mut()
            .zip(x_be[..coord_len].iter().rev())
        {
            *dst = *src;
        }
        for (dst, src) in y_dst[..coord_len]
            .iter_mut()
            .zip(y_be[..coord_len].iter().rev())
        {
            *dst = *src;
        }

        priv_out[..priv_actual].copy_from_slice(&scratch_priv[..priv_actual]);
        pub_out[..wire_pub_len].copy_from_slice(scratch_pub);

        Ok((priv_actual, wire_pub_len))
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Per the [`HsmEcc::ecc_sign`] trait contract, `hash` is the
    /// message digest in wire-native **little-endian** byte order,
    /// and the output signature is `r || s` with **each component
    /// in little-endian** byte order (P-521 components padded from
    /// 66 to 68 wire bytes).  OpenSSL is big-endian-native for both
    /// the digest scalar and the signature components, so we reverse
    /// the digest before signing and reverse each signature
    /// component after signing.
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

        // Reverse wire-LE digest to OpenSSL-BE; stack scratch sized
        // for any SHA up to SHA-512 (64 bytes).  Reject longer inputs
        // rather than silently truncating — the trait contract is
        // that `hash` carries exactly the digest's native length.
        let mut hash_be = [0u8; 64];
        let h_len = hash.len();
        if h_len > hash_be.len() {
            return Err(HsmError::InvalidArg);
        }
        for (dst, src) in hash_be[..h_len].iter_mut().zip(hash[..h_len].iter().rev()) {
            *dst = *src;
        }
        let sig_be = self.ecc.ecc_sign(&key, &hash_be[..h_len]).await?;

        // OpenSSL returns `r_be || s_be` of length `2 * priv_key_len`.
        // Reverse each component into the LE wire layout, leaving the
        // P-521 trailing pad bytes zero.
        let pal_component = curve.priv_key_len();
        let wire_component = curve.wire_coord_len();
        if sig_be.len() < pal_component * 2 {
            return Err(HsmError::EccSignFailed);
        }
        signature[..wire_len].fill(0);
        let (r_be, s_be) = sig_be.split_at(pal_component);
        for (dst, src) in signature[..pal_component].iter_mut().zip(r_be.iter().rev()) {
            *dst = *src;
        }
        for (dst, src) in signature[wire_component..wire_component + pal_component]
            .iter_mut()
            .zip(s_be.iter().rev())
        {
            *dst = *src;
        }
        Ok(())
    }

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// Per the [`HsmEcc::ecc_verify`] trait contract, `pub_key` is the
    /// raw uncompressed point `x || y` with **each coordinate in
    /// little-endian** byte order, and `signature` is `r || s` with
    /// each component in little-endian.  OpenSSL is big-endian-native
    /// for elliptic-curve scalars, so we reverse each component before
    /// constructing the verification inputs.
    async fn ecc_verify(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        pub_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &DmaBuf,
    ) -> HsmResult<bool> {
        let coord_len = curve.priv_key_len();
        let pub_key_len = curve.pub_key_len();
        let sig_len = curve.sig_len();

        if pub_key.len() < pub_key_len || signature.len() < sig_len {
            return Err(HsmError::InvalidArg);
        }

        // Reverse each coord from wire-LE to OpenSSL-BE.
        let (x_le, y_le) = pub_key[..pub_key_len].split_at(coord_len);
        let mut x_be = [0u8; 66];
        let mut y_be = [0u8; 66];
        for (dst, src) in x_be[..coord_len].iter_mut().zip(x_le.iter().rev()) {
            *dst = *src;
        }
        for (dst, src) in y_be[..coord_len].iter_mut().zip(y_le.iter().rev()) {
            *dst = *src;
        }

        let key = EccPublicKey::from_coordinates(
            to_ecc_curve(curve),
            &x_be[..coord_len],
            &y_be[..coord_len],
        )
        .map_err(|_| HsmError::InvalidArg)?;

        // Reverse each sig half from wire-LE to OpenSSL-BE.
        let (r_le, s_le) = signature[..sig_len].split_at(coord_len);
        let mut sig_be = [0u8; 132];
        for (dst, src) in sig_be[..coord_len].iter_mut().zip(r_le.iter().rev()) {
            *dst = *src;
        }
        for (dst, src) in sig_be[coord_len..sig_len].iter_mut().zip(s_le.iter().rev()) {
            *dst = *src;
        }

        self.ecc.ecc_verify(&key, hash, &sig_be[..sig_len]).await
    }

    /// ECDH key agreement — derives a shared secret.
    ///
    /// Per the [`HsmEcc::ecdh_derive`] trait contract, `pub_key` is the
    /// raw uncompressed point `x || y` with **each coordinate in
    /// little-endian** byte order.  We reverse each coordinate before
    /// handing to OpenSSL.
    async fn ecdh_derive(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
    ) -> HsmResult<()> {
        let coord_len = curve.priv_key_len();
        let pub_key_len = curve.pub_key_len();
        if pub_key.len() < pub_key_len {
            return Err(HsmError::InvalidArg);
        }

        let pk = EccPrivateKey::from_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;

        let (x_le, y_le) = pub_key[..pub_key_len].split_at(coord_len);
        let mut x_be = [0u8; 66];
        let mut y_be = [0u8; 66];
        for (dst, src) in x_be[..coord_len].iter_mut().zip(x_le.iter().rev()) {
            *dst = *src;
        }
        for (dst, src) in y_be[..coord_len].iter_mut().zip(y_le.iter().rev()) {
            *dst = *src;
        }
        let pubk = EccPublicKey::from_coordinates(
            to_ecc_curve(curve),
            &x_be[..coord_len],
            &y_be[..coord_len],
        )
        .map_err(|_| HsmError::InvalidArg)?;

        self.ecc.ecdh_derive(&pk, &pubk, &mut secret[..]).await
    }
}
