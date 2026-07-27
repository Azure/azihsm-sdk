// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC trait implementation for the Uno PAL.
//!
//! All curve arithmetic is performed by the on-chip PKA engine; this file
//! is a thin adapter that:
//!
//! 1. Maps the trait-level [`HsmEccCurve`] enum to the driver-level
//!    [`UpkaEccCurve`] enum via [`map_ecc_curve`].
//! 2. Forwards the public/private key, hash, and signature buffers to
//!    [`UnoHsmPal::pka`].
//! 3. Performs one piece of buffer surgery for
//!    [`HsmEcc::ecc_gen_keypair`]: the PKA driver writes
//!    `pub_key ‖ priv_key` contiguously into scoped scratch, so this
//!    layer splits that scratch and copies the two halves into the
//!    caller's separate output buffers.
//!
//! Pairwise Consistency Test (PCT) execution is currently a no-op — the
//! `_pct` parameter is accepted for API parity with the trait but no
//! self-test is run.

use core::cmp::Ordering;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmEcc;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_upka::UpkaEccCurve;
use azihsm_fw_uno_drivers_upka::hash_size;
use azihsm_fw_uno_drivers_upka::hsm_point_size;
use azihsm_fw_uno_drivers_upka::mont_operand_size;

use super::rsa::der_tlv;
use super::rsa::write_le;
use crate::UnoHsmPal;

// =============================================================================
// Curve mapping
// =============================================================================

/// Translate the trait-level [`HsmEccCurve`] enum to the PKA driver's
/// [`UpkaEccCurve`] enum.
///
/// # Parameters
/// * `curve` — the curve identifier supplied by the caller.
///
/// # Returns
/// * `Ok(UpkaEccCurve)` — the corresponding driver-level variant
///   (`P256`, `P384`, or `P521`).
///
/// # Errors
/// * [`HsmError::InvalidArg`] if a future variant is added to
///   [`HsmEccCurve`] that this PAL does not yet support. The wildcard
///   arm exists so adding a new variant in the trait crate fails
///   gracefully at runtime instead of failing to compile here.
#[allow(unreachable_patterns)]
fn map_ecc_curve(curve: HsmEccCurve) -> HsmResult<UpkaEccCurve> {
    match curve {
        HsmEccCurve::P256 => Ok(UpkaEccCurve::P256),
        HsmEccCurve::P384 => Ok(UpkaEccCurve::P384),
        HsmEccCurve::P521 => Ok(UpkaEccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

/// NIST P-256 prime modulus in PKA little-endian operand order.
const PRIME256_LE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
];

/// NIST P-384 prime modulus in PKA little-endian operand order.
pub(super) const PRIME384_LE: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// NIST P-521 prime modulus in PKA little-endian operand order (68-byte,
/// DWORD-aligned per PKA hardware requirement).
const PRIME521_LE: [u8; 68] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x01, 0x00, 0x00,
];

/// Curve prime modulus (PKA little-endian) for the Montgomery-constant setup.
fn curve_prime_le(curve: UpkaEccCurve) -> &'static [u8] {
    match curve {
        UpkaEccCurve::P256 => &PRIME256_LE,
        UpkaEccCurve::P384 => &PRIME384_LE,
        UpkaEccCurve::P521 => &PRIME521_LE,
    }
}

/// NIST P-256 base point `G` x-coordinate in PKA little-endian operand order.
const BASE256_X_LE: [u8; 32] = [
    0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4, 0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03, 0x77,
    0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8, 0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b,
];

/// NIST P-256 base point `G` y-coordinate in PKA little-endian operand order.
const BASE256_Y_LE: [u8; 32] = [
    0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb, 0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce, 0x2b,
    0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e, 0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f,
];

/// NIST P-384 base point `G` x-coordinate in PKA little-endian operand order.
pub(super) const BASE384_X_LE: [u8; 48] = [
    0xb7, 0x0a, 0x76, 0x72, 0x38, 0x5e, 0x54, 0x3a, 0x6c, 0x29, 0x55, 0xbf, 0x5d, 0xf2, 0x02, 0x55,
    0x38, 0x2a, 0x54, 0x82, 0xe0, 0x41, 0xf7, 0x59, 0x98, 0x9b, 0xa7, 0x8b, 0x62, 0x3b, 0x1d, 0x6e,
    0x74, 0xad, 0x20, 0xf3, 0x1e, 0xc7, 0xb1, 0x8e, 0x37, 0x05, 0x8b, 0xbe, 0x22, 0xca, 0x87, 0xaa,
];

/// NIST P-384 base point `G` y-coordinate in PKA little-endian operand order.
pub(super) const BASE384_Y_LE: [u8; 48] = [
    0x5f, 0x0e, 0xea, 0x90, 0x7c, 0x1d, 0x43, 0x7a, 0x9d, 0x81, 0x7e, 0x1d, 0xce, 0xb1, 0x60, 0x0a,
    0xc0, 0xb8, 0xf0, 0xb5, 0x13, 0x31, 0xda, 0xe9, 0x7c, 0x14, 0x9a, 0x28, 0xbd, 0x1d, 0xf4, 0xf8,
    0x29, 0xdc, 0x92, 0x92, 0xbf, 0x98, 0x9e, 0x5d, 0x6f, 0x2c, 0x26, 0x96, 0x4a, 0xde, 0x17, 0x36,
];

/// NIST P-521 base point `G` x-coordinate in PKA little-endian operand order
/// (68-byte, DWORD-aligned per PKA hardware requirement).
const BASE521_X_LE: [u8; 68] = [
    0x66, 0xbd, 0xe5, 0xc2, 0x31, 0x7e, 0x7e, 0xf9, 0x9b, 0x42, 0x6a, 0x85, 0xc1, 0xb3, 0x48, 0x33,
    0xde, 0xa8, 0xff, 0xa2, 0x27, 0xc1, 0x1d, 0xfe, 0x28, 0x59, 0xe7, 0xef, 0x77, 0x5e, 0x4b, 0xa1,
    0xba, 0x3d, 0x4d, 0x6b, 0x60, 0xaf, 0x28, 0xf8, 0x21, 0xb5, 0x3f, 0x05, 0x39, 0x81, 0x64, 0x9c,
    0x42, 0xb4, 0x95, 0x23, 0x66, 0xcb, 0x3e, 0x9e, 0xcd, 0xe9, 0x04, 0x04, 0xb7, 0x06, 0x8e, 0x85,
    0xc6, 0x00, 0x00, 0x00,
];

/// NIST P-521 base point `G` y-coordinate in PKA little-endian operand order
/// (68-byte, DWORD-aligned per PKA hardware requirement).
const BASE521_Y_LE: [u8; 68] = [
    0x50, 0x66, 0xd1, 0x9f, 0x76, 0x94, 0xbe, 0x88, 0x40, 0xc2, 0x72, 0xa2, 0x86, 0x70, 0x3c, 0x35,
    0x61, 0x07, 0xad, 0x3f, 0x01, 0xb9, 0x50, 0xc5, 0x40, 0x26, 0xf4, 0x5e, 0x99, 0x72, 0xee, 0x97,
    0x2c, 0x66, 0x3e, 0x27, 0x17, 0xbd, 0xaf, 0x17, 0x68, 0x44, 0x9b, 0x57, 0x49, 0x44, 0xf5, 0x98,
    0xd9, 0x1b, 0x7d, 0x2c, 0xb4, 0x5f, 0x8a, 0x5c, 0x04, 0xc0, 0x3b, 0x9a, 0x78, 0x6a, 0x29, 0x39,
    0x18, 0x01, 0x00, 0x00,
];

/// Curve base point `G = (x, y)` in PKA little-endian operand order, for the
/// `Q = d·G` point multiply.
fn curve_base_point_le(curve: UpkaEccCurve) -> (&'static [u8], &'static [u8]) {
    match curve {
        UpkaEccCurve::P256 => (&BASE256_X_LE, &BASE256_Y_LE),
        UpkaEccCurve::P384 => (&BASE384_X_LE, &BASE384_Y_LE),
        UpkaEccCurve::P521 => (&BASE521_X_LE, &BASE521_Y_LE),
    }
}

/// DER OID value bytes of `id-ecPublicKey` (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// DER OID value bytes of `prime256v1` / `secp256r1` (1.2.840.10045.3.1.7).
const OID_P256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER OID value bytes of `secp384r1` (1.3.132.0.34).
const OID_P384: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x22];
/// DER OID value bytes of `secp521r1` (1.3.132.0.35).
const OID_P521: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x23];

/// Classify a NIST curve from its `namedCurve` OID value bytes.
fn curve_from_oid(oid: &[u8]) -> Option<HsmEccCurve> {
    if oid == OID_P256 {
        Some(HsmEccCurve::P256)
    } else if oid == OID_P384 {
        Some(HsmEccCurve::P384)
    } else if oid == OID_P521 {
        Some(HsmEccCurve::P521)
    } else {
        None
    }
}

/// Parse a PKCS#8 DER ECC private key (`PrivateKeyInfo` wrapping an SEC1
/// `ECPrivateKey`) into `(curve, scalar_start, scalar_len)`, where the scalar
/// `d` is the big-endian value `der[scalar_start..][..scalar_len]`.
fn parse_ec_priv_der(der: &[u8]) -> Option<(HsmEccCurve, usize, usize)> {
    // Outer SEQUENCE (PrivateKeyInfo).
    let (tag, seq_start, _seq_len, _next) = der_tlv(der, 0)?;
    if tag != 0x30 {
        return None;
    }
    // version INTEGER (skip).
    let (vtag, _vs, _vl, after_ver) = der_tlv(der, seq_start)?;
    if vtag != 0x02 {
        return None;
    }
    // AlgorithmIdentifier ::= SEQUENCE { id-ecPublicKey OID, namedCurve OID }.
    let (atag, alg_start, _al, after_alg) = der_tlv(der, after_ver)?;
    if atag != 0x30 {
        return None;
    }
    let (otag, oid_s, oid_l, after_oid) = der_tlv(der, alg_start)?;
    if otag != 0x06 || der[oid_s..oid_s + oid_l] != OID_EC_PUBLIC_KEY {
        return None;
    }
    let (ctag, cs, cl, _after_curve) = der_tlv(der, after_oid)?;
    if ctag != 0x06 {
        return None;
    }
    let curve = curve_from_oid(&der[cs..cs + cl])?;
    // privateKey OCTET STRING wrapping the inner ECPrivateKey SEQUENCE.
    let (ptag, pk_start, _pl, _pn) = der_tlv(der, after_alg)?;
    if ptag != 0x04 {
        return None;
    }
    let (itag, inner_start, _il, _in) = der_tlv(der, pk_start)?;
    if itag != 0x30 {
        return None;
    }
    // Inner ECPrivateKey version INTEGER (value 1) (skip).
    let (ivtag, _ivs, _ivl, after_iver) = der_tlv(der, inner_start)?;
    if ivtag != 0x02 {
        return None;
    }
    // privateKey OCTET STRING = the raw scalar `d` (big-endian, field-length).
    let (dtag, ds, dl, _dn) = der_tlv(der, after_iver)?;
    if dtag != 0x04 || dl == 0 {
        return None;
    }
    Some((curve, ds, dl))
}

// =============================================================================
// Peer public-key range validation
// =============================================================================

/// Validate that a single coordinate satisfies `1 <= coordinate <= p - 1`.
///
/// `coordinate` and `p` are equal-length big numbers in little-endian byte
/// order. This is a byte-wise port of the reference firmware's
/// `EccPublicKeyRangeValidation::is_in_valid_range`: it walks from the most
/// significant byte (highest index in little-endian) down to the least,
/// short-circuiting as soon as the comparison is decided.
///
/// # Returns
/// * `true` — the coordinate is in the closed interval `[1, p - 1]`.
/// * `false` — the coordinate is `0`, is `>= p`, or the lengths differ.
fn coord_in_valid_range(coordinate: &[u8], p: &[u8]) -> bool {
    // A length mismatch means a malformed coordinate; reject it.
    if coordinate.len() != p.len() {
        return false;
    }

    // Tracks whether any non-least-significant byte of the coordinate is > 0,
    // i.e. whether the coordinate is already known to be >= 1.
    let mut coord_gt_zero = false;

    // Compare bytes from most to least significant (right to left in
    // little-endian). At a non-LSB position i:
    // - p[i] > coordinate[i]: the gap is at least 2^8, so coordinate < p.
    // - p[i] < coordinate[i]: coordinate exceeds p, so coordinate >= p.
    // - equal: continue to the next lower byte.
    for i in (1..p.len()).rev() {
        coord_gt_zero |= coordinate[i] > 0;

        match p[i].cmp(&coordinate[i]) {
            Ordering::Greater => {
                if coord_gt_zero {
                    return true;
                }
                // coordinate < p is established; it is valid iff coordinate >= 1.
                return coordinate[1..i].iter().rev().any(|&byte| byte > 0) || coordinate[0] >= 1;
            }
            Ordering::Less => return false,
            Ordering::Equal => {}
        }
    }

    // All non-LSB bytes were equal: valid iff coordinate >= 1 and
    // coordinate[0] <= p[0] - 1 (i.e. coordinate[0] < p[0], as p[0] > 0 for
    // every supported curve prime).
    (coord_gt_zero || coordinate[0] >= 1) && coordinate[0] < p[0]
}

/// Validate that a peer public key `(X ‖ Y)` has both coordinates in
/// `[1, p - 1]` for the given curve.
///
/// `pub_key` is the little-endian wire buffer laid out as two
/// [`hsm_point_size`] slots (`X` then `Y`). Each coordinate is validated at
/// its **full wire width** against the wire-width curve prime
/// ([`curve_prime_le`], whose P-521 DWORD-alignment pad bytes are zero).
/// Comparing the padded coordinate against the padded prime means a
/// non-zero MSB pad byte (P-521's 2 trailing bytes) makes the coordinate
/// compare `>= p` and is rejected here, rather than being silently ignored
/// and slipping an out-of-range coordinate through to the PKA. This matches
/// the exact bytes the hardware will consume. The caller must have ensured
/// `pub_key.len() >= hsm_point_size(curve) * 2`.
fn pub_key_in_valid_range(pub_key: &[u8], curve: UpkaEccCurve) -> bool {
    let wire = hsm_point_size(curve);
    let p = &curve_prime_le(curve)[..wire];

    let x = &pub_key[..wire];
    let y = &pub_key[wire..wire * 2];

    coord_in_valid_range(x, p) && coord_in_valid_range(y, p)
}

// =============================================================================
// HsmEcc trait impl
// =============================================================================
//
// The primary contract for each method (intended semantics, parameter
// shapes, error model) lives on the [`HsmEcc`] trait itself. The notes
// below describe only the Uno-specific behaviour and the buffer
// surgery `ecc_gen_keypair` performs on top of the PKA driver.

impl HsmEcc for UnoHsmPal {
    /// Generate an ECC key pair on the selected NIST curve.
    ///
    /// # Layout
    ///
    /// The PKA driver writes `pub_key ‖ priv_key` contiguously into a
    /// scratch buffer allocated from `alloc`. This PAL then copies the
    /// public and private halves into the caller's separate output
    /// buffers.
    ///
    /// `pub_len` is `2 * hsm_point_size(curve)` (X ‖ Y in HSM
    /// wire-format coordinates); `priv_len` is whatever remains of the
    /// `total_len` returned by the driver.
    ///
    /// # Parameters
    /// * `curve` — NIST curve to use ([`HsmEccCurve::P256`],
    ///   [`HsmEccCurve::P384`], or [`HsmEccCurve::P521`]).
    /// * `alloc` — scoped allocator used for the internal contiguous
    ///   `pub_key ‖ priv_key` PKA scratch buffer.
    /// * `out` — `None` to query required buffer sizes, or
    ///   `Some((priv_key, pub_key))` to generate into caller-provided
    ///   output buffers.
    /// * `_pct` — pairwise consistency test mode. Accepted for API
    ///   parity with the trait; no self-test is currently executed.
    ///
    /// # Returns
    /// * `Ok((priv_len, pub_len))` — the private and public key lengths.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if the supplied curve is not one of
    ///   P-256/P-384/P-521, or `out` is `Some` and either output buffer
    ///   is shorter than required.
    /// * Any [`HsmError`] surfaced by [`UnoHsmPal::pka.ecc_gen_keypair`]
    ///   or the scoped allocator.
    async fn ecc_gen_keypair(
        &self,
        _io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        curve: HsmEccCurve,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        let pka_curve = map_ecc_curve(curve)?;
        let priv_len = hsm_point_size(pka_curve);
        let pub_len = hsm_point_size(pka_curve) * 2;

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, pub_len));
        };

        if priv_out.len() < priv_len || pub_out.len() < pub_len {
            return Err(HsmError::InvalidArg);
        }

        let scratch = alloc.dma_alloc(pub_len + priv_len)?;
        let total_len = match self.pka.ecc_gen_keypair(pka_curve, scratch).await {
            Ok(n) => n,
            Err(e) => {
                // Keygen may have written partial key material into
                // `scratch`; wipe the whole buffer before it returns to the
                // per-IO pool (scope rewind does not clear DMA memory).
                scratch.zeroize();
                return Err(e);
            }
        };
        let (pub_key, priv_key) = scratch[..total_len].split_at(pub_len);

        priv_out[..priv_len].copy_from_slice(priv_key);
        pub_out[..pub_len].copy_from_slice(pub_key);

        // Scrub the private-scalar half of the scratch before returning:
        // scope rewind does not clear DMA memory, so the freshly generated
        // scalar would otherwise linger in — and leak through — a later
        // per-IO allocation. (The pub half is not secret.)
        scratch[pub_len..total_len].zeroize();

        Ok((priv_len, pub_len))
    }

    /// Deterministic ECC key generation from caller-supplied OKM is not
    /// yet implemented on this PAL.
    async fn ecc_gen_keypair_from_okm(
        &self,
        _io: &impl HsmIo,
        _alloc: &impl HsmScopedAlloc,
        _curve: HsmEccCurve,
        _okm: &DmaBuf,
        _out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        Err(HsmError::UnsupportedCmd)
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Delegates to [`UnoHsmPal::pka.ecc_sign`] after curve mapping.
    /// The PKA driver enforces the per-curve length requirements on
    /// `priv_key`, `hash`, and `signature`.
    ///
    /// # Parameters
    /// * `curve` — NIST curve the key was generated on.
    /// * `priv_key` — signing key in the wire format produced by
    ///   [`Self::ecc_gen_keypair`].
    /// * `hash` — pre-computed hash digest to sign. Caller is responsible
    ///   for hashing the message first.
    /// * `signature` — destination buffer for `R ‖ S`. Must be at least
    ///   [`HsmEccCurve::sig_len`] bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success. `signature` contains the `R ‖ S` pair.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is not one of the supported
    ///   NIST curves.
    /// * Any [`HsmError`] surfaced by the PKA driver.
    async fn ecc_sign(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;
        self.pka
            .ecc_sign(pka_curve, priv_key, hash, signature)
            .await
    }

    /// Raw EC verify of a signature over a pre-computed hash digest.
    ///
    /// Delegates to [`UnoHsmPal::pka.ecc_verify`] after curve mapping.
    ///
    /// # Parameters
    /// * `curve` — NIST curve the key was generated on.
    /// * `pub_key` — verification key as `(X ‖ Y)` in the wire format
    ///   produced by [`Self::ecc_gen_keypair`].
    /// * `hash` — pre-computed hash digest that was signed.
    /// * `signature` — `R ‖ S` signature pair to verify.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is not one of the supported
    ///   NIST curves.
    /// * Any [`HsmError`] surfaced by the PKA driver (e.g. malformed
    ///   inputs, hardware fault).
    async fn ecc_verify(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        pub_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &DmaBuf,
        result: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;

        let digest_len = hash_size(pka_curve);
        if hash.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }
        let prime_le = curve_prime_le(pka_curve);

        // Allocate the per-call PKA scratch (curve prime + transient
        // Montgomery-constant scratch) from a scoped heap so it is released
        // as soon as the verify completes rather than living for the whole
        // IO. A single IO that verifies several signatures (e.g. cert-chain
        // validation) would otherwise accumulate this scratch and can
        // exhaust the DMA pool.
        self.alloc_scoped_async(io, async |scope| {
            // The digest arrives PKA-native little-endian: the DDI handler
            // hashes big-endian and then fully byte-reverses it (a full BE->LE
            // reversal, not `hash(.., big_endian = false)`, which only swaps
            // within each 32-bit word). pub_key and signature likewise arrive
            // LE via the host DDI serde. No byte-order conversion is done below
            // the PAL.

            // Per-call Montgomery constant from the curve prime (like
            // ecdh_derive). `mont_result` is transient scratch consumed
            // internally by the driver's verify; it is not surfaced back.
            let prime = scope.dma_alloc(prime_le.len())?;
            prime.copy_from_slice(prime_le);
            let mont_result = scope.dma_alloc(prime_le.len())?;

            self.pka
                .ecc_verify(
                    pka_curve,
                    pub_key,
                    &hash[..digest_len],
                    signature,
                    result,
                    prime,
                    mont_result,
                )
                .await
        })
        .await
    }

    /// Derive an ECDH shared secret.
    ///
    /// Delegates to [`UnoHsmPal::pka.ecdh_derive`] after curve mapping.
    ///
    /// # Parameters
    /// * `curve` — NIST curve both peers agreed on.
    /// * `priv_key` — local private key.
    /// * `pub_key` — remote party's public key as `(X ‖ Y)`.
    /// * `secret` — destination buffer for the derived shared secret.
    ///   Must be at least [`HsmEccCurve::secret_len`] bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success. `secret` contains the shared secret.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is not one of the supported
    ///   NIST curves.
    /// * [`HsmError::EccDerKeyShorterThanCurve`] if `pub_key` is too short to
    ///   hold both wire-format coordinates.
    /// * [`HsmError::EccPublicKeyValidationFailed`] if either coordinate is
    ///   outside `[1, p - 1]`.
    /// * [`HsmError::EccPointValidationFailed`] if the point is not on the
    ///   curve.
    /// * Any [`HsmError`] surfaced by the PKA driver (e.g. undersized buffer,
    ///   hardware fault).
    async fn ecdh_derive(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;

        // Reject a peer public key that cannot even hold both wire-format
        // coordinates, then reject one whose coordinates are out of range,
        // before touching the PKA. This mirrors the reference firmware, which
        // range-checks the software-visible coordinates prior to the hardware
        // on-curve validation, and also prevents a coordinate equal to the
        // curve prime from ever reaching the engine.
        let wire = hsm_point_size(pka_curve);
        if pub_key.len() < wire * 2 {
            return Err(HsmError::EccDerKeyShorterThanCurve);
        }
        if !pub_key_in_valid_range(pub_key, pka_curve) {
            return Err(HsmError::EccPublicKeyValidationFailed);
        }

        let prime_le = curve_prime_le(pka_curve);

        // Scope the per-call Montgomery scratch (curve prime + result) so it is
        // freed as soon as the point-multiply completes instead of living for
        // the whole IO; keeping it IO-bounded needlessly grows DMA-pool
        // pressure in multi-step flows.
        self.alloc_scoped_async(io, async |scope| {
            // The PKA point-multiply requires a per-call Montgomery constant
            // computed from the curve prime.
            let prime = scope.dma_alloc(prime_le.len())?;
            prime.copy_from_slice(prime_le);
            let mont_result = scope.dma_alloc(prime_le.len())?;

            // Status word for the hardware on-curve validation that runs
            // between the Montgomery-constant setup and the ECDH compute.
            let point_valid = scope.dma_alloc(4)?;

            self.pka
                .ecdh_derive(
                    pka_curve,
                    priv_key,
                    pub_key,
                    secret,
                    prime,
                    mont_result,
                    point_valid,
                )
                .await?;

            // The shared secret is returned PKA-native little-endian, like
            // pub_key and priv_key. Any byte-order conversion (e.g. LE->BE for
            // an internal HKDF consumer that must match the host's openssl-BE
            // secret) is the DDI handler's responsibility, not the PAL's.
            Ok(())
        })
        .await
    }

    fn ecc_priv_der_to_vault(
        &self,
        _io: &impl HsmIo,
        der: &DmaBuf,
        out: Option<&mut DmaBuf>,
    ) -> HsmResult<(usize, HsmEccCurve)> {
        // Parse the recovered PKCS#8 ECC private key: classify the curve from
        // its `namedCurve` OID and locate the raw scalar `d` (big-endian).
        let (curve, ds, dl) = parse_ec_priv_der(der).ok_or(HsmError::InvalidArg)?;
        let vault_len = curve.wire_coord_len();
        if dl > vault_len {
            return Err(HsmError::InvalidArg);
        }
        if let Some(out) = out {
            if out.len() < vault_len {
                return Err(HsmError::InvalidArg);
            }
            // The vault stores the scalar little-endian (PKA-native),
            // zero-padded to the wire coordinate length.
            write_le(&mut out[..vault_len], &der[ds..ds + dl]);
        }
        Ok((vault_len, curve))
    }

    async fn ecc_priv_pub_key(
        &self,
        io: &impl HsmIo,
        priv_key: &DmaBuf,
        pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        // The vault scalar length is the wire coordinate length, which is
        // unique per curve (32 / 48 / 68).
        let curve = match priv_key.len() {
            32 => HsmEccCurve::P256,
            48 => HsmEccCurve::P384,
            68 => HsmEccCurve::P521,
            _ => return Err(HsmError::InvalidArg),
        };
        let wire_pub_len = curve.wire_pub_key_len();
        let Some(pub_out) = pub_out else {
            return Ok(wire_pub_len);
        };
        if pub_out.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }
        let pka_curve = map_ecc_curve(curve)?;
        let field = curve.wire_coord_len();
        let (bx, by) = curve_base_point_le(pka_curve);
        let mont = mont_operand_size(pka_curve);

        // Q = d·G on one held engine: `ecc_mont_const_calc` over the field
        // prime, then `ecc_point_mul` with the base point `G` supplied
        // explicitly (the proven primitive — the driver's `ecc_gen_pub_key`
        // issues the opcode with a null scalar operand and faults). Every
        // operand is a GSRAM DMA buffer, which the PKA requires.
        self.alloc_scoped_async(io, async |scope| -> HsmResult<usize> {
            let prime = scope.dma_alloc(field)?;
            prime.copy_from_slice(curve_prime_le(pka_curve));
            let base_xy = scope.dma_alloc(field * 2)?;
            base_xy[..field].copy_from_slice(bx);
            base_xy[field..].copy_from_slice(by);
            let mont_scratch = scope.dma_alloc(mont)?;
            self.pka
                .with_engine(async |eng| {
                    eng.ecc_mont_const_calc(pka_curve, prime, mont_scratch)
                        .await?;
                    eng.ecc_point_mul(
                        pka_curve,
                        base_xy,
                        &priv_key[..field],
                        &mut pub_out[..wire_pub_len],
                    )
                    .await
                })
                .await?;
            Ok(wire_pub_len)
        })
        .await
    }

    /// Derive the public key from a raw private scalar (`pub = priv · G`).
    ///
    /// Delegates to [`UnoHsmPal::pka.ecc_gen_pub_key`] (PKA base-point
    /// scalar multiplication) after curve mapping. Both buffers are in
    /// the little-endian PKA wire format.
    ///
    /// # Parameters
    /// * `curve` — NIST curve the private key is on.
    /// * `priv_key` — raw HSM-format private scalar
    ///   ([`HsmEccCurve::wire_priv_key_len`] bytes).
    /// * `pub_key` — output buffer for `X ‖ Y`
    ///   ([`HsmEccCurve::wire_pub_key_len`] bytes).
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is unsupported or a buffer is
    ///   undersized.
    /// * Any [`HsmError`] surfaced by the PKA driver.
    async fn ecc_pub_from_priv(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;
        let wire_pub_len = curve.wire_pub_key_len();
        if priv_key.len() != curve.wire_priv_key_len() || pub_key.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }
        // Pass an exact-sized sub-view: the PKA writes a fixed number of
        // bytes per curve and is not given a length, so an oversized caller
        // buffer would otherwise keep stale bytes in its tail.
        self.pka
            .ecc_gen_pub_key(pka_curve, priv_key, &mut pub_key[..wire_pub_len])
            .await
    }
}
