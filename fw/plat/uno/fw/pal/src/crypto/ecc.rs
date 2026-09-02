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

use super::ecc_det::ORDER384_BE;
use super::ecc_det::ct_in_range;
use super::ecc_det::ct_in_range_le;
use super::reverse_copy;
use crate::UnoHsmPal;
use crate::asn1::parse_ec_private_key;

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

/// NIST P-256 curve order `n` in big-endian (for the `1 <= d < n` scalar check).
const ORDER256_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// NIST P-521 curve order `n` in big-endian (for the `1 <= d < n` scalar check).
const ORDER521_BE: [u8; 66] = [
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
    0x64, 0x09,
];

/// Curve order `n` (big-endian, raw `priv_key_len` bytes) used to validate an
/// imported scalar is in range `[1, n-1]`. P-384's lives in [`super::ecc_det`].
fn curve_order_be(curve: HsmEccCurve) -> &'static [u8] {
    match curve {
        HsmEccCurve::P256 => &ORDER256_BE,
        HsmEccCurve::P384 => &ORDER384_BE,
        HsmEccCurve::P521 => &ORDER521_BE,
    }
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

        // Note: `scratch` holds the generated keypair (and, on a PKA failure,
        // possibly partial key material) when this returns. It is intentionally
        // left dirty: per the #602 review, the wipe belongs in the per-IO
        // teardown scrub rather than here, so a local wipe would be redundant
        // work that has to be removed again. That teardown scrub lands in #632
        // (`drop_io` wipes the slot via the GDMA engine); until it merges this
        // slot is not wiped, so #632 must land before — or together with — this
        // change.
        let scratch = alloc.dma_alloc(pub_len + priv_len)?;
        let total_len = self.pka.ecc_gen_keypair(pka_curve, scratch).await?;
        let (pub_key, priv_key) = scratch[..total_len].split_at(pub_len);

        priv_out[..priv_len].copy_from_slice(priv_key);
        pub_out[..pub_len].copy_from_slice(pub_key);

        Ok((priv_len, pub_len))
    }

    /// Deterministic ECC key generation from a caller-supplied
    /// key-derivation root (the partition `PartRoot`).
    ///
    /// Routes to [`UnoHsmPal::ecc_gen_keypair_deterministic`], which
    /// HKDF-expands `root` and applies FIPS 186-5 §A.2.2 rejection
    /// sampling to obtain the private scalar, then computes the public
    /// point `Q = d·G` on the PKA. §A.2.2 (not §A.2.1) is used because
    /// the UPKA Montgomery modular unit cannot reduce by the even
    /// value `n − 1`; rejection sampling needs only a range check.
    /// Only P-384 — the PTA / alias identity curve — is supported;
    /// other curves surface as [`HsmError::UnsupportedCmd`] from the
    /// inner primitive.
    ///
    /// The private scalar and both public coordinates are returned in
    /// PKA-native little-endian wire form, identical to
    /// [`Self::ecc_gen_keypair`]; byte-order canonicalisation is the
    /// DDI handler's responsibility.
    ///
    /// The std PAL derives from the same `root` with a different info
    /// string, OKM length and §A.2 method, so it produces a
    /// **different** keypair. Determinism holds per-platform only; see
    /// the trait doc.
    ///
    /// # Parameters
    /// * `curve` — must be [`HsmEccCurve::P384`].
    /// * `root` — the 48-byte partition `PartRoot`, used as the HKDF
    ///   PRK for the per-attempt candidate derivation.
    /// * `out` — `None` to query the required `(priv_len, pub_len)`, or
    ///   `Some((priv_key, pub_key))` to derive into caller buffers.
    /// * `_pct` — accepted for trait parity; no pairwise-consistency
    ///   self-test is currently executed.
    ///
    /// # Returns
    /// * `Ok((priv_len, pub_len))` — the private and public key lengths.
    ///
    /// # Errors
    /// * [`HsmError::UnsupportedCmd`] if `curve` is not P-384.
    /// * [`HsmError::InvalidArg`] if `out` is `Some` and either output
    ///   buffer is shorter than required, or `root` is not 48 bytes.
    /// * Any [`HsmError`] surfaced by the HKDF / SHA / PKA drivers.
    async fn ecc_gen_keypair_from_root(
        &self,
        io: &impl HsmIo,
        _alloc: &impl HsmScopedAlloc,
        curve: HsmEccCurve,
        root: &DmaBuf,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        let pka_curve = map_ecc_curve(curve)?;
        // Only P-384 (the PTA / alias identity curve) is supported. Reject
        // other curves here rather than deep inside the derivation, so
        // query mode agrees with use mode instead of handing back sizes
        // for a curve that would later fail with `UnsupportedCmd`.
        if pka_curve != UpkaEccCurve::P384 {
            return Err(HsmError::UnsupportedCmd);
        }

        let priv_len = hsm_point_size(pka_curve);
        let pub_len = hsm_point_size(pka_curve) * 2;

        // `root` is the derivation input in both modes, so validate its
        // length before the query-mode return — the documented
        // `InvalidArg` on a non-48-byte root must not depend on `out`.
        if root.len() != priv_len {
            return Err(HsmError::InvalidArg);
        }

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, pub_len));
        };

        if priv_out.len() < priv_len || pub_out.len() < pub_len {
            return Err(HsmError::InvalidArg);
        }

        self.ecc_gen_keypair_deterministic(io, pka_curve, root, priv_out, pub_out)
            .await?;

        Ok((priv_len, pub_len))
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
            // The digest arrives PKA-native little-endian: it is a full BE->LE
            // byte reversal of the big-endian hash, which is what
            // `hash(.., big_endian = false)` produces. pub_key and signature
            // likewise arrive LE via the host DDI serde. No byte-order
            // conversion is done below the PAL.

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
        // Parse the recovered PKCS#8 ECC private key (curve from its `namedCurve`
        // OID, plus the raw big-endian scalar `d`).
        let (curve, scalar) = parse_ec_private_key(der).ok_or(HsmError::InvalidArg)?;
        let vault_len = curve.wire_coord_len();
        // SEC1 / RFC 5915 encodes the scalar as a fixed-width octet string for
        // the curve (P-256 32, P-384 48, P-521 66 bytes). Require exactly that
        // raw length — reject shorter (non-canonical) or overlong scalars,
        // matching the std PAL. `vault_len` is only the (padded) vault / output
        // size, used for wire zero-padding below.
        if scalar.len() != curve.priv_key_len() {
            return Err(HsmError::InvalidArg);
        }
        // SEC1 requires the scalar in `[1, n-1]`; reject `d == 0` or `d >= n`
        // (the curve order). `ct_in_range` compares the same-length big-endian
        // `d` and `n` in constant time, matching the std PAL's `check_key`.
        if !ct_in_range(scalar, curve_order_be(curve)) {
            return Err(HsmError::InvalidArg);
        }
        if let Some(out) = out {
            if out.len() < vault_len {
                return Err(HsmError::InvalidArg);
            }
            // The vault stores the scalar little-endian (PKA-native),
            // zero-padded to the wire coordinate length. `reverse_copy` only
            // writes `scalar.len()` bytes, so clear the high remainder.
            reverse_copy(&mut out[..vault_len], scalar);
            out[scalar.len()..vault_len].fill(0);
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
        // P-521's 66-byte raw scalar is zero-padded to the 68-byte wire length;
        // the two high (little-endian) bytes must be zero, otherwise the scalar
        // is out of range and would feed a malformed operand to the PKA.
        if priv_key.len() == 68 && (priv_key[66] != 0 || priv_key[67] != 0) {
            return Err(HsmError::InvalidArg);
        }
        // Validate the scalar is in `[1, n-1]` against the curve order — the
        // same trust-boundary contract as the import path / std PAL, since this
        // is called on untrusted vault keys (import / unmask / unwrap). Read
        // the LE scalar directly against the BE order (no reversed-copy scratch
        // of the secret scalar).
        let raw_len = curve.priv_key_len();
        if !ct_in_range_le(&priv_key[..raw_len], curve_order_be(curve)) {
            return Err(HsmError::InvalidArg);
        }
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
    /// Delegates to [`ecc_priv_pub_key`](Self::ecc_priv_pub_key), which
    /// performs the point multiply with every operand in a GSRAM DMA
    /// buffer.
    ///
    /// This deliberately does **not** use the PKA driver's
    /// `ecc_gen_pub_key`: that issues the point-mul opcode with a null (0)
    /// scalar operand, so the engine reads the scalar from address 0
    /// rather than GSRAM and faults with an AXI `BUS_ERROR`
    /// (`0x08f0c003`). The same note appears on the deterministic-keygen
    /// path in `ecc_det.rs`, which avoids the primitive for the same
    /// reason. Emulator builds do not model PKA operand addressing, so
    /// this fault only ever appears on silicon.
    ///
    /// `ecc_priv_pub_key` infers the curve from the scalar length — which
    /// is exactly `wire_priv_key_len()`, itself defined as
    /// `wire_coord_len()` — so the mapping is equivalent to the explicit
    /// `curve` argument, and it additionally range-checks the scalar
    /// against the curve order.
    ///
    /// # Parameters
    /// * `curve` — NIST curve the private key is on.
    /// * `priv_key` — raw HSM-format private scalar
    ///   ([`HsmEccCurve::wire_priv_key_len`] bytes).
    /// * `pub_key` — output buffer for `X ‖ Y`
    ///   ([`HsmEccCurve::wire_pub_key_len`] bytes).
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is unsupported, a buffer is
    ///   undersized, or the scalar is out of range.
    /// * Any [`HsmError`] surfaced by the PKA driver.
    async fn ecc_pub_from_priv(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &mut DmaBuf,
    ) -> HsmResult<()> {
        // Validate `curve` up front rather than leaving it implicit in the
        // length check below. `ecc_priv_pub_key` re-derives the curve from
        // the scalar length, so without this an unsupported variant would
        // never meet the documented `InvalidArg` contract here — it would
        // either be rejected further down for the wrong reason, or, if a
        // future variant shared a wire length with a supported one, be
        // computed on the wrong curve. `wire_priv_key_len` is pairwise
        // distinct across the supported curves (32 / 48 / 68), which
        // `wire_priv_key_len_is_unambiguous` in the traits crate pins so a
        // colliding variant fails CI rather than mis-dispatching here.
        map_ecc_curve(curve)?;
        let wire_pub_len = curve.wire_pub_key_len();
        if priv_key.len() != curve.wire_priv_key_len() || pub_key.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }
        // Pass an exact-sized sub-view: the PKA writes a fixed number of
        // bytes per curve and is not given a length, so an oversized caller
        // buffer would otherwise keep stale bytes in its tail.
        let (head, _rest) = pub_key.split_at_mut(wire_pub_len);
        self.ecc_priv_pub_key(io, priv_key, Some(head)).await?;
        Ok(())
    }
}
