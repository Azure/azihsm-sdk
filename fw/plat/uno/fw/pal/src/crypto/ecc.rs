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
const PRIME384_LE: [u8; 48] = [
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

// =============================================================================
// P-384 deterministic-sign constants (RFC 6979)
// =============================================================================
//
// The on-the-fly partition-id (PID) certificate leaf is signed with the P-384
// alias key using a PKA-primitive ECDSA sign (see the A1 modular opcodes in the
// upka driver). That path needs the curve order `n` and base point `G` in
// addition to the prime `p` above. P-384 only — the alias key curve. Values are
// the significant 48 little-endian operand bytes (no PKA slot padding), matching
// `PRIME384_LE`. Consumed by `ecc_sign_with_k` (A4).

/// NIST P-384 curve order `n` in PKA little-endian operand order.
///
/// Modulus for the scalar arithmetic in the ECDSA sign
/// (`s = k⁻¹·(e + r·d) mod n`).
const ORDER384_LE: [u8; 48] = [
    0x73, 0x29, 0xc5, 0xcc, 0x6a, 0x19, 0xec, 0xec, 0x7a, 0xa7, 0xb0, 0x48, 0xb2, 0x0d, 0x1a, 0x58,
    0xdf, 0x2d, 0x37, 0xf4, 0x81, 0x4d, 0x63, 0xc7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// NIST P-384 base point `G` x-coordinate in PKA little-endian operand order.
const BASE384_X_LE: [u8; 48] = [
    0xb7, 0x0a, 0x76, 0x72, 0x38, 0x5e, 0x54, 0x3a, 0x6c, 0x29, 0x55, 0xbf, 0x5d, 0xf2, 0x02, 0x55,
    0x38, 0x2a, 0x54, 0x82, 0xe0, 0x41, 0xf7, 0x59, 0x98, 0x9b, 0xa7, 0x8b, 0x62, 0x3b, 0x1d, 0x6e,
    0x74, 0xad, 0x20, 0xf3, 0x1e, 0xc7, 0xb1, 0x8e, 0x37, 0x05, 0x8b, 0xbe, 0x22, 0xca, 0x87, 0xaa,
];

/// NIST P-384 base point `G` y-coordinate in PKA little-endian operand order.
const BASE384_Y_LE: [u8; 48] = [
    0x5f, 0x0e, 0xea, 0x90, 0x7c, 0x1d, 0x43, 0x7a, 0x9d, 0x81, 0x7e, 0x1d, 0xce, 0xb1, 0x60, 0x0a,
    0xc0, 0xb8, 0xf0, 0xb5, 0x13, 0x31, 0xda, 0xe9, 0x7c, 0x14, 0x9a, 0x28, 0xbd, 0x1d, 0xf4, 0xf8,
    0x29, 0xdc, 0x92, 0x92, 0xbf, 0x98, 0x9e, 0x5d, 0x6f, 0x2c, 0x26, 0x96, 0x4a, 0xde, 0x17, 0x36,
];

/// Montgomery-representation operand width, in bytes, for the selected curve.
///
/// The PKA `mont_const_calc` / Montgomery-domain operands are wider than the
/// raw field element (field size rounded up to the engine's Montgomery slot):
/// 36 B for P-256, 52 B for P-384, 72 B for P-521.
fn montgomery_size(curve: UpkaEccCurve) -> usize {
    match curve {
        UpkaEccCurve::P256 => 36,
        UpkaEccCurve::P384 => 52,
        UpkaEccCurve::P521 => 72,
    }
}

// =============================================================================
// Deterministic P-384 ECDSA sign (RFC 6979) — PAL orchestration
// =============================================================================

impl UnoHsmPal {
    /// Deterministic ECDSA-P384 sign with a caller-supplied per-message secret
    /// `k` (RFC 6979): computes `(r, s)` for `digest` under private key `d`.
    /// All operands are PKA little-endian, 48 bytes.
    ///
    /// The on-the-fly PID cert leaf is regenerated lazily, so its signature
    /// must be byte-stable — hence `k` is supplied by the caller (RFC 6979)
    /// rather than drawn from the PKA RNG. This is orchestrated on ONE held
    /// PKA engine so a single `mont_const_calc`'s Montgomery state persists 
    /// across the modular ops. Follows the zero-copy driver convention: 
    /// operands/results are supplied by the caller already in DMA-accessible
    /// GSRAM (as with `ecc_verify`/`ecdh_derive`); only the internal scratch 
    /// (~0.7 KB) is allocated here.
    /// # Parameters
    /// * `curve` — must be [`UpkaEccCurve::P384`]; any other curve returns
    ///   [`HsmError::UnsupportedCmd`].
    /// * `k`, `digest`, `d` — 48-byte P-384 scalars (LE) in caller-owned DMA
    ///   buffers: per-message secret, hash `e`, and private key.
    /// * `r`, `s` — caller-owned DMA output buffers (≥ 48 B) for the LE
    ///   signature components.
    ///
    /// # Errors
    /// * [`HsmError::UnsupportedCmd`] — `curve` is not P-384.
    /// * [`HsmError::InvalidArg`] — a bad operand length, or a degenerate
    ///   `r == 0` / `s == 0` result.
    /// * Any [`HsmError`] surfaced by the PKA driver.
    #[allow(dead_code)] // consumed by ecc_sign_deterministic (A6) / PID cert gen (B)
    pub(crate) async fn ecc_sign_with_k(
        &self,
        io: &impl HsmIo,
        curve: UpkaEccCurve,
        k: &DmaBuf,
        digest: &DmaBuf,
        d: &DmaBuf,
        r: &mut DmaBuf,
        s: &mut DmaBuf,
    ) -> HsmResult<()> {
        // Implemented for P-384 only (the cert-chain PID leaf is signed with the
        // P-384 alias key). Other curves are rejected until their constants /
        // sizes are wired in.
        if curve != UpkaEccCurve::P384 {
            return Err(HsmError::UnsupportedCmd);
        }
        let field = PRIME384_LE.len();
        let mont = montgomery_size(curve);

        if k.len() != field
            || digest.len() != field
            || d.len() != field
            || r.len() < field
            || s.len() < field
        {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            // Curve constants (LE) into DMA buffers.
            let prime = scope.dma_alloc(field)?;
            prime.copy_from_slice(&PRIME384_LE);
            let order = scope.dma_alloc(field)?;
            order.copy_from_slice(&ORDER384_LE);
            let base_xy = scope.dma_alloc(field * 2)?;
            base_xy[..field].copy_from_slice(&BASE384_X_LE);
            base_xy[field..].copy_from_slice(&BASE384_Y_LE);

            // Internal scratch. Normal operands are `field` (48) bytes;
            // Montgomery-form operands are `mont` (52) bytes. Each buffer is
            // fully overwritten by its producing PKA op before it is read, so
            // only `xr_wide` needs zero-init: modular reduction is a
            // *double-width* primitive (the hardware reads a `2 * field`
            // dividend), so `xr_wide` holds `xR ‖ 0` — its zeroed high half is
            // essential, or the reduction sees `xR ‖ garbage` and yields a
            // wrong `r`.
            let mont_scratch = scope.dma_alloc(mont)?;
            let xr = scope.dma_alloc(field)?;
            let xr_wide = scope.dma_alloc_zeroed(field * 2)?;
            let k_mont = scope.dma_alloc(mont)?;
            let r_mont = scope.dma_alloc(mont)?;
            let e_mont = scope.dma_alloc(mont)?;
            let d_mont = scope.dma_alloc(mont)?;
            let k_inv = scope.dma_alloc(mont)?;
            let s_mont = scope.dma_alloc(mont)?;
            let t_mont = scope.dma_alloc(mont)?;
            let t_dot_r = scope.dma_alloc(mont)?;
            let s_plus_t = scope.dma_alloc(mont)?;

            // Drive the whole sequence on one held engine so the Montgomery
            // constant set below stays resident for the ops that follow.
            self.pka
                .with_engine(async |eng| {
                    // Montgomery constant = curve prime p, then xR = (k·G).x.
                    eng.ecc_mont_const_calc(curve, prime, mont_scratch).await?;
                    eng.ecc_point_mul(curve, base_xy, k, xr).await?;

                    // Switch the Montgomery constant to the order n for the
                    // scalar arithmetic, then r = xR mod n (must be non-zero).
                    // Reduction is double-width: stage xR into the low half of
                    // the zeroed xr_wide so the hardware reduces `xR ‖ 0`.
                    eng.ecc_mont_const_calc(curve, order, mont_scratch).await?;
                    xr_wide[..field].copy_from_slice(&xr[..field]);
                    eng.ecc_mod_reduction(curve, r, xr_wide).await?;
                    if r[..field].iter().all(|&b| b == 0) {
                        return Err(HsmError::InvalidArg);
                    }

                    // Montgomery form of k, r, e, d.
                    eng.ecc_mont_repr_in(curve, k_mont, k).await?;
                    eng.ecc_mont_repr_in(curve, r_mont, r).await?;
                    eng.ecc_mont_repr_in(curve, e_mont, digest).await?;
                    eng.ecc_mont_repr_in(curve, d_mont, d).await?;

                    // k⁻¹ mod n, then s = k⁻¹·(e + r·d) mod n:
                    //   s = k⁻¹·e ; t = k⁻¹·d ; t = t·r ; s = s + t.
                    eng.ecc_mod_inverse(curve, k_inv, k_mont).await?;
                    eng.ecc_mod_mul(curve, s_mont, k_inv, e_mont).await?;
                    eng.ecc_mod_mul(curve, t_mont, k_inv, d_mont).await?;
                    eng.ecc_mod_mul(curve, t_dot_r, t_mont, r_mont).await?;
                    eng.ecc_mod_add(curve, s_plus_t, s_mont, t_dot_r).await?;

                    // Back to normal representation (must be non-zero).
                    eng.ecc_mont_repr_out(curve, s, s_plus_t).await?;
                    if s[..field].iter().all(|&b| b == 0) {
                        return Err(HsmError::InvalidArg);
                    }

                    // Scrub secret-bearing *internal* scratch (everything derived
                    // from k/d). `DmaBuf::zeroize` uses volatile writes + a
                    // compiler fence (not an elidable `fill`), and the scoped
                    // allocator only rewinds a watermark on release — it does not
                    // clear freed DMA. The caller owns scrubbing the k/d it
                    // supplied; r/s are the public signature.
                    k_mont.zeroize();
                    d_mont.zeroize();
                    k_inv.zeroize();
                    s_mont.zeroize();
                    t_mont.zeroize();
                    t_dot_r.zeroize();
                    s_plus_t.zeroize();
                    Ok(())
                })
                .await
        })
        .await
    }

    /// THROWAWAY: one-shot ECDSA-P384 known-answer self-test for
    /// `ecc_sign_with_k`. Signs the NIST CAVP 186-3 P-384 SigGen vector with
    /// its published per-message secret `k` and compares `(r, s)` to the
    /// expected values (all PKA little-endian, 48 bytes). Runs on the internal
    /// admin IO slot; returns `(pass, r, s)` so the caller can log the computed
    /// components. Remove once the sign is validated on hardware.
    pub async fn ecdsa_sign_self_test(&self) -> HsmResult<(bool, [u8; 48], [u8; 48])> {
        const K: [u8; 48] = [
            0x43, 0x24, 0xa3, 0xf3, 0x24, 0x7e, 0x87, 0x04, 0xa8, 0xd4, 0xea, 0x36, 0x3d, 0xcd,
            0x0f, 0xb3, 0xcc, 0x57, 0xc7, 0x6c, 0xaf, 0xe7, 0xd1, 0x0d, 0x8c, 0x79, 0x9b, 0x29,
            0xb5, 0x96, 0x24, 0x93, 0xc0, 0xcd, 0x97, 0x86, 0xd8, 0xd0, 0x27, 0x78, 0x0b, 0x3d,
            0x68, 0xc4, 0x25, 0x5c, 0x0b, 0xc1,
        ];
        const DIGEST: [u8; 48] = [
            0xd1, 0x3e, 0x7f, 0x7d, 0x01, 0xcd, 0x18, 0x3e, 0x83, 0xc2, 0xfb, 0xe0, 0x00, 0xff,
            0x9d, 0x5f, 0x45, 0x99, 0xb2, 0x72, 0xd1, 0x88, 0xe2, 0x10, 0xda, 0x3f, 0x5d, 0x64,
            0x5f, 0x0a, 0xbd, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        const D: [u8; 48] = [
            0x6b, 0x9e, 0x7f, 0x6d, 0x47, 0x87, 0xc9, 0x83, 0x77, 0x5a, 0x85, 0x9b, 0xd9, 0xf0,
            0x52, 0x4b, 0x18, 0x30, 0x26, 0x16, 0x58, 0xf0, 0x89, 0x2a, 0xc4, 0x6c, 0x67, 0x74,
            0x72, 0x20, 0xf7, 0x84, 0x2c, 0x83, 0xe0, 0x61, 0x96, 0x56, 0xa6, 0x11, 0xc3, 0x92,
            0x45, 0xa3, 0x74, 0xbc, 0x02, 0xc6,
        ];
        const EXP_R: [u8; 48] = [
            0x78, 0xe8, 0x40, 0xd4, 0x46, 0x79, 0x26, 0xc3, 0x2e, 0xaa, 0x88, 0x17, 0x85, 0x61,
            0x8c, 0x97, 0x59, 0x03, 0xab, 0xa0, 0x1d, 0x55, 0x54, 0x90, 0x60, 0xad, 0xc2, 0xeb,
            0xd7, 0x7e, 0x47, 0x48, 0x59, 0x78, 0x02, 0xcd, 0x38, 0x3f, 0x48, 0xd4, 0x86, 0x32,
            0xf5, 0xda, 0x0c, 0xb0, 0x1d, 0xb1,
        ];
        const EXP_S: [u8; 48] = [
            0xf2, 0xcb, 0xf8, 0x7d, 0x02, 0xac, 0x48, 0x10, 0x67, 0x87, 0x78, 0x4b, 0xe7, 0x27,
            0x8b, 0xc9, 0xd7, 0x12, 0x65, 0x07, 0x5a, 0x06, 0xf5, 0x2f, 0x76, 0x3a, 0x68, 0x9c,
            0x31, 0xe3, 0xb6, 0xe2, 0xe8, 0x73, 0xe9, 0xfe, 0xa8, 0x12, 0x81, 0xe6, 0x4c, 0x60,
            0xb0, 0xc5, 0x73, 0x78, 0x00, 0x16,
        ];

        let io = crate::io::UnoHsmIo::admin(azihsm_fw_hsm_pal_traits::HsmPartId::from(0u8));
        self.alloc_scoped_async(&io, async |scope| {
            // Stage the caller-owned operands/results into DMA (as a real caller
            // would); ecc_sign_with_k allocates only its own scratch (nested).
            let k = scope.dma_alloc(48)?;
            k.copy_from_slice(&K);
            let digest = scope.dma_alloc(48)?;
            digest.copy_from_slice(&DIGEST);
            let d = scope.dma_alloc(48)?;
            d.copy_from_slice(&D);
            let r = scope.dma_alloc_zeroed(48)?;
            let s = scope.dma_alloc_zeroed(48)?;
            self.ecc_sign_with_k(&io, UpkaEccCurve::P384, k, digest, d, r, s)
                .await?;
            let mut ro = [0u8; 48];
            ro.copy_from_slice(&r[..48]);
            let mut so = [0u8; 48];
            so.copy_from_slice(&s[..48]);
            Ok((ro == EXP_R && so == EXP_S, ro, so))
        })
        .await
    }
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
    /// * Any [`HsmError`] surfaced by the PKA driver (e.g. invalid
    ///   public-key point, undersized buffer, hardware fault).
    async fn ecdh_derive(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;

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

            self.pka
                .ecdh_derive(pka_curve, priv_key, pub_key, secret, prime, mont_result)
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
        _der: &DmaBuf,
        _out: Option<&mut DmaBuf>,
    ) -> HsmResult<(usize, HsmEccCurve)> {
        // TODO: parse the recovered PKCS#8 ECC private key on Uno and
        // re-export it in the vault representation (RsaUnwrap ECC import).
        Err(HsmError::UnsupportedCmd)
    }

    async fn ecc_priv_pub_key(
        &self,
        _io: &impl HsmIo,
        _priv_key: &DmaBuf,
        _pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        // TODO: derive the wire public key from a vault-stored ECC private
        // key on Uno PKA (RsaUnwrap ECC import).
        Err(HsmError::UnsupportedCmd)
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
