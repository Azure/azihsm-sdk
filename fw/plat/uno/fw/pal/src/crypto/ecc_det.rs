// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deterministic ECC operations for the Uno PAL (RFC 6979).
//!
//! Split out of [`super::ecc`] to keep the base [`HsmEcc`] trait adapter
//! focused on the standard curve operations. This module holds the
//! deterministic ECDSA-P384 sign path built on the PKA modular opcodes:
//!
//! - the RFC 6979 HMAC-SHA384 DRBG ([`Rfc6979Drbg`]) and its
//!   seed/generate/reseed steps,
//! - deterministic per-message secret `k` derivation
//!   ([`UnoHsmPal::ecc_generate_k_rfc6979`]),
//! - the PKA sign orchestration with a supplied `k`
//!   ([`UnoHsmPal::ecc_sign_with_k`]), and
//! - the end-to-end deterministic sign
//!   ([`UnoHsmPal::ecc_sign_deterministic`]) that composes the two.
//!
//! P-384 only — the alias key curve used to sign the partition-id (PID)
//! certificate leaf. The shared prime modulus [`PRIME384_LE`] lives in
//! [`super::ecc`]; the order and base-point constants are P-384 specific
//! to this path and defined here.
//!
//! [`HsmEcc`]: azihsm_fw_hsm_pal_traits::HsmEcc

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmHmac;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_upka::UpkaEccCurve;
use azihsm_fw_uno_drivers_upka::mont_operand_size;

use super::ecc::PRIME384_LE;
use crate::UnoHsmPal;

// =============================================================================
// P-384 deterministic-sign constants (RFC 6979)
// =============================================================================
//
// The on-the-fly partition-id (PID) certificate leaf is signed with the P-384
// alias key using a PKA-primitive ECDSA sign (see the A1 modular opcodes in the
// upka driver). That path needs the curve order `n` and base point `G` in
// addition to the prime `p` ([`PRIME384_LE`] in [`super::ecc`]). P-384 only —
// the alias key curve. Values are the significant 48 little-endian operand bytes
// (no PKA slot padding), matching [`PRIME384_LE`]. Consumed by `ecc_sign_with_k`
// (A4).

/// NIST P-384 curve order `n` in PKA little-endian operand order.
///
/// Modulus for the scalar arithmetic in the ECDSA sign
/// (`s = k⁻¹·(e + r·d) mod n`).
const ORDER384_LE: [u8; 48] = [
    0x73, 0x29, 0xc5, 0xcc, 0x6a, 0x19, 0xec, 0xec, 0x7a, 0xa7, 0xb0, 0x48, 0xb2, 0x0d, 0x1a, 0x58,
    0xdf, 0x2d, 0x37, 0xf4, 0x81, 0x4d, 0x63, 0xc7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Reverse a 48-byte operand at compile time.
const fn reverse48(mut a: [u8; 48]) -> [u8; 48] {
    let mut i = 0;
    while i < 24 {
        let t = a[i];
        a[i] = a[47 - i];
        a[47 - i] = t;
        i += 1;
    }
    a
}

/// NIST P-384 curve order `n` in big-endian.
///
/// The RFC 6979 DRBG emits candidates big-endian (`bits2int`), so the
/// candidate-range check ([`ct_in_range`]) compares big-endian. Derived from
/// [`ORDER384_LE`] at compile time so the sign hot path does not reverse the
/// order on every call.
const ORDER384_BE: [u8; 48] = reverse48(ORDER384_LE);

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

/// Big-endian `a -= b` for equal-length operands, assuming `a >= b`.
///
/// Used for the single conditional subtraction in RFC 6979 `bits2octets`
/// (`digest mod n`). Operates from the least-significant byte with a running
/// borrow.
fn be_sub_assign(a: &mut [u8], b: &[u8]) {
    let mut borrow = 0i16;
    for i in (0..a.len()).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            a[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            a[i] = diff as u8;
            borrow = 0;
        }
    }
}

/// Constant-time check that the big-endian candidate `v` is in `[1, n-1]`.
///
/// `v` is the RFC 6979 DRBG output — i.e. the secret per-message nonce
/// candidate — so the accept/reject decision must not leak its magnitude via
/// timing (cf. the Minerva / TPM-Fail ECDSA nonce-leak attacks, which recover
/// the private key from a few biased/leaked nonce bits). Both operands are
/// equal-length big-endian; every byte is read with no data-dependent early
/// exit.
fn ct_in_range(v: &[u8], n: &[u8]) -> bool {
    // v != 0: OR all bytes, then test the accumulator once.
    let mut acc = 0u8;
    for &b in v {
        acc |= b;
    }
    let nonzero = acc != 0;

    // v < n: full-width big-endian subtraction (LSB->MSB) with an 8-bit
    // borrow; the final borrow is 1 iff v < n. `diff >> 8` is -1 (=> `& 1` is
    // 1) exactly on underflow, so the loop is branch-free over the byte values.
    let mut borrow = 0i32;
    for i in (0..v.len()).rev() {
        let diff = v[i] as i32 - n[i] as i32 - borrow;
        borrow = (diff >> 8) & 1;
    }
    let lt = borrow == 1;

    nonzero & lt
}

/// `V ‖ 0x00/0x01 ‖ int2octets(x) ‖ bits2octets(h1)` = 48 + 1 + 48 + 48.
const RFC6979_SEED_MSG_LEN: usize = 48 + 1 + 48 + 48;

/// RFC 6979 HMAC-SHA384 DRBG for P-384, backed by DMA scratch.
///
/// `K`, `V`, and a `tag` output slot are 48-byte DMA buffers; `msg` is the
/// reusable [`RFC6979_SEED_MSG_LEN`]-byte input-assembly buffer. Keeping the
/// state DMA-resident lets the SHA engine read and write it in place, so each
/// HMAC step avoids per-call staging copies and allocations: `V = HMAC_K(V)`
/// writes into `tag`, then rotates `v`/`tag` *by reference* (zero-copy). All
/// four buffers hold key-derived material and are wiped by [`Self::scrub`].
/// `n_be` is the curve order `n` (big-endian) for the candidate-range test.
struct Rfc6979Drbg<'a> {
    key: &'a mut DmaBuf,
    v: &'a mut DmaBuf,
    tag: &'a mut DmaBuf,
    msg: &'a mut DmaBuf,
    n_be: [u8; 48],
}

impl Rfc6979Drbg<'_> {
    /// Volatile-scrub every key-derived DMA buffer.
    fn scrub(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
        self.tag.zeroize();
        self.msg.zeroize();
    }
}

/// Upper bound on RFC 6979 candidate attempts before giving up.
///
/// Two independent rejections can advance the DRBG: the candidate falling
/// outside `[1, n-1]`, and a degenerate `r == 0` / `s == 0` signature. For
/// P-384 the range check is the dominant one at ~`2^-194` (the top 192 bits
/// of `n` are 1s, so `n` is within ~`2^190` of `2^384`); the
/// degenerate-signature cases are ~`2^-384`. Both are astronomically rare, so
/// the first attempt always succeeds in practice; the bound only guarantees
/// the loop terminates.
const RFC6979_MAX_TRIES: usize = 8;

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
    #[allow(clippy::too_many_arguments)]
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
        let mont = mont_operand_size(curve);

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
            let res = self
                .pka
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

                    Ok(())
                })
                .await;

            // Scrub secret-bearing internal scratch on EVERY exit path (success,
            // degenerate r/s, or a mid-sequence PKA error): the scoped allocator
            // only rewinds a watermark on release — it does not clear freed DMA,
            // so key-derived bytes must be wiped here. `DmaBuf::zeroize` uses
            // volatile writes + a compiler fence (not an elidable `fill`). `xr` /
            // `xr_wide` hold (k·G).x — public as `r`, but k-derived, so they are
            // scrubbed as defense-in-depth. The caller owns scrubbing the k/d it
            // supplied; r/s are the public signature.
            xr.zeroize();
            xr_wide.zeroize();
            k_mont.zeroize();
            d_mont.zeroize();
            k_inv.zeroize();
            s_mont.zeroize();
            t_mont.zeroize();
            t_dot_r.zeroize();
            s_plus_t.zeroize();
            res
        })
        .await
    }

    /// RFC 6979 deterministic per-message secret `k` for ECDSA-P384.
    ///
    /// Derives `k` from the private key `d` and message hash `digest` via the
    /// HMAC-SHA384 DRBG of RFC 6979 §3.2, so the lazily regenerated PID cert
    /// signature is byte-stable without drawing `k` from a PRNG.
    ///
    /// All PAL operands are little-endian, but RFC 6979's integer/octet
    /// conversions are big-endian, so `d`/`digest` are byte-reversed on input
    /// and `k` on output. Because `hlen == qlen == 384` for P-384, each DRBG
    /// block yields exactly one candidate (`T = V`) and `bits2octets(digest)`
    /// reduces mod `n` with a single conditional subtraction (`n > 2^383`, so
    /// `digest < 2n`).
    ///
    /// # Parameters
    /// * `curve` — must be [`UpkaEccCurve::P384`]; other curves return
    ///   [`HsmError::UnsupportedCmd`].
    /// * `d` — 48-byte P-384 private key (LE) in a caller-owned DMA buffer.
    /// * `digest` — 48-byte message hash `e` (LE, SHA-384) in a caller-owned
    ///   DMA buffer.
    /// * `k` — caller-owned DMA output buffer (>= 48 B) for the LE secret.
    ///
    /// # Errors
    /// * [`HsmError::UnsupportedCmd`] — `curve` is not P-384.
    /// * [`HsmError::InvalidArg`] — a bad operand length.
    /// * Any [`HsmError`] surfaced by the HMAC driver.
    #[allow(dead_code)] // consumed by ecc_sign_deterministic (A6) / PID cert gen (B)
    pub(crate) async fn ecc_generate_k_rfc6979(
        &self,
        io: &impl HsmIo,
        curve: UpkaEccCurve,
        d: &DmaBuf,
        digest: &DmaBuf,
        k: &mut DmaBuf,
    ) -> HsmResult<()> {
        if curve != UpkaEccCurve::P384 {
            return Err(HsmError::UnsupportedCmd);
        }
        let field = PRIME384_LE.len(); // 48; also the SHA-384 digest length
        if d.len() != field || digest.len() != field || k.len() < field {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            let mut drbg = Rfc6979Drbg {
                key: scope.dma_alloc(field)?,
                v: scope.dma_alloc(field)?,
                tag: scope.dma_alloc(field)?,
                msg: scope.dma_alloc(RFC6979_SEED_MSG_LEN)?,
                n_be: ORDER384_BE,
            };
            // Run the fallible DRBG sequence in an inner block so the secret
            // state (`K`, `V`, and the assembled `x ‖ h1` in `msg`) is scrubbed
            // on EVERY exit path — including an early `?` from
            // seed/generate/reseed. The scoped allocator only rewinds its
            // watermark on release; it does not clear freed DMA.
            let outcome = async {
                self.rfc6979_seed(io, &mut drbg, d, digest).await?;

                // RFC 6979 §3.2 (h): generate candidates until 1 <= k < n.
                for _ in 0..RFC6979_MAX_TRIES {
                    self.rfc6979_generate(io, &mut drbg).await?;
                    let v_be: &[u8] = &drbg.v[..];
                    if ct_in_range(&v_be[..field], &drbg.n_be[..field]) {
                        // Candidate `k` (big-endian) in [1, n-1]; emit little-endian.
                        k[..field].copy_from_slice(&drbg.v[..field]);
                        k[..field].reverse();
                        return Ok(());
                    }
                    self.rfc6979_reseed(io, &mut drbg).await?;
                }
                Err(HsmError::InvalidArg)
            }
            .await;

            drbg.scrub();
            outcome
        })
        .await
    }

    /// Deterministic ECDSA-P384 sign (RFC 6979): derive the per-message secret
    /// `k` from `d`/`digest` and produce the signature `(r, s)`.
    ///
    /// Composes the RFC 6979 HMAC-SHA384 DRBG (A5) with the PKA sign (A4). The
    /// DRBG state, its `k` output, and the sign scratch all live in one scope.
    /// On the astronomically unlikely degenerate result (`r == 0` or `s == 0`)
    /// the DRBG is advanced to the next candidate, as required by RFC 6979
    /// §3.2; because this function supplies valid P-384 operands,
    /// [`ecc_sign_with_k`](Self::ecc_sign_with_k)'s only [`HsmError::InvalidArg`]
    /// is that degenerate check, which is treated as a retry signal.
    ///
    /// # Parameters
    /// * `curve` — must be [`UpkaEccCurve::P384`]; other curves return
    ///   [`HsmError::UnsupportedCmd`].
    /// * `digest` — 48-byte message hash `e` (LE, SHA-384) in a caller-owned
    ///   DMA buffer.
    /// * `d` — 48-byte P-384 private key (LE) in a caller-owned DMA buffer.
    /// * `r`, `s` — caller-owned DMA output buffers (>= 48 B) for the LE
    ///   signature components.
    ///
    /// # Errors
    /// * [`HsmError::UnsupportedCmd`] — `curve` is not P-384.
    /// * [`HsmError::InvalidArg`] — a bad operand length, or every candidate in
    ///   [`RFC6979_MAX_TRIES`] was exhausted (unreachable in practice).
    /// * Any [`HsmError`] surfaced by the HMAC or PKA drivers.
    #[allow(dead_code)] // consumed by PID cert gen (B)
    pub(crate) async fn ecc_sign_deterministic(
        &self,
        io: &impl HsmIo,
        curve: UpkaEccCurve,
        digest: &DmaBuf,
        d: &DmaBuf,
        r: &mut DmaBuf,
        s: &mut DmaBuf,
    ) -> HsmResult<()> {
        if curve != UpkaEccCurve::P384 {
            return Err(HsmError::UnsupportedCmd);
        }
        let field = PRIME384_LE.len();
        if digest.len() != field || d.len() != field || r.len() < field || s.len() < field {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            let mut drbg = Rfc6979Drbg {
                key: scope.dma_alloc(field)?,
                v: scope.dma_alloc(field)?,
                tag: scope.dma_alloc(field)?,
                msg: scope.dma_alloc(RFC6979_SEED_MSG_LEN)?,
                n_be: ORDER384_BE,
            };
            let k = scope.dma_alloc(field)?;

            // Run the fallible derive+sign in an inner block so `k` and the DRBG
            // state are wiped on EVERY exit path — including an early `?` from
            // seed/generate/reseed. The scoped allocator only rewinds its
            // watermark on release; it does not clear freed DMA.
            let outcome = async {
                self.rfc6979_seed(io, &mut drbg, d, digest).await?;

                for _ in 0..RFC6979_MAX_TRIES {
                    self.rfc6979_generate(io, &mut drbg).await?;
                    let v_be: &[u8] = &drbg.v[..];
                    if ct_in_range(&v_be[..field], &drbg.n_be[..field]) {
                        // Candidate k in [1, n-1]; stage little-endian and sign.
                        k[..field].copy_from_slice(&drbg.v[..field]);
                        k[..field].reverse();
                        match self.ecc_sign_with_k(io, curve, k, digest, d, r, s).await {
                            Ok(()) => return Ok(()),
                            // Degenerate r/s — advance the DRBG and retry.
                            Err(HsmError::InvalidArg) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    self.rfc6979_reseed(io, &mut drbg).await?;
                }
                Err(HsmError::InvalidArg)
            }
            .await;

            k.zeroize();
            drbg.scrub();
            outcome
        })
        .await
    }

    /// RFC 6979 §3.2 (b)-(g): seed the HMAC-SHA384 DRBG for P-384 from the
    /// private key `d` and message hash `digest` (both 48-byte LE).
    ///
    /// The RFC's integer/octet conversions are big-endian, so `d`/`digest` are
    /// byte-reversed into `x = int2octets(d)` and `h1 = bits2octets(digest)`
    /// directly inside the DMA-resident assembly buffer. Since `hlen == qlen ==
    /// 384` and `n > 2^383` (so `digest < 2n`), `h1` reduces mod `n` with a
    /// single conditional subtraction. `x`/`h1` stay fixed across both key
    /// derivations, so only the `V`-prefix and the tag byte change between them.
    /// Assumes `drbg.n_be` is already set.
    async fn rfc6979_seed(
        &self,
        io: &impl HsmIo,
        drbg: &mut Rfc6979Drbg<'_>,
        d: &DmaBuf,
        digest: &DmaBuf,
    ) -> HsmResult<()> {
        let field = PRIME384_LE.len();

        // K = 0x00…, V = 0x01…
        drbg.key.fill(0x00);
        drbg.v.fill(0x01);

        // msg = V ‖ 0x00 ‖ int2octets(x) ‖ bits2octets(h1).
        drbg.msg[..field].copy_from_slice(&drbg.v[..field]);
        drbg.msg[field] = 0x00;
        drbg.msg[field + 1..field + 1 + field].copy_from_slice(&d[..field]);
        drbg.msg[field + 1..field + 1 + field].reverse();
        {
            // h1 = bits2octets(digest): big-endian digest reduced mod n.
            let (_, tail) = drbg.msg.split_at_mut(field + 1 + field);
            let h1: &mut [u8] = &mut tail[..field];
            h1.copy_from_slice(&digest[..field]);
            h1.reverse();
            if h1[..] >= drbg.n_be[..] {
                be_sub_assign(h1, &drbg.n_be);
            }
        }

        // (d) K = HMAC_K(V ‖ 0x00 ‖ x ‖ h1) ; (e) V = HMAC_K(V)
        self.rfc6979_update_key(io, drbg, RFC6979_SEED_MSG_LEN)
            .await?;
        self.rfc6979_update_v(io, drbg).await?;
        // (f) K = HMAC_K(V ‖ 0x01 ‖ x ‖ h1) ; (g) V = HMAC_K(V)
        drbg.msg[..field].copy_from_slice(&drbg.v[..field]);
        drbg.msg[field] = 0x01;
        self.rfc6979_update_key(io, drbg, RFC6979_SEED_MSG_LEN)
            .await?;
        self.rfc6979_update_v(io, drbg).await?;
        Ok(())
    }

    /// RFC 6979 §3.2 (h) one generate block: `V = HMAC_K(V)`. Because
    /// `hlen == qlen == 384`, `T = V`, so the candidate is `drbg.v`
    /// (big-endian) on return.
    async fn rfc6979_generate(&self, io: &impl HsmIo, drbg: &mut Rfc6979Drbg<'_>) -> HsmResult<()> {
        self.rfc6979_update_v(io, drbg).await
    }

    /// RFC 6979 §3.2 (h) reseed after a rejected candidate:
    /// `K = HMAC_K(V ‖ 0x00)` then `V = HMAC_K(V)`.
    async fn rfc6979_reseed(&self, io: &impl HsmIo, drbg: &mut Rfc6979Drbg<'_>) -> HsmResult<()> {
        let field = PRIME384_LE.len();
        drbg.msg[..field].copy_from_slice(&drbg.v[..field]);
        drbg.msg[field] = 0x00;
        self.rfc6979_update_key(io, drbg, field + 1).await?;
        self.rfc6979_update_v(io, drbg).await?;
        Ok(())
    }

    /// `K = HMAC_K(msg[..len])` (RFC 6979 §3.2 (d)/(f) and reseed). Writes the
    /// tag into the DMA `tag` slot, then rotates `key`/`tag` *by reference* so
    /// `drbg.key` holds the new `K` with no copy. The caller stages `msg`.
    async fn rfc6979_update_key(
        &self,
        io: &impl HsmIo,
        drbg: &mut Rfc6979Drbg<'_>,
        len: usize,
    ) -> HsmResult<()> {
        if len > drbg.msg.len() {
            return Err(HsmError::InvalidArg);
        }
        let (data, _) = drbg.msg.split_at(len);
        self.hmac_sign(io, HsmHashAlgo::Sha384, &*drbg.key, data, &mut *drbg.tag)
            .await?;
        core::mem::swap(&mut drbg.key, &mut drbg.tag);
        Ok(())
    }

    /// `V = HMAC_K(V)` (RFC 6979 §3.2 (e)/(g)/(h2)). Writes the tag into the
    /// DMA `tag` slot, then rotates `v`/`tag` *by reference* so `drbg.v` holds
    /// the new `V` (the next candidate, big-endian) with no copy.
    async fn rfc6979_update_v(&self, io: &impl HsmIo, drbg: &mut Rfc6979Drbg<'_>) -> HsmResult<()> {
        self.hmac_sign(
            io,
            HsmHashAlgo::Sha384,
            &*drbg.key,
            &*drbg.v,
            &mut *drbg.tag,
        )
        .await?;
        core::mem::swap(&mut drbg.v, &mut drbg.tag);
        Ok(())
    }
}
