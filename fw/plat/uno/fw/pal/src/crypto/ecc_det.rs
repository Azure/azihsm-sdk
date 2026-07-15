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

/// RFC 6979 §3.2 DRBG message-assembly length for P-384:
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
/// Each rejection (candidate out of `[1, n-1]`, or a degenerate `r == 0` /
/// `s == 0` signature) has probability ~`2^-384` for P-384, so the first
/// attempt always succeeds in practice; the bound only guarantees the loop
/// terminates.
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
            let mut n_be = ORDER384_LE;
            n_be.reverse();
            let mut drbg = Rfc6979Drbg {
                key: scope.dma_alloc(field)?,
                v: scope.dma_alloc(field)?,
                tag: scope.dma_alloc(field)?,
                msg: scope.dma_alloc(RFC6979_SEED_MSG_LEN)?,
                n_be,
            };
            self.rfc6979_seed(io, &mut drbg, d, digest).await?;

            // RFC 6979 §3.2 (h): generate candidates until 1 <= k < n.
            let mut outcome = Err(HsmError::InvalidArg);
            for _ in 0..RFC6979_MAX_TRIES {
                self.rfc6979_generate(io, &mut drbg).await?;
                let v_be: &[u8] = &drbg.v[..];
                if v_be.iter().any(|&b| b != 0) && v_be[..field] < drbg.n_be[..field] {
                    // Candidate `k` (big-endian) in [1, n-1]; emit little-endian.
                    k[..field].copy_from_slice(&drbg.v[..field]);
                    k[..field].reverse();
                    outcome = Ok(());
                    break;
                }
                self.rfc6979_reseed(io, &mut drbg).await?;
            }
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
            let mut n_be = ORDER384_LE;
            n_be.reverse();
            let mut drbg = Rfc6979Drbg {
                key: scope.dma_alloc(field)?,
                v: scope.dma_alloc(field)?,
                tag: scope.dma_alloc(field)?,
                msg: scope.dma_alloc(RFC6979_SEED_MSG_LEN)?,
                n_be,
            };
            let k = scope.dma_alloc(field)?;

            self.rfc6979_seed(io, &mut drbg, d, digest).await?;

            let mut outcome = Err(HsmError::InvalidArg);
            for _ in 0..RFC6979_MAX_TRIES {
                self.rfc6979_generate(io, &mut drbg).await?;
                let v_be: &[u8] = &drbg.v[..];
                if v_be.iter().any(|&b| b != 0) && v_be[..field] < drbg.n_be[..field] {
                    // Candidate k in [1, n-1]; stage little-endian and sign.
                    k[..field].copy_from_slice(&drbg.v[..field]);
                    k[..field].reverse();
                    match self.ecc_sign_with_k(io, curve, k, digest, d, r, s).await {
                        Ok(()) => {
                            outcome = Ok(());
                            break;
                        }
                        // Degenerate r/s — advance the DRBG and retry.
                        Err(HsmError::InvalidArg) => {}
                        Err(e) => {
                            outcome = Err(e);
                            break;
                        }
                    }
                }
                self.rfc6979_reseed(io, &mut drbg).await?;
            }
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
        self.rfc6979_update_key(io, drbg, RFC6979_SEED_MSG_LEN).await?;
        self.rfc6979_update_v(io, drbg).await?;
        // (f) K = HMAC_K(V ‖ 0x01 ‖ x ‖ h1) ; (g) V = HMAC_K(V)
        drbg.msg[..field].copy_from_slice(&drbg.v[..field]);
        drbg.msg[field] = 0x01;
        self.rfc6979_update_key(io, drbg, RFC6979_SEED_MSG_LEN).await?;
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
        self.hmac_sign(io, HsmHashAlgo::Sha384, &*drbg.key, &*drbg.v, &mut *drbg.tag)
            .await?;
        core::mem::swap(&mut drbg.v, &mut drbg.tag);
        Ok(())
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

    /// THROWAWAY: known-answer self-test for `ecc_generate_k_rfc6979`.
    /// Derives `k` from the RFC 6979 Appendix A.2.6 P-384 example (private key
    /// `x`, `digest = SHA-384("sample")`) and compares it to the published
    /// `k` (all PKA little-endian, 48 bytes). Runs on the internal admin IO
    /// slot; returns `(pass, k)` so the caller can log the derived value.
    /// Remove once the derivation is validated on hardware.
    pub async fn rfc6979_k_self_test(&self) -> HsmResult<(bool, [u8; 48])> {
        const D: [u8; 48] = [
            0xf5, 0xed, 0xd2, 0x60, 0xea, 0xc9, 0x72, 0xf8, 0x25, 0xa8, 0x70, 0x4c, 0x4e, 0x72,
            0xd5, 0x96, 0xd8, 0x37, 0x71, 0x78, 0x40, 0x77, 0xa4, 0x9a, 0xba, 0x97, 0xf2, 0x7b,
            0x66, 0x3b, 0x3c, 0xe2, 0x4d, 0x9f, 0x65, 0xb6, 0x75, 0x98, 0xb1, 0x05, 0x1c, 0x8c,
            0x1b, 0x2e, 0xad, 0x3d, 0x9d, 0x6b,
        ];
        const DIGEST: [u8; 48] = [
            0xfe, 0x25, 0xee, 0xb1, 0x77, 0x2c, 0xe4, 0xfe, 0x0e, 0x89, 0x5b, 0x9b, 0x4a, 0xca,
            0x3b, 0x31, 0x12, 0x53, 0x58, 0x40, 0xf3, 0x29, 0xa0, 0x96, 0x11, 0x38, 0xbd, 0x4b,
            0x3f, 0x60, 0xbf, 0xf3, 0x7b, 0xef, 0x96, 0x26, 0x31, 0xbe, 0xc4, 0xae, 0x76, 0x22,
            0xc9, 0x5b, 0x50, 0x83, 0x90, 0x9a,
        ];
        const EXP_K: [u8; 48] = [
            0xf9, 0x5c, 0x91, 0x86, 0x46, 0x8c, 0x3b, 0x62, 0x68, 0x53, 0xa9, 0x3b, 0xe8, 0xe3,
            0x07, 0x29, 0xca, 0xfb, 0x10, 0x6d, 0xd5, 0x5f, 0x55, 0x7a, 0xa8, 0x0c, 0xaf, 0x8e,
            0x16, 0x15, 0xba, 0xe4, 0xbd, 0x5a, 0xe8, 0x2a, 0x24, 0xe9, 0x54, 0x32, 0xad, 0x9d,
            0x09, 0x1a, 0x0d, 0x91, 0xed, 0x94,
        ];

        let io = crate::io::UnoHsmIo::admin(azihsm_fw_hsm_pal_traits::HsmPartId::from(0u8));
        self.alloc_scoped_async(&io, async |scope| {
            let digest = scope.dma_alloc(48)?;
            digest.copy_from_slice(&DIGEST);
            let d = scope.dma_alloc(48)?;
            d.copy_from_slice(&D);
            let k = scope.dma_alloc_zeroed(48)?;
            self.ecc_generate_k_rfc6979(&io, UpkaEccCurve::P384, d, digest, k)
                .await?;
            let mut ko = [0u8; 48];
            ko.copy_from_slice(&k[..48]);
            Ok((ko == EXP_K, ko))
        })
        .await
    }

    /// THROWAWAY: end-to-end known-answer self-test for
    /// `ecc_sign_deterministic`. Signs the RFC 6979 Appendix A.2.6 P-384 /
    /// SHA-384 example (private key `x`, `digest = SHA-384("sample")`) and
    /// compares `(r, s)` to the published signature (all PKA little-endian, 48
    /// bytes). Exercises the full deterministic path (RFC 6979 `k` derivation
    /// composed with the PKA sign). Runs on the internal admin IO slot; returns
    /// `(pass, r, s)`. Remove once validated on hardware.
    pub async fn ecdsa_deterministic_sign_self_test(
        &self,
    ) -> HsmResult<(bool, [u8; 48], [u8; 48])> {
        const D: [u8; 48] = [
            0xf5, 0xed, 0xd2, 0x60, 0xea, 0xc9, 0x72, 0xf8, 0x25, 0xa8, 0x70, 0x4c, 0x4e, 0x72,
            0xd5, 0x96, 0xd8, 0x37, 0x71, 0x78, 0x40, 0x77, 0xa4, 0x9a, 0xba, 0x97, 0xf2, 0x7b,
            0x66, 0x3b, 0x3c, 0xe2, 0x4d, 0x9f, 0x65, 0xb6, 0x75, 0x98, 0xb1, 0x05, 0x1c, 0x8c,
            0x1b, 0x2e, 0xad, 0x3d, 0x9d, 0x6b,
        ];
        const DIGEST: [u8; 48] = [
            0xfe, 0x25, 0xee, 0xb1, 0x77, 0x2c, 0xe4, 0xfe, 0x0e, 0x89, 0x5b, 0x9b, 0x4a, 0xca,
            0x3b, 0x31, 0x12, 0x53, 0x58, 0x40, 0xf3, 0x29, 0xa0, 0x96, 0x11, 0x38, 0xbd, 0x4b,
            0x3f, 0x60, 0xbf, 0xf3, 0x7b, 0xef, 0x96, 0x26, 0x31, 0xbe, 0xc4, 0xae, 0x76, 0x22,
            0xc9, 0x5b, 0x50, 0x83, 0x90, 0x9a,
        ];
        const EXP_R: [u8; 48] = [
            0x46, 0xbe, 0xfa, 0x80, 0x1e, 0xdd, 0x36, 0x6e, 0xf9, 0xac, 0x44, 0x2e, 0x15, 0x48,
            0xa6, 0x81, 0x3c, 0x13, 0xad, 0x95, 0xea, 0xc4, 0x64, 0x3d, 0xa7, 0x9f, 0xce, 0x66,
            0x06, 0x14, 0x88, 0x3f, 0x6b, 0x91, 0x91, 0xc6, 0x56, 0x6e, 0x73, 0xd4, 0xaa, 0xb8,
            0xec, 0xa5, 0x92, 0xbb, 0xed, 0x94,
        ];
        const EXP_S: [u8; 48] = [
            0xc8, 0x8a, 0x62, 0x38, 0x1a, 0xc7, 0x82, 0x7b, 0x9e, 0x67, 0x6e, 0x78, 0x45, 0xc1,
            0x29, 0xa3, 0x4f, 0xa9, 0xa3, 0xd0, 0x51, 0x63, 0x3b, 0x20, 0x26, 0x45, 0x62, 0x19,
            0x0a, 0x74, 0x0e, 0x13, 0x8f, 0x13, 0x03, 0x26, 0xdb, 0x40, 0xfe, 0xa1, 0xce, 0x78,
            0xf1, 0x15, 0xeb, 0x4a, 0xef, 0x99,
        ];

        let io = crate::io::UnoHsmIo::admin(azihsm_fw_hsm_pal_traits::HsmPartId::from(0u8));
        self.alloc_scoped_async(&io, async |scope| {
            let digest = scope.dma_alloc(48)?;
            digest.copy_from_slice(&DIGEST);
            let d = scope.dma_alloc(48)?;
            d.copy_from_slice(&D);
            let r = scope.dma_alloc_zeroed(48)?;
            let s = scope.dma_alloc_zeroed(48)?;
            self.ecc_sign_deterministic(&io, UpkaEccCurve::P384, digest, d, r, s)
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
