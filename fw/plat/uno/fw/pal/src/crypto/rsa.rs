// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA trait implementation for the Uno PAL.
//!
//! Implements raw modular exponentiation via the PKA hardware engine,
//! and four padding schemes (PKCS#1 v1.5, OAEP, PSS) synthesized in
//! firmware from SHA, MGF1, and RNG primitives.
//!
//! Key generation is not supported — RSA keys are provisioned
//! off-platform.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHash;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKdf;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRng;
use azihsm_fw_hsm_pal_traits::HsmRsa;
use azihsm_fw_hsm_pal_traits::HsmRsaKey;
use azihsm_fw_hsm_pal_traits::HsmRsaPct;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_upka::UpkaModSize;
use azihsm_fw_uno_drivers_upka::UpkaRsaKeyType;

use super::reverse_copy;
use crate::UnoHsmPal;
use crate::asn1::parse_rsa_private_key;

// =============================================================================
// Helper functions
// =============================================================================

/// Convert HsmRsaKey to UpkaRsaKeyType.
fn rsa_key_to_upka_key_type(key: HsmRsaKey) -> UpkaRsaKeyType {
    match key {
        HsmRsaKey::Rsa2048Pub | HsmRsaKey::Rsa2048Priv => UpkaRsaKeyType::Rsa2048,
        HsmRsaKey::Rsa2048CrtPriv => UpkaRsaKeyType::Rsa2048Crt,
        HsmRsaKey::Rsa3072Pub | HsmRsaKey::Rsa3072Priv => UpkaRsaKeyType::Rsa3072,
        HsmRsaKey::Rsa3072CrtPriv => UpkaRsaKeyType::Rsa3072Crt,
        HsmRsaKey::Rsa4096Pub | HsmRsaKey::Rsa4096Priv => UpkaRsaKeyType::Rsa4096,
        HsmRsaKey::Rsa4096CrtPriv => UpkaRsaKeyType::Rsa4096Crt,
    }
}

fn digest_info_prefix(algo: HsmHashAlgo) -> &'static [u8] {
    match algo {
        // SHA-256: SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING(32) }
        HsmHashAlgo::Sha256 => &[
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        // SHA-384: SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.2, NULL }, OCTET STRING(48) }
        HsmHashAlgo::Sha384 => &[
            0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        // SHA-512: SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.3, NULL }, OCTET STRING(64) }
        HsmHashAlgo::Sha512 => &[
            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        // SHA-1: SEQUENCE { SEQUENCE { OID 1.3.14.3.2.26, NULL }, OCTET STRING(20) }
        HsmHashAlgo::Sha1 => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04,
            0x14,
        ],
    }
}

// =============================================================================
// Vault operand assembly (imported RSA private key → PKA layout)
// =============================================================================

/// Width of the public-exponent slot in the Uno vault's RSA private-key
/// operand `d(k) ‖ n(k) ‖ e(EXP_WIRE_LEN)`. Fixed and zero-padded, so `e` is
/// always stored in exactly this many little-endian bytes regardless of how
/// few significant bytes the DER carries.
const EXP_WIRE_LEN: usize = 4;

/// Big-endian layout of the three RSA fields the non-CRT vault operand needs,
/// recovered from a parsed DER: the byte offsets of the modulus `n` and private
/// exponent `d` within the source buffer, plus the (short) public exponent `e`.
/// `n` is exactly `modulus_len` bytes; `d` is `d_len ≤ modulus_len`.
struct RsaOperandLayout {
    modulus_len: usize,
    n_off: usize,
    d_off: usize,
    d_len: usize,
    /// `e` already in the operand's wire form: little-endian, zero-padded to the
    /// fixed [`EXP_WIRE_LEN`]-byte slot, so assembly is a single copy.
    e: [u8; EXP_WIRE_LEN],
}

/// Byte offset of `field` within `buf`. Sound because `field` is a `UintRef`
/// sub-slice of `buf` (same allocation), so the pointer difference is in range.
fn offset_in(buf: &[u8], field: &[u8]) -> usize {
    (field.as_ptr() as usize) - (buf.as_ptr() as usize)
}

/// Parses and validates the RSA key in `buf`, returning the [`RsaOperandLayout`]
/// for in-place operand assembly. Rejects moduli that are not 2048/3072/4096-bit,
/// an exponent wider than [`EXP_WIRE_LEN`], or a `d` wider than the modulus. `e`
/// is copied out (it is tiny and its DER slot is overwritten during assembly),
/// converted to the operand's little-endian wire form as it goes; `n`/`d` are
/// located by offset so the assembler can move them once the borrow of `buf`
/// (held by the decoded `UintRef`s) is released.
fn rsa_operand_layout(buf: &[u8]) -> Option<RsaOperandLayout> {
    let key = parse_rsa_private_key(buf)?;
    let n = key.modulus.as_bytes();
    let e = key.public_exponent.as_bytes();
    let d = key.private_exponent.as_bytes();
    let modulus_len = n.len();
    if !matches!(modulus_len, 256 | 384 | 512) || e.len() > EXP_WIRE_LEN || d.len() > modulus_len {
        return None;
    }
    // DER `e` is big-endian and minimally encoded; the operand slot is a fixed
    // little-endian `EXP_WIRE_LEN` field, so reverse into a zeroed array.
    let mut e_le = [0u8; EXP_WIRE_LEN];
    reverse_copy(&mut e_le, e);
    Some(RsaOperandLayout {
        modulus_len,
        n_off: offset_in(buf, n),
        d_off: offset_in(buf, d),
        d_len: d.len(),
        e: e_le,
    })
}

/// Assembles the little-endian vault operand
/// `[d(k) ‖ n(k) ‖ e(EXP_WIRE_LEN)]` into the front of `buf`, entirely in place.
///
/// The operand overlaps the DER field offsets it reads from (`d` and `n` mutually
/// clobber each other's source), so `d` is first staged into `buf`'s tail scratch
/// (`[vault_len..]`) via `copy_within` (memmove — safe on overlap). `n`'s source
/// may overlap its destination too, so it is moved with `copy_within` and then
/// reversed in place; `d`'s staged copy is disjoint from the front of the buffer,
/// so it is folded into a single [`reverse_copy`]. Requires
/// `buf.len() >= vault_len + d_len` (checked by the caller). The tail is left
/// dirty; the per-IO teardown scrub wipes it.
fn assemble_rsa_operand_in_place(buf: &mut [u8], layout: &RsaOperandLayout) {
    let k = layout.modulus_len;
    let vault_len = 2 * k + EXP_WIRE_LEN;
    let d_len = layout.d_len;
    // 1. Stage big-endian `d` into the tail scratch before its source is
    //    clobbered by the `n` move below.
    buf.copy_within(layout.d_off..layout.d_off + d_len, vault_len);
    // 2. vault `n` at [k, 2k): move DER `n` (big-endian, exactly k bytes) into
    //    place, then reverse to little-endian. Source and destination can
    //    overlap, so this stays a memmove plus an in-place reverse.
    buf.copy_within(layout.n_off..layout.n_off + k, k);
    buf[k..2 * k].reverse();
    // 3. vault `d` at [0, k): the staged copy at `vault_len` is disjoint from
    //    `[0, d_len)`, so split the buffer and reverse-copy it to the front in
    //    one pass. `d` may be shorter than the modulus (DER strips leading
    //    zeros), and the bytes above it still hold DER, so zero the high end —
    //    the vault field is a fixed k bytes.
    let (front, staged) = buf.split_at_mut(vault_len);
    reverse_copy(&mut front[..d_len], &staged[..d_len]);
    front[d_len..k].fill(0);
    // 4. vault `e` at [2k, 2k+EXP_WIRE_LEN): already little-endian and
    //    zero-padded, so a single copy fills the fixed slot.
    front[2 * k..vault_len].copy_from_slice(&layout.e);
}

// =============================================================================
// HsmRsa trait impl
// =============================================================================

impl UnoHsmPal {
    async fn pss_message_digest<'a>(
        &'a self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        message_hash: &DmaBuf,
        salt: &DmaBuf,
        digest: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()> {
        let mut ctx = self.hash_begin(io, algo, alloc)?;

        self.hash_continue_bytes(&mut ctx, &[0u8; 8]).await?;
        self.hash_continue(io, &mut ctx, message_hash).await?;
        if !salt.is_empty() {
            self.hash_continue(io, &mut ctx, salt).await?;
        }
        self.hash_finish(io, ctx, &mut digest[..algo.digest_len()], true)
            .await
    }
    /// Compute the derived RSA-CRT PKA operands from the recovered primes.
    ///
    /// `n1q = qInv·q` and `n2p = (p⁻¹ mod q)·p` are the two values the Uno PKA
    /// needs in the CRT private operand beyond the raw DER fields. Inputs are
    /// the big-endian magnitudes of `p`, `q`, and `qInv` (`qInv = q⁻¹ mod p`)
    /// as recovered from the DER; `modulus_len` (k) is 256/384/512. Writes the
    /// `k`-byte little-endian results into the first `k` bytes of `n1q_out` /
    /// `n2p_out`.
    ///
    /// The two products use an all-`0xFF` modulus so the PKA performs no
    /// reduction — the mathematical products `qInv·q` and `p⁻¹·p` are already
    /// `< 2^(8k)`, so the full-width result is exact — while the `p⁻¹ mod q`
    /// inverse runs at the half operand size with modulus `q`. All PKA scratch
    /// lives in a nested alloc scope and is scrubbed then freed on return; each
    /// derived value runs atomically on one held engine.
    // The primes, coefficient, and two output operands are distinct crypto
    // values with no natural grouping; a parameter struct would only obscure them.
    #[allow(clippy::too_many_arguments)]
    async fn compute_crt_params(
        &self,
        io: &impl HsmIo,
        modulus_len: usize,
        p_be: &[u8],
        q_be: &[u8],
        qinv_be: &[u8],
        n1q_out: &mut DmaBuf,
        n2p_out: &mut DmaBuf,
    ) -> HsmResult<()> {
        // Full operand = the modulus size k; the `p⁻¹ mod q` inverse runs at
        // the next PKA size that covers the k/2-byte prime.
        let (full, half) = match modulus_len {
            256 => (UpkaModSize::Rsa2k, UpkaModSize::Rsa1k),
            384 => (UpkaModSize::Rsa3k, UpkaModSize::Rsa2k),
            512 => (UpkaModSize::Rsa4k, UpkaModSize::Rsa2k),
            _ => return Err(HsmError::InvalidArg),
        };
        let k = modulus_len;
        let half_len = k / 2;
        let half_op = half.operand_len();
        if p_be.len() > half_len
            || q_be.len() > half_len
            || qinv_be.len() > half_len
            || n1q_out.len() < k
            || n2p_out.len() < k
        {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            // Full-size (k) scratch, reused across the n1q and n2p multiplies.
            // The all-`0xFF` buffer is the no-reduction modulus.
            let ff = scope.dma_alloc(k)?;
            ff.fill(0xff);
            let mont_c = scope.dma_alloc(k)?;
            let a_full = scope.dma_alloc_zeroed(k)?;
            let b_full = scope.dma_alloc_zeroed(k)?;
            let a_mont = scope.dma_alloc_zeroed(k + 4)?;
            let b_mont = scope.dma_alloc_zeroed(k + 4)?;
            let prod_mont = scope.dma_alloc_zeroed(k + 4)?;

            // Half-size scratch for p⁻¹ mod q (modulus q, zero-padded to the
            // half operand width). Allocate every fallible buffer BEFORE writing
            // any secret prime material, so an allocation failure (`?`) cannot
            // return early leaving `p`/`q` in reused DMA SRAM ahead of the
            // scrub block below.
            let q_half = scope.dma_alloc_zeroed(half_op)?;
            let p_half = scope.dma_alloc_zeroed(half_op)?;
            let mont_c_h = scope.dma_alloc(half_op)?;
            let p_mont_h = scope.dma_alloc_zeroed(half_op + 4)?;
            let pinv_mont_h = scope.dma_alloc_zeroed(half_op + 4)?;
            let pinvq = scope.dma_alloc_zeroed(half_op)?;

            // All DMA scratch is now reserved; from here no `?` can early-return
            // before the unconditional scrub, so it is safe to write secrets.
            reverse_copy(&mut q_half[..half_len], q_be);
            reverse_copy(&mut p_half[..half_len], p_be);

            // Run the three PKA phases, capturing the outcome instead of
            // `?`-returning, so the scrub below runs on BOTH success and error
            // paths. A mid-computation PKA failure would otherwise return
            // before scrubbing, and the scoped alloc Drop only resets
            // watermarks — it does not wipe the reused DMA SRAM. Each phase is
            // gated on the previous succeeding so no PKA op runs on stale data.

            // n1q = qInv · q. Operands sit in the low half of the full width;
            // the all-`0xFF` modulus disables reduction so the product is exact.
            reverse_copy(&mut a_full[..half_len], qinv_be);
            reverse_copy(&mut b_full[..half_len], q_be);
            let mut result = self
                .pka
                .with_engine(async |eng| {
                    eng.rsa_mont_const_calc(full, ff, mont_c).await?;
                    eng.rsa_mont_repr_in(full, a_mont, a_full).await?;
                    eng.rsa_mont_repr_in(full, b_mont, b_full).await?;
                    eng.rsa_mod_mul(full, prod_mont, a_mont, b_mont).await?;
                    eng.rsa_mont_repr_out(full, n1q_out, prod_mont).await
                })
                .await;

            // p⁻¹ mod q (half size, modulus q).
            if result.is_ok() {
                result = self
                    .pka
                    .with_engine(async |eng| {
                        eng.rsa_mont_const_calc(half, q_half, mont_c_h).await?;
                        eng.rsa_mont_repr_in(half, p_mont_h, p_half).await?;
                        eng.rsa_mod_inverse(half, pinv_mont_h, p_mont_h).await?;
                        eng.rsa_mont_repr_out(half, pinvq, pinv_mont_h).await
                    })
                    .await;
            }

            // n2p = (p⁻¹ mod q) · p. Reuse the full-size scratch: load the plain
            // little-endian inverse and p, then multiply with no reduction.
            if result.is_ok() {
                a_full.fill(0);
                a_full[..half_len].copy_from_slice(&pinvq[..half_len]);
                b_full.fill(0);
                reverse_copy(&mut b_full[..half_len], p_be);
                result = self
                    .pka
                    .with_engine(async |eng| {
                        eng.rsa_mont_const_calc(full, ff, mont_c).await?;
                        eng.rsa_mont_repr_in(full, a_mont, a_full).await?;
                        eng.rsa_mont_repr_in(full, b_mont, b_full).await?;
                        eng.rsa_mod_mul(full, prod_mont, a_mont, b_mont).await?;
                        eng.rsa_mont_repr_out(full, n2p_out, prod_mont).await
                    })
                    .await;
            }

            // Scratch that held secret prime-derived material is left dirty
            // here: the per-IO teardown scrub wipes the whole slot, so a local
            // wipe would be redundant work that has to be removed again.
            result
        })
        .await
    }
}

impl HsmRsa for UnoHsmPal {
    async fn rsa_gen_keypair(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _priv_key: &mut DmaBuf,
        _pub_key: &mut DmaBuf,
        _pct: HsmRsaPct,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    async fn mod_exp_priv(
        &self,
        _io: &impl HsmIo,
        key_size: HsmRsaKey,
        key: &DmaBuf,
        y: &DmaBuf,
        x: &mut DmaBuf,
    ) -> HsmResult<()> {
        let upka_key_type = rsa_key_to_upka_key_type(key_size);
        self.pka.rsa_mod_exp_priv(upka_key_type, key, y, x).await
    }

    async fn mod_exp_pub(
        &self,
        _io: &impl HsmIo,
        key_size: HsmRsaKey,
        key: &DmaBuf,
        x: &DmaBuf,
        y: &mut DmaBuf,
    ) -> HsmResult<()> {
        let upka_key_type = rsa_key_to_upka_key_type(key_size);
        self.pka.rsa_mod_exp_pub(upka_key_type, key, x, y).await
    }

    fn rsa_priv_pub_key(
        &self,
        _io: &impl HsmIo,
        priv_key: &DmaBuf,
        pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        // The wire public key is `n_le ‖ e_le` (`k + 4` bytes), extracted from
        // the Uno vault private operand. Two vault layouts carry the same
        // `n`/`e`, both little-endian:
        //   non-CRT `d(k) ‖ n(k) ‖ e(4)`                          (`2k+4` bytes)
        //   CRT     `p ‖ q ‖ dp ‖ dq ‖ n(k) ‖ n1q(k) ‖ n2p(k) ‖ e(4)` (`5k+4`)
        // In both, `e` is the trailing 4 bytes; `n` starts at offset `k`
        // (non-CRT) or `2k` (CRT). The two length sets are disjoint, so the
        // operand length selects the layout — no endianness flip / PKA op.
        let total = priv_key.len();
        if total <= EXP_WIRE_LEN {
            return Err(HsmError::InvalidArg);
        }
        let body = total - EXP_WIRE_LEN;
        let (modulus_len, n_off) = if body.is_multiple_of(2) && matches!(body / 2, 256 | 384 | 512)
        {
            let k = body / 2;
            (k, k)
        } else if body.is_multiple_of(5) && matches!(body / 5, 256 | 384 | 512) {
            let k = body / 5;
            (k, 2 * k)
        } else {
            return Err(HsmError::InvalidArg);
        };
        let wire_len = modulus_len + EXP_WIRE_LEN;
        if let Some(out) = pub_out {
            if out.len() < wire_len {
                return Err(HsmError::RsaInvalidKeyLength);
            }
            out[..modulus_len].copy_from_slice(&priv_key[n_off..n_off + modulus_len]);
            out[modulus_len..wire_len].copy_from_slice(&priv_key[total - EXP_WIRE_LEN..total]);
        }
        Ok(wire_len)
    }

    async fn rsa_priv_der_to_vault<'a>(
        &'a self,
        io: &impl HsmIo,
        der: &'a mut DmaBuf,
        crt: bool,
    ) -> HsmResult<(&'a DmaBuf, usize)> {
        // Note: `der` holds recovered plaintext DER — and, on the non-CRT path,
        // the staged `d` plus the leftover CRT components `p`/`q`/`dp`/`dq`/
        // `qinv` — on every path through this function. It is not scrubbed
        // here: the per-IO teardown scrub wipes the whole slot, so a local wipe
        // would be redundant work that has to be removed again.
        if crt {
            // Decode the recovered CRT DER into its big-endian field magnitudes
            // (modulus `n`, exponent `e`, primes `p`/`q`, CRT exponents `dp`/`dq`,
            // coefficient `qInv = q⁻¹ mod p`). The `UintRef`s alias `der`; the
            // borrow ends at the `compute_crt_params` call below, before `der`
            // is scrubbed.
            let Some(key) = parse_rsa_private_key(&der[..]) else {
                return Err(HsmError::InvalidArg);
            };
            let n = key.modulus.as_bytes();
            let e = key.public_exponent.as_bytes();
            let p = key.prime1.as_bytes();
            let q = key.prime2.as_bytes();
            let dp = key.exponent1.as_bytes();
            let dq = key.exponent2.as_bytes();
            let qinv = key.coefficient.as_bytes();
            let k = n.len();
            let half = k / 2;
            // The modulus must be a supported size; `e` fits 4 bytes; each
            // prime-sized field fits the half width (a proper prime is exactly
            // `k/2` bytes, and dp/dq/qInv are `< p`).
            if !matches!(k, 256 | 384 | 512)
                || e.len() > 4
                || p.len() > half
                || q.len() > half
                || dp.len() > half
                || dq.len() > half
                || qinv.len() > half
            {
                return Err(HsmError::InvalidArg);
            }

            // The Uno CRT operand (`5k+4`) is larger than the source DER, so it
            // cannot be built in place — allocate a right-sized buffer. Assemble
            // the little-endian PKA operand
            // `[ p(k/2) ‖ q(k/2) ‖ dp(k/2) ‖ dq(k/2) ‖ n(k) ‖ n1q(k) ‖ n2p(k) ‖ e(4) ]`
            // into it (zeroed first so short fields are left-padded and the
            // derived `n1q`/`n2p` regions start clean).
            let vault_len = 5 * k + 4;
            let out = self.dma_alloc(io, vault_len)?;
            out.fill(0);
            reverse_copy(&mut out[0..half], p);
            reverse_copy(&mut out[half..k], q);
            reverse_copy(&mut out[k..k + half], dp);
            reverse_copy(&mut out[k + half..2 * k], dq);
            reverse_copy(&mut out[2 * k..3 * k], n);
            reverse_copy(&mut out[5 * k..vault_len], e);

            // Derive `n1q = qInv·q` and `n2p = (p⁻¹ mod q)·p` on the PKA straight
            // into the operand: split off the `[3k..5k]` region into two disjoint
            // `k`-byte views so no extra copy is needed.
            let (_head, tail) = out.split_at_mut(3 * k);
            let (n1q_out, rest) = tail.split_at_mut(k);
            let (n2p_out, _e) = rest.split_at_mut(k);
            let result = self
                .compute_crt_params(io, k, p, q, qinv, n1q_out, n2p_out)
                .await;
            result?;
            return Ok((&out[..vault_len], k));
        }

        // Non-CRT: assemble the little-endian vault operand
        // `[d(k) ‖ n(k) ‖ e(EXP_WIRE_LEN)]` in place over the source DER. The
        // `key` borrow of `der` (held by the decoded `UintRef`s) is released
        // before the in-place rewrite.
        let Some(layout) = rsa_operand_layout(&der[..]) else {
            return Err(HsmError::InvalidArg);
        };
        let k = layout.modulus_len;
        let vault_len = 2 * k + EXP_WIRE_LEN;
        // In-place assembly stages `d` into `der[vault_len..]`, so the recovered
        // DER must be at least `vault_len + d_len` bytes. A full RSAPrivateKey is
        // always larger, but reject rather than panic on a malformed / truncated
        // DER.
        if der.len() < vault_len + layout.d_len {
            return Err(HsmError::InvalidArg);
        }
        assemble_rsa_operand_in_place(&mut der[..], &layout);
        Ok((&der[..vault_len], k))
    }

    // ── PKCS#1 v1.5 encryption ─────────────────────────────────────

    async fn rsa_pkcs1_encrypt<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        pub_key: &DmaBuf,
        message: &DmaBuf,
        output: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        let k = key_size.modulus_len();
        if message.len() > k - 11 || output.len() < k {
            return Err(HsmError::InvalidArg);
        }

        let em = alloc.dma_alloc(k)?;
        let m_len = message.len();

        // EM = 0x00 || 0x02 || PS || 0x00 || M
        em[0] = 0x00;
        em[1] = 0x02;

        // PS: non-zero random bytes, at least 8 bytes
        let ps = &mut em[2..k - m_len - 1];
        self.rng_fill_bytes(io, ps)?;
        // Replace any zero bytes (PS must be non-zero)
        for byte in ps.iter_mut() {
            while *byte == 0 {
                let mut replacement = [0u8; 1];
                self.rng_fill_bytes(io, &mut replacement)?;
                *byte = replacement[0];
            }
        }

        em[k - m_len - 1] = 0x00;
        em[k - m_len..].copy_from_slice(message);

        self.mod_exp_pub(io, key_size, pub_key, em, &mut output[..k])
            .await
    }

    async fn rsa_pkcs1_decrypt<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        priv_key: &DmaBuf,
        ciphertext: &DmaBuf,
        output: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a,
    {
        let k = key_size.modulus_len();
        if ciphertext.len() != k {
            return Err(HsmError::InvalidArg);
        }

        let em = alloc.dma_alloc(k)?;
        self.mod_exp_priv(io, key_size, priv_key, ciphertext, em)
            .await?;

        // Verify EM = 0x00 || 0x02 || PS || 0x00 || M
        if em[0] != 0x00 || em[1] != 0x02 {
            return Err(HsmError::RsaDecryptFailed);
        }

        // Find the 0x00 separator after PS (PS must be >= 8 bytes)
        let sep = em[2..].iter().position(|&b| b == 0).map(|i| i + 2);
        let sep = match sep {
            Some(s) if s >= 10 => s,
            _ => return Err(HsmError::RsaDecryptFailed),
        };

        let m_len = k - sep - 1;
        if output.len() < m_len {
            return Err(HsmError::InvalidArg);
        }

        output[..m_len].copy_from_slice(&em[sep + 1..k]);
        Ok(m_len)
    }

    // ── PKCS#1 v1.5 signatures ─────────────────────────────────────

    async fn rsa_pkcs1_sign<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &DmaBuf,
        message_hash: &DmaBuf,
        signature: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        let k = key_size.modulus_len();
        let digest_len = algo.digest_len();
        if message_hash.len() != digest_len || signature.len() < k {
            return Err(HsmError::InvalidArg);
        }

        let prefix = digest_info_prefix(algo);
        let t_len = prefix.len() + digest_len;
        if k < t_len + 11 {
            return Err(HsmError::InvalidArg);
        }

        let em = alloc.dma_alloc(k)?;

        // EM = 0x00 || 0x01 || PS(0xFF) || 0x00 || T
        em[0] = 0x00;
        em[1] = 0x01;
        let ps_len = k - t_len - 3;
        em[2..2 + ps_len].fill(0xFF);
        em[2 + ps_len] = 0x00;
        em[3 + ps_len..3 + ps_len + prefix.len()].copy_from_slice(prefix);
        em[3 + ps_len + prefix.len()..k].copy_from_slice(message_hash);

        self.mod_exp_priv(io, key_size, priv_key, em, &mut signature[..k])
            .await
    }

    async fn rsa_pkcs1_verify<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &DmaBuf,
        message_hash: &DmaBuf,
        signature: &DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a,
    {
        let k = key_size.modulus_len();
        let digest_len = algo.digest_len();
        if message_hash.len() != digest_len || signature.len() != k {
            return Err(HsmError::InvalidArg);
        }

        let em = alloc.dma_alloc(k)?;
        self.mod_exp_pub(io, key_size, pub_key, signature, em)
            .await?;

        // Verify EM = 0x00 || 0x01 || PS(0xFF) || 0x00 || T
        if em[0] != 0x00 || em[1] != 0x01 {
            return Ok(false);
        }

        let prefix = digest_info_prefix(algo);
        let t_len = prefix.len() + digest_len;
        if k < t_len + 11 {
            return Ok(false);
        }

        let ps_len = k - t_len - 3;

        // Check PS is all 0xFF
        if !em[2..2 + ps_len].iter().all(|&b| b == 0xFF) {
            return Ok(false);
        }
        if em[2 + ps_len] != 0x00 {
            return Ok(false);
        }

        // Check DigestInfo prefix
        let prefix_region: &[u8] = &em[3 + ps_len..3 + ps_len + prefix.len()];
        if prefix_region != prefix {
            return Ok(false);
        }

        // Check digest
        let digest_region: &[u8] = &em[3 + ps_len + prefix.len()..k];
        let message_hash_bytes: &[u8] = message_hash;
        Ok(digest_region == message_hash_bytes)
    }

    // ── OAEP encryption ────────────────────────────────────────────

    async fn rsa_oaep_encrypt<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &DmaBuf,
        message: &DmaBuf,
        label: &DmaBuf,
        output: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        let k = key_size.modulus_len();
        let h_len = algo.digest_len();
        let db_len = k - h_len - 1;

        if message.len() > k - 2 * h_len - 2 || output.len() < k {
            return Err(HsmError::InvalidArg);
        }
        let em = alloc.dma_alloc(k)?;

        // Initialize EM to zeros
        em.fill(0);
        // em[0] = 0x00 (already)

        let m_len = message.len();
        let ps_len = db_len - h_len - m_len - 1;

        // Build DB in em[1+hLen..k]: lHash || PS || 0x01 || M
        // Hash label directly into DB[0..hLen]
        self.hash(io, algo, label, &mut em[1 + h_len..1 + 2 * h_len], true)
            .await?;
        // PS is already zeros
        em[1 + 2 * h_len + ps_len] = 0x01;
        em[1 + 2 * h_len + ps_len + 1..k].copy_from_slice(message);

        // Generate random seed in em[1..1+hLen]
        self.rng_fill_bytes(io, &mut em[1..1 + h_len])?;

        // maskedDB = DB XOR MGF(seed, dbLen)
        {
            let (seed, db) = em[1..k].split_at_mut(h_len);
            self.mgf1_xor(io, algo, seed, db).await?;
        }

        // maskedSeed = seed XOR MGF(maskedDB, hLen)
        {
            let (seed, db) = em[1..k].split_at_mut(h_len);
            self.mgf1_xor(io, algo, db, seed).await?;
        }

        self.mod_exp_pub(io, key_size, pub_key, em, &mut output[..k])
            .await
    }

    async fn rsa_oaep_decrypt<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &DmaBuf,
        ciphertext: &DmaBuf,
        label: &DmaBuf,
        output: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a,
    {
        let k = key_size.modulus_len();
        let h_len = algo.digest_len();
        let db_len = k - h_len - 1;

        if ciphertext.len() != k {
            return Err(HsmError::InvalidArg);
        }
        let em = alloc.dma_alloc(k)?;
        let label_hash = alloc.dma_alloc(h_len)?;

        self.mod_exp_priv(io, key_size, priv_key, ciphertext, em)
            .await?;

        // `mod_exp_priv` is little-endian (PKA-native): both the ciphertext
        // operand and the `em` result are LE wire form. The RSA-OAEP decode
        // below (RFC 8017 EME-OAEP) operates on the big-endian encoded
        // message `EM = 0x00 ‖ maskedSeed ‖ maskedDB`, so flip the result
        // LE→BE first (the std PAL does the same flip around OpenSSL).
        em[..k].reverse();

        if em[0] != 0x00 {
            return Err(HsmError::RsaDecryptFailed);
        }

        // Recover seed: seed = maskedSeed XOR MGF(maskedDB, hLen)
        {
            let (seed, db) = em[1..k].split_at_mut(h_len);
            self.mgf1_xor(io, algo, db, seed).await?;
        }

        // Recover DB: DB = maskedDB XOR MGF(seed, dbLen)
        {
            let (seed, db) = em[1..k].split_at_mut(h_len);
            self.mgf1_xor(io, algo, seed, db).await?;
        }

        // Verify lHash using reusable scratch allocated from the alloc.
        let db = &em[1 + h_len..k];
        self.hash(io, algo, label, label_hash, true).await?;
        let db_hash: &[u8] = &db[..h_len];
        let label_hash_slice: &[u8] = &label_hash[..h_len];
        if db_hash != label_hash_slice {
            return Err(HsmError::RsaDecryptFailed);
        }

        // Find 0x01 separator in DB after lHash
        let ps_and_m = &db[h_len..];
        let sep = ps_and_m.iter().position(|&b| b == 0x01);
        let sep = match sep {
            Some(s) if ps_and_m[..s].iter().all(|&b| b == 0x00) => s,
            _ => return Err(HsmError::RsaDecryptFailed),
        };

        let m_start = h_len + sep + 1;
        let m_len = db_len - m_start;
        // Contract (matches the std PAL): a recovered message longer than
        // the caller's output buffer is a key/output-length error, reported
        // as `RsaInvalidKeyLength`. The RsaUnwrap KEK path relies on this to
        // map an oversized recovered KEK to `RsaUnwrapInvalidKek`.
        if output.len() < m_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }

        output[..m_len].copy_from_slice(&db[m_start..]);
        Ok(m_len)
    }

    // ── PSS signatures ─────────────────────────────────────────────

    async fn rsa_pss_sign<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &DmaBuf,
        message_hash: &DmaBuf,
        salt_len: usize,
        signature: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        let k = key_size.modulus_len();
        let h_len = algo.digest_len();
        let db_len = k - h_len - 1;

        if message_hash.len() != h_len || signature.len() < k {
            return Err(HsmError::InvalidArg);
        }
        if k < h_len + salt_len + 2 {
            return Err(HsmError::InvalidArg);
        }

        let em = alloc.dma_alloc(k)?;

        let ps_len = db_len - salt_len - 1;

        // Build DB in em[0..db_len]: PS(zeros) || 0x01 || salt
        em[..ps_len].fill(0);
        em[ps_len] = 0x01;
        if salt_len > 0 {
            self.rng_fill_bytes(io, &mut em[ps_len + 1..ps_len + 1 + salt_len])?;
        }

        // Trailer byte
        em[k - 1] = 0xBC;

        // Compute H = Hash(0x00*8 || mHash || salt) → em[db_len..db_len+hLen]
        let (db, h_region) = em.split_at_mut(db_len);
        {
            let salt = &db[ps_len + 1..ps_len + 1 + salt_len];
            self.pss_message_digest(io, algo, message_hash, salt, &mut h_region[..h_len], alloc)
                .await?;
        }

        // maskedDB = DB XOR MGF(H, dbLen)
        self.mgf1_xor(io, algo, &h_region[..h_len], db).await?;

        // Clear top bit
        em[0] &= 0x7F;

        self.mod_exp_priv(io, key_size, priv_key, em, &mut signature[..k])
            .await
    }

    async fn rsa_pss_verify<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &DmaBuf,
        message_hash: &DmaBuf,
        salt_len: usize,
        signature: &DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a,
    {
        let k = key_size.modulus_len();
        let h_len = algo.digest_len();
        let db_len = k - h_len - 1;

        if message_hash.len() != h_len || signature.len() != k {
            return Err(HsmError::InvalidArg);
        }
        if k < h_len + salt_len + 2 {
            return Err(HsmError::InvalidArg);
        }

        let em = alloc.dma_alloc(k)?;
        let expected_hash = alloc.dma_alloc(h_len)?;

        self.mod_exp_pub(io, key_size, pub_key, signature, em)
            .await?;

        // Check trailer
        if em[k - 1] != 0xBC {
            return Ok(false);
        }

        // RFC 8017 §9.1.2 step 4: reject if leftmost bit is set
        if (em[0] & 0x80) != 0 {
            return Ok(false);
        }

        // Unmask DB: DB = maskedDB XOR MGF(H, dbLen)
        let (db, h_region) = em.split_at_mut(db_len);
        self.mgf1_xor(io, algo, &h_region[..h_len], db).await?;

        // Clear top bit
        em[0] &= 0x7F;

        // Verify DB format: PS(zeros) || 0x01 || salt
        let ps_len = db_len - salt_len - 1;
        if !em[..ps_len].iter().all(|&b| b == 0x00) {
            return Ok(false);
        }
        if em[ps_len] != 0x01 {
            return Ok(false);
        }

        // Recompute H' = Hash(0x00*8 || mHash || salt)
        let salt = &em[ps_len + 1..ps_len + 1 + salt_len];
        self.pss_message_digest(io, algo, message_hash, salt, expected_hash, alloc)
            .await?;

        // Compare H (in em[db_len..]) with H'
        let actual_hash: &[u8] = &em[db_len..db_len + h_len];
        let expected_hash: &[u8] = &expected_hash[..h_len];
        Ok(actual_hash == expected_hash)
    }
}
