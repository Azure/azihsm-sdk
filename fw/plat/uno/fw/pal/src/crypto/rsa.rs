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
use azihsm_fw_uno_drivers_upka::UpkaRsaKeyType;
use zeroize::Zeroize;

use crate::UnoHsmPal;

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
// DER parsing for RSA private-key import (PKCS#8 / PKCS#1 RSAPrivateKey)
// =============================================================================

/// Maximum RSA modulus length in bytes (RSA-4096).
const MAX_RSA_MODULUS_LEN: usize = 512;

/// DER value bytes of the rsaEncryption OID (1.2.840.113549.1.1.1), i.e. the
/// content of the `OBJECT IDENTIFIER` inside a PKCS#8 `AlgorithmIdentifier`.
const RSA_ENCRYPTION_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Reads one DER TLV at `der[pos..]`. Returns `(tag, content_start,
/// content_len, next)` where the value is `der[content_start..][..content_len]`
/// and `next` is the offset just past this TLV. Handles short- and long-form
/// definite lengths (DER never uses indefinite length).
fn der_tlv(der: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
    let tag = *der.get(pos)?;
    let len_byte = *der.get(pos + 1)?;
    let (len, hdr_len) = if len_byte < 0x80 {
        (len_byte as usize, 2)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        // DER requires minimal length encoding: the most-significant length
        // byte must be non-zero (no leading-zero padding).
        if *der.get(pos + 2)? == 0 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | (*der.get(pos + 2 + i)? as usize);
        }
        // Long form must not be used for lengths that fit in short form.
        if len < 0x80 {
            return None;
        }
        (len, 2 + n)
    };
    let content_start = pos.checked_add(hdr_len)?;
    let next = content_start.checked_add(len)?;
    if next > der.len() {
        return None;
    }
    Some((tag, content_start, len, next))
}

/// Reads a DER INTEGER at `pos`, returning its positive value `(start, len)`
/// with the leading `0x00` sign pad (if present) stripped, plus the offset just
/// past it. Because the input is untrusted recovered key material, this rejects
/// negative integers (MSB set on the first content byte, i.e. no sign pad) and
/// non-minimal encodings; the integer zero (a lone `0x00`) is still accepted so
/// the PKCS#8/PKCS#1 `version` fields parse.
fn der_int(der: &[u8], pos: usize) -> Option<(usize, usize, usize)> {
    let (tag, start, len, next) = der_tlv(der, pos)?;
    if tag != 0x02 || len == 0 {
        return None;
    }
    let first = der[start];
    // A negative INTEGER (two's-complement: MSB of the first byte set, with no
    // `0x00` sign pad) is never a valid RSA field.
    if first & 0x80 != 0 {
        return None;
    }
    // A leading `0x00` is a sign pad; per DER it is minimal only when the next
    // byte has its MSB set. The sole exception is the integer zero, encoded as
    // a single `0x00` byte.
    if first == 0x00 && len > 1 {
        if der[start + 1] & 0x80 == 0 {
            return None;
        }
        return Some((start + 1, len - 1, next));
    }
    Some((start, len, next))
}

/// Big-endian value ranges `((start, len), ...)` for the RSA `n`, `e`, `d`
/// integers within a parsed DER buffer.
type RsaDerRanges = ((usize, usize), (usize, usize), (usize, usize));

/// Parses a DER RSA private key — PKCS#8 `PrivateKeyInfo` or a bare PKCS#1
/// `RSAPrivateKey` — and returns the big-endian value ranges `(start, len)` of
/// the modulus `n`, public exponent `e`, and private exponent `d`.
fn parse_rsa_priv_der(der: &[u8]) -> Option<RsaDerRanges> {
    // Outer SEQUENCE — must span the entire input (reject trailing garbage).
    let (tag, seq_start, _seq_len, outer_next) = der_tlv(der, 0)?;
    if tag != 0x30 || outer_next != der.len() {
        return None;
    }
    // version INTEGER (skip).
    let (_vs, _vl, after_ver) = der_int(der, seq_start)?;
    let mut p = after_ver;
    // A SEQUENCE here is the PKCS#8 algorithm id — validate it is
    // `rsaEncryption` and descend through the OCTET STRING into the inner
    // PKCS#1 key; an INTEGER is the PKCS#1 `n` directly.
    let (peek_tag, alg_start, _acl, after_alg) = der_tlv(der, p)?;
    if peek_tag == 0x30 {
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }.
        let (oid_tag, oid_start, oid_len, after_oid) = der_tlv(der, alg_start)?;
        if oid_tag != 0x06 || der[oid_start..oid_start + oid_len] != RSA_ENCRYPTION_OID {
            return None;
        }
        // The rsaEncryption parameters must be NULL (tag 0x05, length 0), and
        // must be the last field of the AlgorithmIdentifier SEQUENCE (no extra
        // trailing fields).
        let (null_tag, _null_start, null_len, null_next) = der_tlv(der, after_oid)?;
        if null_tag != 0x05 || null_len != 0 || null_next != after_alg {
            return None;
        }
        let (ot, oct_start, _ol, oct_next) = der_tlv(der, after_alg)?;
        if ot != 0x04 {
            return None;
        }
        // The privateKey OCTET STRING must wrap exactly the inner
        // RSAPrivateKey SEQUENCE with no trailing bytes.
        let (st, inner_start, _sl, inner_next) = der_tlv(der, oct_start)?;
        if st != 0x30 || inner_next != oct_next {
            return None;
        }
        let (_v2s, _v2l, after_v2) = der_int(der, inner_start)?;
        p = after_v2;
    }
    // n, e, d in order (p, q, dp, dq, qinv follow but are unused for non-CRT).
    let (ns, nl, after_n) = der_int(der, p)?;
    let (es, el, after_e) = der_int(der, after_n)?;
    let (ds, dl, _after_d) = der_int(der, after_e)?;
    Some(((ns, nl), (es, el), (ds, dl)))
}

/// Writes the big-endian bytes `be` as little-endian into `dst`, zero-padding
/// the remaining high bytes. Requires `be.len() <= dst.len()`.
fn write_le(dst: &mut [u8], be: &[u8]) {
    for (i, &b) in be.iter().rev().enumerate() {
        dst[i] = b;
    }
    dst[be.len()..].fill(0);
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
        // The Uno vault RSA private key is the PKA little-endian layout
        // `d(k) ‖ n(k) ‖ e(4)` (k = modulus length), the same 516-byte form the
        // HSP publishes for RSA-2048, so `priv_key.len() == 2*k + 4`. The wire
        // public key is `n_le ‖ e_le` (`k + 4` bytes) — already little-endian,
        // so it is exactly the trailing `priv_key[k..]` slice with no
        // endianness flip and no PKA operation.
        const EXP_WIRE_LEN: usize = 4;
        let total = priv_key.len();
        if total <= EXP_WIRE_LEN || !(total - EXP_WIRE_LEN).is_multiple_of(2) {
            return Err(HsmError::InvalidArg);
        }
        let modulus_len = (total - EXP_WIRE_LEN) / 2;
        let wire_len = modulus_len + EXP_WIRE_LEN;
        if let Some(out) = pub_out {
            if out.len() < wire_len {
                return Err(HsmError::RsaInvalidKeyLength);
            }
            out[..wire_len].copy_from_slice(&priv_key[modulus_len..total]);
        }
        Ok(wire_len)
    }

    fn rsa_priv_der_to_vault(
        &self,
        _io: &impl HsmIo,
        buf: &mut DmaBuf,
        crt: bool,
    ) -> HsmResult<(usize, usize)> {
        // CRT import needs the derived PKA operands (n1q, n2p) computed from
        // p/q/n via PKA modular arithmetic — not yet brought up on Uno.
        if crt {
            // `buf` still holds the recovered plaintext DER; scrub it before
            // any early return so no secret key material lingers in the reused
            // DMA SRAM after a failed import.
            buf.zeroize();
            return Err(HsmError::UnsupportedCmd);
        }
        // Parse the recovered DER (PKCS#8 or bare PKCS#1) into the big-endian
        // value ranges of the modulus `n`, public exponent `e`, and private
        // exponent `d`. The ranges alias `buf`.
        let Some(((ns, nl), (es, el), (ds, dl))) = parse_rsa_priv_der(&buf[..]) else {
            buf.zeroize();
            return Err(HsmError::InvalidArg);
        };
        let modulus_len = nl;
        if !matches!(modulus_len, 256 | 384 | 512) || el > 4 || dl > modulus_len {
            buf.zeroize();
            return Err(HsmError::InvalidArg);
        }
        // Assemble the vault operand `[d(k) ‖ n(k) ‖ e(4)]` little-endian in a
        // scratch buffer, then write it back in place — the vault form is
        // smaller than the source DER, so the overwrite is safe.
        let vault_len = 2 * modulus_len + 4;
        // The in-place rewrite requires the vault operand to fit within `buf`.
        // A malformed / truncated DER (e.g. a very short `d`) can make
        // `vault_len` exceed `buf.len()`; reject rather than panic on the
        // slices below. `buf` still holds recovered plaintext, so scrub first.
        if vault_len > buf.len() {
            buf.zeroize();
            return Err(HsmError::InvalidArg);
        }
        let mut out = [0u8; MAX_RSA_MODULUS_LEN * 2 + 4];
        write_le(&mut out[0..modulus_len], &buf[ds..ds + dl]);
        write_le(&mut out[modulus_len..2 * modulus_len], &buf[ns..ns + nl]);
        write_le(&mut out[2 * modulus_len..vault_len], &buf[es..es + el]);
        buf[..vault_len].copy_from_slice(&out[..vault_len]);
        // Scrub the leftover source DER in the tail of `buf` — for a full
        // RSAPrivateKey it still holds secret CRT components (`p`, `q`, `dp`,
        // `dq`, `qinv`). The scoped DMA buffer is reused without automatic
        // wiping, so scrub it here before returning.
        buf[vault_len..].zeroize();
        // Scrub the assembled operand (holds the private exponent `d`) from the
        // stack scratch. `Zeroize` uses volatile writes so the wipe is not
        // elided as a dead store.
        out.zeroize();
        Ok((vault_len, modulus_len))
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

        // `em` holds the decrypted encoded message and then the recovered DB —
        // both secret. The scoped allocator only rewinds its watermark on drop
        // and never clears freed DMA, so scrub `em` on *every* exit path
        // (including `?`-propagated errors) before it can be handed to a later
        // per-IO allocation. The fallible decode runs in an inner block so the
        // single `em.zeroize()` below covers all of them.
        let result = async {
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
        .await;

        em.zeroize();
        result
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
