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

/// Big-endian layout of the three RSA fields the non-CRT vault operand needs,
/// recovered from a parsed DER: the byte offsets of the modulus `n` and private
/// exponent `d` within the source buffer, plus a copy of the (short) public
/// exponent `e`. `n` is exactly `modulus_len` bytes; `d` is `d_len ≤ modulus_len`.
struct RsaOperandLayout {
    modulus_len: usize,
    n_off: usize,
    d_off: usize,
    d_len: usize,
    e: [u8; 4],
    e_len: usize,
}

/// Byte offset of `field` within `buf`. Sound because `field` is a `UintRef`
/// sub-slice of `buf` (same allocation), so the pointer difference is in range.
fn offset_in(buf: &[u8], field: &[u8]) -> usize {
    (field.as_ptr() as usize) - (buf.as_ptr() as usize)
}

/// Parses and validates the RSA key in `buf`, returning the [`RsaOperandLayout`]
/// for in-place operand assembly. Rejects moduli that are not 2048/3072/4096-bit,
/// an exponent wider than 4 bytes, or a `d` wider than the modulus. `e` is copied
/// out (it is tiny and its DER slot is overwritten during assembly); `n`/`d` are
/// located by offset so the assembler can move them once the borrow of `buf`
/// (held by the decoded `UintRef`s) is released.
fn rsa_operand_layout(buf: &[u8]) -> Option<RsaOperandLayout> {
    let key = parse_rsa_private_key(buf)?;
    let n = key.modulus.as_bytes();
    let e = key.public_exponent.as_bytes();
    let d = key.private_exponent.as_bytes();
    let modulus_len = n.len();
    if !matches!(modulus_len, 256 | 384 | 512) || e.len() > 4 || d.len() > modulus_len {
        return None;
    }
    let mut e_arr = [0u8; 4];
    e_arr[..e.len()].copy_from_slice(e);
    Some(RsaOperandLayout {
        modulus_len,
        n_off: offset_in(buf, n),
        d_off: offset_in(buf, d),
        d_len: d.len(),
        e: e_arr,
        e_len: e.len(),
    })
}

/// Assembles the little-endian vault operand `[d(k) ‖ n(k) ‖ e(4)]` into the
/// front of `buf`, entirely in place.
///
/// The operand overlaps the DER field offsets it reads from (`d` and `n` mutually
/// clobber each other's source), so `d` is first staged into `buf`'s tail scratch
/// (`[vault_len..]`, which the caller scrubs) via `copy_within` (memmove — safe on
/// overlap); `n` is then moved and reversed big-endian→little-endian into place,
/// followed by the staged `d` and the saved `e`. Requires `buf.len() >=
/// vault_len + d_len` (checked by the caller).
fn assemble_rsa_operand_in_place(buf: &mut [u8], layout: &RsaOperandLayout) {
    let k = layout.modulus_len;
    let vault_len = 2 * k + 4;
    let d_len = layout.d_len;
    // 1. Stage big-endian `d` into the tail scratch before its source is
    //    clobbered by the `n` move below.
    buf.copy_within(layout.d_off..layout.d_off + d_len, vault_len);
    // 2. vault `n` at [k, 2k): move DER `n` (big-endian, exactly k bytes) into
    //    place, then reverse to little-endian.
    buf.copy_within(layout.n_off..layout.n_off + k, k);
    buf[k..2 * k].reverse();
    // 3. vault `d` at [0, k): move the staged big-endian `d` to the front,
    //    reverse to little-endian, and zero-pad the high bytes.
    buf.copy_within(vault_len..vault_len + d_len, 0);
    buf[0..d_len].reverse();
    buf[d_len..k].fill(0);
    // 4. vault `e` at [2k, 2k+4): write the saved exponent little-endian.
    let e_len = layout.e_len;
    buf[2 * k..2 * k + e_len].copy_from_slice(&layout.e[..e_len]);
    buf[2 * k..2 * k + e_len].reverse();
    buf[2 * k + e_len..vault_len].fill(0);
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
        // TODO(RSA-CRT bring-up): derive the CRT PKA operands (n1q = qInv·q and
        // n2p = (p⁻¹ mod q)·p) from p/q/n via PKA modular arithmetic and assemble
        // the CRT vault operand. Not yet brought up on Uno, so reject CRT keys.
        if crt {
            // `buf` still holds the recovered plaintext DER; scrub it before
            // any early return so no secret key material lingers in the reused
            // DMA SRAM after a failed import.
            buf.zeroize();
            return Err(HsmError::UnsupportedCmd);
        }
        // Parse + validate + capture the field layout. The `key` borrow of `buf`
        // (held by the decoded `UintRef`s) is released before the in-place
        // rewrite below.
        let Some(layout) = rsa_operand_layout(&buf[..]) else {
            buf.zeroize();
            return Err(HsmError::InvalidArg);
        };
        let k = layout.modulus_len;
        let vault_len = 2 * k + 4;
        // In-place assembly stages `d` into `buf[vault_len..]`, so the recovered
        // DER must be at least `vault_len + d_len` bytes. A full RSAPrivateKey is
        // always larger, but reject rather than panic on a malformed / truncated
        // DER. `buf` holds recovered plaintext, so scrub first.
        if buf.len() < vault_len + layout.d_len {
            buf.zeroize();
            return Err(HsmError::InvalidArg);
        }
        assemble_rsa_operand_in_place(&mut buf[..], &layout);
        // Scrub the tail — the staged `d` plus the leftover DER CRT components
        // (`p`, `q`, `dp`, `dq`, `qinv`). The scoped DMA buffer is reused without
        // automatic wiping, so scrub it here before returning.
        buf[vault_len..].zeroize();
        Ok((vault_len, k))
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
