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
        _priv_key: &DmaBuf,
        _pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        // TODO: convert the raw vault-format RSA private key into the
        // wire public key on Uno PKA (GetUnwrappingKey / RsaUnwrap).
        Err(HsmError::UnsupportedCmd)
    }

    fn rsa_priv_der_to_vault(
        &self,
        _io: &impl HsmIo,
        _buf: &mut DmaBuf,
        _crt: bool,
    ) -> HsmResult<(usize, usize)> {
        // TODO: parse the recovered RSA private-key DER on Uno and rewrite
        // it in place into the vault representation — the raw non-CRT
        // (`n`/`e`/`d`) or the custom CRT layout selected by `crt`
        // (RsaUnwrap RSA import).
        Err(HsmError::UnsupportedCmd)
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
        if output.len() < m_len {
            return Err(HsmError::InvalidArg);
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
