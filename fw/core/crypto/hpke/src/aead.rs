// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE AEAD seal / open — dispatches to AES-256-GCM or
//! AES-256-CBC + HMAC depending on the chosen [`HpkeSuite`].
//!
//! ## Output layouts
//!
//! | Suite type | Layout                                |
//! |------------|---------------------------------------|
//! | GCM        | `ct[pt.len()] ‖ tag[16]`              |
//! | CBC-HMAC   | `iv[16] ‖ ciphertext[padded] ‖ tag[Nt]` |
//!
//! ## CBC-HMAC details
//!
//! The CBC variants use the FIPS-compliant key sizing scheme defined
//! in [`HpkeSuite`]:
//!
//! ```text
//! key       = MAC_KEY[Nh] ‖ ENC_KEY[32]
//! tag_len   = Nh             (full HMAC output, no truncation)
//! mac_input = aad ‖ iv ‖ ciphertext ‖ I2OSP(aad.len() * 8, 8)
//! ```
//!
//! Encryption uses encrypt-then-MAC; decryption verifies the MAC
//! before unpadding so a tag mismatch never reveals padding-oracle
//! information.

use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::helpers::dma_copy_in;
use crate::suite::HpkeSuite;

// =============================================================================
// Constants
// =============================================================================

/// AES-256-GCM tag length in bytes.
const GCM_TAG_LEN: usize = 16;

/// CBC IV length in bytes (= one AES block).
const CBC_IV_LEN: usize = 16;

/// Maximum SHA digest length supported (SHA-512). Used to size the
/// stack-allocated full-tag buffer used in the CBC paths.
const MAX_DIGEST_LEN: usize = 64;

// =============================================================================
// Public dispatch
// =============================================================================

/// AEAD Seal: encrypt + authenticate. Dispatches on
/// [`HpkeSuite::is_cbc`].
///
/// # Type parameters
///
/// * `P` — any [`HsmCrypto`] PAL implementation.
///
/// # Parameters
///
/// * `pal` — PAL providing AES / HMAC.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite (selects AES-GCM vs AES-CBC + HMAC).
/// * `key` — AEAD key (`Nk` bytes — see [`HpkeSuite::nk`]).
/// * `base_nonce` — for GCM: 12-byte nonce.  For CBC: ignored (the
///   PAL generates a random IV per call).
/// * `aad` — additional authenticated data (may be empty).
/// * `pt` — plaintext to encrypt.
/// * `ct` — destination buffer; sized per the
///   [output-layouts table](self#output-layouts).
/// * `alloc` — scoped allocator used for HMAC scratch in the CBC
///   path (unused on GCM).
///
/// # Returns
///
/// * `Ok(ct_len)` — bytes written to `ct`
///   (`pt.len() + 16` for GCM; `16 + padded(pt.len()) + Nt` for CBC).
/// * `Err(HsmError::InvalidArg)` — length-constraint violation
///   (nonce / key / output-buffer size).
/// * `Err(HsmError)` — propagated from the AES, HMAC, or RNG
///   driver.
pub async fn seal<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    key: &[u8],
    base_nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    if suite.is_cbc() {
        seal_cbc(pal, io, suite, key, aad, pt, ct, alloc).await
    } else {
        seal_gcm(pal, io, key, base_nonce, aad, pt, ct, alloc).await
    }
}

/// AEAD Open: decrypt + verify. Dispatches on [`HpkeSuite::is_cbc`].
///
/// # Type parameters
///
/// * `P` — any [`HsmCrypto`] PAL implementation.
///
/// # Parameters
///
/// * `pal` — PAL providing AES / HMAC.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `key` — AEAD key.
/// * `base_nonce` — for GCM: 12-byte nonce.  For CBC: ignored (IV
///   is read from `ct`).
/// * `aad` — additional authenticated data.
/// * `ct` — sealed buffer.
/// * `pt` — destination for plaintext.
/// * `alloc` — scoped allocator used for HMAC scratch in the CBC
///   path (unused on GCM).
///
/// # Returns
///
/// * `Ok(pt_len)` — number of plaintext bytes written to `pt`.
/// * `Err(HsmError::InvalidArg)` — length-constraint violation.
/// * `Err(HsmError::AesGcmDecryptTagDoesNotMatch)` — GCM
///   authentication tag mismatch.
/// * `Err(HsmError::AesDecryptFailed)` — CBC HMAC tag mismatch or
///   PKCS#7 padding error.
/// * `Err(HsmError)` — propagated from the AES or HMAC driver.
pub async fn open<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    key: &[u8],
    base_nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    pt: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    if suite.is_cbc() {
        open_cbc(pal, io, suite, key, aad, ct, pt, alloc).await
    } else {
        open_gcm(pal, io, key, base_nonce, aad, ct, pt, alloc).await
    }
}

// =============================================================================
// AES-GCM
// =============================================================================

/// AES-256-GCM seal.
///
/// # Returns
///
/// * `Ok(pt.len() + 16)` — bytes written (`ciphertext ‖ tag`).
/// * `Err(HsmError::InvalidArg)` — `nonce.len() != 12` or
///   `ct.len() < pt.len() + 16`.
/// * `Err(HsmError)` — propagated from `gcm_encrypt`.
async fn seal_gcm<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + 'a,
{
    let key_dma = dma_copy_in(alloc, key)?;
    let nonce_dma = dma_copy_in(alloc, nonce)?;

    if aad.is_empty() {
        // No AAD — simple path, no buffer formatting needed.
        let ct_len = pt.len() + GCM_TAG_LEN;
        if ct.len() < ct_len {
            return Err(HsmError::InvalidArg);
        }
        let pt_dma = dma_copy_in(alloc, pt)?;
        let ct_scratch = alloc.dma_alloc(pt.len())?;
        let tag_dma = alloc.dma_alloc(GCM_TAG_LEN)?;
        pal.gcm_encrypt(io, key_dma, nonce_dma, 0, pt_dma, ct_scratch, tag_dma)
            .await?;
        ct[..pt.len()].copy_from_slice(ct_scratch);
        ct[pt.len()..ct_len].copy_from_slice(tag_dma);
        Ok(ct_len)
    } else {
        // Non-empty AAD — format [padded_aad | pt] into ct, encrypt in-place.
        let buf_len = azihsm_fw_core_crypto_gcm_buf::gcm_buf_len(aad.len(), pt.len());
        let ct_len = buf_len + GCM_TAG_LEN;
        if ct.len() < ct_len {
            return Err(HsmError::InvalidArg);
        }
        let aad_len = azihsm_fw_core_crypto_gcm_buf::format_gcm_buf(aad, pt, &mut ct[..buf_len]);
        let work = alloc.dma_alloc(buf_len)?;
        let tag_dma = alloc.dma_alloc(GCM_TAG_LEN)?;
        work.copy_from_slice(&ct[..buf_len]);
        pal.gcm_encrypt_in_place(io, key_dma, nonce_dma, aad_len, work, tag_dma)
            .await?;
        ct[..buf_len].copy_from_slice(work);
        // Move text portion (after padded AAD) to front, append tag.
        let padded = azihsm_fw_core_crypto_gcm_buf::padded_aad_len(aad.len());
        let text_len = buf_len - padded;
        ct.copy_within(padded..buf_len, 0);
        ct[text_len..text_len + GCM_TAG_LEN].copy_from_slice(tag_dma);
        Ok(text_len + GCM_TAG_LEN)
    }
}

/// AES-256-GCM open.
///
/// # Returns
///
/// * `Ok(ct.len() - 16)` — bytes written to `pt`.
/// * `Err(HsmError::InvalidArg)` — length-constraint violation.
/// * `Err(HsmError::AesGcmDecryptTagDoesNotMatch)` — tag mismatch.
/// * `Err(HsmError)` — propagated from `gcm_decrypt`.
async fn open_gcm<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    pt: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + 'a,
{
    if ct.len() < GCM_TAG_LEN {
        return Err(HsmError::InvalidArg);
    }
    let pt_len = ct.len() - GCM_TAG_LEN;
    let tag = &ct[pt_len..];
    let key_dma = dma_copy_in(alloc, key)?;
    let nonce_dma = dma_copy_in(alloc, nonce)?;
    let tag_dma = dma_copy_in(alloc, tag)?;

    if aad.is_empty() {
        if pt.len() < pt_len {
            return Err(HsmError::InvalidArg);
        }
        let ct_dma = dma_copy_in(alloc, &ct[..pt_len])?;
        let pt_scratch = alloc.dma_alloc(pt_len)?;
        pal.gcm_decrypt(io, key_dma, nonce_dma, 0, tag_dma, ct_dma, pt_scratch)
            .await?;
        pt[..pt_len].copy_from_slice(pt_scratch);
        Ok(pt_len)
    } else {
        // Format [padded_aad | ciphertext] into pt (used as work buffer),
        // decrypt in-place, then move plaintext to front.
        let buf_len = azihsm_fw_core_crypto_gcm_buf::gcm_buf_len(aad.len(), pt_len);
        if pt.len() < buf_len {
            return Err(HsmError::InvalidArg);
        }
        let aad_len =
            azihsm_fw_core_crypto_gcm_buf::format_gcm_buf(aad, &ct[..pt_len], &mut pt[..buf_len]);
        let work = alloc.dma_alloc(buf_len)?;
        work.copy_from_slice(&pt[..buf_len]);
        pal.gcm_decrypt_in_place(io, key_dma, nonce_dma, aad_len, tag_dma, work)
            .await?;
        pt[..buf_len].copy_from_slice(work);
        // Move decrypted text (after padded AAD) to front.
        let padded = azihsm_fw_core_crypto_gcm_buf::padded_aad_len(aad.len());
        pt.copy_within(padded..buf_len, 0);
        Ok(pt_len)
    }
}

// =============================================================================
// AES-CBC + HMAC
// =============================================================================

/// AES-256-CBC + HMAC seal.
///
/// Generates a random IV, encrypts with PKCS#7 padding, then computes
/// the encrypt-then-MAC tag over `aad ‖ iv ‖ ciphertext ‖
/// I2OSP(aad_bits, 8)`.
///
/// # Returns
///
/// * `Ok(ct_len)` — `16 + padded(pt.len()) + Nt` bytes written.
/// * `Err(HsmError::InvalidArg)` — the key length disagrees with
///   the suite or `ct` is too small.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small
///   for HMAC state.
/// * `Err(HsmError)` — propagated from the RNG, AES-CBC, or HMAC
///   driver.
async fn seal_cbc<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    key: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let cbc = CbcParams::from_suite(suite, key)?;
    let padded = azihsm_fw_core_crypto_aes_cbc_pad::padded_len(pt.len());
    let ct_len = CBC_IV_LEN + padded + cbc.tag_len;
    if ct.len() < ct_len {
        return Err(HsmError::InvalidArg);
    }

    // Generate the IV in place at the front of `ct`, then keep a
    // mutable copy for the AES-CBC engine which advances it.
    pal.rng_fill_bytes(io, &mut ct[..CBC_IV_LEN])?;
    let mut iv_copy = [0u8; CBC_IV_LEN];
    iv_copy.copy_from_slice(&ct[..CBC_IV_LEN]);

    // Encrypt plaintext into the middle slot.
    let key_dma = dma_copy_in(alloc, cbc.enc_key)?;
    let ct_scratch = alloc.dma_alloc(padded)?;
    azihsm_fw_core_crypto_aes_cbc_pad::aes_cbc_pkcs7_encrypt(
        pal,
        io,
        key_dma,
        &mut iv_copy,
        pt,
        ct_scratch,
    )
    .await?;
    ct[CBC_IV_LEN..CBC_IV_LEN + padded].copy_from_slice(ct_scratch);

    // MAC over [aad || iv || ciphertext || aad_len_bits_be64].
    // Split `ct` into the three disjoint sections so we can borrow
    // the IV + ciphertext immutably while writing the tag mutably.
    let (iv_section, body) = ct[..ct_len].split_at_mut(CBC_IV_LEN);
    let (ciphertext_section, tag_section) = body.split_at_mut(padded);
    compute_hmac_into(
        pal,
        io,
        cbc.hash,
        cbc.mac_key,
        aad,
        iv_section,
        ciphertext_section,
        tag_section,
        cbc.tag_len,
        alloc,
    )
    .await?;

    Ok(ct_len)
}

/// AES-256-CBC + HMAC open.
///
/// Verifies the MAC first (encrypt-then-MAC), then decrypts and
/// unpads.  A tag mismatch returns [`HsmError::AesDecryptFailed`]
/// before any padding bytes are inspected, eliminating the
/// padding-oracle.
///
/// # Returns
///
/// * `Ok(pt_len)` — number of plaintext bytes written after PKCS#7
///   unpadding.
/// * `Err(HsmError::InvalidArg)` — length-constraint violation.
/// * `Err(HsmError::AesDecryptFailed)` — HMAC tag mismatch or
///   PKCS#7 unpadding error.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small
///   for HMAC state.
/// * `Err(HsmError)` — propagated from the AES-CBC or HMAC driver.
async fn open_cbc<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    key: &[u8],
    aad: &[u8],
    ct: &[u8],
    pt: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let cbc = CbcParams::from_suite(suite, key)?;
    if ct.len() < CBC_IV_LEN + CBC_IV_LEN + cbc.tag_len {
        return Err(HsmError::InvalidArg);
    }

    let enc_len = ct.len() - CBC_IV_LEN - cbc.tag_len;
    let iv = &ct[..CBC_IV_LEN];
    let ciphertext = &ct[CBC_IV_LEN..CBC_IV_LEN + enc_len];
    let received_tag = &ct[CBC_IV_LEN + enc_len..];

    // Verify MAC first (encrypt-then-MAC pattern).
    let mut computed_tag = [0u8; MAX_DIGEST_LEN];
    compute_hmac_into(
        pal,
        io,
        cbc.hash,
        cbc.mac_key,
        aad,
        iv,
        ciphertext,
        &mut computed_tag[..cbc.tag_len],
        cbc.tag_len,
        alloc,
    )
    .await?;

    if computed_tag[..cbc.tag_len] != *received_tag {
        return Err(HsmError::AesDecryptFailed);
    }

    // Decrypt + unpad.
    let mut iv_copy = [0u8; CBC_IV_LEN];
    iv_copy.copy_from_slice(iv);
    let key_dma = dma_copy_in(alloc, cbc.enc_key)?;
    let ct_dma = dma_copy_in(alloc, ciphertext)?;
    let pt_scratch = alloc.dma_alloc(ciphertext.len())?;
    let pt_len = azihsm_fw_core_crypto_aes_cbc_pad::aes_cbc_pkcs7_decrypt(
        pal,
        io,
        key_dma,
        &mut iv_copy,
        ct_dma,
        pt_scratch,
    )
    .await?;
    pt[..pt_len].copy_from_slice(&pt_scratch[..pt_len]);
    Ok(pt_len)
}

/// Per-suite CBC/HMAC parameters borrowed from a caller-supplied key.
struct CbcParams<'a> {
    /// Hash algorithm for the HMAC (= suite hash).
    hash: HsmHashAlgo,
    /// Tag length in bytes (= full `Nh`, no truncation).
    tag_len: usize,
    /// HMAC key prefix of `key`.
    mac_key: &'a [u8],
    /// AES-CBC key suffix of `key`.
    enc_key: &'a [u8],
}

impl<'a> CbcParams<'a> {
    /// Validate `key.len()` against the suite's `MAC_KEY ‖ ENC_KEY`
    /// layout and return borrowed slices for each half.
    ///
    /// # Returns
    ///
    /// * `Ok(params)` — split `(mac_key, enc_key)` plus the suite's
    ///   hash algorithm and tag length.
    /// * `Err(HsmError::InvalidArg)` — `key.len() != mac_key_len +
    ///   enc_key_len`.
    fn from_suite(suite: HpkeSuite, key: &'a [u8]) -> HsmResult<Self> {
        let mac_key_len = suite.cbc_mac_key_len();
        let enc_key_len = suite.cbc_enc_key_len();
        if key.len() != mac_key_len + enc_key_len {
            return Err(HsmError::InvalidArg);
        }
        Ok(Self {
            hash: suite.aead_hash(),
            tag_len: suite.nt(),
            mac_key: &key[..mac_key_len],
            enc_key: &key[mac_key_len..],
        })
    }
}

/// Compute `HMAC(mac_key, aad ‖ iv ‖ ciphertext ‖ I2OSP(aad_bits, 8))`
/// and write the tag into `dest`.
///
/// Shared by [`seal_cbc`] (which writes the tag straight into the
/// output buffer) and [`open_cbc`] (which writes it into a stack
/// buffer for constant-time comparison).
///
/// # Parameters
///
/// * `pal` — PAL providing the HMAC engine.
/// * `io` — caller's I/O context (per-IO scope).
/// * `algo` — hash algorithm.
/// * `mac_key` — HMAC key (full hash output length).
/// * `aad` — additional authenticated data (may be empty).
/// * `iv` — 16-byte AES-CBC IV.
/// * `ciphertext` — already-encrypted CBC body.
/// * `dest` — destination for the tag; must be at least `tag_len`
///   bytes (= `Nh`).
/// * `tag_len` — number of leading HMAC output bytes to copy
///   (always `Nh` in current callers; the parameter is retained
///   so this helper could support truncation in the future).
/// * `alloc` — scoped allocator backing the HMAC state buffer.
///
/// # Returns
///
/// * `Ok(())` — `dest[..tag_len]` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the HMAC engine.
async fn compute_hmac_into<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    algo: HsmHashAlgo,
    mac_key: &[u8],
    aad: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    dest: &mut [u8],
    tag_len: usize,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + 'a,
{
    let aad_len_bits = (aad.len() as u64 * 8).to_be_bytes();
    let hash_len = algo.digest_len();

    let full_tag = alloc.dma_alloc_zeroed(hash_len)?;
    let mac_key_dma = dma_copy_in(alloc, mac_key)?;

    let mut ctx = pal.hmac_begin(io, algo, mac_key_dma, alloc).await?;
    if !aad.is_empty() {
        let aad_dma = dma_copy_in(alloc, aad)?;
        pal.hmac_continue(io, &mut ctx, aad_dma).await?;
    }
    let iv_dma = dma_copy_in(alloc, iv)?;
    let ct_dma = dma_copy_in(alloc, ciphertext)?;
    let len_dma = dma_copy_in(alloc, &aad_len_bits)?;
    pal.hmac_continue(io, &mut ctx, iv_dma).await?;
    pal.hmac_continue(io, &mut ctx, ct_dma).await?;
    pal.hmac_continue(io, &mut ctx, len_dma).await?;
    pal.hmac_finish_into(io, ctx, full_tag).await?;

    dest[..tag_len].copy_from_slice(&full_tag[..tag_len]);
    Ok(())
}
