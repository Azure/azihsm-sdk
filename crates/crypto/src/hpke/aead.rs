// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE AEAD seal / open — dispatches to AES-256-GCM or
//! AES-256-CBC + HMAC depending on the chosen [`HpkeSuite`].
//!
//! Output layouts (must match `fw/core/crypto/hpke/src/aead.rs` so the
//! host and firmware sides can decrypt each other's ciphertexts):
//!
//! | Suite type | Layout                                  |
//! |------------|-----------------------------------------|
//! | GCM        | `ct[pt.len()] ‖ tag[16]`                |
//! | CBC-HMAC   | `iv[16] ‖ ciphertext[padded] ‖ tag[Nt]` |
//!
//! ## CBC-HMAC details
//!
//! Encrypt-then-MAC; the key concatenates `MAC_KEY[Nh] ‖ ENC_KEY[32]`
//! and the MAC input is `aad ‖ iv ‖ ciphertext ‖ I2OSP(aad.len() * 8, 8)`.
//! Tag is the full HMAC output (`Nh`), no truncation. Decryption verifies
//! the MAC before unpadding to eliminate the padding-oracle.

use super::suite::HpkeSuite;
use crate::AesCbcAlgo;
use crate::AesGcmAlgo;
use crate::AesKey;
use crate::CryptoError;
use crate::DecryptOp;
use crate::EncryptOp;
use crate::HashAlgo;
use crate::HmacAlgo;
use crate::HmacKey;
use crate::ImportableKey;
use crate::Rng;
use crate::SignOp;

const GCM_TAG_LEN: usize = 16;
const CBC_IV_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;

/// Compute the ciphertext length for a given plaintext length.
pub(crate) fn ct_len(suite: HpkeSuite, pt_len: usize) -> usize {
    if suite.is_cbc() {
        // 16-byte IV + PKCS#7 padded ciphertext + full HMAC tag (Nh bytes).
        CBC_IV_LEN + padded_len(pt_len) + suite.nt()
    } else {
        pt_len + GCM_TAG_LEN
    }
}

/// PKCS#7 padded length for `pt_len` bytes (always ≥ pt_len + 1).
fn padded_len(pt_len: usize) -> usize {
    pt_len + AES_BLOCK_LEN - (pt_len % AES_BLOCK_LEN)
}

// =============================================================================
// Public dispatch
// =============================================================================

/// AEAD Seal: encrypt + authenticate. Writes to `ct`, returns bytes
/// written. For CBC suites, `nonce` is ignored (random IV generated).
pub(crate) fn seal(
    suite: HpkeSuite,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
) -> Result<usize, CryptoError> {
    if suite.is_cbc() {
        seal_cbc(suite, key, aad, pt, ct)
    } else {
        seal_gcm(key, nonce, aad, pt, ct)
    }
}

/// AEAD Open: decrypt + verify. Writes plaintext to `pt`, returns
/// bytes written. For CBC suites, `nonce` is ignored (IV read from
/// `ct`).
pub(crate) fn open(
    suite: HpkeSuite,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    pt: &mut [u8],
) -> Result<usize, CryptoError> {
    if suite.is_cbc() {
        open_cbc(suite, key, aad, ct, pt)
    } else {
        open_gcm(key, nonce, aad, ct, pt)
    }
}

// =============================================================================
// AES-GCM
// =============================================================================

fn seal_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
) -> Result<usize, CryptoError> {
    let needed = pt.len() + GCM_TAG_LEN;
    if ct.len() < needed {
        return Err(CryptoError::HpkeOutputBufferTooSmall);
    }
    let aes_key = AesKey::from_bytes(key)?;
    let aad_opt = if aad.is_empty() { None } else { Some(aad) };
    let mut algo = AesGcmAlgo::for_encrypt(nonce, aad_opt)?;
    let n = algo.encrypt(&aes_key, pt, Some(&mut ct[..pt.len()]))?;
    if n != pt.len() {
        return Err(CryptoError::HpkeAeadSealFailed);
    }
    ct[pt.len()..pt.len() + GCM_TAG_LEN].copy_from_slice(algo.tag());
    Ok(needed)
}

fn open_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    pt: &mut [u8],
) -> Result<usize, CryptoError> {
    if ct.len() < GCM_TAG_LEN {
        return Err(CryptoError::HpkeInvalidBufferSize);
    }
    let body_len = ct.len() - GCM_TAG_LEN;
    if pt.len() < body_len {
        return Err(CryptoError::HpkeOutputBufferTooSmall);
    }
    let (body, tag) = ct.split_at(body_len);
    let aes_key = AesKey::from_bytes(key)?;
    let aad_opt = if aad.is_empty() { None } else { Some(aad) };
    let mut algo = AesGcmAlgo::for_decrypt(nonce, tag, aad_opt)?;
    let n = algo
        .decrypt(&aes_key, body, Some(&mut pt[..body_len]))
        .map_err(|_| CryptoError::HpkeAeadOpenFailed)?;
    if n != body_len {
        return Err(CryptoError::HpkeAeadOpenFailed);
    }
    Ok(body_len)
}

// =============================================================================
// AES-CBC + HMAC
// =============================================================================

struct CbcKey<'a> {
    mac_key: &'a [u8],
    enc_key: &'a [u8],
    hash: HashAlgo,
    tag_len: usize,
}

impl<'a> CbcKey<'a> {
    fn from_suite(suite: HpkeSuite, key: &'a [u8]) -> Result<Self, CryptoError> {
        let mac_len = suite.cbc_mac_key_len();
        let enc_len = suite.cbc_enc_key_len();
        if key.len() != mac_len + enc_len {
            return Err(CryptoError::HpkeInvalidBufferSize);
        }
        Ok(Self {
            mac_key: &key[..mac_len],
            enc_key: &key[mac_len..],
            hash: suite.kdf_hash(),
            tag_len: suite.nt(),
        })
    }
}

fn seal_cbc(
    suite: HpkeSuite,
    key: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
) -> Result<usize, CryptoError> {
    let cbc = CbcKey::from_suite(suite, key)?;
    let padded = padded_len(pt.len());
    let total = CBC_IV_LEN + padded + cbc.tag_len;
    if ct.len() < total {
        return Err(CryptoError::HpkeOutputBufferTooSmall);
    }

    // 1. Random IV in place at ct[..16].
    Rng::rand_bytes(&mut ct[..CBC_IV_LEN])?;
    // AES-CBC engine wants an owned, mutable copy because it advances
    // the IV across blocks. Construct directly from the (already
    // random) bytes we just wrote into `ct` — avoids a transient
    // zero-init buffer.
    let iv: [u8; CBC_IV_LEN] = ct[..CBC_IV_LEN]
        .try_into()
        .expect("ct[..CBC_IV_LEN] has exactly CBC_IV_LEN bytes");

    // 2. Encrypt pt into ct[16..16+padded].
    let aes_key = AesKey::from_bytes(cbc.enc_key)?;
    let mut algo = AesCbcAlgo::with_padding(&iv);
    // OpenSSL's CBC encrypt requires the destination buffer to be at
    // least pt.len() + block_size, even though only `padded` bytes are
    // written. Encrypt into a scratch Vec and copy back the exact slice.
    let mut scratch = vec![0u8; pt.len() + AES_BLOCK_LEN];
    let n = algo.encrypt(&aes_key, pt, Some(&mut scratch))?;
    if n != padded {
        return Err(CryptoError::HpkeAeadSealFailed);
    }
    ct[CBC_IV_LEN..CBC_IV_LEN + padded].copy_from_slice(&scratch[..padded]);

    // 3. Compute HMAC over [aad || iv || ciphertext || aad_bits_be64].
    let mac_key = HmacKey::from_bytes(cbc.mac_key)?;
    let tag = compute_hmac(
        &cbc.hash,
        &mac_key,
        aad,
        &iv,
        &ct[CBC_IV_LEN..CBC_IV_LEN + padded],
    )?;
    ct[CBC_IV_LEN + padded..total].copy_from_slice(&tag[..cbc.tag_len]);
    Ok(total)
}

fn open_cbc(
    suite: HpkeSuite,
    key: &[u8],
    aad: &[u8],
    ct: &[u8],
    pt: &mut [u8],
) -> Result<usize, CryptoError> {
    let cbc = CbcKey::from_suite(suite, key)?;
    if ct.len() < CBC_IV_LEN + AES_BLOCK_LEN + cbc.tag_len {
        return Err(CryptoError::HpkeInvalidBufferSize);
    }
    let enc_len = ct.len() - CBC_IV_LEN - cbc.tag_len;
    let iv = &ct[..CBC_IV_LEN];
    let body = &ct[CBC_IV_LEN..CBC_IV_LEN + enc_len];
    let received_tag = &ct[CBC_IV_LEN + enc_len..];

    // 1. Verify MAC first (encrypt-then-MAC).
    let mac_key = HmacKey::from_bytes(cbc.mac_key)?;
    let computed = compute_hmac(&cbc.hash, &mac_key, aad, iv, body)?;
    if !constant_time_eq(&computed[..cbc.tag_len], received_tag) {
        return Err(CryptoError::HpkeAeadOpenFailed);
    }

    // 2. Decrypt + unpad.
    let aes_key = AesKey::from_bytes(cbc.enc_key)?;
    let mut algo = AesCbcAlgo::with_padding(iv);
    let mut scratch = vec![0u8; enc_len + AES_BLOCK_LEN];
    let written = algo
        .decrypt(&aes_key, body, Some(&mut scratch))
        .map_err(|_| CryptoError::HpkeAeadOpenFailed)?;
    if pt.len() < written {
        return Err(CryptoError::HpkeOutputBufferTooSmall);
    }
    pt[..written].copy_from_slice(&scratch[..written]);
    Ok(written)
}

fn compute_hmac(
    hash: &HashAlgo,
    mac_key: &HmacKey,
    aad: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let aad_bits = (aad.len() as u64 * 8).to_be_bytes();
    let mut input = Vec::with_capacity(aad.len() + iv.len() + ciphertext.len() + 8);
    input.extend_from_slice(aad);
    input.extend_from_slice(iv);
    input.extend_from_slice(ciphertext);
    input.extend_from_slice(&aad_bits);

    let mut algo = HmacAlgo::new(hash.clone());
    let len = hash.size();
    let mut out = vec![0u8; len];
    algo.sign(mac_key, &input, Some(&mut out))?;
    Ok(out)
}

/// Constant-time slice equality check (length-independent comparison is
/// performed when lengths match; mismatched lengths fast-fail).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
