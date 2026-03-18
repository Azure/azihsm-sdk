// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::HsmAesCbcAlgo;
use azihsm_api::HsmAesKey;
use azihsm_api::HsmDecrypter;
use azihsm_api::HsmEncrypter;
use azihsm_api::HsmResult;
use azihsm_crypto::Rng;

pub const AES_CBC_BLOCK_SIZE: usize = 16;

// ================================
// Misc
// ================================

pub fn test_iv() -> [u8; AES_CBC_BLOCK_SIZE] {
    Rng::rand_vec(AES_CBC_BLOCK_SIZE)
        .expect("RNG failure generating IV")
        .try_into()
        .expect("IV length mismatch")
}
// ================================
// Key  Algorithm Helpers
// ================================

/// Create an AES-CBC algorithm instance configured for PKCS#7 padding (true) or no padding (false).
pub fn new_cbc_algo(padding: bool, iv: &[u8]) -> HsmAesCbcAlgo {
    if padding {
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES CBC algo")
    } else {
        HsmAesCbcAlgo::with_no_padding(iv.to_vec()).expect("Failed to create AES CBC algo")
    }
}

// ================================
// Encrypt/Decrypt Helpers
// ================================
/// Encrypt then decrypt via AES-CBC and assert round-trip equality.
///
/// Notes:
/// - CBC mutates IV internally, so this helper always uses fresh algo instances.
/// - When `padding == false`, plaintext must be block-aligned and ciphertext length must match.
pub fn cbc_encrypt(
    key: &HsmAesKey,
    padding: bool,
    iv: &[u8],
    plaintext: &[u8],
) -> HsmResult<Vec<u8>> {
    // Length query uses the algo and mutates IV, so use a fresh algo instance.
    let cipher_len = {
        let mut algo = new_cbc_algo(padding, iv);
        HsmEncrypter::encrypt(&mut algo, key, plaintext, None)?
    };

    let mut out = vec![0u8; cipher_len];

    let written = {
        let mut algo = new_cbc_algo(padding, iv);
        HsmEncrypter::encrypt(&mut algo, key, plaintext, Some(&mut out))?
    };
    out.truncate(written);

    Ok(out)
}

pub fn cbc_decrypt(
    key: &HsmAesKey,
    padding: bool,
    iv: &[u8],
    ciphertext: &[u8],
) -> HsmResult<Vec<u8>> {
    // Length query uses the algo and mutates IV, so use a fresh algo instance.
    let max_plain_len = {
        let mut algo = new_cbc_algo(padding, iv);
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?
    };

    let mut out = vec![0xCCu8; max_plain_len];

    let written = {
        let mut algo = new_cbc_algo(padding, iv);
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut out))?
    };
    out.truncate(written);

    Ok(out)
}
