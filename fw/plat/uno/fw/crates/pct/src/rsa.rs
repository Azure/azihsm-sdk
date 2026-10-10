// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA pairwise consistency tests.
//!
//! - **Sign/verify:** Hash a fixed message, raise the digest to the private
//!   exponent, raise the result to the public exponent, and compare.
//! - **Encrypt/decrypt:** Raise a fixed value to the public exponent, raise
//!   the result to the private exponent, and compare.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmHash;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRsa;
use azihsm_fw_hsm_pal_traits::HsmRsaKey;
use azihsm_fw_hsm_pal_traits::HsmRsaPct;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

/// Byte that fills the sign/verify test message.
const MESSAGE_BYTE: u8 = 100;

/// Byte that fills the encrypt/decrypt test value.
const PLAINTEXT_BYTE: u8 = 0x5A;

/// Runs the RSA pairwise consistency test that `pct` selects.
///
/// `key` selects the modulus size and the private-key layout (CRT or not).
/// `priv_key` is in the PAL's vault format. `pub_key` is in the format the
/// PAL's `mod_exp_pub` takes. Values cross the PAL little-endian. Scratch
/// buffers come from `alloc`.
///
/// # Returns
///
/// - `Ok(true)` — the key pair passed, or `pct` is [`HsmRsaPct::None`].
/// - `Ok(false)` — the key pair is inconsistent.
/// - `Err(_)` — an allocation or PAL operation failed, so the test didn't
///   finish.
pub async fn rsa_pct<P: HsmRsa + HsmHash>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    key: HsmRsaKey,
    pct: &HsmRsaPct,
    priv_key: &DmaBuf,
    pub_key: &DmaBuf,
) -> HsmResult<bool> {
    let sign = match pct {
        HsmRsaPct::None => return Ok(true),
        HsmRsaPct::SignVerify => true,
        HsmRsaPct::EncryptDecrypt => false,
    };
    let k = key.modulus_len();

    // The test value must be smaller than the modulus. The little-endian
    // digest fills only the low bytes, and the plaintext's top byte is zero.
    let input = crate::scratch_zeroed(alloc, k)?;
    if sign {
        let algo = digest_algo(key);
        let message = crate::scratch(alloc, k)?;
        message.fill(MESSAGE_BYTE);
        pal.hash(io, algo, message, &mut input[..algo.digest_len()], false)
            .await?;
    } else {
        input.fill(PLAINTEXT_BYTE);
        input[k - 1] = 0;
    }

    // Sign/verify applies the private exponent first, and encrypt/decrypt
    // applies the public exponent first. One loop runs either order, so each
    // PAL operation has one await point, which keeps the compiled state
    // machine small.
    let middle = crate::scratch_zeroed(alloc, k)?;
    // Start the output different from the input, so an operation that
    // writes nothing can't pass.
    let output = crate::scratch(alloc, k)?;
    output.fill(0xFF);
    let result: HsmResult<()> = async {
        for private in [sign, !sign] {
            let (x, y): (&DmaBuf, &mut DmaBuf) = if private == sign {
                (&*input, &mut *middle)
            } else {
                (&*middle, &mut *output)
            };
            if private {
                pal.mod_exp_priv(io, key, priv_key, x, y).await?;
            } else {
                pal.mod_exp_pub(io, key.pub_variant(), pub_key, x, y)
                    .await?;
            }
        }
        Ok(())
    }
    .await;
    let consistent = result.is_ok() && output[..] == input[..];
    output.zeroize();
    result.map(|()| consistent)
}

/// Returns the hash that the sign/verify PCT uses for each modulus size.
fn digest_algo(key: HsmRsaKey) -> HsmHashAlgo {
    match key.modulus_len() {
        256 => HsmHashAlgo::Sha256,
        384 => HsmHashAlgo::Sha384,
        _ => HsmHashAlgo::Sha512,
    }
}
