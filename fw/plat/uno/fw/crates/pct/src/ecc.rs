// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC pairwise consistency tests.
//!
//! - **Sign/verify:** Hash a fixed message, sign the digest with the private
//!   key, and verify the signature with the public key.
//! - **Key agreement:** Run ECDH in both directions against a fixed test key
//!   pair, as SP 800-56A allows: the key under test with the test public key,
//!   and the test private key with the public key under test. Both must give
//!   the same shared secret. Only the X coordinate is compared.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEcc;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmHash;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::vectors;

/// Byte that fills the sign/verify test message.
const MESSAGE_BYTE: u8 = 100;

/// Length of the sign/verify test message: the widest ECC operand.
const MESSAGE_LEN: usize = 68;

/// Length of the status word that `ecc_verify` writes.
const VERIFY_RESULT_LEN: usize = 4;

/// Runs the ECC pairwise consistency test that `pct` selects.
///
/// `priv_key` and `pub_key` use the PAL's wire format: little-endian, with
/// each P-521 value padded to 68 bytes. Scratch buffers come from `alloc`.
///
/// # Returns
///
/// - `Ok(true)` — the key pair passed, or `pct` is [`HsmEccPct::None`].
/// - `Ok(false)` — the key pair is inconsistent.
/// - `Err(_)` — an allocation or PAL operation failed, so the test didn't
///   finish.
pub async fn ecc_pct<P: HsmEcc + HsmHash>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    curve: HsmEccCurve,
    pct: &HsmEccPct,
    priv_key: &DmaBuf,
    pub_key: &DmaBuf,
) -> HsmResult<bool> {
    match pct {
        HsmEccPct::None => Ok(true),
        HsmEccPct::SignVerify => sign_verify(pal, io, alloc, curve, priv_key, pub_key).await,
        HsmEccPct::KeyAgreement => key_agreement(pal, io, alloc, curve, priv_key, pub_key).await,
    }
}

/// Returns the hash that the sign/verify PCT uses for each curve.
fn digest_algo(curve: HsmEccCurve) -> HsmHashAlgo {
    match curve {
        HsmEccCurve::P256 => HsmHashAlgo::Sha256,
        HsmEccCurve::P384 => HsmHashAlgo::Sha384,
        HsmEccCurve::P521 => HsmHashAlgo::Sha512,
    }
}

async fn sign_verify<P: HsmEcc + HsmHash>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    curve: HsmEccCurve,
    priv_key: &DmaBuf,
    pub_key: &DmaBuf,
) -> HsmResult<bool> {
    let algo = digest_algo(curve);
    let message = crate::scratch(alloc, MESSAGE_LEN)?;
    message.fill(MESSAGE_BYTE);

    // The PKA reads a full field-width digest operand (68 bytes for P-521),
    // so the little-endian digest sits in a zeroed buffer of that width. The
    // PAL receives the ECDSA digest width, which is at most 64 bytes.
    let digest = crate::scratch_zeroed(alloc, curve.wire_coord_len())?;
    pal.hash(io, algo, message, &mut digest[..algo.digest_len()], false)
        .await?;
    let digest = &digest[..curve.ecdsa_digest_len()];

    let signature = crate::scratch_zeroed(alloc, curve.wire_sig_len())?;
    pal.ecc_sign(io, curve, priv_key, digest, signature).await?;

    // Start from "invalid" so a verify that writes nothing can't pass.
    let result = crate::scratch(alloc, VERIFY_RESULT_LEN)?;
    result.fill(0xFF);
    pal.ecc_verify(io, curve, pub_key, digest, signature, result)
        .await?;
    Ok(result[0] & 1 == 0)
}

async fn key_agreement<P: HsmEcc>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    curve: HsmEccCurve,
    priv_key: &DmaBuf,
    pub_key: &DmaBuf,
) -> HsmResult<bool> {
    let coord = curve.wire_coord_len();
    let test = vectors::ecdh_test_pair(curve);

    let test_priv = test_private_key(alloc, curve)?;
    let test_pub = crate::scratch_zeroed(alloc, 2 * coord)?;
    vectors::be_to_le(test.qx, &mut test_pub[..test.qx.len()]);
    vectors::be_to_le(test.qy, &mut test_pub[coord..coord + test.qy.len()]);

    // The PKA may write the whole shared point, so each output holds X and
    // Y. The two outputs start different, so they can only match if both
    // derivations write them.
    let from_key = crate::scratch_zeroed(alloc, 2 * coord)?;
    let from_test_key = crate::scratch(alloc, 2 * coord)?;
    from_test_key.fill(0xFF);

    // Both derivations share one await point, which keeps the compiled
    // code small.
    let derived: HsmResult<()> = async {
        for (d, q, out) in [
            (priv_key, &*test_pub, &mut *from_key),
            (&*test_priv, pub_key, &mut *from_test_key),
        ] {
            pal.ecdh_derive(io, curve, d, q, out).await?;
        }
        Ok(())
    }
    .await;

    let secret_len = curve.secret_len();
    let consistent =
        derived.is_ok() && crate::ct_eq(&from_key[..secret_len], &from_test_key[..secret_len]);
    from_key.zeroize();
    from_test_key.zeroize();
    derived.map(|()| consistent)
}

/// Builds the fixed test private key for `curve` in the Uno PAL's vault
/// format: the scalar little-endian, zero-padded to the curve's wire
/// coordinate length.
///
/// The test vectors hold only the raw scalar, so the key is built directly
/// instead of through the PAL's DER conversion.
pub(crate) fn test_private_key(
    alloc: &impl HsmScopedAlloc,
    curve: HsmEccCurve,
) -> HsmResult<&mut DmaBuf> {
    let d = vectors::ecdh_test_pair(curve).d;
    let test_priv = crate::scratch_zeroed(alloc, curve.wire_coord_len())?;
    vectors::be_to_le(d, &mut test_priv[..d.len()]);
    Ok(test_priv)
}
