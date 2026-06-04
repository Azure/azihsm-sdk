// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DHKEM (RFC 9180 §4.1) — Encap / Decap and their Auth variants.
//!
//! All four entry points produce a [`HpkeSuite::nsecret`]-byte shared
//! secret via:
//!
//! 1. One ECDH (or two for Auth) using either an ephemeral keypair
//!    (Encap / AuthEncap) or the recipient's static private key
//!    (Decap / AuthDecap).
//! 2. A `kem_context` of `enc ‖ pk_r` (Base) or `enc ‖ pk_r ‖ pk_s`
//!    (Auth) — the SEC1 uncompressed serialisations are concatenated
//!    per RFC 9180.
//! 3. `ExtractAndExpand(dh, kem_context)` (the KEM-suite-scoped HKDF).
//!
//! ## Wire format
//!
//! Public keys and the encapsulated key cross the wire as SEC1
//! uncompressed (`0x04 ‖ x ‖ y`) — see [`encode_pk`]. The API layer
//! (`super::ops`) exposes [`EccPublicKey`] / [`EccPrivateKey`] for
//! callers; this module owns the (de)serialisation glue.

use super::kdf::labeled_expand;
use super::kdf::labeled_extract;
use super::suite::HpkeSuite;
use crate::CryptoError;
use crate::DeriveOp;
use crate::EccKeyOp;
use crate::EccPrivateKey;
use crate::EccPublicKey;
use crate::EcdhAlgo;
use crate::ExportableKey;
use crate::PrivateKey;

/// SEC1 uncompressed-point tag byte (0x04).
const SEC1_UNCOMPRESSED: u8 = 0x04;

// =============================================================================
// Public key serialisation between SEC1 uncompressed and EccPublicKey
// =============================================================================

/// Encode an [`EccPublicKey`] in SEC1 uncompressed form
/// (`0x04 ‖ x ‖ y`). Returned `Vec` length equals [`HpkeSuite::npk`].
///
/// Used internally to build the `kem_context` byte string fed into
/// the KEM HKDF. Callers wishing to transmit `enc` over a wire should
/// use [`EccKeyOp::coord`] directly.
pub(crate) fn encode_pk(suite: HpkeSuite, pk: &EccPublicKey) -> Result<Vec<u8>, CryptoError> {
    if pk.curve() != suite.kem_curve() {
        return Err(CryptoError::HpkeInvalidPublicKey);
    }
    let coord_len = suite.nsk();
    let mut out = vec![0u8; suite.npk()];
    out[0] = SEC1_UNCOMPRESSED;
    let (x, y) = out[1..].split_at_mut(coord_len);
    pk.coord(Some((x, y)))?;
    Ok(out)
}

// =============================================================================
// Curve consistency checks
// =============================================================================

fn check_pk_curve(pk: &EccPublicKey, suite: HpkeSuite) -> Result<(), CryptoError> {
    if pk.curve() != suite.kem_curve() {
        Err(CryptoError::HpkeInvalidPublicKey)
    } else {
        Ok(())
    }
}

fn check_sk_curve(sk: &EccPrivateKey, suite: HpkeSuite) -> Result<(), CryptoError> {
    // `EccPrivateKey` exposes its curve via the `EccKeyOp` trait by way
    // of its derived public key. The platform backends keep curve as
    // an internal field; we rely on `public_key().curve()` to read it
    // without copying scalars.
    let pk = sk
        .public_key()
        .map_err(|_| CryptoError::HpkeInvalidPrivateKey)?;
    if pk.curve() != suite.kem_curve() {
        return Err(CryptoError::HpkeInvalidPrivateKey);
    }
    Ok(())
}

// =============================================================================
// ECDH helper
// =============================================================================

/// Perform an ECDH derivation and copy the raw shared secret into `out`.
fn ecdh(
    suite: HpkeSuite,
    sk: &EccPrivateKey,
    pk: &EccPublicKey,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let ndh = suite.ndh();
    debug_assert_eq!(out.len(), ndh);
    let ecdh = EcdhAlgo::new(pk);
    let secret = ecdh
        .derive(sk, ndh)
        .map_err(|_| CryptoError::HpkeKemEncapFailed)?;
    let written = secret.to_bytes(Some(out))?;
    if written != ndh {
        return Err(CryptoError::HpkeKemEncapFailed);
    }
    Ok(())
}

/// `ExtractAndExpand(dh, kem_context) → shared_secret` (RFC 9180 §4.1).
fn extract_and_expand(
    suite: HpkeSuite,
    dh: &[u8],
    kem_context: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let algo = suite.kdf_hash();
    let kem_suite_id = suite.kem_suite_id();
    let eae_prk = labeled_extract(&algo, &kem_suite_id, &[], b"eae_prk", dh)?;
    labeled_expand(
        &algo,
        &kem_suite_id,
        &eae_prk,
        b"shared_secret",
        kem_context,
        suite.nsecret(),
    )
}

/// Assemble the HPKE `kem_context` from the SEC1 uncompressed byte
/// strings:
/// * Base: `enc ‖ pk_r`
/// * Auth: `enc ‖ pk_r ‖ pk_s`
fn kem_context(enc: &[u8], pk_r: &[u8], pk_s: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(enc.len() + pk_r.len() + pk_s.map_or(0, |b| b.len()));
    out.extend_from_slice(enc);
    out.extend_from_slice(pk_r);
    if let Some(pk_s) = pk_s {
        out.extend_from_slice(pk_s);
    }
    out
}

// =============================================================================
// Public entry points (typed keys)
// =============================================================================

/// DHKEM Encap (Base mode). Generates an ephemeral keypair, derives
/// `dh = DH(skE, pkR)`, and runs `ExtractAndExpand(dh, enc ‖ pkR)`.
/// Returns `(pk_e, shared_secret)`.
pub(crate) fn encap(
    suite: HpkeSuite,
    pk_r: &EccPublicKey,
) -> Result<(EccPublicKey, Vec<u8>), CryptoError> {
    check_pk_curve(pk_r, suite)?;
    let pk_r_bytes = encode_pk(suite, pk_r)?;

    let sk_e = EccPrivateKey::from_curve(suite.kem_curve())
        .map_err(|_| CryptoError::HpkeKemEncapFailed)?;
    let pk_e = sk_e
        .public_key()
        .map_err(|_| CryptoError::HpkeKemEncapFailed)?;
    let pk_e_bytes = encode_pk(suite, &pk_e)?;

    let mut dh = vec![0u8; suite.ndh()];
    ecdh(suite, &sk_e, pk_r, &mut dh)?;

    let ctx = kem_context(&pk_e_bytes, &pk_r_bytes, None);
    let ss = extract_and_expand(suite, &dh, &ctx)?;
    Ok((pk_e, ss))
}

/// DHKEM Decap (Base mode).
pub(crate) fn decap(
    suite: HpkeSuite,
    enc: &EccPublicKey,
    sk_r: &EccPrivateKey,
    pk_r: &EccPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    check_pk_curve(enc, suite)?;
    check_sk_curve(sk_r, suite)?;
    check_pk_curve(pk_r, suite)?;

    let mut dh = vec![0u8; suite.ndh()];
    ecdh(suite, sk_r, enc, &mut dh).map_err(|_| CryptoError::HpkeKemDecapFailed)?;

    let enc_bytes = encode_pk(suite, enc)?;
    let pk_r_bytes = encode_pk(suite, pk_r)?;
    let ctx = kem_context(&enc_bytes, &pk_r_bytes, None);
    extract_and_expand(suite, &dh, &ctx)
}

/// DHKEM AuthEncap (RFC 9180 §4.1).
///
/// Per RFC 9180, the sender's public key `pk_s` is derived internally
/// from `sk_s` — callers only supply the private key.
pub(crate) fn auth_encap(
    suite: HpkeSuite,
    pk_r: &EccPublicKey,
    sk_s: &EccPrivateKey,
) -> Result<(EccPublicKey, Vec<u8>), CryptoError> {
    check_pk_curve(pk_r, suite)?;
    check_sk_curve(sk_s, suite)?;

    let pk_s = sk_s
        .public_key()
        .map_err(|_| CryptoError::HpkeInvalidPrivateKey)?;

    let sk_e = EccPrivateKey::from_curve(suite.kem_curve())
        .map_err(|_| CryptoError::HpkeKemEncapFailed)?;
    let pk_e = sk_e
        .public_key()
        .map_err(|_| CryptoError::HpkeKemEncapFailed)?;

    let ndh = suite.ndh();
    let mut dh = vec![0u8; 2 * ndh];
    ecdh(suite, &sk_e, pk_r, &mut dh[..ndh])?;
    ecdh(suite, sk_s, pk_r, &mut dh[ndh..])?;

    let pk_e_bytes = encode_pk(suite, &pk_e)?;
    let pk_r_bytes = encode_pk(suite, pk_r)?;
    let pk_s_bytes = encode_pk(suite, &pk_s)?;
    let ctx = kem_context(&pk_e_bytes, &pk_r_bytes, Some(&pk_s_bytes));
    let ss = extract_and_expand(suite, &dh, &ctx)?;
    Ok((pk_e, ss))
}

/// DHKEM AuthDecap.
pub(crate) fn auth_decap(
    suite: HpkeSuite,
    enc: &EccPublicKey,
    sk_r: &EccPrivateKey,
    pk_r: &EccPublicKey,
    pk_s: &EccPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    check_pk_curve(enc, suite)?;
    check_sk_curve(sk_r, suite)?;
    check_pk_curve(pk_r, suite)?;
    check_pk_curve(pk_s, suite)?;

    let ndh = suite.ndh();
    let mut dh = vec![0u8; 2 * ndh];
    ecdh(suite, sk_r, enc, &mut dh[..ndh]).map_err(|_| CryptoError::HpkeKemDecapFailed)?;
    ecdh(suite, sk_r, pk_s, &mut dh[ndh..]).map_err(|_| CryptoError::HpkeKemDecapFailed)?;

    let enc_bytes = encode_pk(suite, enc)?;
    let pk_r_bytes = encode_pk(suite, pk_r)?;
    let pk_s_bytes = encode_pk(suite, pk_s)?;
    let ctx = kem_context(&enc_bytes, &pk_r_bytes, Some(&pk_s_bytes));
    extract_and_expand(suite, &dh, &ctx)
}
