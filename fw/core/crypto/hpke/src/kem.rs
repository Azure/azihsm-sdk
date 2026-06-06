// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DHKEM (RFC 9180 §4.1) — Encap / Decap and their Auth variants.
//!
//! All four entry points produce a [`HpkeSuite::nsecret`]-byte
//! shared secret via:
//!
//! 1. One ECDH (or two for Auth) using either an ephemeral keypair
//!    (Encap / AuthEncap) or the recipient's static private key
//!    (Decap / AuthDecap).
//! 2. A `kem_context` made up of `enc ‖ pk_r` (Base) or
//!    `enc ‖ pk_r ‖ pk_s` (Auth).
//! 3. The shared `ExtractAndExpand` step that maps `(dh, kem_context)`
//!    to the final shared secret via [`labeled_extract`] +
//!    [`labeled_expand`].
//!
//! Each public function allocates its intermediate buffers from the
//! caller's [`HsmScopedAlloc`], then funnels through
//! [`extract_and_expand`].
//!
//! [`labeled_extract`]: crate::kdf::labeled_extract
//! [`labeled_expand`]: crate::kdf::labeled_expand

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::helpers::dma_copy_in;
use crate::kdf;
use crate::suite::HpkeSuite;

// =============================================================================
// kem_context layout
// =============================================================================

/// Fill `dst` with the HPKE `kem_context` value:
///
/// * If `pk_s` is `None`: `enc ‖ pk_r` (Base modes).
/// * If `pk_s` is `Some(_)`: `enc ‖ pk_r ‖ pk_s` (Auth modes).
///
/// All public keys are RFC 9180 §7.1.1 serialized form — for the
/// curves currently supported (DHKEM(P-256), DHKEM(P-384)) that is
/// SEC1 uncompressed (`0x04 ‖ X_be ‖ Y_be`).  Every slice **must**
/// be exactly `npk_wire` bytes long; callers are expected to
/// validate before calling.
///
/// # Parameters
/// * `dst` — destination buffer of `npk_wire * (2 + auth as usize)` bytes.
/// * `npk_wire` — wire-format public-key length ([`HpkeSuite::npk`]).
/// * `enc` — serialised ephemeral / received public key.
/// * `pk_r` — recipient public key.
/// * `pk_s` — sender public key for Auth modes; `None` for Base.
fn build_kem_context(
    dst: &mut [u8],
    npk_wire: usize,
    enc: &[u8],
    pk_r: &[u8],
    pk_s: Option<&[u8]>,
) {
    debug_assert_eq!(enc.len(), npk_wire);
    debug_assert_eq!(pk_r.len(), npk_wire);
    dst[..npk_wire].copy_from_slice(enc);
    dst[npk_wire..2 * npk_wire].copy_from_slice(pk_r);
    if let Some(pk_s) = pk_s {
        debug_assert_eq!(pk_s.len(), npk_wire);
        dst[2 * npk_wire..3 * npk_wire].copy_from_slice(pk_s);
    }
}

fn alloc_bytes(len: usize, alloc: &impl HsmScopedAlloc) -> HsmResult<&mut DmaBuf> {
    alloc.dma_alloc(len)
}

// =============================================================================
// SEC1 ↔ PAL-native byte-format conversion helpers
// =============================================================================
//
// HPKE wire format for DHKEM(P-256/P-384) is RFC 9180 §7.1.1 SEC1
// uncompressed:
//
//     enc / pk = 0x04 ‖ X_be ‖ Y_be   (length = 1 + 2*coord_len)
//
// The PAL ECC traits — [`HsmEcc::ecc_gen_keypair`] /
// [`HsmEcc::ecdh_derive`] — traffic in HSM-native LE coordinates with
// no SEC1 prefix:
//
//     pal pub = X_le ‖ Y_le             (length = 2*coord_len)
//
// These helpers do the byte-reversal + 0x04 prefix add/strip.
//
// Curve constraint: the SEC1 BE form is exactly one byte longer
// than the PAL-native LE form (`npk_wire = npk_pal + 1`).  This
// holds for P-256 and P-384.  P-521 currently violates this in
// `HpkeSuite` (both sizes are 136) because the suite registry uses
// the PAL-padded length for `npk` to keep callers compiling; HPKE
// P-521 is unusable, so all four entry points reject it explicitly
// rather than silently mis-encoding the transcript.

/// Convert SEC1-uncompressed BE bytes (`0x04 ‖ X_be ‖ Y_be`) into
/// the PAL-native LE coordinate form (`X_le ‖ Y_le`) the PAL ECC
/// trait expects.
///
/// Input length must be **exactly** `1 + 2*coord_len`; output buffer
/// must be **at least** `2*coord_len`.  A missing or wrong SEC1 tag
/// byte is rejected so callers can't pass compressed / hybrid
/// encodings the PAL would silently mis-interpret.
fn sec1_be_to_pal_le(sec1: &[u8], dst: &mut [u8], coord_len: usize) -> HsmResult<()> {
    let need = 1 + 2 * coord_len;
    if sec1.len() != need || dst.len() < 2 * coord_len || sec1[0] != 0x04 {
        return Err(HsmError::InvalidArg);
    }
    for i in 0..coord_len {
        dst[i] = sec1[1 + (coord_len - 1 - i)];
        dst[coord_len + i] = sec1[1 + coord_len + (coord_len - 1 - i)];
    }
    Ok(())
}

/// Convert PAL-native LE coordinates (`X_le ‖ Y_le`) into SEC1
/// uncompressed BE (`0x04 ‖ X_be ‖ Y_be`) for HPKE on-wire / kem_context use.
///
/// Input length must be **exactly** `2*coord_len`; output buffer
/// must be **at least** `1 + 2*coord_len`.
fn pal_le_to_sec1_be(le: &[u8], dst: &mut [u8], coord_len: usize) -> HsmResult<()> {
    if le.len() != 2 * coord_len || dst.len() < 1 + 2 * coord_len {
        return Err(HsmError::InvalidArg);
    }
    dst[0] = 0x04;
    for i in 0..coord_len {
        dst[1 + i] = le[coord_len - 1 - i];
        dst[1 + coord_len + i] = le[2 * coord_len - 1 - i];
    }
    Ok(())
}

/// Common preflight for the four KEM entry points.  Returns the
/// `(npk_wire, npk_pal, coord_len)` triple after rejecting suites
/// whose serialized public-key length does not match the SEC1
/// (`0x04`-prefixed) shape this code generates.
///
/// Today that means rejecting P-521 — see the module-level comment
/// above the helpers.
fn kem_sizes(suite: HpkeSuite) -> HsmResult<(usize, usize, usize)> {
    let npk_wire = suite.npk();
    let npk_pal = suite.npk_pal();
    if npk_wire != npk_pal + 1 {
        // Suite registry exposes a PAL-padded `npk` (e.g., P-521); SEC1
        // BE encoding would not round-trip.
        return Err(HsmError::InvalidArg);
    }
    Ok((npk_wire, npk_pal, npk_pal / 2))
}

// =============================================================================
// Public entry points
// =============================================================================

/// DHKEM Encap (Base mode).
///
/// Generates an ephemeral keypair, derives `dh = DH(skE, pkR)`, and
/// runs `ExtractAndExpand(dh, enc ‖ pkR)`.
///
/// # Type parameters
///
/// * `P` — any [`HsmCrypto`] PAL implementation.
///
/// # Parameters
///
/// * `pal` — PAL providing ECC + HKDF.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `pk_r` — recipient public key (`Npk` bytes).
/// * `enc` — output: encapsulated key (`Nenc` bytes).
/// * `shared_secret` — output: KEM shared secret (`Nsecret`
///   bytes).
/// * `alloc` — scoped allocator used for the ephemeral keypair,
///   intermediate buffers, and internal HKDF / HMAC state.
///
/// # Returns
///
/// * `Ok(())` — `enc` and `shared_secret` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the ECC keypair / ECDH /
///   HKDF calls.
pub async fn encap<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    pk_r: &[u8],
    enc: &mut [u8],
    shared_secret: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let curve = suite.kem_curve();
    let (npk_wire, npk_pal, coord_len) = kem_sizes(suite)?;
    let ndh = suite.ndh();

    if pk_r.len() != npk_wire || enc.len() < npk_wire {
        return Err(HsmError::InvalidArg);
    }

    // Query-alloc-use ECC keygen.  PAL writes `pk_e_le` as
    // `X_le ‖ Y_le` (no SEC1 prefix), `npk_pal` bytes.
    let (priv_size, pub_size) = pal
        .ecc_gen_keypair(io, alloc, curve, None, HsmEccPct::None)
        .await?;
    if pub_size != npk_pal {
        return Err(HsmError::InvalidArg);
    }
    let sk_e = alloc_bytes(priv_size, alloc)?;
    let pk_e_le = alloc_bytes(pub_size, alloc)?;
    let (sk_len, pk_len) = pal
        .ecc_gen_keypair(
            io,
            alloc,
            curve,
            Some((&mut *sk_e, &mut *pk_e_le)),
            HsmEccPct::None,
        )
        .await?;
    if pk_len != npk_pal {
        return Err(HsmError::InvalidArg);
    }

    // Convert caller-supplied SEC1 BE `pk_r` to PAL-native LE so the
    // PAL ECDH primitive can consume it directly.
    let pk_r_le = alloc_bytes(npk_pal, alloc)?;
    sec1_be_to_pal_le(pk_r, &mut pk_r_le[..], coord_len)?;

    let dh = alloc_bytes(ndh, alloc)?;
    pal.ecdh_derive(io, curve, &sk_e[..sk_len], pk_r_le, dh)
        .await?;

    // Serialise ephemeral public key into SEC1 BE wire form for `enc`
    // and the transcript-binding `kem_context`.
    pal_le_to_sec1_be(&pk_e_le[..pk_len], &mut enc[..npk_wire], coord_len)?;

    let kem_context = alloc_bytes(npk_wire * 2, alloc)?;
    build_kem_context(kem_context, npk_wire, &enc[..npk_wire], pk_r, None);

    extract_and_expand(pal, io, suite, dh, kem_context, shared_secret, alloc).await
}

/// DHKEM Decap (Base mode).
///
/// Derives `dh = DH(skR, pkE)` and runs
/// `ExtractAndExpand(dh, enc ‖ pkR)`.
///
/// # Parameters
///
/// * `pal` — PAL providing ECC + HKDF.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `enc` — encapsulated key from sender (`Nenc` bytes).
/// * `sk_r` — recipient private key.
/// * `pk_r` — recipient public key.
/// * `shared_secret` — output: KEM shared secret.
/// * `alloc` — scoped allocator used for the DH buffer,
///   intermediate context, and internal HKDF / HMAC state.
///
/// # Returns
///
/// * `Ok(())` — `shared_secret` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the ECDH / HKDF calls.
pub async fn decap<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    enc: &[u8],
    sk_r: &[u8],
    pk_r: &[u8],
    shared_secret: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let curve = suite.kem_curve();
    let (npk_wire, npk_pal, coord_len) = kem_sizes(suite)?;
    let ndh = suite.ndh();

    if enc.len() != npk_wire || pk_r.len() != npk_wire {
        return Err(HsmError::InvalidArg);
    }

    // Convert SEC1 BE `enc` to PAL-native LE before the ECDH.
    let pk_e_le = alloc_bytes(npk_pal, alloc)?;
    sec1_be_to_pal_le(enc, &mut pk_e_le[..], coord_len)?;

    let dh = alloc_bytes(ndh, alloc)?;
    let sk_r_dma = dma_copy_in(alloc, sk_r)?;
    pal.ecdh_derive(io, curve, sk_r_dma, pk_e_le, dh).await?;

    let kem_context = alloc_bytes(npk_wire * 2, alloc)?;
    build_kem_context(kem_context, npk_wire, enc, pk_r, None);

    extract_and_expand(pal, io, suite, dh, kem_context, shared_secret, alloc).await
}

/// DHKEM AuthEncap.
///
/// Generates an ephemeral keypair, derives both
/// `dh1 = DH(skE, pkR)` and `dh2 = DH(skS, pkR)`, then runs
/// `ExtractAndExpand(dh1 ‖ dh2, enc ‖ pkR ‖ pkS)`.
///
/// # Parameters
///
/// * `pal` — PAL providing ECC + HKDF.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `pk_r` — recipient public key.
/// * `sk_s` — sender private key.
/// * `pk_s` — sender public key.
/// * `enc` — output: encapsulated key.
/// * `shared_secret` — output: KEM shared secret.
/// * `alloc` — scoped allocator used for the ephemeral keypair,
///   DH buffers, intermediate context, and internal HKDF / HMAC
///   state.
///
/// # Returns
///
/// * `Ok(())` — `enc` and `shared_secret` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the ECC keypair / ECDH /
///   HKDF calls.
pub async fn auth_encap<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    pk_r: &[u8],
    sk_s: &[u8],
    pk_s: &[u8],
    enc: &mut [u8],
    shared_secret: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let curve = suite.kem_curve();
    let (npk_wire, npk_pal, coord_len) = kem_sizes(suite)?;
    let ndh = suite.ndh();

    if pk_r.len() != npk_wire || pk_s.len() != npk_wire || enc.len() < npk_wire {
        return Err(HsmError::InvalidArg);
    }

    // Query-alloc-use ECC keygen — same flow as `encap`.
    let (priv_size, pub_size) = pal
        .ecc_gen_keypair(io, alloc, curve, None, HsmEccPct::None)
        .await?;
    if pub_size != npk_pal {
        return Err(HsmError::InvalidArg);
    }
    let sk_e = alloc_bytes(priv_size, alloc)?;
    let pk_e_le = alloc_bytes(pub_size, alloc)?;
    let (sk_len, pk_len) = pal
        .ecc_gen_keypair(
            io,
            alloc,
            curve,
            Some((&mut *sk_e, &mut *pk_e_le)),
            HsmEccPct::None,
        )
        .await?;
    if pk_len != npk_pal {
        return Err(HsmError::InvalidArg);
    }

    // SEC1 BE → PAL-native LE for the recipient public key (shared
    // across both ECDH calls).
    let pk_r_le = alloc_bytes(npk_pal, alloc)?;
    sec1_be_to_pal_le(pk_r, &mut pk_r_le[..], coord_len)?;

    let sk_s_dma = dma_copy_in(alloc, sk_s)?;

    let dh = alloc_bytes(ndh * 2, alloc)?;
    pal.ecdh_derive(io, curve, &sk_e[..sk_len], pk_r_le, &mut dh[..ndh])
        .await?;
    pal.ecdh_derive(io, curve, sk_s_dma, pk_r_le, &mut dh[ndh..])
        .await?;

    pal_le_to_sec1_be(&pk_e_le[..pk_len], &mut enc[..npk_wire], coord_len)?;

    let kem_context = alloc_bytes(npk_wire * 3, alloc)?;
    build_kem_context(kem_context, npk_wire, &enc[..npk_wire], pk_r, Some(pk_s));

    extract_and_expand(pal, io, suite, dh, kem_context, shared_secret, alloc).await
}

/// DHKEM AuthDecap.
///
/// Derives both `dh1 = DH(skR, pkE)` and `dh2 = DH(skR, pkS)`, then
/// runs `ExtractAndExpand(dh1 ‖ dh2, enc ‖ pkR ‖ pkS)`.
///
/// # Parameters
///
/// * `pal` — PAL providing ECC + HKDF.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `enc` — encapsulated key from sender.
/// * `sk_r` — recipient private key.
/// * `pk_r` — recipient public key.
/// * `pk_s` — sender public key (used to authenticate the
///   encapsulation).
/// * `shared_secret` — output: KEM shared secret.
/// * `alloc` — scoped allocator used for the DH buffers,
///   intermediate context, and internal HKDF / HMAC state.
///
/// # Returns
///
/// * `Ok(())` — `shared_secret` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the ECDH / HKDF calls.
pub async fn auth_decap<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    enc: &[u8],
    sk_r: &[u8],
    pk_r: &[u8],
    pk_s: &[u8],
    shared_secret: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let curve = suite.kem_curve();
    let (npk_wire, npk_pal, coord_len) = kem_sizes(suite)?;
    let ndh = suite.ndh();

    if enc.len() != npk_wire || pk_r.len() != npk_wire || pk_s.len() != npk_wire {
        return Err(HsmError::InvalidArg);
    }

    let pk_e_le = alloc_bytes(npk_pal, alloc)?;
    sec1_be_to_pal_le(enc, &mut pk_e_le[..], coord_len)?;
    let pk_s_le = alloc_bytes(npk_pal, alloc)?;
    sec1_be_to_pal_le(pk_s, &mut pk_s_le[..], coord_len)?;

    let dh = alloc_bytes(ndh * 2, alloc)?;
    let sk_r_dma = dma_copy_in(alloc, sk_r)?;
    pal.ecdh_derive(io, curve, sk_r_dma, pk_e_le, &mut dh[..ndh])
        .await?;
    pal.ecdh_derive(io, curve, sk_r_dma, pk_s_le, &mut dh[ndh..])
        .await?;

    let kem_context = alloc_bytes(npk_wire * 3, alloc)?;
    build_kem_context(kem_context, npk_wire, enc, pk_r, Some(pk_s));

    extract_and_expand(pal, io, suite, dh, kem_context, shared_secret, alloc).await
}

// =============================================================================
// ExtractAndExpand
// =============================================================================

/// `ExtractAndExpand(dh, kem_context) → shared_secret`
///
/// ```text
/// eae_prk       = LabeledExtract("",         "eae_prk",      dh)
/// shared_secret = LabeledExpand (eae_prk,   "shared_secret", kem_context, Nsecret)
/// ```
///
/// # Parameters
///
/// * `pal` — PAL providing HKDF.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `dh` — concatenated ECDH output(s).
/// * `kem_context` — `enc ‖ pkR` (Base) or `enc ‖ pkR ‖ pkS`
///   (Auth).
/// * `shared_secret` — output: `Nsecret` bytes.
/// * `alloc` — scoped allocator used for the intermediate `eae_prk`
///   and internal HKDF / HMAC state.
///
/// # Returns
///
/// * `Ok(())` — `shared_secret` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the HKDF Extract / Expand
///   calls.
async fn extract_and_expand<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    dh: &[u8],
    kem_context: &[u8],
    shared_secret: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let algo = suite.kem_hash();
    let nh = suite.nh();
    let kem_suite_id = suite.kem_suite_id();

    let eae_prk = alloc_bytes(nh, alloc)?;
    kdf::labeled_extract(
        pal,
        io,
        algo,
        &kem_suite_id,
        &[],
        b"eae_prk",
        dh,
        eae_prk,
        alloc,
    )
    .await?;

    kdf::labeled_expand(
        pal,
        io,
        algo,
        &kem_suite_id,
        eae_prk,
        b"shared_secret",
        kem_context,
        shared_secret,
        alloc,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Pure-byte unit tests for the SEC1↔PAL-LE conversion helpers.
    //!
    //! End-to-end ECDH coverage lives in the TBOR `OpenSessionInit`
    //! integration tests (`ddi/tbor/types/tests/integration/`); these
    //! tests pin the byte-ordering contract that those rely on.

    use super::*;

    const P384_COORD: usize = 48;

    fn sample_sec1() -> [u8; 1 + 2 * P384_COORD] {
        let mut out = [0u8; 1 + 2 * P384_COORD];
        out[0] = 0x04;
        for i in 0..P384_COORD {
            out[1 + i] = i as u8;
            out[1 + P384_COORD + i] = 0x80 ^ (i as u8);
        }
        out
    }

    #[test]
    fn sec1_to_pal_reverses_each_coordinate() {
        let sec1 = sample_sec1();
        let mut le = [0u8; 2 * P384_COORD];
        sec1_be_to_pal_le(&sec1, &mut le, P384_COORD).unwrap();
        for i in 0..P384_COORD {
            assert_eq!(le[i], sec1[1 + (P384_COORD - 1 - i)]);
            assert_eq!(
                le[P384_COORD + i],
                sec1[1 + P384_COORD + (P384_COORD - 1 - i)],
            );
        }
    }

    #[test]
    fn pal_to_sec1_round_trip() {
        let sec1 = sample_sec1();
        let mut le = [0u8; 2 * P384_COORD];
        sec1_be_to_pal_le(&sec1, &mut le, P384_COORD).unwrap();
        let mut sec1_rt = [0u8; 1 + 2 * P384_COORD];
        pal_le_to_sec1_be(&le, &mut sec1_rt, P384_COORD).unwrap();
        assert_eq!(sec1, sec1_rt);
    }

    #[test]
    fn sec1_to_pal_rejects_missing_tag() {
        let mut sec1 = sample_sec1();
        sec1[0] = 0x02;
        let mut le = [0u8; 2 * P384_COORD];
        assert!(matches!(
            sec1_be_to_pal_le(&sec1, &mut le, P384_COORD),
            Err(HsmError::InvalidArg),
        ));
    }

    #[test]
    fn sec1_to_pal_rejects_short_input() {
        let short = [0x04u8; 1 + 2 * P384_COORD - 1];
        let mut le = [0u8; 2 * P384_COORD];
        assert!(matches!(
            sec1_be_to_pal_le(&short, &mut le, P384_COORD),
            Err(HsmError::InvalidArg),
        ));
    }

    #[test]
    fn sec1_to_pal_rejects_long_input() {
        let long = [0x04u8; 1 + 2 * P384_COORD + 1];
        let mut le = [0u8; 2 * P384_COORD];
        assert!(matches!(
            sec1_be_to_pal_le(&long, &mut le, P384_COORD),
            Err(HsmError::InvalidArg),
        ));
    }

    #[test]
    fn pal_to_sec1_rejects_wrong_length() {
        let bad_le = [0u8; 2 * P384_COORD + 1];
        let mut sec1 = [0u8; 1 + 2 * P384_COORD];
        assert!(matches!(
            pal_le_to_sec1_be(&bad_le, &mut sec1, P384_COORD),
            Err(HsmError::InvalidArg),
        ));
    }

    /// Hand-checked small fixture: `coord_len = 4`, simple ascending bytes.
    /// Verifies the BE↔LE math byte-for-byte without relying on a round-trip.
    #[test]
    fn sec1_to_pal_known_vector() {
        // X_be = [0x01, 0x02, 0x03, 0x04], Y_be = [0x05, 0x06, 0x07, 0x08]
        let sec1: [u8; 9] = [0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut le = [0u8; 8];
        sec1_be_to_pal_le(&sec1, &mut le, 4).unwrap();
        assert_eq!(le, [0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05]);
    }
}
