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
/// All inputs are SEC1 uncompressed (`0x04 ‖ X ‖ Y`, big-endian) per
/// RFC 9180 §7.1.1.
///
/// # Parameters
/// * `dst` — destination buffer of `npk * (2 + auth as usize)` bytes.
/// * `enc` — serialised ephemeral / received public key (`Npk` bytes).
/// * `pk_r` — recipient public key (`Npk` bytes).
/// * `pk_s` — sender public key for Auth modes (`Npk` bytes), `None`
///   for Base modes.
fn build_kem_context(dst: &mut [u8], enc: &[u8], pk_r: &[u8], pk_s: Option<&[u8]>) {
    let npk = pk_r.len();
    dst[..npk].copy_from_slice(enc);
    dst[npk..2 * npk].copy_from_slice(pk_r);
    if let Some(pk_s) = pk_s {
        dst[2 * npk..3 * npk].copy_from_slice(pk_s);
    }
}

fn alloc_bytes(len: usize, alloc: &impl HsmScopedAlloc) -> HsmResult<&mut DmaBuf> {
    alloc.dma_alloc(len)
}

// =============================================================================
// Wire ↔ PAL coordinate conversion
// =============================================================================
//
// HPKE on the wire (and inside `kem_context`) uses SEC1 uncompressed
// `0x04 ‖ X_be ‖ Y_be` per RFC 9180 §7.1.1. The HSM PAL, by contrast,
// passes raw `X_le ‖ Y_le` (no prefix) to / from
// [`HsmCrypto::ecc_gen_keypair`] / [`HsmCrypto::ecdh_derive`]. These
// helpers are the only place the two encodings touch each other; all
// public entry points below take and return wire-format bytes.

/// Convert a SEC1 wire-format public key into the PAL's
/// `X_le ‖ Y_le` layout.
///
/// `wire.len() == 1 + 2 * nsk` (SEC1 with 0x04 prefix).
/// `pal.len()  == 2 * nsk` (raw, LE).
///
/// Returns `Err(HsmError::InvalidArg)` if the wire prefix is not 0x04
/// or the lengths don't match.
fn wire_to_pal(wire: &[u8], pal: &mut [u8], nsk: usize) -> HsmResult<()> {
    if wire.len() != 1 + 2 * nsk || pal.len() != 2 * nsk {
        return Err(HsmError::InvalidArg);
    }
    if wire[0] != 0x04 {
        return Err(HsmError::InvalidArg);
    }
    pal[..nsk].copy_from_slice(&wire[1..1 + nsk]);
    pal[..nsk].reverse();
    pal[nsk..].copy_from_slice(&wire[1 + nsk..1 + 2 * nsk]);
    pal[nsk..].reverse();
    Ok(())
}

/// Convert a PAL-format public key (`X_le ‖ Y_le`) into the SEC1
/// uncompressed wire layout (`0x04 ‖ X_be ‖ Y_be`).
fn pal_to_wire(pal: &[u8], wire: &mut [u8], nsk: usize) -> HsmResult<()> {
    if wire.len() != 1 + 2 * nsk || pal.len() != 2 * nsk {
        return Err(HsmError::InvalidArg);
    }
    wire[0] = 0x04;
    wire[1..1 + nsk].copy_from_slice(&pal[..nsk]);
    wire[1..1 + nsk].reverse();
    wire[1 + nsk..1 + 2 * nsk].copy_from_slice(&pal[nsk..2 * nsk]);
    wire[1 + nsk..1 + 2 * nsk].reverse();
    Ok(())
}

/// Allocate a PAL-format scratch buffer and populate it from a
/// wire-format pk. Returns the borrowed scratch buffer.
fn pk_wire_to_pal_dma<'a>(
    wire: &[u8],
    nsk: usize,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<&'a mut DmaBuf> {
    let pal = alloc_bytes(2 * nsk, alloc)?;
    wire_to_pal(wire, pal, nsk)?;
    Ok(pal)
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
    let nsk = suite.nsk();
    let npk = suite.npk();
    let npk_pal = suite.npk_pal();
    let ndh = suite.ndh();

    // PAL impls may return the private key as raw scalar bytes
    // (`nsk`) *or* as a PKCS#8 DER blob (up to `priv_key_der_max`),
    // depending on whether they're hardware-backed or std/OpenSSL.
    // Use the larger upper bound so both shapes fit.
    let keygen_buf = alloc_bytes(curve.priv_key_der_max() + npk_pal, alloc)?;
    let (sk_e, pk_e) = pal
        .ecc_gen_keypair(io, curve, keygen_buf, HsmEccPct::None)
        .await?;

    let dh = alloc_bytes(ndh, alloc)?;
    let pk_r_pal = pk_wire_to_pal_dma(pk_r, nsk, alloc)?;
    pal.ecdh_derive(io, curve, sk_e, pk_r_pal, dh).await?;

    pal_to_wire(pk_e, &mut enc[..npk], nsk)?;

    let kem_context = alloc_bytes(npk * 2, alloc)?;
    build_kem_context(kem_context, &enc[..npk], pk_r, None);

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
    let nsk = suite.nsk();
    let npk = suite.npk();
    let ndh = suite.ndh();

    let dh = alloc_bytes(ndh, alloc)?;
    let sk_r_dma = dma_copy_in(alloc, sk_r)?;
    let pk_e_pal = pk_wire_to_pal_dma(&enc[..npk], nsk, alloc)?;
    pal.ecdh_derive(io, curve, sk_r_dma, pk_e_pal, dh).await?;

    let kem_context = alloc_bytes(npk * 2, alloc)?;
    build_kem_context(kem_context, &enc[..npk], pk_r, None);

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
    let nsk = suite.nsk();
    let npk = suite.npk();
    let npk_pal = suite.npk_pal();
    let ndh = suite.ndh();

    // See `encap` for buffer-sizing rationale.
    let keygen_buf = alloc_bytes(curve.priv_key_der_max() + npk_pal, alloc)?;
    let (sk_e, pk_e) = pal
        .ecc_gen_keypair(io, curve, keygen_buf, HsmEccPct::None)
        .await?;

    let dh = alloc_bytes(ndh * 2, alloc)?;
    let pk_r_pal = pk_wire_to_pal_dma(pk_r, nsk, alloc)?;
    let sk_s_dma = dma_copy_in(alloc, sk_s)?;
    pal.ecdh_derive(io, curve, sk_e, pk_r_pal, &mut dh[..ndh])
        .await?;
    pal.ecdh_derive(io, curve, sk_s_dma, pk_r_pal, &mut dh[ndh..])
        .await?;

    pal_to_wire(pk_e, &mut enc[..npk], nsk)?;

    let kem_context = alloc_bytes(npk * 3, alloc)?;
    build_kem_context(kem_context, &enc[..npk], pk_r, Some(pk_s));

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
    let nsk = suite.nsk();
    let npk = suite.npk();
    let ndh = suite.ndh();

    let dh = alloc_bytes(ndh * 2, alloc)?;
    let sk_r_dma = dma_copy_in(alloc, sk_r)?;
    let pk_e_pal = pk_wire_to_pal_dma(&enc[..npk], nsk, alloc)?;
    let pk_s_pal = pk_wire_to_pal_dma(pk_s, nsk, alloc)?;
    pal.ecdh_derive(io, curve, sk_r_dma, pk_e_pal, &mut dh[..ndh])
        .await?;
    pal.ecdh_derive(io, curve, sk_r_dma, pk_s_pal, &mut dh[ndh..])
        .await?;

    let kem_context = alloc_bytes(npk * 3, alloc)?;
    build_kem_context(kem_context, &enc[..npk], pk_r, Some(pk_s));

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
