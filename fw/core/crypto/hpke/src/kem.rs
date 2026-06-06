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
    let npk = suite.npk();
    let ndh = suite.ndh();

    // Query-alloc-use ECC keygen.  Both lengths are deterministic
    // per-curve: `priv_size` is the raw HSM scalar length; `pub_size`
    // equals the wire-format public-key length (== npk).
    let (priv_size, pub_size) = pal
        .ecc_gen_keypair(io, alloc, curve, None, HsmEccPct::None)
        .await?;
    let sk_e = alloc_bytes(priv_size, alloc)?;
    let pk_e = alloc_bytes(pub_size, alloc)?;
    let (sk_len, pk_len) = pal
        .ecc_gen_keypair(
            io,
            alloc,
            curve,
            Some((&mut *sk_e, &mut *pk_e)),
            HsmEccPct::None,
        )
        .await?;
    // Validate the PAL honored the query-alloc-use contract (pk_len
    // must equal npk for the wire format) and the caller's `enc`
    // buffer is large enough — fail fast before doing the ECDH so we
    // don't burn an ephemeral keypair on a request we can't complete.
    if pk_len != npk || enc.len() < npk {
        return Err(HsmError::InvalidArg);
    }

    let dh = alloc_bytes(ndh, alloc)?;
    let pk_r_dma = dma_copy_in(alloc, pk_r)?;
    pal.ecdh_derive(io, curve, &sk_e[..sk_len], pk_r_dma, dh)
        .await?;

    enc[..npk].copy_from_slice(&pk_e[..npk]);

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
    let npk = suite.npk();
    let ndh = suite.ndh();

    let pk_e = &enc[..npk];

    let dh = alloc_bytes(ndh, alloc)?;
    let sk_r_dma = dma_copy_in(alloc, sk_r)?;
    let pk_e_dma = dma_copy_in(alloc, pk_e)?;
    pal.ecdh_derive(io, curve, sk_r_dma, pk_e_dma, dh).await?;

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
    let npk = suite.npk();
    let ndh = suite.ndh();

    // Query-alloc-use ECC keygen — same flow as `encap`.
    let (priv_size, pub_size) = pal
        .ecc_gen_keypair(io, alloc, curve, None, HsmEccPct::None)
        .await?;
    let sk_e = alloc_bytes(priv_size, alloc)?;
    let pk_e = alloc_bytes(pub_size, alloc)?;
    let (sk_len, pk_len) = pal
        .ecc_gen_keypair(
            io,
            alloc,
            curve,
            Some((&mut *sk_e, &mut *pk_e)),
            HsmEccPct::None,
        )
        .await?;
    // Same fail-fast as `encap` — validate before any ECDH work.
    if pk_len != npk || enc.len() < npk {
        return Err(HsmError::InvalidArg);
    }

    let dh = alloc_bytes(ndh * 2, alloc)?;
    let pk_r_dma = dma_copy_in(alloc, pk_r)?;
    let sk_s_dma = dma_copy_in(alloc, sk_s)?;
    pal.ecdh_derive(io, curve, &sk_e[..sk_len], pk_r_dma, &mut dh[..ndh])
        .await?;
    pal.ecdh_derive(io, curve, sk_s_dma, pk_r_dma, &mut dh[ndh..])
        .await?;

    enc[..npk].copy_from_slice(&pk_e[..npk]);

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
    let npk = suite.npk();
    let ndh = suite.ndh();

    let pk_e = &enc[..npk];

    let dh = alloc_bytes(ndh * 2, alloc)?;
    let sk_r_dma = dma_copy_in(alloc, sk_r)?;
    let pk_e_dma = dma_copy_in(alloc, pk_e)?;
    let pk_s_dma = dma_copy_in(alloc, pk_s)?;
    pal.ecdh_derive(io, curve, sk_r_dma, pk_e_dma, &mut dh[..ndh])
        .await?;
    pal.ecdh_derive(io, curve, sk_r_dma, pk_s_dma, &mut dh[ndh..])
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
