// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE key schedule (RFC 9180 §5.1).
//!
//! Both [`key_schedule`] and [`key_schedule_export`] start by deriving
//! `secret`, the `key_schedule_context` (`KSC`), and the per-suite
//! `hpke_suite_id` from the shared inputs. They then diverge:
//!
//! * [`key_schedule`] expands `secret` into the AEAD `key` and
//!   `base_nonce`.
//! * [`key_schedule_export`] expands `secret` into the export
//!   `exporter_secret`.
//!
//! The shared prefix lives in [`derive_secret_and_ksc`] so the two
//! public entry points stay short and the slice arithmetic does not
//! get duplicated.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::kdf;
use crate::suite::HpkeSuite;

// =============================================================================
// Shared key-schedule prefix
// =============================================================================

/// Outputs of [`derive_secret_and_ksc`] borrowed from the scoped allocator.
struct ScheduleState<'a> {
    /// Hash algorithm used by HKDF.
    algo: HsmHashAlgo,
    /// Cached HPKE suite identifier.
    suite_id: [u8; 10],
    /// `secret = LabeledExtract(shared_secret, "secret", psk)` (`Nh` bytes).
    secret: &'a DmaBuf,
    /// `key_schedule_context = mode || psk_id_hash || info_hash`
    /// (`1 + 2*Nh` bytes).
    ksc: &'a DmaBuf,
}

fn alloc_bytes(len: usize, alloc: &impl HsmScopedAlloc) -> HsmResult<&mut DmaBuf> {
    alloc.dma_alloc(len)
}

/// Compute the shared `(secret, ksc)` pair used by every HPKE key
/// schedule (export and AEAD).
///
/// Allocates `psk_id_hash`, `info_hash`, `ksc`, and `secret` from
/// `alloc` and returns the shared `secret` / `ksc` pair used by
/// both key-schedule entry points.
///
/// # Parameters
///
/// * `pal` — PAL providing HKDF / HMAC.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `mode` — RFC 9180 §5.1 mode byte (Base, PSK, Auth, AuthPSK).
/// * `shared_secret` — KEM output (`Nsecret` bytes).
/// * `info` — application-supplied info (may be empty).
/// * `psk` — pre-shared key (empty for non-PSK modes).
/// * `psk_id` — PSK identifier (empty for non-PSK modes).
/// * `alloc` — scoped allocator used for the intermediate buffers
///   and internal HKDF / HMAC state.
///
/// # Returns
///
/// * `Ok(state)` — [`ScheduleState`] borrowing slices from `alloc`.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the HKDF Extract calls.
async fn derive_secret_and_ksc<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &DmaBuf,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<ScheduleState<'a>>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let algo = suite.kdf_hash();
    let nh = suite.nh();
    let suite_id = suite.hpke_suite_id();

    // `key_schedule_context = mode ‖ psk_id_hash ‖ info_hash`.  Allocate
    // it up front and write the two hashes straight into their slots —
    // no separate hash buffers, no copy into the KSC.
    let ksc = alloc_bytes(1 + 2 * nh, alloc)?;
    ksc[0] = mode;
    {
        let slot = &mut ksc[1..1 + nh];
        kdf::labeled_extract(
            pal,
            io,
            algo,
            &suite_id,
            None,
            b"psk_id_hash",
            psk_id,
            slot,
            alloc,
        )
        .await?;
    }
    {
        let slot = &mut ksc[1 + nh..1 + 2 * nh];
        kdf::labeled_extract(
            pal,
            io,
            algo,
            &suite_id,
            None,
            b"info_hash",
            info,
            slot,
            alloc,
        )
        .await?;
    }

    let secret = alloc_bytes(nh, alloc)?;
    kdf::labeled_extract(
        pal,
        io,
        algo,
        &suite_id,
        Some(shared_secret),
        b"secret",
        psk,
        secret,
        alloc,
    )
    .await?;

    Ok(ScheduleState {
        algo,
        suite_id,
        secret: &*secret,
        ksc: &*ksc,
    })
}

// =============================================================================
// Public entry points
// =============================================================================

/// Derive the AEAD `key` and `base_nonce` from `shared_secret +
/// info`.
///
/// Implements the RFC 9180 §5.1 KeySchedule for all four modes —
/// the `mode` / `psk` / `psk_id` parameters select Base, PSK, Auth,
/// or AuthPSK.  For Base / Auth modes pass empty `psk` / `psk_id`.
///
/// # Type parameters
///
/// * `P` — any [`HsmCrypto`] PAL implementation.
///
/// # Parameters
///
/// * `pal` — PAL providing HKDF / HMAC.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `mode` — RFC 9180 §5.1 mode byte (`0x00..=0x03`).
/// * `shared_secret` — KEM output (`Nsecret` bytes).
/// * `info` — application-supplied info.
/// * `psk` — pre-shared key (empty for Base / Auth modes).
/// * `psk_id` — PSK identifier (empty for Base / Auth modes).
/// * `key` — output: AEAD key (`Nk` bytes).
/// * `base_nonce` — output: AEAD base nonce (`Nn` bytes).
/// * `alloc` — scoped allocator used for intermediate buffers and
///   the internal HKDF / HMAC state.
///
/// # Returns
///
/// * `Ok(())` — `key` and `base_nonce` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the HKDF Extract / Expand
///   calls.
pub async fn key_schedule<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &DmaBuf,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    key: &mut DmaBuf,
    base_nonce: &mut DmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let st = derive_secret_and_ksc(
        pal,
        io,
        suite,
        mode,
        shared_secret,
        info,
        psk,
        psk_id,
        alloc,
    )
    .await?;

    // key = LabeledExpand(secret, "key", ksc, Nk)
    kdf::labeled_expand(
        pal,
        io,
        st.algo,
        &st.suite_id,
        st.secret,
        b"key",
        st.ksc,
        key,
        alloc,
    )
    .await?;

    // base_nonce = LabeledExpand(secret, "base_nonce", ksc, Nn)
    kdf::labeled_expand(
        pal,
        io,
        st.algo,
        &st.suite_id,
        st.secret,
        b"base_nonce",
        st.ksc,
        base_nonce,
        alloc,
    )
    .await
}

/// Derive an `exporter_secret` from `shared_secret + info`.
///
/// Same algorithm as [`key_schedule`] but stops after the secret /
/// KSC step and emits a single `LabeledExpand` for the export
/// secret.
///
/// # Parameters
///
/// Same as [`key_schedule`] except `exporter_secret` replaces
/// `key` / `base_nonce` and is `Nh` bytes.  `alloc` provides the
/// intermediate buffers and internal HKDF / HMAC state.
///
/// # Returns
///
/// * `Ok(())` — `exporter_secret` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the HKDF Extract / Expand
///   calls.
pub async fn key_schedule_export<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &DmaBuf,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    exporter_secret: &mut DmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let st = derive_secret_and_ksc(
        pal,
        io,
        suite,
        mode,
        shared_secret,
        info,
        psk,
        psk_id,
        alloc,
    )
    .await?;

    kdf::labeled_expand(
        pal,
        io,
        st.algo,
        &st.suite_id,
        st.secret,
        b"exp",
        st.ksc,
        exporter_secret,
        alloc,
    )
    .await
}
