// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE single-shot seal / open / export operations (RFC 9180 §6).
//!
//! All four HPKE modes (Base / PSK / Auth / AuthPSK) reduce to the
//! same three steps:
//!
//! 1. **KEM** — encapsulate or decapsulate a `Nsecret`-byte shared
//!    secret using the recipient's public key (and the sender's own
//!    keypair for Auth modes).
//! 2. **Key schedule** — derive an AEAD `key` and a `base_nonce` from
//!    the shared secret, the application info, and the optional PSK
//!    (RFC 9180 §5.1).
//! 3. **AEAD** — seal or open with `key`/`base_nonce` against the
//!    caller-supplied AAD and plaintext/ciphertext.
//!
//! [`seal`] and [`open`] perform the full pipeline under a single
//! caller-provided [`HsmScopedAlloc`]. The eight thin wrappers
//! ([`seal_base`], [`open_psk`], …) match the trait-level naming
//! convention of the HSM core and select the right [`Mode`] /
//! [`AuthInputs`] / [`PskInputs`] arguments.
//!
//! ## Buffer layout invariants
//!
//! Each helper allocates only the intermediates it needs from `alloc`:
//! a KEM shared secret, then AEAD key + base nonce, then any
//! key-schedule / KDF formatting buffers. The scoped allocator frees the
//! whole tree when the public call returns.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::aead;
use crate::kdf;
use crate::kem;
use crate::schedule;
use crate::suite::HpkeSuite;

// =============================================================================
// HPKE mode (RFC 9180 §5.1 Table 1)
// =============================================================================

/// HPKE operating mode (RFC 9180 §5.1 Table 1).
///
/// Encoded as a single byte at byte 0 of the key-schedule context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Mode {
    Base = 0x00,
    Psk = 0x01,
    Auth = 0x02,
    AuthPsk = 0x03,
}

// =============================================================================
// Request / parameter structs
// =============================================================================

/// Common parameters for an HPKE seal (encrypt) operation.
#[derive(Debug)]
pub struct SealRequest<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient public key (`Npk` bytes).
    pub pk_r: &'a [u8],
    /// Application-supplied info (may be empty).
    pub info: &'a [u8],
    /// Additional authenticated data (may be empty).
    pub aad: &'a [u8],
    /// Plaintext to encrypt.
    pub pt: &'a [u8],
    /// Output: encapsulated key (`Nenc` bytes).
    pub enc: &'a mut [u8],
    /// Output: ciphertext.
    pub ct: &'a mut [u8],
}

/// Common parameters for an HPKE open (decrypt) operation.
#[derive(Debug)]
pub struct OpenRequest<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient private key (`Nsk` bytes).
    pub sk_r: &'a [u8],
    /// Recipient public key (`Npk` bytes).
    pub pk_r: &'a [u8],
    /// Encapsulated key from the sender (`Nenc` bytes).
    pub enc: &'a [u8],
    /// Application-supplied info — must equal the sender's value.
    pub info: &'a [u8],
    /// Additional authenticated data — must equal the sender's value.
    pub aad: &'a [u8],
    /// Ciphertext to decrypt.
    pub ct: &'a [u8],
    /// Output: recovered plaintext.
    pub pt: &'a mut [u8],
}

/// Pre-shared key parameters for [`seal_psk`] / [`open_psk`] and
/// [`seal_auth_psk`] / [`open_auth_psk`].
#[derive(Debug)]
pub struct PskParams<'a> {
    /// Pre-shared key (≥ 32 bytes of entropy recommended by RFC 9180).
    pub psk: &'a [u8],
    /// PSK identifier.
    pub psk_id: &'a [u8],
}

/// Sender authentication parameters for [`seal_auth`] /
/// [`seal_auth_psk`] (sender side only — the recipient passes
/// `auth_pk_s` directly to [`open_auth`] / [`open_auth_psk`]).
#[derive(Debug)]
pub struct AuthParams<'a> {
    /// Sender private key.
    pub sk_s: &'a [u8],
    /// Sender public key.
    pub pk_s: &'a [u8],
}

// =============================================================================
// Internal driver
// =============================================================================

/// PSK inputs threaded into [`Mode::Psk`] / [`Mode::AuthPsk`] calls.
/// Equivalent to a flattened `Option<PskParams>` (empty slices mean
/// "no PSK").
#[derive(Default, Clone, Copy)]
struct PskInputs<'a> {
    psk: &'a [u8],
    psk_id: &'a [u8],
}

impl<'a> From<Option<&'a PskParams<'a>>> for PskInputs<'a> {
    fn from(p: Option<&'a PskParams<'a>>) -> Self {
        match p {
            Some(p) => Self {
                psk: p.psk,
                psk_id: p.psk_id,
            },
            None => Self::default(),
        }
    }
}

/// Sender-authentication inputs threaded into [`Mode::Auth`] /
/// [`Mode::AuthPsk`] encap calls.
#[derive(Clone, Copy)]
struct AuthInputs<'a> {
    sk_s: &'a [u8],
    pk_s: &'a [u8],
}

fn alloc_bytes(len: usize, alloc: &impl HsmScopedAlloc) -> HsmResult<&mut DmaBuf> {
    alloc.dma_alloc(len)
}

/// Run the key schedule on `ss`, then AEAD-seal `pt → ct`.
async fn seal_finish<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    mode: Mode,
    ss: &mut [u8],
    info: &[u8],
    psk: PskInputs<'_>,
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let key = alloc_bytes(suite.nk(), alloc)?;
    let nonce = alloc_bytes(suite.nn(), alloc)?;
    schedule::key_schedule(
        pal, io, suite, mode as u8, ss, info, psk.psk, psk.psk_id, key, nonce, alloc,
    )
    .await?;
    aead::seal(pal, io, suite, key, nonce, aad, pt, ct, alloc).await
}

/// Run the key schedule on `ss`, then AEAD-open `ct → pt`.
async fn open_finish<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    mode: Mode,
    ss: &mut [u8],
    info: &[u8],
    psk: PskInputs<'_>,
    aad: &[u8],
    ct: &[u8],
    pt: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let key = alloc_bytes(suite.nk(), alloc)?;
    let nonce = alloc_bytes(suite.nn(), alloc)?;
    schedule::key_schedule(
        pal, io, suite, mode as u8, ss, info, psk.psk, psk.psk_id, key, nonce, alloc,
    )
    .await?;
    aead::open(pal, io, suite, key, nonce, aad, ct, pt, alloc).await
}

/// Unified seal driver used by every mode-specific wrapper.
///
/// Allocates the `Nsecret`-byte KEM shared secret from `alloc`, runs
/// encapsulation to populate it, then passes it to [`seal_finish`].
async fn seal<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut SealRequest<'_>,
    mode: Mode,
    auth: Option<&AuthInputs<'_>>,
    psk: PskInputs<'_>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let ss = alloc_bytes(req.suite.nsecret(), alloc)?;
    match auth {
        None => kem::encap(pal, io, req.suite, req.pk_r, req.enc, ss, alloc).await?,
        Some(a) => {
            kem::auth_encap(
                pal, io, req.suite, req.pk_r, a.sk_s, a.pk_s, req.enc, ss, alloc,
            )
            .await?;
        }
    }
    seal_finish(
        pal, io, req.suite, mode, ss, req.info, psk, req.aad, req.pt, req.ct, alloc,
    )
    .await
}

/// Unified open driver used by every mode-specific wrapper.
async fn open<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut OpenRequest<'_>,
    mode: Mode,
    auth_pk_s: Option<&[u8]>,
    psk: PskInputs<'_>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let ss = alloc_bytes(req.suite.nsecret(), alloc)?;
    match auth_pk_s {
        None => kem::decap(pal, io, req.suite, req.enc, req.sk_r, req.pk_r, ss, alloc).await?,
        Some(pk_s) => {
            kem::auth_decap(
                pal, io, req.suite, req.enc, req.sk_r, req.pk_r, pk_s, ss, alloc,
            )
            .await?;
        }
    }
    open_finish(
        pal, io, req.suite, mode, ss, req.info, psk, req.aad, req.ct, req.pt, alloc,
    )
    .await
}

// =============================================================================
// Mode-specific public entry points
// =============================================================================

/// HPKE Base-mode seal: encrypt to the recipient's public key.
///
/// # Type parameters
///
/// * `P` — any [`HsmCrypto`] PAL implementation.
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `req` — input/output buffers; see [`SealRequest`].
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// * `Ok(ct_len)` — ciphertext bytes written to `req.ct`.
/// * `Err(HsmError::InvalidArg)` — buffer-size violation.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the KEM, key schedule, or
///   AEAD step.
pub async fn seal_base<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut SealRequest<'_>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    seal(pal, io, req, Mode::Base, None, PskInputs::default(), alloc).await
}

/// HPKE Base-mode open: decrypt with the recipient's private key.
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `req` — input/output buffers; see [`OpenRequest`].
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// * `Ok(pt_len)` — plaintext bytes written to `req.pt`.
/// * `Err(HsmError::InvalidArg)` — buffer-size violation.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError::AesGcmDecryptTagDoesNotMatch)` — AEAD tag
///   mismatch (GCM suites).
/// * `Err(HsmError::AesDecryptFailed)` — AEAD tag mismatch (CBC
///   suites).
/// * `Err(HsmError)` — propagated from the KEM, key schedule, or
///   AEAD step.
pub async fn open_base<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut OpenRequest<'_>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    open(pal, io, req, Mode::Base, None, PskInputs::default(), alloc).await
}

/// HPKE PSK-mode seal: encrypt with PSK authentication.
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `req` — input/output buffers.
/// * `psk` — pre-shared key + identifier.
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// Same shape as [`seal_base`].
pub async fn seal_psk<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut SealRequest<'_>,
    psk: &PskParams<'_>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    seal(pal, io, req, Mode::Psk, None, Some(psk).into(), alloc).await
}

/// HPKE PSK-mode open: decrypt with PSK authentication.
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `req` — input/output buffers.
/// * `psk` — pre-shared key + identifier; must equal the sender's.
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// Same shape as [`open_base`].
pub async fn open_psk<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut OpenRequest<'_>,
    psk: &PskParams<'_>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    open(pal, io, req, Mode::Psk, None, Some(psk).into(), alloc).await
}

/// HPKE Auth-mode seal: encrypt with sender-key authentication.
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `req` — input/output buffers.
/// * `auth` — sender keypair used to authenticate the
///   encapsulation.
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// Same shape as [`seal_base`].
pub async fn seal_auth<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut SealRequest<'_>,
    auth: &AuthParams<'_>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let auth_inputs = AuthInputs {
        sk_s: auth.sk_s,
        pk_s: auth.pk_s,
    };
    seal(
        pal,
        io,
        req,
        Mode::Auth,
        Some(&auth_inputs),
        PskInputs::default(),
        alloc,
    )
    .await
}

/// HPKE Auth-mode open: decrypt with sender-key authentication.
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `req` — input/output buffers.
/// * `auth_pk_s` — sender's public key (used to verify the
///   authenticated encapsulation).
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// Same shape as [`open_base`].
pub async fn open_auth<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut OpenRequest<'_>,
    auth_pk_s: &[u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    open(
        pal,
        io,
        req,
        Mode::Auth,
        Some(auth_pk_s),
        PskInputs::default(),
        alloc,
    )
    .await
}

/// HPKE AuthPSK-mode seal: encrypt with both sender-key and PSK
/// authentication.
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `req` — input/output buffers.
/// * `auth` — sender keypair.
/// * `psk` — pre-shared key + identifier.
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// Same shape as [`seal_base`].
pub async fn seal_auth_psk<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut SealRequest<'_>,
    auth: &AuthParams<'_>,
    psk: &PskParams<'_>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let auth_inputs = AuthInputs {
        sk_s: auth.sk_s,
        pk_s: auth.pk_s,
    };
    seal(
        pal,
        io,
        req,
        Mode::AuthPsk,
        Some(&auth_inputs),
        Some(psk).into(),
        alloc,
    )
    .await
}

/// HPKE AuthPSK-mode open: decrypt with both sender-key and PSK
/// authentication.
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `req` — input/output buffers.
/// * `auth_pk_s` — sender's public key.
/// * `psk` — pre-shared key + identifier; must equal the sender's.
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// Same shape as [`open_base`].
pub async fn open_auth_psk<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    req: &mut OpenRequest<'_>,
    auth_pk_s: &[u8],
    psk: &PskParams<'_>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    open(
        pal,
        io,
        req,
        Mode::AuthPsk,
        Some(auth_pk_s),
        Some(psk).into(),
        alloc,
    )
    .await
}

// =============================================================================
// Export operations (Base mode only)
// =============================================================================

/// Sender-side derivation of an HPKE export key (Base mode).
///
/// Performs encap + the Base-mode key-schedule export step, then
/// `LabeledExpand`s the exporter secret with `exporter_context` to
/// produce `exported.len()` derived bytes.
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `pk_r` — recipient public key.
/// * `info` — application-supplied info; must equal the
///   receiver's.
/// * `exporter_context` — context bytes mixed into the final
///   export; must equal the receiver's.
/// * `enc` — output: encapsulated key (`Nenc` bytes).
/// * `exported` — output: derived key bytes.
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// * `Ok(())` — `enc` and `exported` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the KEM, key schedule, or
///   HKDF.
pub async fn send_export_base<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    pk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    enc: &mut [u8],
    exported: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let ss = alloc_bytes(suite.nsecret(), alloc)?;
    kem::encap(pal, io, suite, pk_r, enc, ss, alloc).await?;
    export_finish(pal, io, suite, ss, info, exporter_context, exported, alloc).await
}

/// Receiver-side derivation of an HPKE export key (Base mode).
///
/// # Parameters
///
/// * `pal` — PAL providing all crypto primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `sk_r` — recipient private key.
/// * `pk_r` — recipient public key.
/// * `enc` — encapsulated key from sender.
/// * `info` — application-supplied info; must equal the sender's.
/// * `exporter_context` — context bytes mixed into the final
///   export; must equal the sender's.
/// * `exported` — output: derived key bytes.
/// * `alloc` — scoped allocator owning every HPKE intermediate.
///
/// # Returns
///
/// * `Ok(())` — `exported` populated.
/// * `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
/// * `Err(HsmError)` — propagated from the KEM, key schedule, or
///   HKDF.
pub async fn receive_export_base<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    sk_r: &[u8],
    pk_r: &[u8],
    enc: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    exported: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let ss = alloc_bytes(suite.nsecret(), alloc)?;
    kem::decap(pal, io, suite, enc, sk_r, pk_r, ss, alloc).await?;
    export_finish(pal, io, suite, ss, info, exporter_context, exported, alloc).await
}

/// Run the Base-mode export key schedule, then expand the exporter
/// secret with `exporter_context`. Shared by [`send_export_base`] and
/// [`receive_export_base`].
async fn export_finish<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    ss: &mut [u8],
    info: &[u8],
    exporter_context: &[u8],
    exported: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let exp_secret = alloc_bytes(suite.nh(), alloc)?;
    schedule::key_schedule_export(
        pal,
        io,
        suite,
        Mode::Base as u8,
        ss,
        info,
        &[],
        &[],
        exp_secret,
        alloc,
    )
    .await?;
    kdf::labeled_expand(
        pal,
        io,
        suite.kdf_hash(),
        &suite.hpke_suite_id(),
        exp_secret,
        b"sec",
        exporter_context,
        exported,
        alloc,
    )
    .await
}
