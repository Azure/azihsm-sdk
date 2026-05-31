// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE single-shot seal / open / export operations (RFC 9180 §6).
//!
//! Each of the four operations ([`seal`], [`open`], [`send_export`],
//! [`receive_export`]) takes a per-operation configuration struct that
//! carries the ciphersuite, the static inputs (`info`, `aad`, keys),
//! and the HPKE mode. The mode is selected at construction time via
//! `Config::base / psk / auth / auth_psk` (mirrors the host
//! `azihsm_crypto::hpke` API).
//!
//! Outputs are passed as `Option<&mut [u8]>` slices following the
//! `EccKeyOp::coord` pattern: passing `None` for the output slice
//! returns a [`SealSizes`] / [`ExportSizes`] sizing structure without
//! writing anything. Passing `Some(_)` writes the operation's outputs
//! and returns the actual byte counts.
//!
//! ## Symbol parity with host
//!
//! Symbol names match the host `azihsm_crypto` HPKE module exactly so
//! that callers reading host code can read firmware code by adding
//! `pal`/`io`/`alloc` parameters and `.await`. The only host-only
//! symbols are the `_vec` convenience wrappers, which are not exposed
//! on the firmware side because the crate is `#![no_std]`.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::aead;
use crate::kdf;
use crate::kem;
use crate::schedule;
use crate::suite::HpkeSuite;

// =============================================================================
// Mode + auxiliary input structs
// =============================================================================

/// HPKE operating mode (RFC 9180 §5.1 Table 1). Encoded as the first
/// byte of the key-schedule context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Mode {
    Base = 0x00,
    Psk = 0x01,
    Auth = 0x02,
    AuthPsk = 0x03,
}

/// Pre-shared key parameters for `Config::psk` / `Config::auth_psk`.
#[derive(Debug, Clone, Copy)]
pub struct PskParams<'a> {
    /// Pre-shared key (≥ 32 bytes of entropy recommended by RFC 9180).
    pub psk: &'a [u8],
    /// PSK identifier.
    pub psk_id: &'a [u8],
}

/// Sender-authentication parameters for `Config::auth` /
/// `Config::auth_psk`. The receiver-side configs take `auth_pk_s`
/// directly.
#[derive(Debug, Clone, Copy)]
pub struct AuthParams<'a> {
    /// Sender private key.
    pub sk_s: &'a [u8],
    /// Sender public key.
    pub pk_s: &'a [u8],
}

// =============================================================================
// Output size types
// =============================================================================

/// Returned by [`seal`] — number of bytes written to (or required for)
/// each output buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealSizes {
    /// Encapsulated-key buffer size in bytes.
    pub enc_len: usize,
    /// Ciphertext (AEAD output) buffer size in bytes.
    pub ct_len: usize,
}

/// Returned by [`send_export`] — number of bytes written to (or
/// required for) each output buffer. `exported_len` is caller-chosen
/// (it equals the caller's `exported_out.len()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportSizes {
    /// Encapsulated-key buffer size in bytes.
    pub enc_len: usize,
    /// Exported-bytes buffer size (caller-supplied `L`).
    pub exported_len: usize,
}

// =============================================================================
// Config: HpkeSealConfig
// =============================================================================

/// Configuration for an HPKE seal operation.
#[derive(Debug, Clone, Copy)]
pub struct HpkeSealConfig<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient public key.
    pub pk_r: &'a [u8],
    /// Application-supplied info (may be empty).
    pub info: &'a [u8],
    /// Additional authenticated data (may be empty).
    pub aad: &'a [u8],
    pub(crate) mode: Mode,
    pub(crate) auth: Option<AuthParams<'a>>,
    pub(crate) psk: Option<PskParams<'a>>,
}

impl<'a> HpkeSealConfig<'a> {
    /// Base mode.
    pub fn base(suite: HpkeSuite, pk_r: &'a [u8], info: &'a [u8], aad: &'a [u8]) -> Self {
        Self {
            suite,
            pk_r,
            info,
            aad,
            mode: Mode::Base,
            auth: None,
            psk: None,
        }
    }
    /// PSK mode.
    pub fn psk(
        suite: HpkeSuite,
        pk_r: &'a [u8],
        info: &'a [u8],
        aad: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r,
            info,
            aad,
            mode: Mode::Psk,
            auth: None,
            psk: Some(psk),
        }
    }
    /// Auth mode.
    pub fn auth(
        suite: HpkeSuite,
        pk_r: &'a [u8],
        info: &'a [u8],
        aad: &'a [u8],
        auth: AuthParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r,
            info,
            aad,
            mode: Mode::Auth,
            auth: Some(auth),
            psk: None,
        }
    }
    /// AuthPSK mode.
    pub fn auth_psk(
        suite: HpkeSuite,
        pk_r: &'a [u8],
        info: &'a [u8],
        aad: &'a [u8],
        auth: AuthParams<'a>,
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r,
            info,
            aad,
            mode: Mode::AuthPsk,
            auth: Some(auth),
            psk: Some(psk),
        }
    }
}

// =============================================================================
// Config: HpkeOpenConfig
// =============================================================================

/// Configuration for an HPKE open operation.
#[derive(Debug, Clone, Copy)]
pub struct HpkeOpenConfig<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient private key.
    pub sk_r: &'a [u8],
    /// Recipient public key.
    pub pk_r: &'a [u8],
    /// Application-supplied info — must equal sender's value.
    pub info: &'a [u8],
    /// Additional authenticated data — must equal sender's value.
    pub aad: &'a [u8],
    pub(crate) mode: Mode,
    pub(crate) auth_pk_s: Option<&'a [u8]>,
    pub(crate) psk: Option<PskParams<'a>>,
}

impl<'a> HpkeOpenConfig<'a> {
    /// Base mode.
    pub fn base(
        suite: HpkeSuite,
        sk_r: &'a [u8],
        pk_r: &'a [u8],
        info: &'a [u8],
        aad: &'a [u8],
    ) -> Self {
        Self {
            suite,
            sk_r,
            pk_r,
            info,
            aad,
            mode: Mode::Base,
            auth_pk_s: None,
            psk: None,
        }
    }
    /// PSK mode.
    pub fn psk(
        suite: HpkeSuite,
        sk_r: &'a [u8],
        pk_r: &'a [u8],
        info: &'a [u8],
        aad: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            sk_r,
            pk_r,
            info,
            aad,
            mode: Mode::Psk,
            auth_pk_s: None,
            psk: Some(psk),
        }
    }
    /// Auth mode.
    pub fn auth(
        suite: HpkeSuite,
        sk_r: &'a [u8],
        pk_r: &'a [u8],
        info: &'a [u8],
        aad: &'a [u8],
        auth_pk_s: &'a [u8],
    ) -> Self {
        Self {
            suite,
            sk_r,
            pk_r,
            info,
            aad,
            mode: Mode::Auth,
            auth_pk_s: Some(auth_pk_s),
            psk: None,
        }
    }
    /// AuthPSK mode.
    pub fn auth_psk(
        suite: HpkeSuite,
        sk_r: &'a [u8],
        pk_r: &'a [u8],
        info: &'a [u8],
        aad: &'a [u8],
        auth_pk_s: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            sk_r,
            pk_r,
            info,
            aad,
            mode: Mode::AuthPsk,
            auth_pk_s: Some(auth_pk_s),
            psk: Some(psk),
        }
    }
}

// =============================================================================
// Config: HpkeSendExportConfig
// =============================================================================

/// Configuration for an HPKE send-export operation.
#[derive(Debug, Clone, Copy)]
pub struct HpkeSendExportConfig<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient public key.
    pub pk_r: &'a [u8],
    /// Application-supplied info.
    pub info: &'a [u8],
    /// Exporter context bytes.
    pub exporter_context: &'a [u8],
    pub(crate) mode: Mode,
    pub(crate) auth: Option<AuthParams<'a>>,
    pub(crate) psk: Option<PskParams<'a>>,
}

impl<'a> HpkeSendExportConfig<'a> {
    /// Base mode.
    pub fn base(
        suite: HpkeSuite,
        pk_r: &'a [u8],
        info: &'a [u8],
        exporter_context: &'a [u8],
    ) -> Self {
        Self {
            suite,
            pk_r,
            info,
            exporter_context,
            mode: Mode::Base,
            auth: None,
            psk: None,
        }
    }
    /// PSK mode.
    pub fn psk(
        suite: HpkeSuite,
        pk_r: &'a [u8],
        info: &'a [u8],
        exporter_context: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r,
            info,
            exporter_context,
            mode: Mode::Psk,
            auth: None,
            psk: Some(psk),
        }
    }
    /// Auth mode.
    pub fn auth(
        suite: HpkeSuite,
        pk_r: &'a [u8],
        info: &'a [u8],
        exporter_context: &'a [u8],
        auth: AuthParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r,
            info,
            exporter_context,
            mode: Mode::Auth,
            auth: Some(auth),
            psk: None,
        }
    }
    /// AuthPSK mode.
    pub fn auth_psk(
        suite: HpkeSuite,
        pk_r: &'a [u8],
        info: &'a [u8],
        exporter_context: &'a [u8],
        auth: AuthParams<'a>,
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r,
            info,
            exporter_context,
            mode: Mode::AuthPsk,
            auth: Some(auth),
            psk: Some(psk),
        }
    }
}

// =============================================================================
// Config: HpkeReceiveExportConfig
// =============================================================================

/// Configuration for an HPKE receive-export operation.
#[derive(Debug, Clone, Copy)]
pub struct HpkeReceiveExportConfig<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient private key.
    pub sk_r: &'a [u8],
    /// Recipient public key.
    pub pk_r: &'a [u8],
    /// Application-supplied info — must equal sender's value.
    pub info: &'a [u8],
    /// Exporter context bytes — must equal sender's value.
    pub exporter_context: &'a [u8],
    pub(crate) mode: Mode,
    pub(crate) auth_pk_s: Option<&'a [u8]>,
    pub(crate) psk: Option<PskParams<'a>>,
}

impl<'a> HpkeReceiveExportConfig<'a> {
    /// Base mode.
    pub fn base(
        suite: HpkeSuite,
        sk_r: &'a [u8],
        pk_r: &'a [u8],
        info: &'a [u8],
        exporter_context: &'a [u8],
    ) -> Self {
        Self {
            suite,
            sk_r,
            pk_r,
            info,
            exporter_context,
            mode: Mode::Base,
            auth_pk_s: None,
            psk: None,
        }
    }
    /// PSK mode.
    pub fn psk(
        suite: HpkeSuite,
        sk_r: &'a [u8],
        pk_r: &'a [u8],
        info: &'a [u8],
        exporter_context: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            sk_r,
            pk_r,
            info,
            exporter_context,
            mode: Mode::Psk,
            auth_pk_s: None,
            psk: Some(psk),
        }
    }
    /// Auth mode.
    pub fn auth(
        suite: HpkeSuite,
        sk_r: &'a [u8],
        pk_r: &'a [u8],
        info: &'a [u8],
        exporter_context: &'a [u8],
        auth_pk_s: &'a [u8],
    ) -> Self {
        Self {
            suite,
            sk_r,
            pk_r,
            info,
            exporter_context,
            mode: Mode::Auth,
            auth_pk_s: Some(auth_pk_s),
            psk: None,
        }
    }
    /// AuthPSK mode.
    pub fn auth_psk(
        suite: HpkeSuite,
        sk_r: &'a [u8],
        pk_r: &'a [u8],
        info: &'a [u8],
        exporter_context: &'a [u8],
        auth_pk_s: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            sk_r,
            pk_r,
            info,
            exporter_context,
            mode: Mode::AuthPsk,
            auth_pk_s: Some(auth_pk_s),
            psk: Some(psk),
        }
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

fn alloc_bytes(len: usize, alloc: &impl HsmScopedAlloc) -> HsmResult<&mut DmaBuf> {
    alloc.dma_alloc(len)
}

fn psk_bytes<'a>(psk: &Option<PskParams<'a>>) -> (&'a [u8], &'a [u8]) {
    match psk {
        Some(p) => (p.psk, p.psk_id),
        None => (&[], &[]),
    }
}

fn aead_ct_len(suite: HpkeSuite, pt_len: usize) -> usize {
    if suite.is_cbc() {
        let padded = pt_len + 16 - (pt_len % 16);
        16 + padded + suite.nt()
    } else {
        pt_len + 16
    }
}

// =============================================================================
// seal
// =============================================================================

/// HPKE seal (encrypt). Writes `enc` and `ct` to caller-supplied
/// buffers. Passing `None` for both performs a size query and returns
/// the required [`SealSizes`] without writing anything.
pub async fn seal<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    cfg: &HpkeSealConfig<'_>,
    pt: &[u8],
    enc_out: Option<&mut [u8]>,
    ct_out: Option<&mut [u8]>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<SealSizes>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let sizes = SealSizes {
        enc_len: cfg.suite.nenc(),
        ct_len: aead_ct_len(cfg.suite, pt.len()),
    };
    match (enc_out, ct_out) {
        (None, None) => Ok(sizes),
        (Some(enc), Some(ct)) => {
            if enc.len() < sizes.enc_len || ct.len() < sizes.ct_len {
                return Err(HsmError::InvalidArg);
            }
            do_seal(
                pal,
                io,
                cfg,
                pt,
                &mut enc[..sizes.enc_len],
                &mut ct[..sizes.ct_len],
                alloc,
            )
            .await?;
            Ok(sizes)
        }
        _ => Err(HsmError::InvalidArg),
    }
}

async fn do_seal<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    cfg: &HpkeSealConfig<'_>,
    pt: &[u8],
    enc_out: &mut [u8],
    ct_out: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let suite = cfg.suite;
    let ss = alloc_bytes(suite.nsecret(), alloc)?;
    match (cfg.mode, &cfg.auth) {
        (Mode::Base, None) | (Mode::Psk, None) => {
            kem::encap(pal, io, suite, cfg.pk_r, enc_out, ss, alloc).await?
        }
        (Mode::Auth, Some(a)) | (Mode::AuthPsk, Some(a)) => {
            kem::auth_encap(pal, io, suite, cfg.pk_r, a.sk_s, a.pk_s, enc_out, ss, alloc).await?
        }
        _ => return Err(HsmError::InvalidArg),
    }

    let key = alloc_bytes(suite.nk(), alloc)?;
    let nonce = alloc_bytes(suite.nn(), alloc)?;
    let (psk, psk_id) = psk_bytes(&cfg.psk);
    schedule::key_schedule(
        pal,
        io,
        suite,
        cfg.mode as u8,
        ss,
        cfg.info,
        psk,
        psk_id,
        key,
        nonce,
        alloc,
    )
    .await?;
    aead::seal(pal, io, suite, key, nonce, cfg.aad, pt, ct_out, alloc).await?;
    Ok(())
}

// =============================================================================
// open
// =============================================================================

/// HPKE open (decrypt). Writes plaintext to `pt_out`.
///
/// `pt_out = None` returns the upper-bound plaintext length (= `ct.len()`).
pub async fn open<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    cfg: &HpkeOpenConfig<'_>,
    enc: &[u8],
    ct: &[u8],
    pt_out: Option<&mut [u8]>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let max_pt = ct.len();
    let pt = match pt_out {
        None => return Ok(max_pt),
        Some(buf) => {
            if buf.len() < max_pt {
                return Err(HsmError::InvalidArg);
            }
            buf
        }
    };

    let suite = cfg.suite;
    let ss = alloc_bytes(suite.nsecret(), alloc)?;
    match (cfg.mode, cfg.auth_pk_s) {
        (Mode::Base, None) | (Mode::Psk, None) => {
            kem::decap(pal, io, suite, enc, cfg.sk_r, cfg.pk_r, ss, alloc).await?
        }
        (Mode::Auth, Some(pk_s)) | (Mode::AuthPsk, Some(pk_s)) => {
            kem::auth_decap(pal, io, suite, enc, cfg.sk_r, cfg.pk_r, pk_s, ss, alloc).await?
        }
        _ => return Err(HsmError::InvalidArg),
    }

    let key = alloc_bytes(suite.nk(), alloc)?;
    let nonce = alloc_bytes(suite.nn(), alloc)?;
    let (psk, psk_id) = psk_bytes(&cfg.psk);
    schedule::key_schedule(
        pal,
        io,
        suite,
        cfg.mode as u8,
        ss,
        cfg.info,
        psk,
        psk_id,
        key,
        nonce,
        alloc,
    )
    .await?;

    aead::open(pal, io, suite, key, nonce, cfg.aad, ct, pt, alloc).await
}

// =============================================================================
// send_export
// =============================================================================

/// HPKE send-export.
///
/// Both `None` returns [`ExportSizes`] with `enc_len` and
/// `exported_len = 0` (the caller chooses `L`, so its size can't be
/// pre-computed).
pub async fn send_export<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    cfg: &HpkeSendExportConfig<'_>,
    enc_out: Option<&mut [u8]>,
    exported_out: Option<&mut [u8]>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<ExportSizes>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let enc_len = cfg.suite.nenc();
    match (enc_out, exported_out) {
        (None, None) => Ok(ExportSizes {
            enc_len,
            exported_len: 0,
        }),
        (Some(enc), Some(exported)) => {
            if enc.len() < enc_len {
                return Err(HsmError::InvalidArg);
            }
            do_send_export(pal, io, cfg, &mut enc[..enc_len], exported, alloc).await?;
            Ok(ExportSizes {
                enc_len,
                exported_len: exported.len(),
            })
        }
        _ => Err(HsmError::InvalidArg),
    }
}

async fn do_send_export<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    cfg: &HpkeSendExportConfig<'_>,
    enc_out: &mut [u8],
    exported_out: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let suite = cfg.suite;
    let ss = alloc_bytes(suite.nsecret(), alloc)?;
    match (cfg.mode, &cfg.auth) {
        (Mode::Base, None) | (Mode::Psk, None) => {
            kem::encap(pal, io, suite, cfg.pk_r, enc_out, ss, alloc).await?
        }
        (Mode::Auth, Some(a)) | (Mode::AuthPsk, Some(a)) => {
            kem::auth_encap(pal, io, suite, cfg.pk_r, a.sk_s, a.pk_s, enc_out, ss, alloc).await?
        }
        _ => return Err(HsmError::InvalidArg),
    }

    derive_exported(
        pal,
        io,
        suite,
        cfg.mode,
        ss,
        cfg.info,
        &cfg.psk,
        cfg.exporter_context,
        exported_out,
        alloc,
    )
    .await
}

// =============================================================================
// receive_export
// =============================================================================

/// HPKE receive-export.
///
/// `exported_out = None` returns 0 — the export length is
/// caller-chosen and not pre-computed.
pub async fn receive_export<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    cfg: &HpkeReceiveExportConfig<'_>,
    enc: &[u8],
    exported_out: Option<&mut [u8]>,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let exported = match exported_out {
        None => return Ok(0),
        Some(buf) => buf,
    };

    let suite = cfg.suite;
    let ss = alloc_bytes(suite.nsecret(), alloc)?;
    match (cfg.mode, cfg.auth_pk_s) {
        (Mode::Base, None) | (Mode::Psk, None) => {
            kem::decap(pal, io, suite, enc, cfg.sk_r, cfg.pk_r, ss, alloc).await?
        }
        (Mode::Auth, Some(pk_s)) | (Mode::AuthPsk, Some(pk_s)) => {
            kem::auth_decap(pal, io, suite, enc, cfg.sk_r, cfg.pk_r, pk_s, ss, alloc).await?
        }
        _ => return Err(HsmError::InvalidArg),
    }

    derive_exported(
        pal,
        io,
        suite,
        cfg.mode,
        ss,
        cfg.info,
        &cfg.psk,
        cfg.exporter_context,
        exported,
        alloc,
    )
    .await?;
    Ok(exported.len())
}

/// Run `key_schedule_export` + a final `LabeledExpand("sec", ctx, L)`.
#[allow(clippy::too_many_arguments)]
async fn derive_exported<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    suite: HpkeSuite,
    mode: Mode,
    shared_secret: &[u8],
    info: &[u8],
    psk: &Option<PskParams<'_>>,
    exporter_context: &[u8],
    out: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let (psk_b, psk_id) = psk_bytes(psk);
    let exp_secret = alloc_bytes(suite.nh(), alloc)?;
    schedule::key_schedule_export(
        pal,
        io,
        suite,
        mode as u8,
        shared_secret,
        info,
        psk_b,
        psk_id,
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
        out,
        alloc,
    )
    .await
}
