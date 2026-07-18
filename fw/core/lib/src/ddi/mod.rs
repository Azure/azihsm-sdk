// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI command dispatch — split per wire codec.
//!
//! - [`mbor`] hosts the original MBOR-encoded DDI command handlers
//!   reached via the `OP_MBOR` SQE opcode.
//! - [`tbor`] hosts the TBOR-encoded DDI command handlers reached via
//!   the `OP_TBOR` SQE opcode.
//!
//! Both sub-modules expose a `dispatch` entry point invoked from
//! [`crate::Hsm::handle_mbor_op`] / [`crate::Hsm::handle_tbor_op`] and
//! a per-codec error encoder used when post-decode failures need to be
//! surfaced as a typed response body rather than a CQE status code.

pub(crate) mod mbor;
pub(crate) mod tbor;

// Re-expose crate-root symbols (HsmPal, HsmIo, HsmError, …) to the
// child modules' `use super::*;` imports.
use super::*;

/// Recovers the unmasked 80-byte `BK_BOOT` on demand.
///
/// Mirrors the reference firmware: the raw boot key is **never stored**
/// — only its BKx-masked form (`Masked_BK_BOOT`, persisted by `InitBk3`)
/// is.  This recomputes the partition's `BKx` from the firmware boot
/// seed bound to `(svn, owner)` and unmasks the persisted blob, leaving
/// `BK_BOOT` in `out`.
///
/// Shared across both wire codecs (`EstablishCredential` / `OpenSession`
/// / `InitBk3` in [`mbor`], and `OpenSessionFinish` in [`tbor`]), so it
/// lives at the command level rather than in either codec — keeping
/// `tbor` independent of `mbor`.
///
/// `out` must be exactly [`BK_BOOT_LEN`] (80) bytes.  Returns
/// [`HsmError::PartPropNotFound`] if `Masked_BK_BOOT` has not been
/// provisioned (i.e. before `InitBk3`).
pub(crate) async fn recover_bk_boot<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    out: &mut DmaBuf,
) -> HsmResult<()> {
    // Copy the persisted masked BK_BOOT into a working buffer and
    // unmask it (the raw key is never stored; it is created masked at
    // partition allocation).
    let masked_len = crate::part_state::part_masked_bk_boot(pal, io)?.len();
    let masked_buf = pal.dma_alloc(io, masked_len)?;
    {
        let src = crate::part_state::part_masked_bk_boot(pal, io)?;
        masked_buf.copy_from_slice(&src[..masked_len]);
    }
    azihsm_fw_core_crypto_key_derive::unmask_bk_boot(pal, io, masked_buf, out).await
}

/// Map an HMAC vault kind to the hash algorithm whose digest length is
/// the MAC tag size.
///
/// Accepts both the fixed-length (`_HmacSha*`) and variable-length
/// (`VarLenHmacSha*`) HMAC kinds.  Any non-HMAC kind returns
/// [`HsmError::InvalidKeyType`].
///
/// Shared across both wire codecs (`Hmac` in [`mbor`], and the HMAC
/// crypto commands in [`tbor`]), so it lives at the command level rather
/// than in either codec — keeping `tbor` independent of `mbor`.
pub(crate) fn hmac_hash(kind: HsmVaultKeyKind) -> HsmResult<HsmHashAlgo> {
    match kind {
        HsmVaultKeyKind::_HmacSha256 | HsmVaultKeyKind::VarLenHmacSha256 => Ok(HsmHashAlgo::Sha256),
        HsmVaultKeyKind::_HmacSha384 | HsmVaultKeyKind::VarLenHmacSha384 => Ok(HsmHashAlgo::Sha384),
        HsmVaultKeyKind::_HmacSha512 | HsmVaultKeyKind::VarLenHmacSha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidKeyType),
    }
}
