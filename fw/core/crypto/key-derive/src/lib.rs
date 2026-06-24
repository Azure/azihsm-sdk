// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition masking-key derivation and `BK_BOOT` lifecycle.
//!
//! This crate sits one level above the generic masked-key envelope
//! primitive ([`azihsm_fw_core_crypto_key_masking`]) and owns the
//! partition-specific policy that both the PAL and the core firmware
//! share:
//!
//! * [`derive_masking_key`] — derive a partition masking key (`BKx`,
//!   `MK`, …) bound to `(svn, owner)` via SP 800-108 KBKDF over the
//!   device-global seeds exposed by
//!   [`HsmSeedStore`](azihsm_fw_hsm_pal_traits::HsmSeedStore).
//! * [`mask_bk_boot`] — generate a fresh random `BK_BOOT` and envelope
//!   it under the partition's `BKx`, producing the persisted
//!   `Masked_BK_BOOT`.  Called once at partition allocation.
//! * [`unmask_bk_boot`] — recover the raw `BK_BOOT` from a persisted
//!   `Masked_BK_BOOT`.  Called on demand by the core firmware.
//!
//! The raw `BK_BOOT` is **never stored** — only its masked form is.
//! Keeping both the create (PAL) and recover (core) paths on the same
//! derivation/envelope code guarantees they cannot diverge.

#![no_std]

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_core_crypto_key_masking::cbc::unmask;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_ddi_mbor_types::DdiKeyType;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::BK_BOOT_LEN;

/// KBKDF label selecting the `BK_BOOT` masking-key (`BKx`) derivation
/// purpose.  Both the create and recover paths must use this label.
pub const BK_BOOT_MK_LABEL: &[u8] = b"BK_BOOT_MK_DEFAULT";

/// Vault attributes embedded in the `Masked_BK_BOOT` metadata —
/// on-device generated (`local`), internal, never-extractable.
const BK_BOOT_KEY_ATTRIBUTES: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Builds the masked-key metadata for a `BK_BOOT` envelope.
fn bk_boot_metadata(svn: u64, owner: u16) -> DdiMaskedKeyMetadata<'static> {
    DdiMaskedKeyMetadata {
        svn,
        key_type: DdiKeyType::AesCbc256Hmac384,
        key_attributes: BK_BOOT_KEY_ATTRIBUTES.into(),
        bks2_index: Some(owner),
        rsvd: None,
        key_label: b"BKBoot",
        key_length: BK_BOOT_LEN as u16,
    }
}

/// Derives a partition masking key bound to `(svn, owner)`.
///
/// Runs SP 800-108 KBKDF (HMAC-SHA-384) keyed on `kdk`, with `label`
/// and a context of `mfgr_seed[svn] ‖ owner_seed[owner] ‖
/// extra_context`.  The device-global seeds come from
/// [`HsmSeedStore`].  `output` receives the derived key.
pub async fn derive_masking_key<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    kdk: &DmaBuf,
    label: &[u8],
    extra_context: &[u8],
    svn: u64,
    owner: u16,
    output: &mut DmaBuf,
) -> HsmResult<()> {
    let mfgr = pal.mfgr_seed(svn)?;
    let dev_owner = pal.owner_seed(u64::from(owner))?;

    let mfgr_len = mfgr.len();
    let dev_owner_len = dev_owner.len();
    let ctx_len = mfgr_len + dev_owner_len + extra_context.len();
    let ctx = pal.dma_alloc(io, ctx_len)?;
    {
        let (mfgr_slot, rest) = ctx.split_at_mut(mfgr_len);
        let (dev_slot, extra_slot) = rest.split_at_mut(dev_owner_len);
        mfgr_slot.copy_from_slice(mfgr);
        dev_slot.copy_from_slice(dev_owner);
        if !extra_context.is_empty() {
            extra_slot.copy_from_slice(extra_context);
        }
    }

    let label_dma = pal.dma_alloc(io, label.len())?;
    if !label.is_empty() {
        label_dma.copy_from_slice(label);
    }

    pal.sp800_108_kdf(
        io,
        HsmHashAlgo::Sha384,
        kdk,
        Some(label_dma),
        Some(ctx),
        output,
    )
    .await
}

/// Derives the partition's `BKx` (the `BK_BOOT` masking key) into
/// `bkx`, which must be [`BK_BOOT_LEN`] bytes.
async fn derive_bkx<P: HsmPal>(pal: &P, io: &impl HsmIo, bkx: &mut DmaBuf) -> HsmResult<()> {
    let svn = pal.mfgr_svn();
    let owner = u16::try_from(pal.owner_svn()).map_err(|_| HsmError::InvalidArg)?;
    let fw_seed = pal.fw_seed();
    let fw_seed_dma = pal.dma_alloc(io, fw_seed.len())?;
    fw_seed_dma.copy_from_slice(fw_seed);
    derive_masking_key(pal, io, fw_seed_dma, BK_BOOT_MK_LABEL, &[], svn, owner, bkx).await
}

/// Generates a fresh random `BK_BOOT` and envelopes it under the
/// partition's `BKx`, returning the `Masked_BK_BOOT` blob.
///
/// Called once at partition allocation; the caller persists the
/// returned blob.  The raw `BK_BOOT` never leaves this function.
pub async fn mask_bk_boot<'a, P: HsmPal>(pal: &'a P, io: &impl HsmIo) -> HsmResult<&'a mut DmaBuf> {
    let svn = pal.mfgr_svn();
    let owner = u16::try_from(pal.owner_svn()).map_err(|_| HsmError::InvalidArg)?;

    // Fresh random BK_BOOT.
    let bk_boot = pal.dma_alloc(io, BK_BOOT_LEN)?;
    pal.rng_fill_bytes(io, bk_boot)?;

    // Derive BKx, then mask BK_BOOT under it.
    let bkx = pal.dma_alloc(io, BK_BOOT_LEN)?;
    derive_bkx(pal, io, bkx).await?;

    let metadata = bk_boot_metadata(svn, owner);
    let masked_len = mask(pal, io, bkx, bk_boot, &metadata, None).await?;
    let masked = pal.dma_alloc_zeroed(io, masked_len)?;
    mask(pal, io, bkx, bk_boot, &metadata, Some(masked)).await?;
    Ok(masked)
}

/// Recovers the raw 80-byte `BK_BOOT` from a persisted
/// `Masked_BK_BOOT` blob, writing it into `out` (must be
/// [`BK_BOOT_LEN`] bytes).
pub async fn unmask_bk_boot<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    masked: &DmaBuf,
    out: &mut DmaBuf,
) -> HsmResult<()> {
    // `out` is a trust-boundary buffer; validate its length up front so a
    // wrong-sized caller buffer is rejected rather than panicking in the
    // final `copy_from_slice`.
    if out.len() != BK_BOOT_LEN {
        return Err(HsmError::InvalidArg);
    }
    // Unmask decrypts in place, so work on a mutable copy.
    let masked_buf = pal.dma_alloc(io, masked.len())?;
    masked_buf.copy_from_slice(masked);

    let bkx = pal.dma_alloc(io, BK_BOOT_LEN)?;
    derive_bkx(pal, io, bkx).await?;

    let layout = unmask(pal, io, bkx, masked_buf).await?;
    if layout.plaintext_max_len < BK_BOOT_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    out.copy_from_slice(
        &masked_buf[layout.plaintext_offset..layout.plaintext_offset + BK_BOOT_LEN],
    );
    Ok(())
}
