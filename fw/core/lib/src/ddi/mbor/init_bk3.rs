// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI InitBk3 command handler.
//!
//! Masks the caller-supplied 48-byte BK3 against the partition's
//! `BK_BOOT` using the AES-CBC-256 + HMAC-SHA-384 `MaskedKey`
//! envelope, persists `BK_BOOT` itself as a `Masked_BK_BOOT` envelope
//! (under the partition's `BKx` masking key) for later partition
//! lifecycle recovery, and returns the resulting `masked_bk3`
//! together with the partition's `vm_launch_guid`.
//!
//! `InitBk3` is a one-shot per partition incarnation: a second call
//! (or a racing concurrent call after the first has completed) returns
//! [`HsmError::Bk3AlreadyInitialized`].  Sealing the masked BK3
//! happens outside the device — this handler does **not** persist
//! sealed BK3.
//!
//! ## Concurrency
//!
//! Multiple `InitBk3` commands can arrive simultaneously.  Partition
//! writes are serialized by the per-partition write mutex acquired via
//! [`HsmPartitionLock::partition_lock`].  Read-only / hot-path
//! partition getters do **not** take this lock.  The PAL also
//! re-checks the one-shot state atomically inside
//! [`HsmPartitionManager::part_mark_bk3_initialized`] so the lock is
//! an optimization, not the correctness barrier.
//!
//! ## Masking
//!
//! The masking transform is [`MaskingKeyAlgorithm::AesCbc256Hmac384`]:
//! AES-CBC-256 encryption with a random IV, authenticated by an
//! HMAC-SHA-384 tag computed over the entire blob (encrypt-then-MAC).
//! The same envelope is used twice in this handler:
//!
//! 1. **BK3** (plaintext) is enveloped under **`BK_BOOT`** (a fresh
//!    80-byte random boot key generated here).  The result —
//!    `masked_bk3` — is returned to the host.
//! 2. **`BK_BOOT`** (plaintext) is enveloped under **`BKx`** (the
//!    partition's masking key produced per-call by
//!    [`HsmPartitionManager::derive_masking_key`] from the PAL's
//!    firmware boot seed bound to `(svn, bks2_id)`).  The result —
//!    `Masked_BK_BOOT` — is persisted via
//!    [`HsmPartitionManager::part_set_masked_bk_boot`] and never
//!    crosses the wire.  The raw `BK_BOOT` is never stored; later
//!    flows recover it on demand by unmasking `Masked_BK_BOOT`.
//!
//! For each envelope the 80-byte masking key is split into a 32-byte
//! AES key (low half) and a 48-byte HMAC key (high half).  Metadata
//! (`DdiMaskedKeyMetadata`, MBOR-encoded) is embedded inside the blob
//! and bound by the tag so a later decoder can authenticate which
//! key/svn the envelope was produced for.
//!
//! The wire format is bit-compatible with the prior reference
//! firmware's `MaskedKey` blob format used by host-side tooling.
//!
//! Uses the encode-frame-then-fill pattern: the masked BK3 is written
//! directly into the encoder-reserved response slot — zero
//! intermediate copies.

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_ddi_mbor_types::init_bk3::DdiInitBk3Req;
use azihsm_fw_ddi_mbor_types::init_bk3::DdiInitBk3Resp;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_ddi_mbor_types::DdiKeyType;

use super::*;

/// BK3 plaintext length in bytes (also the `key_length` recorded in
/// the masked-key metadata).
const BK3_LEN: usize = 48;

/// PKCS#11-style attributes recorded in BK3's masked-key metadata.
///
/// BK3 is a 48-byte partition root key **imported** by the host via
/// `DdiInitBk3`; firmware uses it internally as the masking key for
/// sealed per-partition state and never exposes its plaintext.
///
/// - `internal` — consumed only by firmware; no DDI exposes BK3 for
///   user-facing crypto, and there is no per-object destroy DDI.
/// - `never_extractable` — BK3's plaintext never leaves the device
///   after import.
///
/// All other attributes are cleared.  In particular `local` is
/// cleared because BK3 is host-imported (contrast with the on-device
/// `BK_BOOT` masking key); the operation-bits (`encrypt`,
/// `sign`, `wrap`, `derive`, …) are cleared because BK3 has no
/// PKCS#11 handle the host could pass to those APIs.
const BK3_KEY_ATTRIBUTES: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_internal(true)
    .with_never_extractable(true);

/// Handle `DdiInitBk3Cmd`.
///
/// Pipeline:
/// 1. Decode body, acquire the per-partition write lock, one-shot
///    fail-fast on `bk3_initialized`.
/// 2. Read `BK_BOOT` and allocate a sibling slot for `BKx` from a
///    single combined DMA buffer.
/// 3. Frame the response, then AES-CBC-256 + HMAC-SHA-384 mask BK3
///    under `BK_BOOT` directly into the response buffer's
///    `masked_bk3` slot (no intermediate DMA copy).
/// 4. Derive `BKx` per-call from the firmware boot seed, mask
///    `BK_BOOT` under `BKx`, and persist the result as
///    `Masked_BK_BOOT` — firmware-internal, never on the wire.
/// 5. Fill `vm_launch_guid` and call `part_mark_bk3_initialized` as
///    the authoritative one-shot commit.
///
/// All partition mutations happen at the end so any earlier failure
/// leaves partition state untouched and the host can retry.
pub(crate) async fn init_bk3<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiInitBk3Req = decoder.decode_data()?;

    let _lock = pal.partition_lock(io).await?;

    // Fail-fast; the authoritative commit below re-checks atomically.
    if crate::part_state::part_is_bk3_initialized(pal, io)? {
        return Err(HsmError::Bk3AlreadyInitialized);
    }

    let svn = crate::part_state::part_mfgr_svn(pal);
    let bks2_id =
        u16::try_from(crate::part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    let metadata = DdiMaskedKeyMetadata {
        svn,
        key_type: DdiKeyType::AesCbc256Hmac384,
        key_attributes: BK3_KEY_ATTRIBUTES.into(),
        // Always-Some on new masking; Option-typed only for backward
        // compatibility with legacy blobs masked with `None`.
        bks2_index: Some(bks2_id),
        rsvd: None,
        key_label: b"BK3",
        key_length: BK3_LEN as u16,
    };

    // Recover BK_BOOT.  The raw boot key is never stored; it is created
    // masked once at partition allocation and recovered here by
    // unmasking the persisted `Masked_BK_BOOT`.
    let bk_boot_dma = pal.dma_alloc(io, BK_BOOT_LEN)?;
    crate::ddi::recover_bk_boot(pal, io, bk_boot_dma).await?;

    // Size-only query (no crypto).
    let masked_bk3_len = mask(pal, io, bk_boot_dma, body.bk3, &metadata, None).await?;

    let vm_launch_guid_len = crate::part_state::part_vm_launch_guid(pal, io)?.len();

    // Reserve the response buffer (encoder-frame-then-fill).  The async
    // mask call below operates on the buffer materialized via
    // `from_layout`.
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(&super::success_hdr(hdr, DdiOp::InitBk3), buf)?;
        let layout = DdiInitBk3Resp::reserve(&mut encoder, masked_bk3_len, vm_launch_guid_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiInitBk3Resp::from_layout(resp, &layout);

    // Authenticated-encrypt BK3 directly into the reserved masked-BK3
    // slot — no intermediate DMA allocations.
    mask(
        pal,
        io,
        bk_boot_dma,
        body.bk3,
        &metadata,
        Some(frame.masked_bk3),
    )
    .await?;

    {
        let guid = crate::part_state::part_vm_launch_guid(pal, io)?;
        frame
            .vm_launch_guid
            .copy_from_slice(&guid[..vm_launch_guid_len]);
    }

    // Authoritative one-shot commit; must be the last fallible op so a
    // failure here cannot leave the partition in `Initialized` state
    // without the host having received the masked BK3.
    crate::part_state::part_mark_bk3_initialized(pal, io)?;

    Ok(resp)
}
