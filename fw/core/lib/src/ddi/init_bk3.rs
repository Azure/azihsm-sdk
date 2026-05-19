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
//! 1. **BK3** (plaintext) is enveloped under **`BK_BOOT`** (the 80-byte
//!    boot key sourced from
//!    [`HsmPartitionManager::part_bk_boot`]).  The result —
//!    `masked_bk3` — is returned to the host.
//! 2. **`BK_BOOT`** (plaintext) is enveloped under **`BKx`** (the
//!    partition's masking key produced per-call by
//!    [`HsmPartitionManager::derive_masking_key`] from the PAL's
//!    firmware boot seed bound to `(svn, bks2_id)`).  The result —
//!    `Masked_BK_BOOT` — is persisted via
//!    [`HsmPartitionManager::part_set_masked_bk_boot`] and never
//!    crosses the wire.
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

use azihsm_fw_core_crypto_masked_key::mask_cbc;
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
/// `DdiInitBk3`; the firmware then consumes it internally as the
/// masking key for sealed per-partition state.  The flag selection
/// reflects that lifecycle.
///
/// Note: BK3's on-device lifetime is bound to the partition.  The
/// host can clear BK3 from the device by disabling or freeing the
/// partition (both routes wipe `bk3_initialized`, `sealed_bk3`, and
/// the masked `BK_BOOT`); the host can also "delete" BK3 simply by
/// dropping its own copy of the masked blob, since the device does
/// not persist BK3 plaintext.  The flag selection below uses
/// strictly per-object PKCS#11 semantics (i.e. "is there an API
/// call to mutate / destroy *this object*?") and is independent of
/// partition lifecycle.
///
/// **Set:**
/// - `internal` — BK3 is consumed only by the firmware as a
///   masking key for sealed partition state.  No DDI exposes it
///   for user-facing crypto, and there is no per-object destroy
///   DDI for BK3 (the only path that clears it is partition
///   disable / free, which clears all partition state together).
/// - `never_extractable` — BK3's plaintext never leaves the device
///   after import.  Per PKCS#11 semantics this flag is set by the
///   token for any key whose `extractable` has always been
///   `false`, which BK3 satisfies because it is consumed and
///   masked immediately on receipt.
///
/// **Cleared (with rationale):**
/// - `local` — BK3 is imported from the host, not generated
///   on-device.  PKCS#11 `CKA_LOCAL` is `false` for imported keys.
/// - `extractable` — BK3 plaintext is never returned to the host.
/// - `modifiable` / `destroyable` — there is no per-object DDI to
///   modify BK3's attributes/value or to destroy BK3 individually.
///   (Partition lifecycle can still clear BK3 along with all other
///   partition state, but that is a coarser operation than
///   `CKA_DESTROYABLE`.)
/// - `private` — there is no PKCS#11 session/login at this layer;
///   BK3 is invisible to all DDI consumers.
/// - `session` — BK3 is partition-scoped, not session-scoped.
/// - `encrypt` / `decrypt` / `sign` / `verify` / `wrap` / `unwrap`
///   / `derive` — BK3 itself is never invoked through these
///   operations; it is used only as an implicit masking key.
/// - `trusted` / `wrap_with_trusted` — wrap-policy bits have no
///   meaning for a firmware-internal partition root key.
const BK3_KEY_ATTRIBUTES: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_internal(true)
    .with_never_extractable(true);

/// KBKDF label that selects the BK_BOOT masking-key derivation
/// purpose when calling
/// [`HsmPartitionManager::derive_masking_key`].  The PAL combines
/// this with its internal firmware boot seed plus the partition's
/// `(svn, bks2_id)` selectors to produce `BKx`.  The literal matches
/// the prior reference firmware's masking-key label so envelopes
/// produced here are bit-compatible with persistent `Masked_BK_BOOT`
/// blobs.
const BK_BOOT_MK_LABEL: &[u8] = b"BK_BOOT_MK_DEFAULT";

/// PKCS#11-style attributes recorded in `Masked_BK_BOOT`'s metadata.
///
/// `BK_BOOT` is a firmware-internal boot key generated inside the
/// device during partition enable.  Its only uses are as a masking
/// key for BK3 (the first envelope in this handler) and as the
/// plaintext that gets re-enveloped under `BKx` (the second envelope
/// here, persisted as `Masked_BK_BOOT`).  It never crosses the wire
/// and there is no DDI to expose, modify, or destroy it
/// individually.
///
/// **Set:**
/// - `local` — `BK_BOOT` is generated on-device by the PAL during
///   partition enable.  PKCS#11 `CKA_LOCAL` is `true` for keys
///   produced by the token itself.  **This is the one attribute
///   that distinguishes `BK_BOOT` from [`BK3_KEY_ATTRIBUTES`]**,
///   which is imported from the host.
/// - `internal` — `BK_BOOT` is consumed only by the firmware as a
///   masking key.  No DDI exposes it for user-facing crypto, and
///   there is no per-object destroy DDI (the only path that clears
///   `BK_BOOT` is partition disable / free, which clears all
///   partition state together).
/// - `never_extractable` — `BK_BOOT` plaintext never leaves the
///   device.  Per PKCS#11 semantics this flag is set by the token
///   for any key whose `extractable` has always been `false`,
///   which `BK_BOOT` satisfies because it is generated and consumed
///   entirely inside the firmware.
///
/// **Cleared (with rationale):**
/// - `extractable` — `BK_BOOT` plaintext is never returned to the
///   host.  (`Masked_BK_BOOT` is an internal-only envelope and
///   does not cross the wire, so it does not count as a PKCS#11
///   `C_WrapKey` export either.)
/// - `modifiable` / `destroyable` — there is no per-object DDI to
///   modify `BK_BOOT`'s attributes/value or destroy it.  Partition
///   lifecycle can clear it along with all other partition state,
///   but that is coarser than `CKA_DESTROYABLE`.
/// - `private` — there is no PKCS#11 session/login at this layer;
///   `BK_BOOT` is invisible to all DDI consumers.
/// - `session` — `BK_BOOT` is partition-scoped, not session-scoped.
/// - `encrypt` / `decrypt` / `sign` / `verify` / `wrap` / `unwrap`
///   / `derive` — `BK_BOOT` is never invoked through these PKCS#11
///   operations.  In particular, although `BK_BOOT` is used to
///   envelope BK3 (producing the `masked_bk3` returned by this
///   handler), that masking is performed by a firmware-internal
///   mechanism inside `DdiInitBk3`, not by a host-issued
///   `C_WrapKey` call; `BK_BOOT` has no PKCS#11 handle that could
///   be passed to any of these APIs.
/// - `trusted` / `wrap_with_trusted` — wrap-policy bits have no
///   meaning for a firmware-internal masking key.
const BK_BOOT_KEY_ATTRIBUTES: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Handle `DdiInitBk3Cmd`.
///
/// 1. **Body decode** — Decodes `DdiInitBk3Req`. The protocol-level
///    length constraint (`len = 48`) is enforced by the MBOR decoder.
///
/// 2. **Write-mutex serialization** — Acquires the per-partition
///    write lock.  Concurrent `InitBk3` commands on the same
///    partition serialize here.
///
/// 3. **One-shot fail-fast** — Reads the partition's BK3 init flag
///    and returns [`HsmError::Bk3AlreadyInitialized`] early without
///    doing any masking work if BK3 has already been initialized.
///    The authoritative commit at the end of the handler still
///    re-checks atomically under the partition table guard.
///
/// 4. **Metadata build** — Constructs [`DdiMaskedKeyMetadata`] (svn /
///    key_type / key_attributes / bks2_index / key_label="BK3" /
///    key_length=48).  The struct is passed by reference to the
///    masking crate, which MBOR-encodes it directly into the metadata
///    slot of the response buffer — no intermediate scratch buffer.
///    Bound by the trailing integrity tag.
///
/// 5. **BK_BOOT fetch** — Allocates an 80-byte DMA buffer for the
///    partition's `BK_BOOT` and fills it via
///    [`HsmPartitionManager::part_bk_boot`].  The DMA brand is
///    required because the buffer is consumed in place by the AES
///    and HMAC engines (low 32 B as AES key, high 48 B as HMAC key).
///
/// 6. **Length compute** — Queries the masked-key crate for the
///    required masked-BK3 length (size-only call; performs no
///    crypto), then frames the response with that size and reserves
///    the masked-BK3 and `vm_launch_guid` slots.
///
/// 7. **Mask BK3** — Invokes [`mask_cbc`] which generates a random
///    IV, copies BK3 into the ciphertext slot of the encoder-reserved
///    `frame.masked_bk3` buffer, AES-CBC-256-encrypts in-place,
///    writes metadata, and computes the HMAC-SHA-384 integrity tag
///    — all inside that buffer with zero intermediate DMA
///    allocations.
///
/// 8. **Mask `BK_BOOT`** — Builds the BK_BOOT metadata
///    (`key_label = "BKBoot"`, `key_length = 80`), derives `BKx`
///    per-call via [`HsmPartitionManager::derive_masking_key`] from
///    the PAL's firmware boot seed bound to `(svn, bks2_id)`,
///    envelopes the partition `BK_BOOT` plaintext under `BKx` into a
///    freshly-allocated DMA buffer, and persists the result via
///    [`HsmPartitionManager::part_set_masked_bk_boot`].  The masked
///    envelope is internal-only and does not appear in the response.
///
/// 9. **VM launch GUID** — Fills `frame.vm_launch_guid` via
///    [`HsmPartitionManager::part_vm_launch_guid`].
///
/// 10. **Commit** — Calls
///     [`HsmPartitionManager::part_mark_bk3_initialized`] last so a
///     failure in any prior step leaves the partition's BK3 state
///     untouched and the host can retry.
pub(crate) async fn init_bk3<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiInitBk3Req = decoder.decode_data()?;

    let _lock = pal.partition_lock(io).await?;

    // Fail-fast; the authoritative commit below re-checks atomically.
    if pal.part_is_bk3_initialized(io)? {
        return Err(HsmError::Bk3AlreadyInitialized);
    }

    let svn = pal.part_svn(io)?;
    let bks2_id = pal.part_bks2_id(io)?;
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

    // Single combined alloc for BK_BOOT + BKx (both live simultaneously
    // during the second mask call below).  `part_bk_boot(None)` queries
    // the canonical BK_BOOT length without copying any bytes.
    let bk_boot_len = pal.part_bk_boot(io, None)?;
    let keys_dma = pal.dma_alloc(io, 2 * bk_boot_len)?;
    let (bk_boot_dma, bkx_dma) = keys_dma.split_at_mut(bk_boot_len);
    pal.part_bk_boot(io, Some(bk_boot_dma))?;

    // Size-only query (no crypto).
    let masked_bk3_len = mask_cbc(pal, io, bk_boot_dma, body.bk3, &metadata, None).await?;

    let vm_launch_guid_len = pal.part_vm_launch_guid(io, None)?;

    // Reserve the response buffer (encoder-frame-then-fill).  The async
    // mask call below operates on the buffer materialized via
    // `from_layout`.
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = ddi::encode_resp_hdr(&ddi::success_hdr(hdr, DdiOp::InitBk3), buf)?;
        let layout = DdiInitBk3Resp::reserve(&mut encoder, masked_bk3_len, vm_launch_guid_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiInitBk3Resp::from_layout(resp, &layout);

    // Authenticated-encrypt BK3 directly into the reserved masked-BK3
    // slot — no intermediate DMA allocations.
    mask_cbc(
        pal,
        io,
        bk_boot_dma,
        body.bk3,
        &metadata,
        Some(frame.masked_bk3),
    )
    .await?;

    // Envelope BK_BOOT under BKx and persist as `Masked_BK_BOOT`.  This
    // blob is firmware-internal — never crosses the wire — but is held
    // in the partition table so raw BK_BOOT can be recovered through
    // the partition lifecycle.  See [`BK_BOOT_KEY_ATTRIBUTES`] for the
    // attribute selection.
    let bk_boot_metadata = DdiMaskedKeyMetadata {
        svn,
        key_type: DdiKeyType::AesCbc256Hmac384,
        key_attributes: BK_BOOT_KEY_ATTRIBUTES.into(),
        bks2_index: Some(bks2_id),
        rsvd: None,
        key_label: b"BKBoot",
        key_length: BK_BOOT_LEN as u16,
    };

    // Derive BKx per-call from the PAL's fw_seed bound to (svn,
    // bks2_id).  The key materializes only inside `bkx_dma`; no BKx
    // value crosses the trait boundary.
    pal.derive_masking_key(
        io,
        pal.fw_seed(),
        BK_BOOT_MK_LABEL,
        &[],
        svn,
        bks2_id,
        bkx_dma,
    )
    .await?;

    // Size-query, then zeroed alloc (mask_cbc requires `out` to be zero
    // on entry).
    let masked_bk_boot_len = mask_cbc(
        pal,
        io,
        bkx_dma,
        &bk_boot_dma[..BK_BOOT_LEN],
        &bk_boot_metadata,
        None,
    )
    .await?;
    let masked_bk_boot_dma = pal.dma_alloc_zeroed(io, masked_bk_boot_len)?;
    mask_cbc(
        pal,
        io,
        bkx_dma,
        &bk_boot_dma[..BK_BOOT_LEN],
        &bk_boot_metadata,
        Some(masked_bk_boot_dma),
    )
    .await?;

    pal.part_set_masked_bk_boot(io, &masked_bk_boot_dma[..masked_bk_boot_len])?;

    pal.part_vm_launch_guid(io, Some(frame.vm_launch_guid))?;

    // Authoritative one-shot commit; must be the last fallible op so a
    // failure here cannot leave the partition in `Initialized` state
    // without the host having received the masked BK3.
    pal.part_mark_bk3_initialized(io)?;

    Ok(resp)
}
