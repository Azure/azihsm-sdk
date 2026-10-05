// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmVault`] implementation for the Uno PAL.
//!
//! Key material lives in the GSRAM key-vault region. The platform-agnostic
//! allocator and key logic live in the [`KeyVault`] crate; the GSRAM table
//! layout and access live in the
//! [`VaultStorage`](azihsm_fw_uno_drivers_vault::VaultStorage) driver. This
//! module just wires the async [`HsmVault`] trait methods to a per-call
//! [`KeyVault`] over that storage, using the PAL's own GDMA controller for
//! large-key copy/zeroize.
//!
//! All state is in GSRAM, so a [`KeyVault`] is constructed per call over a
//! lightweight [`VaultStorage`](azihsm_fw_uno_drivers_vault::VaultStorage)
//! handle that carries only the calling partition's resource mask — there
//! is no PAL-resident vault state.
//!
//! Following the reference firmware, the SDK `meta` (key label) is not
//! stored (see the [`KeyVault`] crate docs).

#![allow(unsafe_code)]

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVault;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_uno_drivers_part_store::PartStore;
use azihsm_fw_uno_drivers_vault::VaultStorage;
use azihsm_fw_uno_key_vault::KeyVault;
use zeroize::Zeroizing;

use crate::UnoHsmPal;

#[inline]
pub(crate) fn vault(io: &impl HsmIo) -> KeyVault<VaultStorage> {
    // Out-of-range partitions own no tables (empty mask → no storage).
    let res_mask = PartStore::partition(io.pid()).map_or(0, |p| p.res_mask());
    KeyVault::new(VaultStorage::new(res_mask))
}

/// Build a `'static` [`DmaBuf`] over a key's blob location in GSRAM.
///
/// `(table, off, len)` must come from `KeyVault::key_location` or
/// `key_location_present`, which validate that the range lies inside that
/// table's blob region.  The region is `'static` GSRAM, so the reference
/// outlives the transient [`KeyVault`] the location was read from.
#[inline]
fn blob_ref(table: usize, off: usize, len: usize) -> &'static DmaBuf {
    let addr = VaultStorage::blob_addr(table) + off;
    // SAFETY: the caller's `key_location{,_present}` validated that
    // `addr..addr+len` lies within that table's 'static GSRAM blob region.
    unsafe { DmaBuf::from_raw(core::slice::from_raw_parts(addr as *const u8, len)) }
}

impl HsmVault for UnoHsmPal {
    async fn vault_key_create(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<HsmKeyId> {
        // Bulk keys (AES-GCM / XTS) are consumed by the fast-path engine,
        // not stored as material in the vault: register the key with the
        // engine and keep only the 2-byte handle here.  Ordinary keys are
        // stored directly.
        if is_bulk_kind(kind) {
            return fp_bulk_create(self, io, key, kind, session_id, attrs).await;
        }
        let app_id = u8::from(io.pid());
        let session = session_id.map(u16::from);
        let mut v = vault(io);
        v.create(self, io, app_id, key, kind, session, attrs).await
    }

    fn bulk_key_id(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<Option<u16>> {
        if !is_bulk_kind(self.vault_key_kind(io, key_id)?) {
            return Ok(None);
        }
        let blob = self.vault_key(io, key_id)?;
        let bytes: &[u8] = blob;
        if bytes.len() != core::mem::size_of::<u16>() {
            return Err(HsmError::InternalError);
        }
        Ok(Some(u16::from_le_bytes([bytes[0], bytes[1]])))
    }

    async fn vault_key_delete(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        // Disabled-aware classification: the undo-log commit deletes a
        // soft-deleted (disabled) key, which the live-entry lookups hide.
        let entry = vault(io).key_entry(key_id)?;

        // Non-bulk keys live entirely in the vault; delete directly.
        if !is_bulk_kind(entry.kind()) {
            return vault(io).delete(self, io, key_id).await;
        }

        // Bulk keys are mirrored in the fast-path engine and keep only their
        // 2-byte handle in the vault.
        let session = entry.session().then(|| entry.session_or_tag());
        let (table, off, len) = vault(io).key_location_present(key_id)?;
        let bytes: &[u8] = blob_ref(table, off, len);
        let bulk_id = u16::from_le_bytes(bytes.try_into().map_err(|_| HsmError::InternalError)?);
        let fp_id = AesBulk256KeyId::from_bits(bulk_id);

        // Hide the key while the engine delete is in flight.  An already
        // disabled entry (undo-log commit) stays as it is: only re-enable on
        // failure if this call disabled it, so the undo log keeps owning that
        // state.
        let disabled_here = vault(io).disable(key_id).is_ok();

        if let Err(e) =
            fp_bulk_delete(self, io, bulk_id, session.unwrap_or(0), session.is_some()).await
        {
            if disabled_here {
                let _ = vault(io).enable(key_id);
            }
            return Err(e);
        }

        // The engine key is destroyed, so the entry must never be usable
        // again: delete it (a disabled entry is still deletable), then
        // release the slot.  If the delete fails, the entry stays disabled
        // and the slot stays reserved — a terminal state that blocks both
        // reuse of the dead handle and slot aliasing until the partition is
        // reset.
        vault(io).delete(self, io, key_id).await?;
        fp_slot_free(fp_id.vault_id(), fp_id.key_index());
        Ok(())
    }

    fn vault_key_disable(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let mut v = vault(io);
        v.disable(key_id)
    }

    fn vault_key_enable(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let mut v = vault(io);
        v.enable(key_id)
    }

    async fn vault_key_delete_by_session(
        &self,
        io: &impl HsmIo,
        session_id: HsmSessId,
    ) -> HsmResult<()> {
        // DeleteSessionOnly drops the session's bulk keys from the engine in
        // one message.  Collect the slots to release but don't free them until
        // the vault entries are gone: a freed slot could otherwise be
        // reallocated while a still-present entry references it (aliasing) if
        // the delete below fails.
        let sess = u16::from(session_id);
        fp_delete_session_only(self, io, sess).await?;
        let mut to_free = [0u8; NUM_FP_TABLES];
        vault(io).for_each_session_key(sess, |_key_id, kind, blob| {
            if is_bulk_kind(kind) {
                let bytes: &[u8] = blob;
                if bytes.len() != core::mem::size_of::<u16>() {
                    return Err(HsmError::InternalError);
                }
                let id = AesBulk256KeyId::from_bits(u16::from_le_bytes([bytes[0], bytes[1]]));
                let (vid, kidx) = (usize::from(id.vault_id()), id.key_index());
                if vid < to_free.len() && kidx < FP_MAX_SLOTS_PER_PART {
                    to_free[vid] |= 1 << kidx;
                }
            }
            Ok(())
        })?;
        vault(io).delete_by_session(self, io, sess).await?;
        fp_slots_free_bits(&to_free);
        Ok(())
    }

    async fn vault_clear(&self, io: &impl HsmIo) -> HsmResult<()> {
        // Partition reset: the engine drops this partition's bulk keys with
        // the accompanying function reset (matching the reference firmware, no
        // per-key delete here).  Clear the vault first, then free the slot
        // bitmap so the bits stay reserved across the vault await.
        let res_mask = PartStore::partition(io.pid()).map_or(0, |p| p.res_mask());
        vault(io).clear(self, io).await?;
        fp_slots_free_mask(res_mask);
        Ok(())
    }

    fn vault_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&DmaBuf> {
        let (table, off, len) = vault(io).key_location(key_id)?;
        Ok(blob_ref(table, off, len))
    }

    fn vault_key_len(&self, _io: &impl HsmIo, kind: HsmVaultKeyKind) -> HsmResult<u16> {
        KeyVault::<VaultStorage>::key_len(kind)
    }

    fn vault_key_kind(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        vault(io).key_kind(key_id)
    }

    fn vault_key_attrs(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        vault(io).key_attrs(key_id)
    }
}

// ---------------------------------------------------------------------------
// Fast-path (FP) bulk-key IPC helpers
// ---------------------------------------------------------------------------

use azihsm_fw_single_cell::SingleCell;

use crate::ipc::AesBulk256KeyId;
use crate::ipc::AesBulkKeyType;
use crate::ipc::AesKeyFlag;
use crate::ipc::IPC_MESSAGE_LENGTH;
use crate::ipc::IPC_MESSAGE_PAYLOAD_LEN;
use crate::ipc::IpcMessage;
use crate::ipc::IpcMessageDecoder;
use crate::ipc::IpcMessageEncoderTrait;
use crate::ipc::IpcMessageHeader;
use crate::ipc::IpcMessageKeyUpdate;
use crate::ipc::IpcMessageStatusCode;
use crate::ipc::IpcMessageType;
use crate::ipc::KeyUpdateAction;
use crate::ipc::KeyUpdateInfo;
use crate::pal::IpcChannel;

/// AES-256 bulk key length in bytes.
const FP_BULK_KEY_LEN: usize = 32;

/// FP application id reported to the fast-path engine.  The firmware
/// reports `short_app_id = 0` to the host, so the engine `app_id` is 0.
const FP_APP_ID: u8 = 0;

/// True for the AES bulk vault kinds mirrored in the fast-path engine
/// rather than stored as material in the vault.
fn is_bulk_kind(kind: HsmVaultKeyKind) -> bool {
    matches!(
        kind,
        HsmVaultKeyKind::AesGcmBulk256
            | HsmVaultKeyKind::AesGcmBulk256Unapproved
            | HsmVaultKeyKind::AesXtsBulk256
    )
}

/// Maximum FP bulk-key slots per resource-group table (FP addresses a key
/// within a table by a 0..=6 sub-index).
const FP_MAX_SLOTS_PER_PART: u8 = 7;

/// Number of global FP key-vault tables (resource groups), ids `0..=64`.
const NUM_FP_TABLES: usize = 65;

/// Per-table FP bulk-key slot occupancy bitmap (bit `i` set = slot `i` in
/// use).  Tables are global and each is owned by at most one partition;
/// a partition may own several (its `res_mask`), so a bulk key is placed
/// in a free slot of one of the calling partition's owned tables — the
/// same table-based scheme the HSM key vault uses, giving `7 × owned`
/// capacity rather than a single table's 7 slots.  The FP engine
/// addresses bulk keys by `(vault_id = table, key_index = slot)`.
static FP_SLOTS: SingleCell<[u8; NUM_FP_TABLES]> = SingleCell::new([0u8; NUM_FP_TABLES]);

/// Validate a partition id ([`HsmIo::pid`]) as the PCIe function number the
/// fast-path engine matches against.
///
/// The FP engine scopes a bulk key by PCIe function; the host's GCM SQE
/// carries that same PCIe function.  Partition ids already use the dense
/// PcieFunction numbering (PF `64`, VF `0..=63`), so a valid id passes
/// through unchanged; an id naming no PCIe function is rejected.
fn part_id_to_pcie_fn(part_id: u8) -> HsmResult<u8> {
    crate::pal::pfn_to_axi_id(part_id)
        .map(|_| part_id)
        .ok_or(HsmError::InvalidArg)
}

/// Allocate a free FP bulk-key slot from one of the partition's owned
/// resource-group tables (`res_mask` bit `t` set = table `t` is owned).
///
/// Returns `(vault_id, key_index)` — the owning table id and the assigned
/// 0..=6 slot — mirroring the HSM key vault's table-based allocation so
/// bulk-key capacity scales with the partition's owned tables.
fn fp_slot_alloc(res_mask: u128) -> HsmResult<(u8, u8)> {
    FP_SLOTS.with(|slots| {
        for (table, used) in slots.iter_mut().enumerate().take(NUM_FP_TABLES) {
            if res_mask & (1u128 << table) == 0 {
                continue; // table not owned by this partition
            }
            for bit in 0..FP_MAX_SLOTS_PER_PART {
                if *used & (1 << bit) == 0 {
                    *used |= 1 << bit;
                    return Ok((table as u8, bit));
                }
            }
        }
        Err(HsmError::NotEnoughSpace)
    })
}

/// Release a previously allocated FP bulk-key slot in table `vault_id`.
fn fp_slot_free(vault_id: u8, key_index: u8) {
    FP_SLOTS.with(|slots| {
        let idx = usize::from(vault_id);
        if idx < slots.len() && key_index < FP_MAX_SLOTS_PER_PART {
            slots[idx] &= !(1 << key_index);
        }
    });
}

/// Clear the slot bits set in `bits` (one bitmap byte per table).  Used to
/// release a batch of slots after their vault entries have been removed.
fn fp_slots_free_bits(bits: &[u8; NUM_FP_TABLES]) {
    FP_SLOTS.with(|slots| {
        for (used, clear) in slots.iter_mut().zip(bits.iter()) {
            *used &= !*clear;
        }
    });
}

/// Free every FP bulk-key slot in the tables owned by `res_mask`.
fn fp_slots_free_mask(res_mask: u128) {
    FP_SLOTS.with(|slots| {
        for (table, used) in slots.iter_mut().enumerate().take(NUM_FP_TABLES) {
            if res_mask & (1u128 << table) != 0 {
                *used = 0;
            }
        }
    });
}

/// Register a bulk key with the fast-path engine and record its 2-byte
/// handle in the vault.
///
/// The engine consumes AES-GCM / XTS bulk keys; the vault keeps only the
/// handle.  `session_id` is the vault binding — `Some` for a session-scoped
/// key (its id is the engine's create/delete match value), `None` for a
/// partition (app) key (which uses `0`).  If the vault write fails after the
/// engine create, the engine key is released so no slot leaks.
async fn fp_bulk_create(
    pal: &UnoHsmPal,
    io: &impl HsmIo,
    key: &DmaBuf,
    kind: HsmVaultKeyKind,
    session_id: Option<HsmSessId>,
    attrs: HsmVaultKeyAttrs,
) -> HsmResult<HsmKeyId> {
    let key_bytes: &[u8] = key;
    if key_bytes.len() != FP_BULK_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    let key_type = match kind {
        HsmVaultKeyKind::AesGcmBulk256 => AesBulkKeyType::Gcm,
        HsmVaultKeyKind::AesGcmBulk256Unapproved => AesBulkKeyType::GcmUnapproved,
        HsmVaultKeyKind::AesXtsBulk256 => AesBulkKeyType::Xts,
        _ => return Err(HsmError::InvalidKeyType),
    };

    // The engine scopes a bulk key by PCIe function, which `io.pid()` carries.
    let pcie_fn = part_id_to_pcie_fn(u8::from(io.pid()))?;
    // Place the key in a free slot of one of the partition's owned tables;
    // `(vault_id, key_index)` addresses it in the engine.
    let res_mask = PartStore::partition(io.pid()).map_or(0, |p| p.res_mask());
    let (vault_id, key_index) = fp_slot_alloc(res_mask)?;

    // The session id the key is scoped to is also the engine's create/delete
    // match value; app keys are unscoped and use 0.
    let session_only = session_id.is_some();
    let fp_session_id = session_id.map(u16::from).unwrap_or(0);

    let mut info = Zeroizing::new(KeyUpdateInfo {
        key_index,
        resource_id: vault_id,
        pfn: pcie_fn,
        action: KeyUpdateAction::Create.0,
        session_id: fp_session_id,
        app_id: FP_APP_ID,
        flag: AesKeyFlag::new()
            .with_session_only(session_only)
            .with_key_type(key_type)
            .into_bits(),
        key_data: [0u8; FP_BULK_KEY_LEN],
    });
    info.key_data.copy_from_slice(key_bytes);
    // `info` is scrubbed on drop, on every exit from this future.
    let sent = fp_send_key_update(pal, &info).await;
    // On failure the backend may already own the key; keep the slot reserved
    // (don't free it) so a later create can't alias it — reclaimed on reset.
    sent?;

    let bulk_id = AesBulk256KeyId::new()
        .with_key_index(key_index)
        .with_vault_id(vault_id)
        .into_bits();

    // The engine key now exists.  Any later failure (handle alloc or vault
    // create) must roll it back so its slot doesn't leak with no vault entry
    // pointing at it.
    let result = async {
        let id_bytes = pal.dma_alloc(io, core::mem::size_of::<u16>())?;
        id_bytes.copy_from_slice(&bulk_id.to_le_bytes());
        let app_id = u8::from(io.pid());
        vault(io)
            .create(
                pal,
                io,
                app_id,
                id_bytes,
                kind,
                session_id.map(u16::from),
                attrs,
            )
            .await
    }
    .await;
    match result {
        Ok(handle) => Ok(handle),
        Err(e) => {
            // Only release the slot if the backend delete confirms the key is
            // gone; otherwise keep it reserved so a live handle can't collide.
            if fp_bulk_delete(pal, io, bulk_id, fp_session_id, session_only)
                .await
                .is_ok()
            {
                fp_slot_free(vault_id, key_index);
            }
            Err(e)
        }
    }
}

/// Delete a single bulk key from the fast-path engine.  The caller frees
/// the HSM-side slot bit after its own vault mutation completes.
///
/// `fp_session_id` / `session_only` must match the create values (the engine
/// matches create against delete); callers read them from the vault entry.
async fn fp_bulk_delete(
    pal: &UnoHsmPal,
    io: &impl HsmIo,
    bulk_id: u16,
    fp_session_id: u16,
    session_only: bool,
) -> HsmResult<()> {
    let id = AesBulk256KeyId::from_bits(bulk_id);
    let pcie_fn = part_id_to_pcie_fn(u8::from(io.pid()))?;
    let info = KeyUpdateInfo {
        key_index: id.key_index(),
        resource_id: id.vault_id(),
        pfn: pcie_fn,
        action: KeyUpdateAction::Delete.0,
        session_id: fp_session_id,
        app_id: FP_APP_ID,
        flag: AesKeyFlag::new()
            .with_session_only(session_only)
            .into_bits(),
        key_data: [0u8; FP_BULK_KEY_LEN],
    };
    fp_send_key_update(pal, &info).await
}

/// Clear all of session `session_id`'s session-scoped bulk keys from the
/// fast-path engine in a single message — the engine iterates its table and
/// matches by session id + app id, mirroring the reference firmware's
/// close-session path.
async fn fp_delete_session_only(
    pal: &UnoHsmPal,
    io: &impl HsmIo,
    session_id: u16,
) -> HsmResult<()> {
    let pcie_fn = part_id_to_pcie_fn(u8::from(io.pid()))?;
    let info = KeyUpdateInfo {
        key_index: 0,
        resource_id: 0,
        pfn: pcie_fn,
        action: KeyUpdateAction::DeleteSessionOnly.0,
        session_id,
        app_id: FP_APP_ID,
        flag: AesKeyFlag::new().with_session_only(true).into_bits(),
        key_data: [0u8; FP_BULK_KEY_LEN],
    };
    fp_send_key_update(pal, &info).await
}

/// Send an `AesKeyUpdate` message to the bulk-crypto backend over the
/// HSM↔backend IPC channel and await the response, mapping a non-`Success`
/// reply to an error.
///
/// `info` is borrowed so the caller keeps the only owned copy (and scrubs it);
/// the encoded request is wrapped in [`Zeroizing`] so its copy of the raw key
/// material is scrubbed on any exit from this future, including a mid-send
/// drop.
async fn fp_send_key_update(pal: &UnoHsmPal, info: &KeyUpdateInfo) -> HsmResult<()> {
    let request = Zeroizing::new(
        IpcMessageKeyUpdate {
            header: IpcMessageHeader::new()
                .with_msg_op(IpcMessageKeyUpdate::OP as u32)
                .with_length(IpcMessageKeyUpdate::LEN as u32),
            info: *info,
            _rsvd: [0u8; IPC_MESSAGE_PAYLOAD_LEN - IpcMessageKeyUpdate::LEN],
        }
        .encode(),
    );

    let mut resp = [0u32; IPC_MESSAGE_LENGTH];
    pal.ipc
        .send(IpcChannel::FpMessage as u8, &request.data, &mut resp)
        .await;

    let header = IpcMessageDecoder::decode_header(&IpcMessage { data: resp })
        .map_err(|_| HsmError::InternalError)?;
    // A genuine FP reply sets the response bit; a spurious wake that left
    // the RX ring empty would leave `resp` zeroed (response=false), which
    // must not be mistaken for a `Success` (0) status.
    if !header.response() {
        return Err(HsmError::InternalError);
    }
    // FP echoes the request opcode; a mismatch means stale RX data, not our ack.
    if header.msg_op() != IpcMessageKeyUpdate::OP as u32 {
        return Err(HsmError::InternalError);
    }
    if header.status() != IpcMessageStatusCode::Success as u32 {
        return Err(HsmError::InternalError);
    }
    Ok(())
}
