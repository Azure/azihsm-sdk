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
use azihsm_fw_uno_reg_soc::psram::HSM_TO_FP_IPC_TX_PI_OFFSET;
use azihsm_fw_uno_reg_soc::psram::HSM_TO_FP_IPC_TX_RING_COUNT;
use azihsm_fw_uno_reg_soc::psram::HSM_TO_FP_IPC_TX_RING_OFFSET;
use azihsm_fw_uno_reg_soc::psram::HSM_TO_FP_IPC_TX_RING_STRIDE;
use azihsm_fw_uno_reg_soc::psram::PSRAM_BASE;

use crate::UnoHsmPal;

#[inline]
pub(crate) fn vault(io: &impl HsmIo) -> KeyVault<VaultStorage> {
    // Out-of-range partitions own no tables (empty mask → no storage).
    let res_mask = PartStore::partition(io.pid()).map_or(0, |p| p.res_mask());
    KeyVault::new(VaultStorage::new(res_mask))
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
        let app_id = u8::from(io.pid());
        let session = session_id.map(u16::from);
        let mut v = vault(io);
        v.create(self, io, app_id, key, kind, session, attrs).await
    }

    async fn bulk_key_create(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        kind: HsmVaultKeyKind,
        session_id: HsmSessId,
        session_only: bool,
    ) -> HsmResult<u16> {
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

        let part_id = u8::from(io.pid());
        // FP scopes a bulk key by PCIe function.  `io.pid()` is the raw SoC
        // partition/AXI id (a MemoryLocation id) used elsewhere in the HSM;
        // the fast-path engine instead matches against the PCIe function
        // number carried on the host's GCM SQE, so translate before sending.
        let pcie_fn = part_id_to_pcie_fn(part_id)?;
        // Place the key in a free slot of one of the partition's owned
        // resource-group tables.  `vault_id` is that table id and
        // `key_index` the 0..=6 slot; together they address the key in FP.
        let res_mask = PartStore::partition(io.pid()).map_or(0, |p| p.res_mask());
        let (vault_id, key_index) = fp_slot_alloc(res_mask)?;

        let mut info = KeyUpdateInfo {
            key_index,
            resource_id: vault_id,
            pfn: pcie_fn,
            action: KeyUpdateAction::Create.0,
            // Scope the FP key to the creating session so later
            // fast-path GCM ops (which carry the session id) match.  The
            // firmware currently reports `short_app_id = 0` to the host,
            // so the FP `app_id` matches at 0.
            session_id: u16::from(session_id),
            app_id: 0,
            flag: AesKeyFlag::new()
                .with_session_only(session_only)
                .with_key_type(key_type)
                .into_bits(),
            key_data: [0u8; FP_BULK_KEY_LEN],
        };
        info.key_data.copy_from_slice(key_bytes);

        match fp_send_key_update(self, info).await {
            Ok(()) => Ok(AesBulk256KeyId::new()
                .with_key_index(key_index)
                .with_vault_id(vault_id)
                .into_bits()),
            Err(e) => {
                fp_slot_free(vault_id, key_index);
                Err(e)
            }
        }
    }

    async fn bulk_key_delete(&self, io: &impl HsmIo, bulk_key_id: u16) -> HsmResult<()> {
        let id = AesBulk256KeyId::from_bits(bulk_key_id);
        let part_id = u8::from(io.pid());
        let pcie_fn = part_id_to_pcie_fn(part_id)?;
        let info = KeyUpdateInfo {
            key_index: id.key_index(),
            resource_id: id.vault_id(),
            pfn: pcie_fn,
            action: KeyUpdateAction::Delete.0,
            session_id: 0,
            app_id: 0,
            flag: 0,
            key_data: [0u8; FP_BULK_KEY_LEN],
        };
        fp_send_key_update(self, info).await?;
        fp_slot_free(id.vault_id(), id.key_index());
        Ok(())
    }

    async fn vault_key_delete(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        // Bulk keys keep only a 2-byte handle in the vault; the actual key
        // material lives in the bulk-crypto backend.  Snapshot the handle
        // synchronously, remove the vault entry first (making it invisible
        // to other handlers atomically w.r.t. the vault), then release the
        // backend slot.  If the backend delete fails the FP key stays
        // live and its handle would remain usable by the host — surface
        // the error so the caller knows deletion did not fully complete.
        let bulk_id = matches!(
            self.vault_key_kind(io, key_id),
            Ok(HsmVaultKeyKind::AesGcmBulk256
                | HsmVaultKeyKind::AesGcmBulk256Unapproved
                | HsmVaultKeyKind::AesXtsBulk256)
        )
        .then(|| {
            self.vault_key(io, key_id).ok().and_then(|b| {
                let bytes: &[u8] = b;
                (bytes.len() == core::mem::size_of::<u16>())
                    .then(|| u16::from_le_bytes([bytes[0], bytes[1]]))
            })
        })
        .flatten();

        let mut v = vault(io);
        v.delete(self, io, key_id).await?;

        if let Some(bulk_id) = bulk_id {
            self.bulk_key_delete(io, bulk_id).await?;
        }
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
        // TODO(aes-gcm follow-up): session-tagged bulk keys are dropped
        // from the vault here but their backend slots are not released.
        // The reference firmware handles this via per-session bulk-key
        // tracking on the partition state (see `close_session` FSM +
        // `AesBulk256Cmd::DeleteKey`).  Porting that tracking model is
        // out of scope for this AES-GCM bring-up; explicit `DeleteKey`
        // DDI still routes through `vault_key_delete` and releases the
        // backend slot correctly.
        let mut v = vault(io);
        v.delete_by_session(self, io, u16::from(session_id)).await
    }

    async fn vault_clear(&self, io: &impl HsmIo) -> HsmResult<()> {
        // TODO(aes-gcm follow-up): partition reset drops the vault
        // entries but does not release backend bulk-key slots.  See the
        // note on `vault_key_delete_by_session` for the same reason.
        let mut v = vault(io);
        v.clear(self, io).await
    }

    fn vault_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&DmaBuf> {
        let (table, off, len) = vault(io).key_location(key_id)?;
        let addr = VaultStorage::blob_addr(table) + off;
        // SAFETY: `key_location` validated the key is live; `addr..addr+len`
        // lies within that table's 'static GSRAM blob region.
        Ok(unsafe { DmaBuf::from_raw(core::slice::from_raw_parts(addr as *const u8, len)) })
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

/// Translate a raw partition id ([`HsmIo::pid`], a SoC MemoryLocation id)
/// into the PCIe function number the fast-path engine matches against.
///
/// The FP engine scopes a bulk key by PCIe function; the host's GCM SQE
/// carries that same PCIe function.  The PF's MemoryLocation id `0x10`
/// maps to PCIe function `64`; VF MemoryLocation ids `0x20..=0x5F` map to
/// VF functions `0..=63`.
fn part_id_to_pcie_fn(part_id: u8) -> HsmResult<u8> {
    const MEM_LOC_PF: u8 = 0x10;
    const MEM_LOC_VF_START: u8 = 0x20;
    const MEM_LOC_VF_END: u8 = 0x5F;
    const PCIE_FN_PF: u8 = 64;
    match part_id {
        MEM_LOC_PF => Ok(PCIE_FN_PF),
        MEM_LOC_VF_START..=MEM_LOC_VF_END => Ok(part_id - MEM_LOC_VF_START),
        _ => Err(HsmError::InvalidArg),
    }
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

/// Send an `AesKeyUpdate` message to FP over the HSM↔FP IPC channel and
/// await the response, mapping a non-`Success` status to an error.
///
/// The message body contains raw 32-byte AES key material.  After the
/// exchange completes the corresponding PSRAM TX ring slot still holds
/// that material until the ring wraps; zero it out here so the plaintext
/// key does not linger in shared SRAM.  The channel is single-use by the
/// HSM and the IPC driver serialises callers, so we can safely observe
/// the PI value we sent to and clear the slot we just occupied.
async fn fp_send_key_update(pal: &UnoHsmPal, info: KeyUpdateInfo) -> HsmResult<()> {
    let msg = IpcMessageKeyUpdate {
        header: IpcMessageHeader::new()
            .with_msg_op(IpcMessageKeyUpdate::OP as u32)
            .with_length(IpcMessageKeyUpdate::LEN as u32),
        info,
        _rsvd: [0u8; IPC_MESSAGE_PAYLOAD_LEN - IpcMessageKeyUpdate::LEN],
    };
    let request = msg.encode();

    // Snapshot the TX PI before the send; the IPC driver writes to this
    // slot and advances PI atomically, so the slot we need to zero is the
    // one at this observed index.
    // SAFETY: TX PI is a fixed 32-bit MMIO register in PSRAM; a plain
    // volatile read is race-free against the FP-side reader.
    let tx_slot =
        unsafe { ((PSRAM_BASE + HSM_TO_FP_IPC_TX_PI_OFFSET) as *const u32).read_volatile() }
            % HSM_TO_FP_IPC_TX_RING_COUNT;

    let mut resp = [0u32; IPC_MESSAGE_LENGTH];
    pal.ipc
        .send(IpcChannel::FpMessage as u8, &request.data, &mut resp)
        .await;

    // Zero the PSRAM TX slot that held the 32-byte AES key.  The FP has
    // already consumed the message (the response bit is only set after
    // the read); subsequent sends target later slots (PI has advanced),
    // so this write does not race with the driver.
    // SAFETY: the slot is a fixed `HSM_TO_FP_IPC_TX_RING_STRIDE`-byte
    // region in PSRAM, aligned and sized for `u32` writes.
    let slot_addr =
        PSRAM_BASE + HSM_TO_FP_IPC_TX_RING_OFFSET + tx_slot * HSM_TO_FP_IPC_TX_RING_STRIDE;
    let words = (HSM_TO_FP_IPC_TX_RING_STRIDE / 4) as usize;
    for i in 0..words {
        unsafe {
            ((slot_addr as usize + i * 4) as *mut u32).write_volatile(0);
        }
    }

    let header = IpcMessageDecoder::decode_header(&IpcMessage { data: resp })
        .map_err(|_| HsmError::InternalError)?;
    // A genuine FP reply sets the response bit; a spurious wake that left
    // the RX ring empty would leave `resp` zeroed (response=false), which
    // must not be mistaken for a `Success` (0) status.
    if !header.response() {
        return Err(HsmError::InternalError);
    }
    if header.status() != IpcMessageStatusCode::Success as u32 {
        return Err(HsmError::InternalError);
    }
    Ok(())
}
