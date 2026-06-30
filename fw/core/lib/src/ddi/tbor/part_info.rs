// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartInfo` command handler.
//!
//! `PartInfo` is an out-of-session info command: it reports device-level
//! fields (kind, FIPS status) together with the bound partition's
//! lifecycle and identity (state, generation counter, owner/manufacturer
//! SVN, the Partition ID, and the raw ECC-P384 identity public key). It
//! is the TBOR analogue of the MBOR `GetDeviceInfo` command combined
//! with the partition identity (Partition ID + identity public key).
//!
//! No session is required. `handle_io` already drops every IO whose
//! partition is not `Enabled`/`Initializing`, so by the time this
//! handler runs the identity key pair (and therefore the PID and its
//! public key) is always present; the identity reads use `?` purely as
//! defense-in-depth.

use azihsm_fw_ddi_tbor_types::tbor_int::U32;
use azihsm_fw_ddi_tbor_types::tbor_int::U64;
use azihsm_fw_ddi_tbor_types::DeviceKind;
use azihsm_fw_ddi_tbor_types::PartStateId;
use azihsm_fw_ddi_tbor_types::TborPartInfoResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::part_state;

/// Module FIPS approval status carried in the TBOR response header flag.
/// `false` matches the MBOR `get_device_info` handler — uno firmware is
/// not yet FIPS-approved.
const FIPS_APPROVED: bool = false;

/// Handle a TBOR `PartInfo` request.
///
/// The caller (`dispatch`) has already structurally validated the
/// buffer via [`RequestView::parse`] and confirmed the opcode is
/// `PART_INFO`, so the request body is not re-inspected here. This
/// handler gathers the device/partition fields and encodes the
/// response.
pub(crate) fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    _req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let part_state_val = part_state::part_state(pal, io)? as u8;
    let generation = part_state::part_gen(pal, io)?;
    let owner_svn = part_state::part_owner_svn(pal);
    let mfgr_svn = part_state::part_mfgr_svn(pal);
    let pid = part_state::part_id(pal, io)?;
    let pid_pub_key = part_state::part_id_pub_key(pal, io)?;

    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborPartInfoResp::encode(buf, 0, FIPS_APPROVED)?
            .device_kind(DeviceKind::Physical)?
            .part_state(PartStateId(part_state_val))?
            .generation(U32::new(generation))?
            .owner_svn(U64::new(owner_svn))?
            .mfgr_svn(U64::new(mfgr_svn))?
            .pid(pid)?
            .pid_pub_key(pid_pub_key)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
