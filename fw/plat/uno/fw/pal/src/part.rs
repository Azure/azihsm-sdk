// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmPartitionManager`] stub for the Uno PAL.
//!
//! Partition management uses the property-based API introduced in
//! `part-prop-api`.  All property accessors return
//! [`HsmError::UnsupportedCmd`] — this stub does not yet maintain any
//! backing store.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartitionManager;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::PartPropId;

use crate::UnoHsmPal;

impl HsmPartitionManager for UnoHsmPal {
    fn part_prop_get_u8(&self, _io: &impl HsmIo, id: PartPropId, _idx: u16) -> HsmResult<u8> {
        // Return PartState::Enabled (2) for STATE so partition_enabled()
        // passes and IOs are not dropped.
        if id == PartPropId::STATE {
            return Ok(2); // PartState::Enabled
        }
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_u8(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u8,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_u16(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<u16> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_u16(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u16,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_u32(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<u32> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_u32(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u32,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_u64(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<u64> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_u64(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u64,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_bool(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<bool> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_bool(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: bool,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_bytes<'a>(
        &'a self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
    ) -> HsmResult<&'a DmaBuf> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_bytes(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _data: &DmaBuf,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_clear(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }
}
