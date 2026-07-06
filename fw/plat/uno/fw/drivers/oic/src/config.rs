// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OIC driver configuration types.

/// Per-channel configuration for [`OicDriver::init`](super::OicDriver::init).
#[derive(Debug, Clone, Copy)]
pub struct ChannelConfig {
    /// Physical channel index (shared for OSQ and OCQ).
    pub channel: u8,

    /// Base address of the OSQ ring buffer (16B-aligned).
    pub osq_base: u32,

    /// Base address of the OCQ ring buffer (32B-aligned).
    pub ocq_base: u32,

    /// Address where HW writes the OCQ tail shadow (32B-aligned).
    pub ocq_tail_shadow: u32,

    /// Base address of the IO_CQ array in DTCM.
    pub io_cq_base: u32,

    /// Base address of the IO_META sidecar array in DTCM.
    pub io_meta_base: u32,

    /// Enable interrupt for this channel during init.
    pub interrupt: bool,
}
