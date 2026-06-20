// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GDMA driver configuration types.

/// Per-channel configuration for [`GdmaDriver::init`](super::GdmaDriver::init).
#[derive(Debug, Clone, Copy)]
pub struct ChannelConfig {
    /// Physical channel index shared by the SQ and CQ register arrays.
    pub channel: u8,

    /// Base address of the SQ ring buffer (64B-aligned).
    pub sq_base: u32,

    /// Base address of the CQ ring buffer (16B-aligned).
    pub cq_base: u32,

    /// Address where hardware mirrors the CQ tail.
    pub cq_tail_shadow: u32,

    /// Address where hardware mirrors the SQ head.
    pub sq_head_shadow: u32,

    /// Whether to arm the CQ interrupt bit on init.
    pub interrupt: bool,
}
