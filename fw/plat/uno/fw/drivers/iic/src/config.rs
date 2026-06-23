// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IIC driver configuration types.

/// Per-channel configuration for [`IicDriver::init`](super::IicDriver::init).
#[derive(Debug, Clone, Copy)]
pub struct ChannelConfig {
    /// Physical channel index (shared for ISQ and ICQ).
    pub channel: u8,

    /// Base address of the ISQ ring buffer (8B-aligned).
    pub isq_base: u32,

    /// Base address of the IO_SQ receive buffer pool.
    pub io_pool_base: u32,

    /// Size of each receive buffer in bytes (e.g. 64).
    /// Must be a multiple of 16. Used as both the stride between
    /// buffers and encoded as `buf_size >> 4` for the hardware register.
    pub io_size: u32,

    /// Base address of the ICQ ring buffer (32B-aligned).
    pub icq_base: u32,

    /// Address where HW writes the ICQ tail shadow (32B-aligned).
    pub icq_tail_shadow: u32,

    /// Base address of the IO_META sidecar array.
    /// One entry per IO_SQ slot — recv() writes completion metadata here.
    pub io_meta_base: u32,

    /// Enable interrupt for this channel during init.
    pub interrupt: bool,
}
