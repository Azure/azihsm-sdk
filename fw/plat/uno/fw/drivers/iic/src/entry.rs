// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ICQ and ISQ queue entry types for the IIC driver.
//!
//! These structs define the in-memory layout of queue entries that
//! hardware reads (ISQ) or writes (ICQ). They live in DTCM or SRAM
//! at addresses provided via [`ChannelConfig`](crate::ChannelConfig).

use bitfield_struct::bitfield;

// ── ISQ Entry (8 bytes) ────────────────────────────────────────────

/// ISQ entry — firmware posts receive buffer addresses for hardware
/// to DMA inbound data into.
#[repr(C)]
pub struct IsqEntry {
    /// Lower 32 bits of the receive buffer address.
    pub addr_lo: u32,

    /// Upper 32 bits of the receive buffer address.
    pub addr_hi: u32,
}

// ── ICQ Entry (16 bytes) ───────────────────────────────────────────

/// ICQ info dword (DW2) — queue index, queue ID, and AXI bus ID.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct IcqInfo {
    /// Index within the source queue.
    #[bits(16)]
    pub queue_index: u16,

    /// Source queue identifier.
    #[bits(8)]
    pub queue_id: u8,

    /// AXI bus ID (source controller identifier).
    #[bits(8)]
    pub axi_id: u8,
}

/// ICQ status dword (DW3) — success flag.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct IcqStatus {
    /// Reserved.
    #[bits(31)]
    _rsvd: u32,

    /// Success flag (true = success, false = failure).
    #[bits(1)]
    pub success: bool,
}

/// ICQ entry — 16 bytes. Hardware writes this after completing an
/// inbound DMA transfer into a receive buffer.
#[repr(C)]
pub struct IcqEntry {
    /// Lower 32 bits of the receive buffer address.
    pub addr_lo: u32,

    /// Upper 32 bits of the receive buffer address.
    pub addr_hi: u32,

    /// Entry info (queue index, queue ID, AXI bus ID).
    pub info: IcqInfo,

    /// Entry status (success flag).
    pub status: IcqStatus,
}

impl IcqEntry {
    /// Returns the receive buffer address recorded in this completion entry.
    #[inline]
    pub fn buffer_addr(&self) -> u32 {
        self.addr_lo
    }
}

// ── IO Meta Entry (8 bytes) ────────────────────────────────────────

/// IO Meta entry — per-slot sidecar written by the driver during recv.
///
/// The caller reads `io_meta[index]` after recv returns the slot index.
#[repr(C)]
pub struct IoMetaEntry {
    /// Source controller identifier.
    pub controller_id: u8,

    /// Reserved padding.
    _pad0: [u8; 3],

    /// Source queue identifier (low 16 bits) and queue index (high 16 bits).
    pub queue: IoMetaQueue,
}

/// IO Meta queue dword — queue_id + queue_index packed.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct IoMetaQueue {
    /// Source queue identifier.
    #[bits(16)]
    pub queue_id: u16,

    /// Index within the source queue.
    #[bits(16)]
    pub queue_index: u16,
}
