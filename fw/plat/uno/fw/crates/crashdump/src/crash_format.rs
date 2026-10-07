// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! On-chip crash-dump layout for the Uno HSM (CP1) core.
//!
//! These structures are a byte-for-byte mirror of the reference `mcr-hsm`
//! `crashdump` format so the SP parser can decode a dump
//! written by either firmware. The header/body layout follows
//! `cp/hsm/docs/ras/crashdump.md` (section: *Production Code Crash Dump
//! Payload CP Admin, CP HSM, and FP core0-2*). All fields are little-endian
//! and the structs are `#[repr(C)]` with no padding.
//!
//! Two helper contexts feed [`crate::crashdump_save`]:
//! - [`CpuRegisterContext`] — the general-purpose register snapshot, either
//!   captured from a hardware [`ExceptionFrame`] or filled in by hand (panic
//!   records the handler's SP/PC, not source-location or message pointers).
//! - [`RegisterBlockContext`] — the SCB fault registers (`CFSR`/`MMFAR`/`BFAR`).

// Only required by the (currently disabled) Debug impl below.
// use core::fmt;

use cortex_m::peripheral::scb;
use cortex_m_rt::ExceptionFrame;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

/// CPU general-purpose register context captured at the point of failure.
#[derive(Default)]
pub struct CpuRegisterContext {
    /// Link register.
    pub lr: u32,
    /// Stack pointer (the *real* SP; see [`Self::from_exception_frame`]).
    pub sp: u32,
    /// Program counter / return address of the fault.
    pub pc: u32,
    /// General-purpose register r0.
    pub r0: u32,
    /// General-purpose register r1.
    pub r1: u32,
    /// General-purpose register r2.
    pub r2: u32,
    /// General-purpose register r3.
    pub r3: u32,
    /// General-purpose register r12.
    pub r12: u32,
}

impl CpuRegisterContext {
    /// Build a context from a hardware exception frame.
    ///
    /// Note: the SP inside the exception frame is *not* the SP at the time of
    /// the fault — the hardware has already pushed the frame. The `sp` field
    /// is left zero here; the crash handler is responsible for computing the
    /// real SP (frame address + `size_of::<ExceptionFrame>()`).
    pub fn from_exception_frame(ef: &ExceptionFrame) -> Self {
        Self {
            lr: ef.lr(),
            sp: 0,
            pc: ef.pc(),
            r0: ef.r0(),
            r1: ef.r1(),
            r2: ef.r2(),
            r3: ef.r3(),
            r12: ef.r12(),
        }
    }
}

/// Fault-status registers: `CFSR`, `MMFAR`, and `BFAR`.
pub struct RegisterBlockContext {
    /// Configurable Fault Status Register.
    pub cfsr: u32,
    /// Memory Management Fault Address Register.
    pub mmfar: u32,
    /// BusFault Address Register.
    pub bfar: u32,
}

impl RegisterBlockContext {
    /// Construct directly from raw register values (used by unit tests).
    pub fn new(cfsr: u32, mmfar: u32, bfar: u32) -> Self {
        Self { cfsr, mmfar, bfar }
    }

    /// Snapshot the fault-status registers from the System Control Block.
    pub fn from_register_block(rb: &scb::RegisterBlock) -> Self {
        Self {
            cfsr: rb.cfsr.read(),
            mmfar: rb.mmfar.read(),
            bfar: rb.bfar.read(),
        }
    }
}

/// Crash-dump header (see `cp/hsm/docs/ras/crashdump.md`).
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy, PartialEq)]
pub(crate) struct CrashDumpHeader {
    /// Magic number identifying the structure (dirty vs committed).
    pub magic: u32,

    /// Failure code of the crash.
    pub failure_code: u32,

    /// Version of the structure.
    pub crashdump_version: u16,

    /// Type of the core that generated the dump.
    pub core_type: u8,

    /// Type of the dump (release/debug).
    pub dump_type: u8,

    /// Crash type.
    pub crash_type: u8,

    /// Reserved for future use.
    pub _rsvd: u8,

    /// Size of the payload that follows the header.
    pub payload_size: u16,
}

/// Crash-dump body: the register snapshot, compliant with
/// `cp/hsm/docs/ras/crashdump.md`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy, PartialEq)]
pub(crate) struct CrashDumpBody {
    /// Stack pointer.
    pub stack_ptr: u32,

    /// The xPSR value during exception handling (indicates exception type).
    pub xpsr: u32,

    /// General-purpose register r0.
    pub r0: u32,

    /// General-purpose register r1.
    pub r1: u32,

    /// General-purpose register r2.
    pub r2: u32,

    /// General-purpose register r3.
    pub r3: u32,

    /// General-purpose register r12.
    pub r12: u32,

    /// Link register.
    pub lr: u32,

    /// Return address from the exception (PC where the exception happened).
    pub return_address: u32,

    /// xPSR register before the exception.
    pub xpsr_pre_exception: u32,

    /// HardFault Status Register.
    pub hfsr: u32,

    /// Configurable Fault Status Register.
    pub cfsr: u32,

    /// Memory Management Fault Address Register.
    pub mmfar: u32,

    /// BusFault Address Register.
    pub bfar: u32,

    /// Auxiliary Fault Status Register.
    pub afsr: u32,
}

/// A complete crash-dump block: header followed by body.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy, PartialEq)]
pub struct CrashDumpBlock {
    pub(crate) header: CrashDumpHeader,
    pub(crate) body: CrashDumpBody,
}

impl CrashDumpBlock {
    /// Dump type derived from the build profile: release = 0, debug = 1.
    #[cfg(not(debug_assertions))]
    pub fn get_dump_type() -> u8 {
        0x0
    }

    /// Dump type derived from the build profile: release = 0, debug = 1.
    #[cfg(debug_assertions)]
    pub fn get_dump_type() -> u8 {
        0x1
    }
}
