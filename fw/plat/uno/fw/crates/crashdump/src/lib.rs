// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Persistent crash-dump capture for the Uno HSM (CP1) core.
//!
//! On an unrecoverable fault the firmware serialises a compact register
//! snapshot into a fixed, reserved slot of HSM DTCM
//! (`0x2003_F400`, `0x400` bytes — see
//! [`hsm_dtcm`](azihsm_fw_uno_reg_soc::hsm_dtcm)). The SP later reads that slot
//! and decodes it with the shared crash-dump format, so a CP crash is diagnosable
//! post-mortem even though the CP core is wedged.
//!
//! The byte layout ([`crash_format`]) and the dirty→committed magic protocol
//! ([`crash_mgr`]) are a faithful port of the reference `mcr-hsm` `crashdump`
//! crate; the SP parser is shared between the two firmwares. Uno is CP1/HSM
//! only, so the `core_type` byte is the constant [`HSM_CORE_ID`] rather than a
//! runtime CPU-id lookup.
//!

#![cfg_attr(not(test), no_std)]
// This crate reinterprets a fixed DTCM address as a byte slice and reads the
// architectural SCB block; both require `unsafe`. The fault path is already
// halting, so the usual aliasing concerns do not apply.
#![allow(unsafe_code)]

pub mod crash_format;
pub mod crash_mgr;
pub mod failure_code;

use azihsm_fw_uno_reg_soc::hsm_dtcm::CRASHDUMP_BASE_OFFSET;
use azihsm_fw_uno_reg_soc::hsm_dtcm::CRASHDUMP_BASE_SIZE;
use azihsm_fw_uno_reg_soc::hsm_dtcm::HSM_DTCM_BASE;
use crash_format::CpuRegisterContext;
use crash_format::RegisterBlockContext;
use crash_mgr::CrashDump;
use crash_mgr::CrashDumpManager;
use failure_code::FailureCode;

/// Core-type byte written into the crash-dump header.
///
/// Uno runs only the CP1/HSM core; the reference enumerates this as
/// `CoreId::Hsm = 2`, and the SP parser expects `2` for an HSM dump.
const HSM_CORE_ID: u8 = 2;

/// Borrow the reserved crash-dump slot in HSM DTCM as a mutable byte slice.
fn crashdump_region() -> &'static mut [u8] {
    // Absolute base `0x2003_F400`; length `0x400`.
    const ADDR: u32 = HSM_DTCM_BASE + CRASHDUMP_BASE_OFFSET;
    // SAFETY: `ADDR`/`CRASHDUMP_BASE_SIZE` name the fixed, reserved crashdump
    // region carved out of HSM DTCM by the linker/RDL map (never linker-managed
    // stack or `.bss`). It is always mapped on the target, and `crashdump_save`
    // is only reached from a halting fault context, so no other reference to
    // this region is live.
    unsafe { core::slice::from_raw_parts_mut(ADDR as *mut u8, CRASHDUMP_BASE_SIZE as usize) }
}

/// Capture a crash dump into the reserved HSM DTCM slot.
///
/// # Arguments
/// * `cpu_register_context` - captured general-purpose register snapshot.
/// * `failure_code` - the classified [`FailureCode`] for the crash.
/// * `additional_info` - optional opaque tail (e.g. a panic message) appended
///   after the fixed block.
pub fn crashdump_save(
    cpu_register_context: &CpuRegisterContext,
    failure_code: FailureCode,
    additional_info: Option<&str>,
) {
    let mut mgr = CrashDumpManager::new(crashdump_region());

    // SAFETY: `SCB::PTR` is the fixed architectural System Control Block
    // address, always mapped on ARMv7-M; the borrow is read-only and used
    // immediately to snapshot the fault-status registers.
    let register_block =
        RegisterBlockContext::from_register_block(unsafe { &*cortex_m::peripheral::SCB::PTR });

    mgr.create_dump(
        failure_code as u32,
        cpu_register_context,
        &register_block,
        HSM_CORE_ID,
        additional_info.unwrap_or(""),
    );
}

/// Capture a crash dump with a **formatted** tail message.
///
/// Identical to [`crashdump_save`] but renders `args` directly into the
/// reserved crash-dump tail via a bounded sink — no allocator or scratch
/// buffer. This captures formatted panics (`panic!("x = {x}")`), whose text
/// the `Option<&str>` path in [`crashdump_save`] cannot express. The message
/// is truncated to the tail capacity of the reserved region.
///
/// # Arguments
/// * `cpu_register_context` - captured general-purpose register snapshot.
/// * `failure_code` - the classified [`FailureCode`] for the crash.
/// * `args` - the formatted message (e.g. `format_args!("{info}")`) rendered
///   into the crash-dump tail.
pub fn crashdump_save_fmt(
    cpu_register_context: &CpuRegisterContext,
    failure_code: FailureCode,
    args: core::fmt::Arguments<'_>,
) {
    let mut mgr = CrashDumpManager::new(crashdump_region());

    // SAFETY: `SCB::PTR` is the fixed architectural System Control Block
    // address, always mapped on ARMv7-M; the borrow is read-only and used
    // immediately to snapshot the fault-status registers.
    let register_block =
        RegisterBlockContext::from_register_block(unsafe { &*cortex_m::peripheral::SCB::PTR });

    mgr.create_dump_fmt(
        failure_code as u32,
        cpu_register_context,
        &register_block,
        HSM_CORE_ID,
        args,
    );
}
