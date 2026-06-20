// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pre-init trampoline for dual-core boot.
//!
//! Both CP0 (Admin) and CP1 (HSM) boot from the same binary at ITCM
//! 0x00000000. This module provides a `__pre_init` naked function that
//! runs before any Rust runtime initialization (before stack usage,
//! before .data/.bss init) to detect which core we are and redirect
//! CP0 to the admin firmware at 0x20020000.
//!
//! CP1 (HSM core) simply returns and continues into the Embassy runtime.
//!
//! # Safety
//!
//! This code runs with no stack and no initialized RAM. It must remain
//! as naked assembly — no Rust code or cortex-m crate calls are valid
//! at this point.

/// CPU ID register address (DualCpM7 base + CP_ID offset)
const CPU_ID_REG_ADDR: u32 = 0xB020_0000;

/// Admin core initiator ID value
const ADMIN_CORE_ID: u32 = 0x2;

/// Admin application base address in DTCM
const ADMIN_APP_BASE: u32 = 0x2002_0000;

/// Vector Table Offset Register (VTOR) address in SCB
const VTOR_REG_ADDR: u32 = 0xE000_ED08;

/// Pre-init trampoline that redirects Admin core (CP0) to admin-app.
///
/// Checks the CPU ID register. CP0 is redirected to the admin firmware
/// vector table at `ADMIN_APP_BASE`. CP1 returns to continue cortex-m-rt
/// boot.
#[unsafe(naked)]
#[unsafe(export_name = "__pre_init")]
pub extern "C" fn boot_trampoline() {
    core::arch::naked_asm!(
        // Read CPU ID register
        "ldr r0, ={cpu_id_reg}",
        "ldr r0, [r0]",
        "and r0, r0, #0x3F",
        "cmp r0, #{admin_id}",
        "bne 1f",

        // Admin core (CP0): jump to admin-app at 0x20020000
        "ldr r0, ={admin_base}",
        "ldr r1, [r0]",
        "ldr r2, [r0, #4]",
        "orr r2, r2, #1",

        "cpsid i",

        "ldr r3, ={vtor_reg}",
        "str r0, [r3]",
        "dsb sy",
        "isb",

        "mov r3, #0",
        "mrs r3, CONTROL",
        "bics r3, r3, #2",
        "msr CONTROL, r3",
        "isb",

        "msr MSP, r1",
        "cpsie i",
        "bx r2",

        // HSM core (CP1): return to continue cortex-m-rt boot
        "1:",
        "bx lr",

        cpu_id_reg = const CPU_ID_REG_ADDR,
        admin_id = const ADMIN_CORE_ID,
        admin_base = const ADMIN_APP_BASE,
        vtor_reg = const VTOR_REG_ADDR,
    );
}
