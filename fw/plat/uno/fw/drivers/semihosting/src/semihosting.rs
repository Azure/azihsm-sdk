// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub fn sys_exit(code: u32) {
    unsafe {
        core::arch::asm!(
            "mov r0, #0x18",
            "mov r1, {code}",
            "bkpt #0xAB",
            code = in(reg) code,
            out("r0") _,
            out("r1") _,
        );
    }
}

/// Signal READY to the host via custom semihosting operation.
pub fn sys_ready() {
    unsafe {
        core::arch::asm!(
            "mov r0, #0x100",
            "mov r1, #0",
            "bkpt #0xAB",
            out("r0") _,
            out("r1") _,
        );
    }
}

/// Write a null-terminated byte slice via SYS_WRITE0 (single BKPT trap).
pub fn sys_write0(buf: &[u8]) {
    unsafe {
        core::arch::asm!(
            "mov r0, #0x04",
            "mov r1, {ptr}",
            "bkpt #0xAB",
            ptr = in(reg) buf.as_ptr(),
            out("r0") _,
            out("r1") _,
        );
    }
}
