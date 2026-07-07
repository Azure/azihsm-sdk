// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Copies all `u32` words from `src` into `dst`.
///
/// On ARM targets this uses `LDM`/`STM` instructions for bulk transfer.
/// On other targets it falls back to `copy_from_slice`.
///
/// # Arguments
///
/// * `dst` - The destination slice that receives the copied words.
/// * `src` - The source slice that provides the words to copy.
///
/// # Panics
///
/// Debug-asserts that `dst.len() == src.len()`. In release builds,
/// mismatched lengths cause undefined behavior on ARM (unsafe asm).
/// All callers in this crate pass const-generic fixed-size arrays.
#[inline(always)]
pub fn copy_slice(dst: &mut [u32], src: &[u32]) {
    debug_assert_eq!(dst.len(), src.len());
    #[cfg(target_arch = "arm")]
    unsafe {
        copy_words(dst.as_mut_ptr(), src.as_ptr(), dst.len());
    }
    #[cfg(not(target_arch = "arm"))]
    dst.copy_from_slice(src);
}

#[cfg(target_arch = "arm")]
use core::arch::asm;

/// # Safety
/// `dst` and `src` must be valid for `len` words, non-overlapping, and 4-byte aligned.
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn copy_words(dst: *mut u32, src: *const u32, len: usize) {
    let mut s = src;
    let mut d = dst;
    let mut remaining = len;

    // Bulk: 8 words (32 bytes) per iteration via LDM/STM
    while remaining >= 8 {
        unsafe {
            asm!(
                "ldm {src}!, {{r2, r3, r4, r5, r8, r9, r10, r11}}",
                "stm {dst}!, {{r2, r3, r4, r5, r8, r9, r10, r11}}",
                src = inout(reg) s,
                dst = inout(reg) d,
                out("r2") _,
                out("r3") _,
                out("r4") _,
                out("r5") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                options(nostack),
            );
        }
        remaining -= 8;
    }

    // Tail: 4 words via LDM/STM
    if remaining >= 4 {
        unsafe {
            asm!(
                "ldm {src}!, {{r2, r3, r4, r5}}",
                "stm {dst}!, {{r2, r3, r4, r5}}",
                src = inout(reg) s,
                dst = inout(reg) d,
                out("r2") _,
                out("r3") _,
                out("r4") _,
                out("r5") _,
                options(nostack),
            );
        }
        remaining -= 4;
    }

    // Final tail: scalar copy for remaining 0-3 words
    while remaining > 0 {
        unsafe {
            asm!(
                "ldr {tmp}, [{src}], #4",
                "str {tmp}, [{dst}], #4",
                src = inout(reg) s,
                dst = inout(reg) d,
                tmp = out(reg) _,
                options(nostack),
            );
        }
        remaining -= 1;
    }
}
