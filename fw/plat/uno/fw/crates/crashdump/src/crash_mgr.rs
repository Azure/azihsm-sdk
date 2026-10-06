// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crash-dump writer: serialises a [`CrashDumpBlock`] into a backing byte
//! region using a dirty→committed magic protocol so a partially written dump
//! is never mistaken for a complete one.
//!
//! The block is written with the *dirty* magic first; the trailing
//! `additional_info` bytes (e.g. a panic message) are appended after the
//! fixed block; then the first word is overwritten with the *committed*
//! magic. A reader (the SP parser) treats a block whose magic is not
//! `MDmp` as absent/incomplete.

use core::fmt;
use core::mem::size_of;

use zerocopy::IntoBytes;

use crate::crash_format::CpuRegisterContext;
use crate::crash_format::CrashDumpBlock;
use crate::crash_format::CrashDumpBody;
use crate::crash_format::CrashDumpHeader;
use crate::crash_format::RegisterBlockContext;

const DUMP_HEADER_VERSION: u16 = 0x1;
const DUMP_HEADER_MAGIC_COMITTED: u32 = 0x4D44_6D70u32; // "MDmp"
const DUMP_HEADER_MAGIC_DIRTY: u32 = 0x2BB2_928F; // ~MDmp

const HEADER_SIZE: usize = size_of::<CrashDumpHeader>();
const BODY_SIZE: usize = size_of::<CrashDumpBody>();
const BLOCK_SIZE: usize = size_of::<CrashDumpBlock>();

pub(crate) trait CrashDump {
    fn create_dump(
        &mut self,
        failure_code: u32,
        cpu_reg_context: &CpuRegisterContext,
        register_block: &RegisterBlockContext,
        cpu_id: u8,
        additional_info: &str,
    );

    /// As [`create_dump`](Self::create_dump) but renders a formatted message
    /// straight into the reserved tail via a bounded sink (no allocator /
    /// scratch buffer). Captures formatted panics; truncates to tail capacity.
    fn create_dump_fmt(
        &mut self,
        failure_code: u32,
        cpu_reg_context: &CpuRegisterContext,
        register_block: &RegisterBlockContext,
        cpu_id: u8,
        args: fmt::Arguments<'_>,
    );
}

/// Build a crash-dump header with the *dirty* magic. `payload_size` is the
/// combined body + tail length; the tail length may be patched in later once
/// known (see [`CrashDumpManager::create_dump_fmt`]).
fn build_header(failure_code: u32, cpu_id: u8, payload_size: u16) -> CrashDumpHeader {
    CrashDumpHeader {
        magic: DUMP_HEADER_MAGIC_DIRTY,
        failure_code,
        crashdump_version: DUMP_HEADER_VERSION,
        core_type: cpu_id,
        dump_type: CrashDumpBlock::get_dump_type(),
        crash_type: 0,
        _rsvd: 0u8,
        payload_size,
    }
}

/// Build the crash-dump body from the captured register snapshot. Fields the
/// uno port does not populate (`xpsr`, `xpsr_pre_exception`, `hfsr`, `afsr`)
/// are left zero, matching the reference for the SP parser.
fn build_body(ctx: &CpuRegisterContext, rb: &RegisterBlockContext) -> CrashDumpBody {
    CrashDumpBody {
        stack_ptr: ctx.sp,
        xpsr: 0,
        r0: ctx.r0,
        r1: ctx.r1,
        r2: ctx.r2,
        r3: ctx.r3,
        r12: ctx.r12,
        lr: ctx.lr,
        return_address: ctx.pc,
        xpsr_pre_exception: 0,
        hfsr: 0,
        cfsr: rb.cfsr,
        mmfar: rb.mmfar,
        bfar: rb.bfar,
        afsr: 0,
    }
}

/// Bounded [`fmt::Write`] sink over the crash-dump tail region.
///
/// Copies as many bytes as fit after the fixed block and silently drops the
/// rest, so rendering a panic message can never overflow the reserved DTCM
/// region or panic — which, inside a panic handler, would abort the core.
/// `len` tracks the bytes actually written (the committed tail size). A byte
/// cap can split a trailing multi-byte UTF-8 char; the SP reads the tail as
/// raw bytes, so a truncated diagnostic string is acceptable.
struct DtcmTailWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl fmt::Write for DtcmTailWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let remaining = self.buf.len() - self.len;
        let n = remaining.min(s.len());
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        // Report success even when truncating: capping at the region size is
        // intended, and returning Err would only abort the remaining format.
        Ok(())
    }
}

/// Writes crash dumps into a caller-supplied byte region (the reserved DTCM
/// crashdump slot on hardware, or a scratch buffer in unit tests).
pub(crate) struct CrashDumpManager<'a> {
    base: &'a mut [u8],
}

impl<'a> CrashDumpManager<'a> {
    pub(crate) fn new(base: &'a mut [u8]) -> Self {
        Self { base }
    }

    pub(crate) fn commit_crash_dump(&mut self) {
        self.base[0..size_of::<u32>()].copy_from_slice(DUMP_HEADER_MAGIC_COMITTED.as_bytes());
    }

    #[allow(dead_code)]
    pub(crate) fn dirty_crash_dump(&mut self) {
        self.base[0..size_of::<u32>()].copy_from_slice(DUMP_HEADER_MAGIC_DIRTY.as_bytes());
    }

    #[allow(dead_code)]
    pub(crate) fn get_crashdump(&self) -> &CrashDumpBlock {
        // SAFETY: `base` is at least `size_of::<CrashDumpBlock>()` bytes and was
        // populated by `create_dump`. `CrashDumpBlock` is `#[repr(C)]` and
        // `FromBytes`, so any byte pattern is a valid instance, making the
        // reinterpreting cast sound.
        unsafe { &*(self.base.as_ptr() as *const CrashDumpBlock) }
    }
}

impl CrashDump for CrashDumpManager<'_> {
    fn create_dump(
        &mut self,
        failure_code: u32,
        cpu_reg_context: &CpuRegisterContext,
        register_block: &RegisterBlockContext,
        cpu_id: u8,
        additional_info: &str,
    ) {
        // Clamp the tail to whatever fits after the fixed block: the reserved
        // DTCM region is fixed-size, so an over-long tail must be truncated
        // rather than panic with an out-of-bounds slice *inside* a fault
        // handler (which would double-panic and abort the core).
        let cap = self.base.len().saturating_sub(BLOCK_SIZE);
        let tail = &additional_info.as_bytes()[..additional_info.len().min(cap)];

        let block = CrashDumpBlock {
            // The payload always fits the reserved region, so the cast cannot
            // lose information in practice.
            header: build_header(failure_code, cpu_id, (BODY_SIZE + tail.len()) as u16),
            body: build_body(cpu_reg_context, register_block),
        };

        self.base[0..BLOCK_SIZE].copy_from_slice(block.as_bytes());
        if !tail.is_empty() {
            self.base[BLOCK_SIZE..BLOCK_SIZE + tail.len()].copy_from_slice(tail);
        }

        // Flip the magic to committed only after the full block + tail have
        // been written, so a torn write is detectable by the reader.
        self.commit_crash_dump();
    }

    fn create_dump_fmt(
        &mut self,
        failure_code: u32,
        cpu_reg_context: &CpuRegisterContext,
        register_block: &RegisterBlockContext,
        cpu_id: u8,
        args: fmt::Arguments<'_>,
    ) {
        // Write the fixed block first (dirty magic, provisional payload = body
        // only). Stamping the dirty magic up front invalidates any previously
        // committed dump before we begin mutating the tail, so a reader can
        // never observe an old committed header alongside a new partial tail.
        let block = CrashDumpBlock {
            header: build_header(failure_code, cpu_id, BODY_SIZE as u16),
            body: build_body(cpu_reg_context, register_block),
        };
        self.base[0..BLOCK_SIZE].copy_from_slice(block.as_bytes());

        // Render the message straight into the reserved tail. The writer is
        // bounded: it copies whatever fits and drops the rest, so it can never
        // overflow the region or panic.
        let tail_len = {
            let mut writer = DtcmTailWriter {
                buf: &mut self.base[BLOCK_SIZE..],
                len: 0,
            };
            // Truncation is intentional and reported as success by the writer.
            let _ = fmt::Write::write_fmt(&mut writer, args);
            writer.len
        };

        // Patch payload_size now the tail length is known; the header is still
        // dirty, so a reader in this window treats the dump as incomplete.
        let header = build_header(failure_code, cpu_id, (BODY_SIZE + tail_len) as u16);
        self.base[0..HEADER_SIZE].copy_from_slice(header.as_bytes());

        // Commit only after the block + tail + patched size are all in place.
        self.commit_crash_dump();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crashdump_size() {
        let mut crashdump_memory = [0u8; 0x1000];
        let mut mgr: CrashDumpManager<'_> = CrashDumpManager::new(&mut crashdump_memory);
        mgr.create_dump(
            1,
            &CpuRegisterContext {
                lr: 0x1234_5678,
                sp: 0x1122_3344,
                pc: 0x8765_4321,
                r0: 0x5566_7788,
                r1: 0x6677_8899,
                r2: 0x7788_9900,
                r3: 0x8899_0011,
                r12: 0x9900_1122,
            },
            &RegisterBlockContext::new(0x1234_5678, 0x8765_4321, 0x1122_3344),
            0,
            "",
        );

        let crashdump = mgr.get_crashdump();
        assert!(crashdump.header.payload_size > 0);
        assert!(crashdump.header.payload_size <= size_of::<CrashDumpBlock>() as u16);
        assert_eq!(crashdump.header.failure_code, 1);
    }

    #[test]
    fn test_crashdump_values() {
        let mut crashdump_memory = [0u8; 0x1000];
        let mut mgr: CrashDumpManager<'_> = CrashDumpManager::new(&mut crashdump_memory);
        mgr.create_dump(
            1,
            &CpuRegisterContext {
                lr: 0x1234_5678,
                sp: 0x1122_3344,
                pc: 0x8765_4321,
                r0: 0x5566_7788,
                r1: 0x6677_8899,
                r2: 0x7788_9900,
                r3: 0x8899_0011,
                r12: 0x9900_1122,
            },
            &RegisterBlockContext::new(0x1234_5678, 0x8765_4321, 0x1122_3344),
            0,
            "",
        );
        let crashdump = mgr.get_crashdump();
        assert_eq!(crashdump.header.magic, DUMP_HEADER_MAGIC_COMITTED);
        assert_eq!(crashdump.header.crashdump_version, DUMP_HEADER_VERSION);
        assert_eq!(crashdump.body.lr, 0x1234_5678);
        assert_eq!(crashdump.body.stack_ptr, 0x1122_3344);
        assert_eq!(crashdump.body.return_address, 0x8765_4321);
        assert_eq!(crashdump.body.r0, 0x5566_7788);
        assert_eq!(crashdump.body.r1, 0x6677_8899);
        assert_eq!(crashdump.body.r2, 0x7788_9900);
        assert_eq!(crashdump.body.r3, 0x8899_0011);
        assert_eq!(crashdump.body.r12, 0x9900_1122);
        assert_eq!(crashdump.body.cfsr, 0x1234_5678);
        assert_eq!(crashdump.body.mmfar, 0x8765_4321);
        assert_eq!(crashdump.body.bfar, 0x1122_3344);
    }

    #[test]
    fn test_crashdump_additional_info() {
        let mut crashdump_memory = [0u8; 0x1000];
        let mut mgr: CrashDumpManager<'_> = CrashDumpManager::new(&mut crashdump_memory);
        let additional_info = "Crash and Dump";
        mgr.create_dump(
            1,
            &CpuRegisterContext {
                lr: 0x1234_5678,
                sp: 0x1122_3344,
                pc: 0x8765_4321,
                r0: 0x5566_7788,
                r1: 0x6677_8899,
                r2: 0x7788_9900,
                r3: 0x8899_0011,
                r12: 0x9900_1122,
            },
            &RegisterBlockContext::new(0x1234_5678, 0x8765_4321, 0x1122_3344),
            0,
            additional_info,
        );

        let info = &mgr.base
            [size_of::<CrashDumpBlock>()..size_of::<CrashDumpBlock>() + additional_info.len()];
        assert!(info == additional_info.as_bytes());
    }

    #[test]
    fn test_crashdump_fmt_message() {
        let mut crashdump_memory = [0u8; 0x1000];
        let mut mgr: CrashDumpManager<'_> = CrashDumpManager::new(&mut crashdump_memory);
        let value = 0x42u32;
        mgr.create_dump_fmt(
            11,
            &CpuRegisterContext {
                lr: 0x1234_5678,
                sp: 0x1122_3344,
                pc: 0x8765_4321,
                r0: 0,
                r1: 0,
                r2: 0,
                r3: 0,
                r12: 0,
            },
            &RegisterBlockContext::new(0x1234_5678, 0x8765_4321, 0x1122_3344),
            2,
            // A *formatted* message — the `&str` path cannot express this.
            format_args!("panic: value = {value}"),
        );

        let expected = "panic: value = 66"; // 0x42 == 66 (Display is decimal)
        let crashdump = mgr.get_crashdump();
        assert_eq!(crashdump.header.magic, DUMP_HEADER_MAGIC_COMITTED);
        assert_eq!(crashdump.header.failure_code, 11);
        assert_eq!(crashdump.header.core_type, 2);
        // payload_size is patched to body + rendered-tail length.
        assert_eq!(
            crashdump.header.payload_size as usize,
            BODY_SIZE + expected.len()
        );
        // The tail bytes equal the rendered message.
        assert_eq!(
            &mgr.base[BLOCK_SIZE..BLOCK_SIZE + expected.len()],
            expected.as_bytes()
        );
    }

    #[test]
    fn test_crashdump_tail_truncation() {
        // Backing region only large enough for the fixed block + 4 tail bytes,
        // so an over-long tail must be clamped (never slice-panic).
        let mut crashdump_memory = [0u8; BLOCK_SIZE + 4];
        let ctx = CpuRegisterContext {
            lr: 0,
            sp: 0,
            pc: 0,
            r0: 0,
            r1: 0,
            r2: 0,
            r3: 0,
            r12: 0,
        };
        let rb = RegisterBlockContext::new(0, 0, 0);

        // &str path: over-long tail clamped to the 4-byte capacity.
        {
            let mut mgr = CrashDumpManager::new(&mut crashdump_memory);
            mgr.create_dump(3, &ctx, &rb, 2, "abcdefghij");
            let crashdump = mgr.get_crashdump();
            assert_eq!(crashdump.header.magic, DUMP_HEADER_MAGIC_COMITTED);
            assert_eq!(crashdump.header.payload_size as usize, BODY_SIZE + 4);
            assert_eq!(&mgr.base[BLOCK_SIZE..BLOCK_SIZE + 4], "abcd".as_bytes());
        }

        // fmt path: same clamp, still commits.
        {
            let mut mgr = CrashDumpManager::new(&mut crashdump_memory);
            mgr.create_dump_fmt(3, &ctx, &rb, 2, format_args!("wxyz1234"));
            let crashdump = mgr.get_crashdump();
            assert_eq!(crashdump.header.magic, DUMP_HEADER_MAGIC_COMITTED);
            assert_eq!(crashdump.header.payload_size as usize, BODY_SIZE + 4);
            assert_eq!(&mgr.base[BLOCK_SIZE..BLOCK_SIZE + 4], "wxyz".as_bytes());
        }
    }
}
