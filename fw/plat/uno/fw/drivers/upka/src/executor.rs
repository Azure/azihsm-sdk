// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::sync::atomic::compiler_fence;
use core::sync::atomic::Ordering;

use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_reg_soc::io_gsram::regs::IoGsramRegs;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use azihsm_fw_uno_reg_soc::io_gsram::UPKA_ENGINE_CMD_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::UPKA_ENGINE_CMD_STRIDE;
use azihsm_fw_uno_reg_soc::upka::UpkaEngine;
use azihsm_fw_uno_reg_soc::upka::ENGINE_STRIDE;
use azihsm_fw_uno_reg_soc::upka::UPKA_BASE;
use azihsm_fw_uno_reg_soc::upka::UPKA_ENGINE_STATUS;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

const STATUS_FLAGS_MASK: u32 = 0x1E;

/// DTCM overlay for PKA command descriptors.
const UPKA_Q: StaticRef<IoGsramRegs> =
    unsafe { StaticRef::new(IO_GSRAM_BASE as *const IoGsramRegs) };

/// Hardware submission and polling helpers for UPKA command execution.
///
/// This type groups low-level MMIO operations used by the engine abstraction.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct EngineExecutor;

impl EngineExecutor {
    /// Stage a descriptor in an engine-local command slot and submit it.
    ///
    /// # Parameters
    ///
    /// - `engine_id`: Target engine index.
    /// - `opcode`: Hardware opcode.
    /// - `result`: Result buffer address written by hardware.
    /// - `arg1`: First command argument address/value.
    /// - `arg2`: Second command argument address/value.
    /// - `arg3`: Third command argument address/value.
    ///
    /// # Returns
    ///
    /// - No return value. Command submission is fire-and-forget; completion is
    ///   observed via status polling and IRQ wake-ups.
    pub(crate) fn submit_engine_command(
        engine_id: u8,
        opcode: u32,
        result: u32,
        arg1: u32,
        arg2: u32,
        arg3: u32,
    ) {
        Self::write_descriptor(engine_id, opcode, result, arg1, arg2, arg3);
        compiler_fence(Ordering::SeqCst);
        Self::submit_cmd(engine_id);
    }

    /// Read completion and error status flags for an engine.
    ///
    /// # Parameters
    ///
    /// - `engine_id`: Engine index to query.
    ///
    /// # Returns
    ///
    /// - Masked completion/error status bits.
    pub(crate) fn completion_flags(engine_id: u8) -> u32 {
        Self::status_flags(engine_id)
    }

    /// Block until the selected engine is no longer busy.
    ///
    /// # Parameters
    ///
    /// - `engine_id`: Engine index to poll.
    ///
    /// # Returns
    ///
    /// - No return value.
    pub(crate) fn wait_until_idle(engine_id: u8) {
        Self::spin_until_idle(engine_id);
    }

    /// Write a command descriptor into an engine's dedicated DTCM slot.
    fn write_descriptor(id: u8, opcode: u32, result: u32, arg1: u32, arg2: u32, arg3: u32) {
        let entry = &UPKA_Q.upka_engine_cmd[id as usize];
        entry.command_code.set(opcode);
        entry.result_addr.set(result);
        entry.arg1_addr.set(arg1);
        entry.arg2_addr.set(arg2);
        entry.arg3_addr.set(arg3);
    }

    /// Submit the command descriptor already staged for an engine.
    fn submit_cmd(id: u8) {
        Self::submit_cmd_at(id, Self::command_addr(id));
    }

    /// Submit an arbitrary descriptor address to an engine's command register.
    fn submit_cmd_at(engine_id: u8, descriptor_addr: u32) {
        Self::engine_regs(engine_id).command.set(descriptor_addr);
    }

    /// Read only the completion and error flag bits from an engine status register.
    fn status_flags(id: u8) -> u32 {
        Self::engine_regs(id).status.get() & STATUS_FLAGS_MASK
    }

    /// Spin until the selected engine is no longer busy.
    fn spin_until_idle(id: u8) {
        while Self::engine_regs(id).status.read(UPKA_ENGINE_STATUS::BUSY) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Get the DTCM address of an engine's dedicated command descriptor.
    fn command_addr(id: u8) -> u32 {
        IO_GSRAM_BASE + UPKA_ENGINE_CMD_OFFSET + u32::from(id) * UPKA_ENGINE_CMD_STRIDE
    }

    /// Get a typed MMIO reference to the selected PKA engine register block.
    fn engine_regs(id: u8) -> StaticRef<UpkaEngine> {
        unsafe { StaticRef::new((UPKA_BASE + u32::from(id) * ENGINE_STRIDE) as *const UpkaEngine) }
    }
}
