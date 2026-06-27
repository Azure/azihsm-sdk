// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Configurable Fault Status Register (CFSR) decoding.
//!
//! Translates the bit fields of the ARMv7-M `CFSR` (MMFSR + BFSR + UFSR)
//! into human-readable lines so a HardFault report names the precise
//! fault cause instead of just a raw hex value. The bus/mem-fault address
//! registers (`BFAR`/`MMFAR`) are reported by the caller when the matching
//! `*VALID` bit is set.

use azihsm_fw_uno_reg_cortex_m::scb::regs::ScbRegs;
use azihsm_fw_uno_reg_cortex_m::scb::CFSR;
use tock_registers::interfaces::Readable;

use crate::println_fault;

/// Print one decoded line per set CFSR fault bit, grouped by fault unit.
///
/// Covers the MemManage (`MMFSR`), BusFault (`BFSR`) and UsageFault
/// (`UFSR`) sub-registers. Only set bits are printed; a clean register
/// produces no output.
pub fn report_cfsr(scb: &ScbRegs) {
    // MemManage faults (MMFSR, CFSR[7:0]).
    if scb.cfsr.is_set(CFSR::IACCVIOL) {
        println_fault!("  MemManage: IACCVIOL  instruction-fetch access violation");
    }
    if scb.cfsr.is_set(CFSR::DACCVIOL) {
        println_fault!("  MemManage: DACCVIOL  data access violation");
    }
    if scb.cfsr.is_set(CFSR::MUNSTKERR) {
        println_fault!("  MemManage: MUNSTKERR fault on exception return unstacking");
    }
    if scb.cfsr.is_set(CFSR::MSTKERR) {
        println_fault!("  MemManage: MSTKERR   fault on exception entry stacking");
    }
    if scb.cfsr.is_set(CFSR::MLSPERR) {
        println_fault!("  MemManage: MLSPERR   fault during FP lazy state preservation");
    }

    // Bus faults (BFSR, CFSR[15:8]).
    if scb.cfsr.is_set(CFSR::IBUSERR) {
        println_fault!("  BusFault:  IBUSERR   instruction prefetch bus error");
    }
    if scb.cfsr.is_set(CFSR::PRECISERR) {
        println_fault!("  BusFault:  PRECISERR precise data bus error (BFAR valid)");
    }
    if scb.cfsr.is_set(CFSR::IMPRECISERR) {
        println_fault!("  BusFault:  IMPRECISERR imprecise data bus error (BFAR unreliable)");
    }
    if scb.cfsr.is_set(CFSR::UNSTKERR) {
        println_fault!("  BusFault:  UNSTKERR  bus fault on exception return unstacking");
    }
    if scb.cfsr.is_set(CFSR::STKERR) {
        println_fault!("  BusFault:  STKERR    bus fault on exception entry stacking");
    }
    if scb.cfsr.is_set(CFSR::LSPERR) {
        println_fault!("  BusFault:  LSPERR    bus fault during FP lazy state preservation");
    }

    // Usage faults (UFSR, CFSR[31:16]).
    if scb.cfsr.is_set(CFSR::UNDEFINSTR) {
        println_fault!("  UsageFault: UNDEFINSTR undefined instruction");
    }
    if scb.cfsr.is_set(CFSR::INVSTATE) {
        println_fault!("  UsageFault: INVSTATE  invalid EPSR/Thumb state");
    }
    if scb.cfsr.is_set(CFSR::INVPC) {
        println_fault!("  UsageFault: INVPC     invalid PC load (exception return)");
    }
    if scb.cfsr.is_set(CFSR::NOCP) {
        println_fault!("  UsageFault: NOCP      coprocessor access denied/absent");
    }
    if scb.cfsr.is_set(CFSR::UNALIGNED) {
        println_fault!("  UsageFault: UNALIGNED unaligned access trap");
    }
    if scb.cfsr.is_set(CFSR::DIVBYZERO) {
        println_fault!("  UsageFault: DIVBYZERO divide-by-zero trap");
    }
}
