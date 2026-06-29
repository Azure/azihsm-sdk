// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Interrupt enum — re-exported as a module for `cortex-m-rt`'s
/// `#[interrupt]` macro which expects `interrupt::NAME` to resolve.
pub mod interrupt {
    /// Interrupt numbers for the Uno SoC.
    ///
    /// These map to NVIC IRQ numbers (exception number = IRQ + 16).
    /// Aligned with the azihsm SoC IRQ assignments.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[repr(u16)]
    pub enum Interrupt {
        /// IIC inbound completion queue (IRQ103, ISPR3 bit 7).
        #[allow(non_camel_case_types)]
        IIC_ICQ = 103,

        /// OIC outbound completion queue (IRQ110, ISPR3 bit 14).
        #[allow(non_camel_case_types)]
        OIC_OCQ = 110,

        /// GDMA completion queue (IRQ66, ISPR2 bit 2).
        #[allow(non_camel_case_types)]
        GDMA_CQ = 66,

        /// AES completion (IRQ57, ISPR1 bit 25).
        #[allow(non_camel_case_types)]
        AES_DONE = 57,

        /// SHA completion (IRQ56, ISPR1 bit 24).
        #[allow(non_camel_case_types)]
        SHA_DONE = 56,

        /// PKA engine Done interrupts (IRQ32–47, ISPR1 bits 0–15).
        #[allow(non_camel_case_types)]
        UPKA_0_DONE = 32,
        #[allow(non_camel_case_types)]
        UPKA_1_DONE = 33,
        #[allow(non_camel_case_types)]
        UPKA_2_DONE = 34,
        #[allow(non_camel_case_types)]
        UPKA_3_DONE = 35,
        #[allow(non_camel_case_types)]
        UPKA_4_DONE = 36,
        #[allow(non_camel_case_types)]
        UPKA_5_DONE = 37,
        #[allow(non_camel_case_types)]
        UPKA_6_DONE = 38,
        #[allow(non_camel_case_types)]
        UPKA_7_DONE = 39,
        #[allow(non_camel_case_types)]
        UPKA_8_DONE = 40,
        #[allow(non_camel_case_types)]
        UPKA_9_DONE = 41,
        #[allow(non_camel_case_types)]
        UPKA_10_DONE = 42,
        #[allow(non_camel_case_types)]
        UPKA_11_DONE = 43,
        #[allow(non_camel_case_types)]
        UPKA_12_DONE = 44,
        #[allow(non_camel_case_types)]
        UPKA_13_DONE = 45,
        #[allow(non_camel_case_types)]
        UPKA_14_DONE = 46,
        #[allow(non_camel_case_types)]
        UPKA_15_DONE = 47,

        /// PKA engine Error interrupts (IRQ0–15, ISPR0 bits 0–15).
        #[allow(non_camel_case_types)]
        UPKA_0_ERROR = 0,
        #[allow(non_camel_case_types)]
        UPKA_1_ERROR = 1,
        #[allow(non_camel_case_types)]
        UPKA_2_ERROR = 2,
        #[allow(non_camel_case_types)]
        UPKA_3_ERROR = 3,
        #[allow(non_camel_case_types)]
        UPKA_4_ERROR = 4,
        #[allow(non_camel_case_types)]
        UPKA_5_ERROR = 5,
        #[allow(non_camel_case_types)]
        UPKA_6_ERROR = 6,
        #[allow(non_camel_case_types)]
        UPKA_7_ERROR = 7,
        #[allow(non_camel_case_types)]
        UPKA_8_ERROR = 8,
        #[allow(non_camel_case_types)]
        UPKA_9_ERROR = 9,
        #[allow(non_camel_case_types)]
        UPKA_10_ERROR = 10,
        #[allow(non_camel_case_types)]
        UPKA_11_ERROR = 11,
        #[allow(non_camel_case_types)]
        UPKA_12_ERROR = 12,
        #[allow(non_camel_case_types)]
        UPKA_13_ERROR = 13,
        #[allow(non_camel_case_types)]
        UPKA_14_ERROR = 14,
        #[allow(non_camel_case_types)]
        UPKA_15_ERROR = 15,

        /// IPC interrupt controller (IRQ129, ISPR4 bit 1).
        #[allow(non_camel_case_types)]
        INTC_IPC = 129,
    }

    unsafe impl cortex_m::interrupt::InterruptNumber for Interrupt {
        fn number(self) -> u16 {
            self as u16
        }
    }

    pub use Interrupt::*;
}

pub use interrupt::Interrupt;

// cortex-m-rt expects a `__INTERRUPTS` symbol: an array of interrupt
// vectors indexed by IRQ number. Must be large enough for the highest
// IRQ number + 1.

extern "C" {
    fn IIC_ICQ();
    fn OIC_OCQ();
    fn GDMA_CQ();
    fn AES_DONE();
    fn SHA_DONE();
}

/// Interrupt vector table — indexed by IRQ number.
///
/// Entries with ISR handlers use `Some(handler)`. Polled interrupts
/// and unused slots use `None`.
#[doc(hidden)]
#[link_section = ".vector_table.interrupts"]
#[no_mangle]
pub static __INTERRUPTS: [Option<unsafe extern "C" fn()>; 224] = {
    let mut table: [Option<unsafe extern "C" fn()>; 224] = [None; 224];
    table[57] = Some(AES_DONE);
    table[56] = Some(SHA_DONE);
    table[66] = Some(GDMA_CQ);
    table[103] = Some(IIC_ICQ);
    table[110] = Some(OIC_OCQ);
    // 129 = INTC_IPC — polled, no ISR
    table
};
