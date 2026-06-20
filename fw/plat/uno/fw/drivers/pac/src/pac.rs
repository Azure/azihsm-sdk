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

        /// AES completion (IRQ5, ISPR0 bit 5).
        #[allow(non_camel_case_types)]
        AES_DONE = 5,

        /// SHA completion (IRQ6, ISPR0 bit 6).
        #[allow(non_camel_case_types)]
        SHA_DONE = 6,

        /// PKA engine Done interrupts (IRQ192–207, ISPR6 bits 0–15).
        #[allow(non_camel_case_types)]
        UPKA_0_DONE = 192,
        #[allow(non_camel_case_types)]
        UPKA_1_DONE = 193,
        #[allow(non_camel_case_types)]
        UPKA_2_DONE = 194,
        #[allow(non_camel_case_types)]
        UPKA_3_DONE = 195,
        #[allow(non_camel_case_types)]
        UPKA_4_DONE = 196,
        #[allow(non_camel_case_types)]
        UPKA_5_DONE = 197,
        #[allow(non_camel_case_types)]
        UPKA_6_DONE = 198,
        #[allow(non_camel_case_types)]
        UPKA_7_DONE = 199,
        #[allow(non_camel_case_types)]
        UPKA_8_DONE = 200,
        #[allow(non_camel_case_types)]
        UPKA_9_DONE = 201,
        #[allow(non_camel_case_types)]
        UPKA_10_DONE = 202,
        #[allow(non_camel_case_types)]
        UPKA_11_DONE = 203,
        #[allow(non_camel_case_types)]
        UPKA_12_DONE = 204,
        #[allow(non_camel_case_types)]
        UPKA_13_DONE = 205,
        #[allow(non_camel_case_types)]
        UPKA_14_DONE = 206,
        #[allow(non_camel_case_types)]
        UPKA_15_DONE = 207,

        /// PKA engine Error interrupts (IRQ208–223, ISPR6 bits 16–31).
        #[allow(non_camel_case_types)]
        UPKA_0_ERROR = 208,
        #[allow(non_camel_case_types)]
        UPKA_1_ERROR = 209,
        #[allow(non_camel_case_types)]
        UPKA_2_ERROR = 210,
        #[allow(non_camel_case_types)]
        UPKA_3_ERROR = 211,
        #[allow(non_camel_case_types)]
        UPKA_4_ERROR = 212,
        #[allow(non_camel_case_types)]
        UPKA_5_ERROR = 213,
        #[allow(non_camel_case_types)]
        UPKA_6_ERROR = 214,
        #[allow(non_camel_case_types)]
        UPKA_7_ERROR = 215,
        #[allow(non_camel_case_types)]
        UPKA_8_ERROR = 216,
        #[allow(non_camel_case_types)]
        UPKA_9_ERROR = 217,
        #[allow(non_camel_case_types)]
        UPKA_10_ERROR = 218,
        #[allow(non_camel_case_types)]
        UPKA_11_ERROR = 219,
        #[allow(non_camel_case_types)]
        UPKA_12_ERROR = 220,
        #[allow(non_camel_case_types)]
        UPKA_13_ERROR = 221,
        #[allow(non_camel_case_types)]
        UPKA_14_ERROR = 222,
        #[allow(non_camel_case_types)]
        UPKA_15_ERROR = 223,

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
    table[5] = Some(AES_DONE);
    table[6] = Some(SHA_DONE);
    table[66] = Some(GDMA_CQ);
    table[103] = Some(IIC_ICQ);
    table[110] = Some(OIC_OCQ);
    // 129 = INTC_IPC — polled, no ISR
    table
};
