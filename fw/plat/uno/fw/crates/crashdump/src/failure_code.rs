// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Failure codes and ARMv7-M exception numbers for crash dumps.
//!
//! [`FailureCode`] is the `failure_code` field written into
//! [`CrashDumpHeader`](crate::crash_format). The value set mirrors the
//! reference `mcr-hsm` `crashdump` crate so the SP parser decodes both
//! firmwares identically. [`IRQn`] maps the negative ARMv7-M system-exception
//! numbers to a failure code for the (deferred) fault handlers that classify
//! by exception number.

/// ARMv7-M system-exception (negative IRQ) numbers.
#[derive(Debug, PartialEq)]
pub enum IRQn {
    /// Non-maskable interrupt.
    IrqnNonMaskableInterrupt = -14,

    /// Hard fault.
    IrqnHardFault = -13,

    /// Memory management fault.
    IrqnMemoryFault = -12,

    /// Bus fault.
    IrqnBusFault = -11,

    /// Usage fault.
    IrqnUsageFault = -10,

    /// Secure fault.
    IrqnSecureFault = -9,

    /// Supervisor call.
    IrqnSVCall = -5,

    /// Debug monitor.
    IrqnDebugMonitor = -4,

    /// PendSV.
    IrqnPendSV = -3,

    /// SysTick.
    IrqnSysTick = -1,

    /// Invalid / unmapped.
    IrqnInvalid = 0,
}

impl From<i16> for IRQn {
    fn from(value: i16) -> Self {
        match value {
            x if x == IRQn::IrqnNonMaskableInterrupt as i16 => IRQn::IrqnNonMaskableInterrupt,
            x if x == IRQn::IrqnHardFault as i16 => IRQn::IrqnHardFault,
            x if x == IRQn::IrqnMemoryFault as i16 => IRQn::IrqnMemoryFault,
            x if x == IRQn::IrqnBusFault as i16 => IRQn::IrqnBusFault,
            x if x == IRQn::IrqnUsageFault as i16 => IRQn::IrqnUsageFault,
            x if x == IRQn::IrqnSecureFault as i16 => IRQn::IrqnSecureFault,
            x if x == IRQn::IrqnSVCall as i16 => IRQn::IrqnSVCall,
            x if x == IRQn::IrqnDebugMonitor as i16 => IRQn::IrqnDebugMonitor,
            x if x == IRQn::IrqnPendSV as i16 => IRQn::IrqnPendSV,
            x if x == IRQn::IrqnSysTick as i16 => IRQn::IrqnSysTick,
            _ => IRQn::IrqnInvalid,
        }
    }
}

/// Failure code recorded in the crash-dump header.
#[derive(Clone, Debug, PartialEq)]
pub enum FailureCode {
    /// Unknown failure code.
    Unknown = 0,

    /// Non-maskable interrupt.
    NonMaskableInterrupt = 1,

    /// Hard fault.
    HardFault = 2,

    /// Memory management fault.
    MemoryFault = 3,

    /// Bus fault.
    BusFault = 4,

    /// Usage fault.
    UsageFault = 5,

    /// Secure fault.
    SecureFault = 6,

    /// Supervisor call.
    SVCall = 7,

    /// Debug monitor.
    DebugMonitor = 8,

    /// PendSV.
    PendSV = 9,

    /// SysTick.
    SysTick = 10,

    /// Rust panic.
    Panic = 11,

    /// Watchdog reset as signalled by the HSP.
    Watchdog = 12,

    /// Stack overflow detected.
    StackOverflow = 13,

    /// Double fault.
    DoubleFault = 14,

    /// Crash triggered by another core.
    OtherCore = 15,

    /// Explicitly triggered on an unrecoverable failure.
    ExplicitFailure = 16,

    /// RNG self-test failure.
    RngSelfTestFailure = 20,

    /// Double-bit ECC error.
    DoubleBitErr = 21,

    /// GDMA data structure error.
    GdmaDataStructureError = 22,

    /// GDMA data access error.
    GdmaDataAccessError = 23,

    /// GDMA completion queue error.
    GdmaCompletionQueueError = 24,

    /// GDMA delivery queue error.
    GdmaDeliveryQueueError = 25,

    /// UCD inbound DFL overflow error.
    UcdIbDflOverflowError = 30,

    /// UCD inbound queue overflow error.
    UcdIbQueueOverflowError = 31,

    /// UCD outbound queue full error.
    UcdObQueueFullError = 32,

    /// UCD inbound completion queue full error.
    UcdIbCqFullError = 33,
}

impl From<IRQn> for FailureCode {
    fn from(value: IRQn) -> Self {
        match value {
            IRQn::IrqnNonMaskableInterrupt => FailureCode::NonMaskableInterrupt,
            IRQn::IrqnHardFault => FailureCode::HardFault,
            IRQn::IrqnMemoryFault => FailureCode::MemoryFault,
            IRQn::IrqnBusFault => FailureCode::BusFault,
            IRQn::IrqnUsageFault => FailureCode::UsageFault,
            IRQn::IrqnSecureFault => FailureCode::SecureFault,
            IRQn::IrqnSVCall => FailureCode::SVCall,
            IRQn::IrqnDebugMonitor => FailureCode::DebugMonitor,
            IRQn::IrqnPendSV => FailureCode::PendSV,
            IRQn::IrqnSysTick => FailureCode::SysTick,
            IRQn::IrqnInvalid => FailureCode::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_code() {
        assert_eq!(
            FailureCode::from(IRQn::IrqnNonMaskableInterrupt),
            FailureCode::NonMaskableInterrupt
        );
        assert_eq!(
            FailureCode::from(IRQn::IrqnHardFault),
            FailureCode::HardFault
        );
        assert_eq!(
            FailureCode::from(IRQn::IrqnMemoryFault),
            FailureCode::MemoryFault
        );
        assert_eq!(FailureCode::from(IRQn::IrqnBusFault), FailureCode::BusFault);
        assert_eq!(
            FailureCode::from(IRQn::IrqnUsageFault),
            FailureCode::UsageFault
        );
        assert_eq!(
            FailureCode::from(IRQn::IrqnSecureFault),
            FailureCode::SecureFault
        );
        assert_eq!(FailureCode::from(IRQn::IrqnSVCall), FailureCode::SVCall);
        assert_eq!(
            FailureCode::from(IRQn::IrqnDebugMonitor),
            FailureCode::DebugMonitor
        );
        assert_eq!(FailureCode::from(IRQn::IrqnPendSV), FailureCode::PendSV);
        assert_eq!(FailureCode::from(IRQn::IrqnSysTick), FailureCode::SysTick);
        assert_eq!(FailureCode::from(IRQn::IrqnInvalid), FailureCode::Unknown);
    }

    #[test]
    fn test_irqn() {
        assert_eq!(
            IRQn::from(IRQn::IrqnNonMaskableInterrupt as i16),
            IRQn::IrqnNonMaskableInterrupt
        );
        assert_eq!(IRQn::from(IRQn::IrqnHardFault as i16), IRQn::IrqnHardFault);
        assert_eq!(
            IRQn::from(IRQn::IrqnMemoryFault as i16),
            IRQn::IrqnMemoryFault
        );
        assert_eq!(IRQn::from(IRQn::IrqnBusFault as i16), IRQn::IrqnBusFault);
        assert_eq!(
            IRQn::from(IRQn::IrqnUsageFault as i16),
            IRQn::IrqnUsageFault
        );
        assert_eq!(
            IRQn::from(IRQn::IrqnSecureFault as i16),
            IRQn::IrqnSecureFault
        );
        assert_eq!(IRQn::from(IRQn::IrqnSVCall as i16), IRQn::IrqnSVCall);
        assert_eq!(
            IRQn::from(IRQn::IrqnDebugMonitor as i16),
            IRQn::IrqnDebugMonitor
        );
        assert_eq!(IRQn::from(IRQn::IrqnPendSV as i16), IRQn::IrqnPendSV);
        assert_eq!(IRQn::from(IRQn::IrqnSysTick as i16), IRQn::IrqnSysTick);
        assert_eq!(IRQn::from(0), IRQn::IrqnInvalid);
    }
}
