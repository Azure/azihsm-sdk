// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Component identifiers for HSM error codes.

/// Component identifier for the 8-bit component field in [`HsmError`](crate::HsmError).
///
/// Each driver or subsystem is assigned a unique ID. New components
/// must be added here to avoid collisions.
#[open_enum::open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ComponentId {
    /// IIC (Inbound IO Controller) driver.
    IIC = 1,

    /// OIC (Outbound IO Controller) driver.
    OIC = 2,

    /// Timer driver.
    TIMER = 3,

    /// NVIC driver.
    NVIC = 4,

    /// Trace / profiling.
    TRACE = 5,

    /// Semihosting driver.
    SEMIHOSTING = 6,

    /// Bulk copy.
    BULK_COPY = 7,

    /// GDMA (General DMA Controller) driver.
    GDMA = 8,

    /// AES crypto engine driver.
    AES = 9,

    /// IPC (Inter-Processor Communication) driver.
    IPC = 10,

    /// SHA crypto engine driver.
    SHA = 11,

    /// UPKA crypto engine driver.
    UPKA = 12,
}
