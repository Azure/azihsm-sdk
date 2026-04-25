// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for the HSM platform abstraction layer.

use core::result::Result;

use bitfield_struct::bitfield;
use open_enum::open_enum;

/// The facility that generated an [`HsmError`].
///
/// Encoded as a 4-bit value in the upper nibble of the error word.
#[open_enum]
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum HsmFacility {
    /// Core layer.
    Core = 0,
    /// Platform abstraction layer.
    Pal = 1,
    /// Application layer.
    App = 2,
}

impl HsmFacility {
    const fn from_bits(val: u8) -> Self {
        Self(val)
    }

    const fn into_bits(self) -> u8 {
        self.0
    }
}

/// The error type for HSM operations.
///
/// Layout (MSB to LSB):
/// - Bits \[31:28\] — 4-bit [`Facility`]
/// - Bits \[27:16\] — 12-bit component identifier
/// - Bits \[15:0\]  — 16-bit error code
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct HsmError {
    /// 16-bit error code.
    #[bits(16)]
    pub code: u16,
    /// 12-bit component identifier.
    #[bits(12)]
    pub component: u16,
    /// The [`Facility`] that generated this error.
    #[bits(4)]
    pub facility: HsmFacility,
}

/// A specialized [`Result`] type for HSM operations.
///
/// Uses [`HsmError`] as the error variant.
pub type HsmResult<T> = Result<T, HsmError>;

impl HsmError {
    /// Creates a new [`HsmError`] with the given facility, component, and error code.
    pub const fn make(facility: HsmFacility, component: u16, code: u16) -> Self {
        Self::new()
            .with_facility(facility)
            .with_component(component)
            .with_code(code)
    }

    /// Creates a new [`HsmError`] in the [`Core`](HsmFacility::Core) facility.
    pub const fn make_core(component: u16, code: u16) -> Self {
        Self::make(HsmFacility::Core, component, code)
    }

    /// Creates a new [`HsmError`] in the [`Pal`](HsmFacility::Pal) facility.
    pub const fn make_pal(component: u16, code: u16) -> Self {
        Self::make(HsmFacility::Pal, component, code)
    }

    /// Creates a new [`HsmError`] in the [`App`](HsmFacility::App) facility.
    pub const fn make_app(component: u16, code: u16) -> Self {
        Self::make(HsmFacility::App, component, code)
    }

    /// Returns the raw `u32` representation of this error.
    pub const fn raw(self) -> u32 {
        self.into_bits()
    }
}
