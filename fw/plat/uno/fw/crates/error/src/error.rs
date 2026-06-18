// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM error helpers.
//!
//! Re-exports [`HsmError`] and [`HsmResult`] from `azihsm_fw_hsm_pal_traits`
//! and provides [`make_pal_error`] to construct PAL-level error codes.
//!
//! ## Layout
//!
//! ```text
//! 31        20 19     12 11         0
//! ┌───────────┬─────────┬────────────┐
//! │   0x08F   │component│    code    │
//! │  (12 bit) │ (8 bit) │  (12 bit)  │
//! └───────────┴─────────┴────────────┘
//! ```

pub use azihsm_fw_hsm_pal_traits::HsmError;
pub use azihsm_fw_hsm_pal_traits::HsmResult;

/// 12-bit facility prefix for PAL-level errors.
const PAL_FACILITY: u32 = 0x08F;

/// Construct a PAL-level [`HsmError`] from a raw component ID and code.
#[inline]
pub const fn make_pal_error(component: u8, code: u16) -> HsmError {
    HsmError((PAL_FACILITY << 20) | ((component as u32 & 0xFF) << 12) | (code as u32 & 0xFFF))
}

/// Construct a PAL-level [`HsmError`] from a [`ComponentId`] and code.
///
/// # Examples
///
/// ```ignore
/// use azihsm_fw_uno_error::{make_component_error, ComponentId};
///
/// pub const MY_ERR: HsmError = make_component_error(ComponentId::GDMA, 1);
/// ```
#[inline]
pub const fn make_component_error(component: crate::ComponentId, code: u16) -> HsmError {
    make_pal_error(component.0, code)
}
