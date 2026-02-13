// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Error type for PAL operations.
///
/// Represented as a 32-bit unsigned integer error code.
pub type PalMgmtError = u32;

/// Result type for PAL operations.
///
/// Returns the success value `T` or a [`PalError`] on failure.
pub type MgmtPalResult<T> = Result<T, PalMgmtError>;

#[repr(u32)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PalMgmtComponent {
    PcieMgr = 1,
    CtrlMgr = 2,
}

#[macro_export]
macro_rules! azihsm_define_pal_error {
    ($comp_name:ident, $vis:vis $enum_name: ident { $($field_name: ident = $field_val: literal,)* }) => {
        /// Component specific error
        #[allow(clippy::enum_variant_names)]
        #[repr(u32)]
        #[open_enum::open_enum]
        $vis enum $enum_name {
            $($field_name =((($crate::PalMgmtComponent::$comp_name) as u32) << 16) | ($field_val ),)*
        }

        impl From<$enum_name> for u32 {
            fn from(val: $enum_name) -> Self {
                ((($crate::PalMgmtComponent::$comp_name) as Self) << 16) | (val.0 as Self)
            }
        }
    }
}
