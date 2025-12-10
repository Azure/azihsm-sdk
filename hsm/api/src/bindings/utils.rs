// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(unsafe_code)]

use std::ffi::CStr;
use std::mem;
use std::slice;

use crate::bindings::ffi_types::AzihsmBuffer;
use crate::bindings::ffi_types::AzihsmKeyPropList;
use crate::types::key_props::*;
use crate::types::AzihsmKeyPropId;
use crate::*;

/// Macro to validate multiple pointers at once
macro_rules! validate_pointers {
    ($($ptr:expr),+ $(,)?) => {{
        $(
            if $ptr.is_null() {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
            }
        )+
    }};
}

/// Macro to safely dereference and validate a mutable pointer
macro_rules! deref_mut_ptr {
    ($ptr:expr) => {{
        if $ptr.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }
        // SAFETY: Pointer has been validated as non-null above
        unsafe { &mut *$ptr }
    }};
}

/// Macro to safely dereference and validate a const pointer
macro_rules! deref_const_ptr {
    ($ptr:expr) => {{
        if $ptr.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }
        // SAFETY: Pointer has been validated as non-null above
        unsafe { &*$ptr }
    }};
}

/// Macro to validate AzihsmBuffer parameters (non-null pointer and non-zero length)
macro_rules! validate_buffer {
    ($buf:expr) => {{
        if $buf.buf.is_null() || $buf.len == 0 {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }
    }};
}

/// Macro to validate conditions and return error if any condition is true
macro_rules! validate_conditions {
    ($($condition:expr),+ $(,)?) => {{
        $(
            if $condition {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
            }
        )+
    }};
}

/// Macro for extracting boolean properties from C FFI.
macro_rules! extract_bool_property {
    ($builder:expr, $prop:expr, $method:ident) => {{
        // Validate length is correct for bool (typically 1 byte)
        if $prop.len != 1 {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }
        let val_ptr = $prop.val as *const u8;
        // Safety: The caller must ensure that `prop.val` is a valid pointer to a u8.
        let bool_val = unsafe { *val_ptr != 0 };
        $builder.$method(bool_val)
    }};
}

/// Macro for extracting u32 properties from C FFI.
macro_rules! extract_u32_property {
    ($builder:expr, $prop:expr, $method:ident) => {{
        // Validate length is correct for u32
        if $prop.len != mem::size_of::<u32>() as u32 {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }
        let val_ptr = $prop.val as *const u32;
        // Safety: The caller must ensure that `prop.val` is a valid pointer to a u32.
        let value = unsafe { *val_ptr };
        $builder.$method(value)
    }};
}

/// Macro for extracting string properties from C FFI.
macro_rules! extract_string_property {
    ($builder:expr, $prop:expr, $method:ident) => {{
        // SAFETY: The caller must ensure that `prop.val` is a valid pointer to a null-terminated C string.
        let c_str = unsafe { CStr::from_ptr($prop.val as *const i8) };
        let string_val = c_str.to_string_lossy().to_string();
        $builder.$method(string_val)
    }};
}

/// Macro for extracting enum properties from C FFI that implement TryFrom<u32>.
macro_rules! extract_enum_property {
    ($builder:expr, $prop:expr, $enum_type:ty, $method:ident) => {{
        // Validate length is correct for u32
        if $prop.len != mem::size_of::<u32>() as u32 {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }
        let val_ptr = $prop.val as *const u32;
        // Safety: The caller must ensure that `prop.val` is a valid pointer to a u32.
        let enum_value = unsafe { *val_ptr };
        let enum_variant = <$enum_type>::try_from(enum_value)?;
        $builder.$method(enum_variant)
    }};
}

/// Macro for converting C FFI key properties to Rust KeyProps.
macro_rules! convert_key_props {
    ($props_ptr:expr) => {{
        if $props_ptr.is_null() {
            KeyProps::builder().build()
        } else {
            let builder = KeyPropsBuilder::try_from($props_ptr)?;
            builder.build()
        }
    }};
}

/// Macro to safely write a value to an output pointer.
/// The pointer must be validated as non-null before calling this macro.
macro_rules! write_to_out_ptr {
    ($ptr:expr, $value:expr) => {{
        // SAFETY: Pointer has been validated as non-null above
        unsafe {
            *$ptr = $value;
        }
    }};
}

impl TryFrom<*const AzihsmKeyPropList> for KeyPropsBuilder {
    type Error = AzihsmError;

    /// Extract key properties from C FFI key property list into a builder.
    ///
    /// # Safety
    ///
    /// This implementation is unsafe because it dereferences raw pointers from C.
    /// The caller must ensure that:
    /// - The pointer is a valid pointer to `AzihsmKeyPropList`
    /// - The `props` array contains `count` valid elements
    /// - Each property's `val` pointer is valid and points to data of `len` bytes
    /// - The memory remains valid for the duration of this function call
    #[allow(unsafe_code)]
    fn try_from(key_props: *const AzihsmKeyPropList) -> Result<Self, Self::Error> {
        if key_props.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        // SAFETY: the function ensures that the pointer is valid
        let key_prop_list = unsafe { &*key_props };

        // Allow empty property lists (props = null and count = 0)
        if key_prop_list.count == 0 {
            return Ok(KeyProps::builder());
        }

        if key_prop_list.props.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        let mut builder = KeyProps::builder();

        // SAFETY: the function ensures that the pointer is valid
        let prop_slice =
            unsafe { slice::from_raw_parts(key_prop_list.props, key_prop_list.count as usize) };

        for prop in prop_slice {
            if prop.val.is_null() {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
            }

            builder = match prop.id {
                // Boolean properties
                AzihsmKeyPropId::Session => extract_bool_property!(builder, prop, session),
                AzihsmKeyPropId::Modifiable => extract_bool_property!(builder, prop, modifiable),
                AzihsmKeyPropId::Encrypt => extract_bool_property!(builder, prop, encrypt),
                AzihsmKeyPropId::Decrypt => extract_bool_property!(builder, prop, decrypt),
                AzihsmKeyPropId::Sign => extract_bool_property!(builder, prop, sign),
                AzihsmKeyPropId::Verify => extract_bool_property!(builder, prop, verify),
                AzihsmKeyPropId::Wrap => extract_bool_property!(builder, prop, wrap),
                AzihsmKeyPropId::Unwrap => extract_bool_property!(builder, prop, unwrap),
                AzihsmKeyPropId::Derive => extract_bool_property!(builder, prop, derive),

                // Numeric properties
                AzihsmKeyPropId::BitLen => extract_u32_property!(builder, prop, bit_len),

                // ECC Curve property
                AzihsmKeyPropId::EcCurve => {
                    extract_enum_property!(builder, prop, EcCurve, ecc_curve)
                }

                // Key Kind property
                AzihsmKeyPropId::Kind => {
                    extract_enum_property!(builder, prop, KeyKind, kind)
                }

                // String properties
                AzihsmKeyPropId::Label => extract_string_property!(builder, prop, label),

                // Read-only properties - not settable by user
                AzihsmKeyPropId::Class
                | AzihsmKeyPropId::Private
                | AzihsmKeyPropId::Copyable
                | AzihsmKeyPropId::Destroyable
                | AzihsmKeyPropId::Local
                | AzihsmKeyPropId::Sensitive
                | AzihsmKeyPropId::AlwaysSensitive
                | AzihsmKeyPropId::Extractable
                | AzihsmKeyPropId::NeverExtractable
                | AzihsmKeyPropId::Trusted
                | AzihsmKeyPropId::WrapWithTrusted => Err(AZIHSM_KEY_PROPERTY_NOT_SETTABLE)?,

                // Handle other properties that might not be implemented yet
                _ => builder, // For unhandled properties, just ignore
            };
        }

        Ok(builder)
    }
}

/// Helper function to validate buffer size and prepare output slice.
/// Required length is updated in the output buffer if insufficient.
/// Returns an empty slice if required_len is 0 (no output needed).
pub(crate) fn prepare_output_buffer(
    output_buf: &mut AzihsmBuffer,
    required_len: u32,
) -> Result<&mut [u8], AzihsmError> {
    // Special case: if no output is required, return empty slice
    if required_len == 0 {
        return Ok(&mut []);
    }

    if output_buf.len < required_len {
        output_buf.len = required_len;
        Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
    }

    output_buf.as_mut_slice()
}

// Export all macros for use in other modules
pub(crate) use convert_key_props;
pub(crate) use deref_const_ptr;
pub(crate) use deref_mut_ptr;
pub(crate) use validate_buffer;
pub(crate) use validate_conditions;
pub(crate) use validate_pointers;
pub(crate) use write_to_out_ptr;
