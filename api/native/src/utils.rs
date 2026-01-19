// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_void;

use super::*;

pub(crate) fn validate_ptr<T>(ptr: *const T) -> Result<(), AzihsmError> {
    if ptr.is_null() {
        Err(AzihsmError::InvalidArgument)
    } else {
        Ok(())
    }
}

/// Safely dereference a mutable pointer
///
/// # Safety
/// The function validates that the pointer is non-null before dereferencing.
#[allow(unsafe_code)]
#[allow(unused)]
pub(crate) fn deref_mut_ptr<'a, T>(ptr: *mut T) -> Result<&'a mut T, AzihsmError> {
    validate_ptr(ptr)?;

    // SAFETY: Pointer has been validated as non-null above
    Ok(unsafe { &mut *ptr })
}

/// Safely dereference a constant pointer
///
/// # Safety
/// The function validates that the pointer is non-null before dereferencing.
#[allow(unsafe_code)]
pub(crate) fn deref_ptr<'a, T>(ptr: *const T) -> Result<&'a T, AzihsmError> {
    validate_ptr(ptr)?;

    // SAFETY: Pointer has been validated as non-null above
    Ok(unsafe { &*ptr })
}

/// Safely assign a value to a pointer
///
/// # Safety
///
/// The function validates that the pointer is non-null before writing.
#[allow(unsafe_code)]
pub(crate) fn assign_ptr<T>(ptr: *mut T, value: T) -> Result<(), AzihsmError> {
    validate_ptr(ptr)?;

    // SAFETY: Pointer has been validated as non-null above
    unsafe {
        *ptr = value;
    }
    Ok(())
}

/// Validate and prepare the caller-provided output buffer.
///
/// - If the buffer is large enough, returns a mutable slice to write into.
/// - If it is too small, sets `output_buf.len` to `required_len` and returns
///   `AzihsmError::BufferTooSmall` so the caller can resize and retry.
///
/// This function does not write any data; it only checks size and produces
/// a slice on success.
pub(crate) fn validate_output_buffer(
    output_buf: &mut crate::AzihsmBuffer,
    required_len: usize,
) -> Result<&mut [u8], AzihsmError> {
    // Check if output buffer is large enough
    if output_buf.len < required_len as u32 {
        output_buf.len = required_len as u32;
        Err(AzihsmError::BufferTooSmall)?;
    }

    // Get output buffer slice
    output_buf.try_into()
}

/// Cast a raw pointer to a typed reference after validation
///
/// # Safety
/// The caller must ensure that:
/// - The pointer points to valid memory containing a properly initialized value of type T
/// - The memory layout matches the expected type T
/// - The pointer's lifetime exceeds the returned reference lifetime
///
/// # Arguments
/// * `ptr` - Raw pointer to cast
///
/// # Returns
/// * `Ok(&T)` - Reference to the typed value
/// * `Err(AzihsmError::NullPointer)` - If the pointer is null
#[allow(unsafe_code)]
pub(crate) fn cast_ptr<'a, T>(ptr: *const c_void) -> Result<&'a T, AzihsmError> {
    validate_ptr(ptr)?;

    // SAFETY: We have validated that the pointer is not null.
    // The caller is responsible for ensuring the pointer points to valid memory
    // containing a properly initialized value of type T.
    Ok(unsafe { &*(ptr as *const T) })
}

/// Copy a byte slice into a key property buffer
///
/// # Arguments
///
/// * `key_prop` - The key property to copy into
/// * `bytes` - The byte slice to copy from
///
/// # Returns
///
/// * `Ok(())` - On success
/// * `Err(AzihsmError::BufferTooSmall)` - If the key property buffer is too small
pub(crate) fn copy_to_key_prop(
    key_prop: &mut AzihsmKeyProp,
    bytes: &[u8],
) -> Result<(), AzihsmError> {
    let required_len = bytes.len() as u32;
    if key_prop.len < required_len {
        key_prop.len = required_len;
        Err(AzihsmError::BufferTooSmall)?;
    }
    let buf: &mut [u8] = key_prop.try_into()?;
    buf[..bytes.len()].copy_from_slice(bytes);
    key_prop.len = required_len;
    Ok(())
}
