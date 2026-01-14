// Copyright (C) Microsoft Corporation. All rights reserved.

use crate::AzihsmError;

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
