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
    if ptr.is_null() {
        return Err(AzihsmError::InvalidArgument);
    }
    // SAFETY: Pointer has been validated as non-null above
    unsafe {
        *ptr = value;
    }
    Ok(())
}
