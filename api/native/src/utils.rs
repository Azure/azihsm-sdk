// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::c_void;

use super::*;

pub(crate) fn validate_ptr<T>(ptr: *const T) -> Result<(), AzihsmStatus> {
    if ptr.is_null() {
        Err(AzihsmStatus::InvalidArgument)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_algo_params<T>(algo: &AzihsmAlgo) -> Result<(), AzihsmStatus> {
    if algo.len != std::mem::size_of::<T>() as u32 {
        Err(AzihsmStatus::InvalidArgument)?;
    }
    validate_ptr(algo.params)
}

/// Validates that an algorithm descriptor intentionally carries no parameter payload.
///
/// Some algorithm IDs are defined by the C ABI as "parameterless" (there is no
/// corresponding `struct` to parse). For those algorithms, callers must pass:
/// - `algo.params == NULL`
/// - `algo.len == 0`
///
/// This is a strict ABI-shape check at the FFI boundary. It ensures malformed
/// pointer/length combinations are rejected early with `InvalidArgument` instead
/// of being silently ignored.
pub(crate) fn validate_algo_params_absent(algo: &AzihsmAlgo) -> Result<(), AzihsmStatus> {
    if !algo.params.is_null() || algo.len != 0 {
        Err(AzihsmStatus::InvalidArgument)?;
    }

    Ok(())
}

pub(crate) fn validate_and_cast_algo_params<T>(algo: &AzihsmAlgo) -> Result<&T, AzihsmStatus> {
    validate_algo_params::<T>(algo)?;
    cast_ptr::<T>(algo.params)
}

pub(crate) fn validate_and_cast_algo_params_mut<T>(
    algo: &mut AzihsmAlgo,
) -> Result<&mut T, AzihsmStatus> {
    validate_algo_params::<T>(algo)?;
    deref_mut_ptr::<T>(algo.params as *mut T)
}

/// Safely dereference a mutable pointer
///
/// # Safety
/// The function validates that the pointer is non-null before dereferencing.
#[allow(unsafe_code)]
#[allow(unused)]
pub(crate) fn deref_mut_ptr<'a, T>(ptr: *mut T) -> Result<&'a mut T, AzihsmStatus> {
    validate_ptr(ptr)?;

    // SAFETY: Pointer has been validated as non-null above
    Ok(unsafe { &mut *ptr })
}

/// Safely dereference a constant pointer
///
/// # Safety
/// The function validates that the pointer is non-null before dereferencing.
#[allow(unsafe_code)]
pub(crate) fn deref_ptr<'a, T>(ptr: *const T) -> Result<&'a T, AzihsmStatus> {
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
pub(crate) fn assign_ptr<T>(ptr: *mut T, value: T) -> Result<(), AzihsmStatus> {
    validate_ptr(ptr)?;

    // SAFETY: Pointer has been validated as non-null above
    unsafe {
        *ptr = value;
    }
    Ok(())
}

/// Validates that two output handle pointers are non-null and distinct.
///
/// Used at the FFI boundary for APIs that return a key pair (private + public).
/// Rejects null pointers and the case where the caller passes the same pointer
/// for both outputs, which would silently overwrite the first handle.
pub(crate) fn validate_output_handle_ptrs(
    first: *mut AzihsmHandle,
    second: *mut AzihsmHandle,
) -> Result<(), AzihsmStatus> {
    validate_ptr(first)?;
    validate_ptr(second)?;

    if std::ptr::eq(first, second) {
        Err(AzihsmStatus::InvalidArgument)?;
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
) -> Result<&mut [u8], AzihsmStatus> {
    if output_buf.ptr.is_null() && output_buf.len != 0 {
        // Only allow null buffer if length is 0 (for size-query case)
        Err(AzihsmStatus::InvalidArgument)?;
    }

    // Check if output buffer is large enough
    if output_buf.len < required_len as u32 {
        output_buf.len = required_len as u32;
        Err(AzihsmStatus::BufferTooSmall)?;
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
pub(crate) fn cast_ptr<'a, T>(ptr: *const c_void) -> Result<&'a T, AzihsmStatus> {
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
) -> Result<(), AzihsmStatus> {
    let required_len = bytes.len() as u32;
    if key_prop.len < required_len {
        key_prop.len = required_len;
        Err(AzihsmStatus::BufferTooSmall)?;
    }
    let buf: &mut [u8] = key_prop.try_into()?;
    buf[..bytes.len()].copy_from_slice(bytes);
    key_prop.len = required_len;
    Ok(())
}

/// Converts an optional AzihsmBuffer pointer to Option<&[u8]>
///
/// # Arguments
///
/// * `buf` - Pointer to an AzihsmBuffer, may be null
///
/// # Returns
///
/// * `Ok(None)` - if the pointer is null
/// * `Ok(Some(&[u8]))` - if the pointer is valid and contains data
/// * `Err(AzihsmStatus)` - if the pointer is invalid or the buffer is malformed
pub(crate) fn buffer_to_optional_slice<'a>(
    buf: *const AzihsmBuffer,
) -> Result<Option<&'a [u8]>, AzihsmStatus> {
    if buf.is_null() {
        Ok(None)
    } else {
        let buffer = deref_ptr(buf)?;
        Ok(Some(buffer.try_into()?))
    }
}
