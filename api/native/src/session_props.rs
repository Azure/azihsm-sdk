// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_void;

use azihsm_api::*;
use open_enum::open_enum;
use zerocopy::IntoBytes;

use super::*;

/// Session property identifier enumeration.
///
/// This enum defines the various properties that can be queried from an HSM session.
/// Each property has a unique identifier that is used to retrieve specific attributes
/// of a session.
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[open_enum]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AzihsmSessionPropId {
    /// API revision used by the session.
    // Corresponds to AZIHSM_SESSION_PROP_ID_API_REV
    ApiRev = 1,
}

/// C FFI structure for a single session property.
///
/// # Safety
/// When using this struct from C code:
/// - `val` must point to valid memory for `len` bytes
/// - `val` lifetime must exceed the lifetime of this struct
/// - Caller is responsible for proper memory management
#[repr(C)]
pub struct AzihsmSessionProp {
    /// Property identifier.
    pub id: AzihsmSessionPropId,

    /// Pointer to the property value.
    pub val: *mut c_void,

    /// Length of the property value in bytes.
    pub len: u32,
}

/// Get a property of a session
///
/// @param[in] handle Handle to the session
/// @param[in/out] session_prop Pointer to session property structure. On input, specifies which property to get. On output, contains the property value.
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_session_get_prop(
    handle: AzihsmHandle,
    session_prop: *mut AzihsmSessionProp,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(session_prop)?;

        let prop = deref_mut_ptr(session_prop)?;
        let session = HsmSession::try_from(handle)?;

        get_session_prop(&session, prop)
    })
}

/// Helper function to get a session property.
fn get_session_prop(
    session: &HsmSession,
    session_prop: &mut AzihsmSessionProp,
) -> Result<(), AzihsmStatus> {
    match session_prop.id {
        AzihsmSessionPropId::ApiRev => {
            let api_rev = session.api_rev();
            let api_rev_ffi = AzihsmApiRev {
                major: api_rev.major,
                minor: api_rev.minor,
            };
            copy_to_session_prop(session_prop, api_rev_ffi.as_bytes())
        }
        _ => Err(AzihsmStatus::UnsupportedSessionProperty),
    }
}

/// Extract a mutable byte slice from a session property
impl<'a> TryFrom<&'a mut AzihsmSessionProp> for &'a mut [u8] {
    type Error = AzihsmStatus;

    /// Converts a session property to a mutable byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `prop.val` points to valid memory
    /// containing at least `prop.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(prop: &'a mut AzihsmSessionProp) -> Result<Self, Self::Error> {
        validate_ptr(prop.val)?;

        // SAFETY: Pointer has been validated as non-null above
        let slice =
            unsafe { std::slice::from_raw_parts_mut(prop.val as *mut u8, prop.len as usize) };
        Ok(slice)
    }
}

/// Copy a byte slice into a session property buffer.
///
/// # Arguments
///
/// * `session_prop` - The session property to copy into
/// * `bytes` - The byte slice to copy from
///
/// # Returns
///
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus::BufferTooSmall)` - If the session property buffer is too small
fn copy_to_session_prop(
    session_prop: &mut AzihsmSessionProp,
    bytes: &[u8],
) -> Result<(), AzihsmStatus> {
    let required_len = bytes.len() as u32;
    if session_prop.len < required_len {
        session_prop.len = required_len;
        Err(AzihsmStatus::BufferTooSmall)?;
    }

    let buf: &mut [u8] = session_prop.try_into()?;
    buf[..bytes.len()].copy_from_slice(bytes);
    session_prop.len = required_len;
    Ok(())
}
