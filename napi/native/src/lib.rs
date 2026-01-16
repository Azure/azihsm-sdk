// Copyright (C) Microsoft Corporation. All rights reserved.

//! Native C API bindings for Azure Industrial HSM (IHSM).
//!
//! This crate provides a Foreign Function Interface (FFI) layer that exposes
//! the Rust HSM API to C and C++ applications. It implements the ABI-stable
//! interface with proper error handling, panic catching, and resource management
//! through a global handle table.
//!
//! # Architecture
//!
//! The native API layer consists of:
//! - Handle-based resource management for partitions, sessions, and other objects
//! - ABI boundary functions that catch panics and convert errors
//! - Type-safe wrappers around the internal Rust API
//! - C-compatible types and calling conventions

mod algo;
mod crypto_digest;
mod crypto_enc_dec;
mod crypto_sign_verify;
#[allow(unused)]
#[path = "../../lib/src/error.rs"]
mod error;
mod handle_table;
mod key_mgmt;
mod key_props;
mod partition;
mod session;
#[allow(unused)]
#[path = "../../lib/src/shared_types.rs"]
mod shared_types;
mod str;
mod utils;

use std::ffi::c_void;
use std::ops::AddAssign;
use std::ops::Deref;
use std::ops::DerefMut;
use std::panic::*;
use std::sync::*;

use algo::*;
use azihsm_napi as api;
use azihsm_napi::HsmEccCurve;
use azihsm_napi::HsmKeyKind;
use error::*;
use handle_table::*;
use key_props::*;
#[allow(unused)]
use shared_types::*;
use str::*;
use utils::*;

/// Handle type for referencing HSM objects across the FFI boundary.
///
/// A 32-bit unsigned integer used as an opaque handle to reference HSM objects
/// such as partitions, sessions, and keys. Handles are managed by the global
/// handle table and should be treated as opaque identifiers by C callers.
#[repr(transparent)]
#[derive(Eq, Hash, PartialEq, Copy, Clone, Default)]
pub struct AzihsmHandle(u32);

impl Deref for AzihsmHandle {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AzihsmHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AddAssign<u32> for AzihsmHandle {
    fn add_assign(&mut self, other: u32) {
        self.0 += other;
    }
}

/// Error type used throughout the native API.
///
/// An alias for `HsmError` that represents all possible error conditions
/// in the HSM API. This type is returned across the ABI boundary and can
/// be converted to appropriate error codes for C callers.
type AzihsmError = HsmError;

/// An alias for ECC curves.
#[allow(unused)]
type AzihsmEccCurve = HsmEccCurve;

/// An alias for key kinds.
#[allow(unused)]
type AzihsmKeyKind = HsmKeyKind;

/// An alias for key classes.
#[allow(unused)]
type AzihsmKeyClass = HsmKeyClass;

/// Global handle table for managing HSM object lifetimes.
///
/// This static variable provides a thread-safe, lazily-initialized handle table
/// that tracks all allocated HSM objects (partitions, sessions, keys, etc.).
/// Handles allocated from this table remain valid until explicitly freed or
/// the process terminates.
static HANDLE_TABLE: LazyLock<HandleTable> = LazyLock::new(HandleTable::default);

/// Executes a function at the ABI boundary with panic catching.
///
/// This internal function wraps API calls to provide a safe boundary between
/// Rust and C code. It catches any panics that occur during execution and
/// converts them to appropriate error codes, preventing unwinding across the
/// FFI boundary which would be undefined behavior.
///
/// # Arguments
///
/// * `f` - A closure that performs the API operation and returns a `Result`
///
/// # Returns
///
/// Returns an `AzihsmError` indicating:
/// - `AzihsmError::Success` if the operation completed successfully
/// - The specific error if the operation failed
/// - `AzihsmError::Panic` if a panic occurred during execution
///
/// # Type Parameters
///
/// * `F` - A function or closure that is `UnwindSafe` and returns a `Result<(), AzihsmError>`
pub(crate) fn abi_boundary<F: FnOnce() -> Result<(), AzihsmError> + UnwindSafe>(
    f: F,
) -> AzihsmError {
    match catch_unwind(f) {
        Ok(hr) => match hr {
            Ok(_) => AzihsmError::Success,
            Err(err) => err,
        },
        Err(_) => AzihsmError::Panic,
    }
}

impl From<api::HsmError> for AzihsmError {
    /// Converts an `api::HsmError` into an `AzihsmError`.
    #[allow(unsafe_code)]
    fn from(err: api::HsmError) -> Self {
        // SAFETY: AzihsmError and api::HsmError have the same representation
        unsafe { std::mem::transmute(err) }
    }
}

/// credentials structure used for authentication.
///
/// This structure contains the identifier and PIN required
/// to authenticate with the HSM.
///
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AzihsmCredentials {
    /// Identifier (16 bytes)
    pub id: [u8; 16],

    /// PIN (16 bytes)
    pub pin: [u8; 16],
}

impl From<AzihsmCredentials> for api::HsmCredentials {
    fn from(creds: AzihsmCredentials) -> Self {
        let AzihsmCredentials { id, pin } = creds;
        api::HsmCredentials { id, pin }
    }
}

impl From<&AzihsmCredentials> for api::HsmCredentials {
    fn from(creds: &AzihsmCredentials) -> Self {
        Self::from(*creds)
    }
}

/// API revision structure used to specify the desired API version.
///
/// This structure allows clients to specify the major and minor version
/// numbers of the API they wish to use. It is used to ensure compatibility
/// between different versions of the HSM API.
///
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AzihsmApiRev {
    /// Major version number
    pub major: u32,

    /// Minor version number
    pub minor: u32,
}

impl From<AzihsmApiRev> for api::HsmApiRev {
    fn from(rev: AzihsmApiRev) -> Self {
        api::HsmApiRev {
            major: rev.major,
            minor: rev.minor,
        }
    }
}

impl From<&AzihsmApiRev> for api::HsmApiRev {
    fn from(rev: &AzihsmApiRev) -> Self {
        Self::from(*rev)
    }
}

impl TryFrom<AzihsmHandle> for api::HsmSession {
    type Error = AzihsmError;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmSession, Self::Error> {
        let session: &api::HsmSession = HANDLE_TABLE.as_ref(value, HandleType::Session)?;
        Ok(session.clone())
    }
}

impl TryFrom<AzihsmHandle> for api::HsmPartition {
    type Error = AzihsmError;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmPartition, Self::Error> {
        let partition: &api::HsmPartition = HANDLE_TABLE.as_ref(value, HandleType::Partition)?;
        Ok(partition.clone())
    }
}

impl TryFrom<AzihsmHandle> for api::HsmAesKey {
    type Error = AzihsmError;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmAesKey, Self::Error> {
        let key: &api::HsmAesKey = HANDLE_TABLE.as_ref(value, HandleType::AesKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<AzihsmHandle> for api::HsmEccPrivateKey {
    type Error = AzihsmError;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmEccPrivateKey, Self::Error> {
        let key: &api::HsmEccPrivateKey = HANDLE_TABLE.as_ref(value, HandleType::EccPrivKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<AzihsmHandle> for api::HsmEccPublicKey {
    type Error = AzihsmError;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmEccPublicKey, Self::Error> {
        let key: &api::HsmEccPublicKey = HANDLE_TABLE.as_ref(value, HandleType::EccPubKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<AzihsmHandle> for HandleType {
    type Error = AzihsmError;

    fn try_from(value: AzihsmHandle) -> Result<HandleType, Self::Error> {
        HANDLE_TABLE.get_handle_type(value)
    }
}

/// C FFI structure for a buffer
///
/// # Safety
/// When using this struct from C code:
/// - `ptr` must point to valid memory for `len` bytes
/// - `ptr` lifetime must exceed the lifetime of this struct
/// - Caller is responsible for proper memory management
#[repr(C)]
pub struct AzihsmBuffer {
    pub ptr: *mut c_void,
    pub len: u32,
}

impl<'a> TryFrom<&'a AzihsmBuffer> for &'a [u8] {
    type Error = AzihsmError;

    /// Converts an AzihsmBuffer to a byte slice.
    ///
    /// # Safety
    /// The caller must ensure that `buffer.buf` points to valid memory
    /// containing at least `buffer.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(buffer: &'a AzihsmBuffer) -> Result<Self, Self::Error> {
        // Check for null pointer
        if buffer.ptr.is_null() {
            return Err(AzihsmError::InvalidArgument);
        }

        // Safety: Caller ensures buffer.buf points to valid memory
        let slice =
            unsafe { std::slice::from_raw_parts(buffer.ptr as *const u8, buffer.len as usize) };

        Ok(slice)
    }
}

impl<'a> TryFrom<&'a mut AzihsmBuffer> for &'a mut [u8] {
    type Error = AzihsmError;

    /// Converts a mutable AzihsmBuffer to a mutable byte slice.
    ///
    /// # Safety
    /// The caller must ensure that `buffer.buf` points to valid memory
    /// containing at least `buffer.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(buffer: &'a mut AzihsmBuffer) -> Result<Self, Self::Error> {
        // Check for null pointer
        if buffer.ptr.is_null() {
            // Only allow null buffer if length is 0
            if buffer.len == 0 {
                return Ok(&mut []);
            } else {
                return Err(AzihsmError::InvalidArgument);
            }
        }

        // Safety: Caller ensures buffer.buf points to valid memory
        let slice =
            unsafe { std::slice::from_raw_parts_mut(buffer.ptr as *mut u8, buffer.len as usize) };

        Ok(slice)
    }
}

impl TryFrom<AzihsmHandle> for api::HsmHmacKey {
    type Error = AzihsmError;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmHmacKey, Self::Error> {
        let key: &api::HsmHmacKey = HANDLE_TABLE.as_ref(value, HandleType::HmacKey)?;
        Ok(key.clone())
    }
}
