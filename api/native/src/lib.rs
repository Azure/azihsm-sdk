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
use azihsm_api as api;
use handle_table::*;
use key_props::*;
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
type AzihsmStatus = error::HsmError;

/// Key class type used in the native API.
///
/// An alias for `HsmKeyClass` that represents the class of a cryptographic key.
/// This type is used across the FFI boundary to indicate whether a key is
/// secret, public, or private.
type AzihsmKeyClass = shared_types::HsmKeyClass;

/// Key kind type used in the native API.
///
/// An alias for `HsmKeyKind` that represents the algorithm type of a cryptographic key.
/// This type is used across the FFI boundary to indicate whether a key is RSA, ECC, AES, etc.
type AzihsmKeyKind = shared_types::HsmKeyKind;

/// ECC curve type used in the native API.
///
/// An alias for `HsmEccCurve` that represents the elliptic curve used for ECC keys.
/// This type is used across the FFI boundary to specify curves like P-256, P-384, and P-521.
type AzihsmEccCurve = shared_types::HsmEccCurve;

impl TryFrom<u32> for AzihsmKeyKind {
    type Error = AzihsmStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AzihsmKeyKind::Rsa),
            2 => Ok(AzihsmKeyKind::Ecc),
            3 => Ok(AzihsmKeyKind::Aes),
            5 => Ok(AzihsmKeyKind::SharedSecret),
            7 => Ok(AzihsmKeyKind::HmacSha256),
            8 => Ok(AzihsmKeyKind::HmacSha384),
            9 => Ok(AzihsmKeyKind::HmacSha512),
            _ => Err(AzihsmStatus::InvalidArgument),
        }
    }
}

impl TryFrom<u32> for AzihsmEccCurve {
    type Error = AzihsmStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AzihsmEccCurve::P256),
            2 => Ok(AzihsmEccCurve::P384),
            3 => Ok(AzihsmEccCurve::P521),
            _ => Err(AzihsmStatus::InvalidArgument),
        }
    }
}

impl TryFrom<u32> for AzihsmKeyClass {
    type Error = AzihsmStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AzihsmKeyClass::Secret),
            2 => Ok(AzihsmKeyClass::Public),
            3 => Ok(AzihsmKeyClass::Private),
            _ => Err(AzihsmStatus::InvalidArgument),
        }
    }
}

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
pub(crate) fn abi_boundary<F: FnOnce() -> Result<(), AzihsmStatus> + UnwindSafe>(
    f: F,
) -> AzihsmStatus {
    match catch_unwind(f) {
        Ok(hr) => match hr {
            Ok(_) => AzihsmStatus::Success,
            Err(err) => err,
        },
        Err(_) => AzihsmStatus::Panic,
    }
}

impl From<api::HsmError> for AzihsmStatus {
    /// Converts an `api::HsmError` into an `AzihsmError`.
    #[allow(unsafe_code)]
    fn from(err: api::HsmError) -> Self {
        // SAFETY: AzihsmError and api::HsmError have the same representation
        unsafe { std::mem::transmute(err) }
    }
}

impl From<AzihsmStatus> for api::HsmError {
    /// Converts an `AzihsmError` into an `api::HsmError`.
    #[allow(unsafe_code)]
    fn from(err: AzihsmStatus) -> Self {
        // SAFETY: AzihsmError and api::HsmError have the same representation
        unsafe { std::mem::transmute(err) }
    }
}

impl From<api::HsmKeyClass> for AzihsmKeyClass {
    /// Converts an `api::HsmKeyClass` into an `AzihsmKeyClass`.
    #[allow(unsafe_code)]
    fn from(class: api::HsmKeyClass) -> Self {
        // SAFETY: AzihsmKeyClass and api::HsmKeyClass have the same representation
        unsafe { std::mem::transmute(class) }
    }
}

impl From<AzihsmKeyClass> for api::HsmKeyClass {
    /// Converts an `AzihsmKeyClass` into an `api::HsmKeyClass`.
    #[allow(unsafe_code)]
    fn from(class: AzihsmKeyClass) -> Self {
        // SAFETY: AzihsmKeyClass and api::HsmKeyClass have the same representation
        unsafe { std::mem::transmute(class) }
    }
}

impl From<api::HsmKeyKind> for AzihsmKeyKind {
    /// Converts an `api::HsmKeyKind` into an `AzihsmKeyKind`.
    #[allow(unsafe_code)]
    fn from(kind: api::HsmKeyKind) -> Self {
        // SAFETY: AzihsmKeyKind and api::HsmKeyKind have the same representation
        unsafe { std::mem::transmute(kind) }
    }
}

impl From<AzihsmKeyKind> for api::HsmKeyKind {
    /// Converts an `AzihsmKeyKind` into an `api::HsmKeyKind`.
    #[allow(unsafe_code)]
    fn from(kind: AzihsmKeyKind) -> Self {
        // SAFETY: AzihsmKeyKind and api::HsmKeyKind have the same representation
        unsafe { std::mem::transmute(kind) }
    }
}

impl From<api::HsmEccCurve> for AzihsmEccCurve {
    /// Converts an `api::HsmEccCurve` into an `AzihsmEccCurve`.
    #[allow(unsafe_code)]
    fn from(curve: api::HsmEccCurve) -> Self {
        // SAFETY: AzihsmEccCurve and api::HsmEccCurve have the same representation
        unsafe { std::mem::transmute(curve) }
    }
}

impl From<AzihsmEccCurve> for api::HsmEccCurve {
    /// Converts an `AzihsmEccCurve` into an `api::HsmEccCurve`.
    #[allow(unsafe_code)]
    fn from(curve: AzihsmEccCurve) -> Self {
        // SAFETY: AzihsmEccCurve and api::HsmEccCurve have the same representation
        unsafe { std::mem::transmute(curve) }
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
    type Error = AzihsmStatus;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmSession, Self::Error> {
        let session: &api::HsmSession = HANDLE_TABLE.as_ref(value, HandleType::Session)?;
        Ok(session.clone())
    }
}

impl TryFrom<AzihsmHandle> for api::HsmPartition {
    type Error = AzihsmStatus;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmPartition, Self::Error> {
        let partition: &api::HsmPartition = HANDLE_TABLE.as_ref(value, HandleType::Partition)?;
        Ok(partition.clone())
    }
}

impl TryFrom<AzihsmHandle> for api::HsmAesKey {
    type Error = AzihsmStatus;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmAesKey, Self::Error> {
        let key: &api::HsmAesKey = HANDLE_TABLE.as_ref(value, HandleType::AesKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<AzihsmHandle> for api::HsmEccPrivateKey {
    type Error = AzihsmStatus;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmEccPrivateKey, Self::Error> {
        let key: &api::HsmEccPrivateKey = HANDLE_TABLE.as_ref(value, HandleType::EccPrivKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<AzihsmHandle> for api::HsmEccPublicKey {
    type Error = AzihsmStatus;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmEccPublicKey, Self::Error> {
        let key: &api::HsmEccPublicKey = HANDLE_TABLE.as_ref(value, HandleType::EccPubKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<AzihsmHandle> for HandleType {
    type Error = AzihsmStatus;

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
    type Error = AzihsmStatus;

    /// Converts an AzihsmBuffer to a byte slice.
    ///
    /// # Safety
    /// The caller must ensure that `buffer.buf` points to valid memory
    /// containing at least `buffer.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(buffer: &'a AzihsmBuffer) -> Result<Self, Self::Error> {
        // Check for null pointer
        if buffer.ptr.is_null() {
            return Err(AzihsmStatus::InvalidArgument);
        }

        // Safety: Caller ensures buffer.buf points to valid memory
        let slice =
            unsafe { std::slice::from_raw_parts(buffer.ptr as *const u8, buffer.len as usize) };

        Ok(slice)
    }
}

impl<'a> TryFrom<&'a mut AzihsmBuffer> for &'a mut [u8] {
    type Error = AzihsmStatus;

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
                return Err(AzihsmStatus::InvalidArgument);
            }
        }

        // Safety: Caller ensures buffer.buf points to valid memory
        let slice =
            unsafe { std::slice::from_raw_parts_mut(buffer.ptr as *mut u8, buffer.len as usize) };

        Ok(slice)
    }
}

impl TryFrom<AzihsmHandle> for api::HsmHmacKey {
    type Error = AzihsmStatus;

    fn try_from(value: AzihsmHandle) -> Result<api::HsmHmacKey, Self::Error> {
        let key: &api::HsmHmacKey = HANDLE_TABLE.as_ref(value, HandleType::HmacKey)?;
        Ok(key.clone())
    }
}

impl<'a> TryFrom<&'a mut AzihsmKeyProp> for &'a mut [u8] {
    type Error = AzihsmStatus;

    /// Converts a mutable AzihsmKeyProp to a mutable byte slice.
    ///
    /// # Safety
    /// The caller must ensure that `key_prop.buf` points to valid memory
    /// containing at least `key_prop.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(key_prop: &'a mut AzihsmKeyProp) -> Result<Self, Self::Error> {
        // Check for null pointer
        if key_prop.val.is_null() {
            // Only allow null buffer if length is 0
            if key_prop.len == 0 {
                return Ok(&mut []);
            } else {
                return Err(AzihsmStatus::InvalidArgument);
            }
        }

        // Safety: Caller ensures key_prop.val points to valid memory
        let slice = unsafe {
            std::slice::from_raw_parts_mut(key_prop.val as *mut u8, key_prop.len as usize)
        };
        Ok(slice)
    }
}
