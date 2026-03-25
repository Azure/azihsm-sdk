// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency FFI types and bridge implementations.
//!
//! Defines `#[repr(C)]` operations structs that C callers populate with their
//! storage, lock, and POTA callback implementations. Bridge structs
//! implement the Rust API traits by dispatching through the C function
//! pointers.
//!
//! # Safety contract for C callers
//!
//! - All function pointers in the ops structs must be valid (non-null).
//! - The `ctx` pointer must remain valid for the lifetime of the partition
//!   handle (i.e., until `azihsm_part_close` is called).
//! - `ctx` **must not** contain or reference the same partition handle
//!   (`azihsm_handle`) that is being initialized — callbacks are invoked
//!   while the partition's internal lock is held, so calling back into the
//!   same partition will deadlock. If a callback needs to query the device
//!   (e.g., retrieve the PID public key), store the device **path** in
//!   `ctx` and open a separate partition handle inside the callback.
//! - All callbacks must be thread-safe — they may be called concurrently
//!   from multiple threads.

use std::ffi::CString;
use std::ffi::c_char;
use std::ffi::c_void;
use std::sync::Arc;

use azihsm_api as api;

use crate::AzihsmBuffer;
use crate::AzihsmStatus;
use crate::utils::deref_ptr;

/// Maximum size (in bytes) for a single resiliency storage value returned
/// by a C callback. Prevents excessive allocation from a misbehaving caller.
/// 1 MiB is far beyond any realistic blob (BMK ~350 B, masked key ~2720 B).
const MAX_STORAGE_READ_SIZE: usize = 1024 * 1024;

/// Maximum size (in bytes) for each POTA endorsement output buffer
/// (signature or public key). POTA uses P-384: signature is 96 bytes,
/// public key is 120 bytes DER. 64 KiB is extremely generous.
const MAX_POTA_BUFFER_SIZE: usize = 64 * 1024;

/// Storage operations for resiliency.
///
/// All three function pointers are required.
///
/// `read`: Reads data for the given key into the output buffer. If the
/// output buffer is too small (or null/zero-length), sets `output->len` to
/// the required size and returns `AZIHSM_STATUS_BUFFER_TOO_SMALL`. Returns
/// `AZIHSM_STATUS_NOT_FOUND` when the key does not exist.
///
/// `write`: Writes data for the given key (create or overwrite).
///
/// `clear`: Deletes data for the given key. No error if key doesn't exist.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AzihsmResiliencyStorageOps {
    pub read: unsafe extern "C" fn(
        ctx: *mut c_void,
        key: *const c_char,
        value: *mut AzihsmBuffer,
    ) -> AzihsmStatus,

    pub write: unsafe extern "C" fn(
        ctx: *mut c_void,
        key: *const c_char,
        value: *const AzihsmBuffer,
    ) -> AzihsmStatus,

    pub clear: unsafe extern "C" fn(ctx: *mut c_void, key: *const c_char) -> AzihsmStatus,
}

/// Lock operations for cross-process/thread restore coordination.
///
/// Both function pointers are required. The lock is non-reentrant.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AzihsmResiliencyLockOps {
    pub lock: unsafe extern "C" fn(ctx: *mut c_void) -> AzihsmStatus,
    pub unlock: unsafe extern "C" fn(ctx: *mut c_void) -> AzihsmStatus,
}

/// POTA endorsement callback.
///
/// The `endorse` callback re-endorses the public key with the caller's OBKE
/// private key. Uses the two-call buffer pattern: first call with null/zero
/// output buffers to query sizes, second call to fill them.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AzihsmPotaCallbackOps {
    pub endorse: unsafe extern "C" fn(
        ctx: *mut c_void,
        pub_key: *const AzihsmBuffer,
        signature: *mut AzihsmBuffer,
        endorsement_pub_key: *mut AzihsmBuffer,
    ) -> AzihsmStatus,
}

/// Resiliency configuration passed to `azihsm_part_init`.
///
/// - `ctx`: Opaque context pointer passed back to every callback. The SDK
///   never dereferences this — the caller owns and manages it. Must remain
///   valid until `azihsm_part_close` returns. **Must not** contain or
///   reference the same partition handle — see module-level safety docs.
/// - `storage_ops` and `lock_ops` are always required (inline).
/// - `pota_callback_ops`: Pointer to POTA callback ops. NULL when POTA
///   endorsement source is TPM. Must be non-null when source is Caller.
#[repr(C)]
pub struct AzihsmResiliencyConfig {
    pub ctx: *mut c_void,
    pub storage_ops: AzihsmResiliencyStorageOps,
    pub lock_ops: AzihsmResiliencyLockOps,
    pub pota_callback_ops: *const AzihsmPotaCallbackOps,
}

/// Bridge that implements [`api::ResiliencyStorage`] by calling through
/// C function pointers.
struct ResiliencyStorageAdapter {
    ctx: *mut c_void,
    ops: AzihsmResiliencyStorageOps,
}

// SAFETY: The C caller is contractually responsible for ensuring their
// callbacks and the ctx pointer are thread-safe. This is documented in
// the AzihsmResiliencyConfig API contract.
#[allow(unsafe_code)]
unsafe impl Send for ResiliencyStorageAdapter {}

// SAFETY: The C caller is contractually responsible for ensuring their
// callbacks and the ctx pointer are thread-safe. This is documented in
// the AzihsmResiliencyConfig API contract.
#[allow(unsafe_code)]
unsafe impl Sync for ResiliencyStorageAdapter {}

/// Bridge that implements [`api::ResiliencyLock`] by calling through
/// C function pointers.
struct ResiliencyLockAdapter {
    ctx: *mut c_void,
    ops: AzihsmResiliencyLockOps,
}

// SAFETY: See ResiliencyStorageBridge safety comment.
#[allow(unsafe_code)]
unsafe impl Send for ResiliencyLockAdapter {}

// SAFETY: See ResiliencyStorageBridge safety comment.
#[allow(unsafe_code)]
unsafe impl Sync for ResiliencyLockAdapter {}

/// Bridge that implements [`api::PotaEndorsementCallback`] by calling
/// through C function pointers.
struct PotaCallbackAdapter {
    ctx: *mut c_void,
    ops: AzihsmPotaCallbackOps,
}

// SAFETY: See ResiliencyStorageBridge safety comment.
#[allow(unsafe_code)]
unsafe impl Send for PotaCallbackAdapter {}

// SAFETY: See ResiliencyStorageBridge safety comment.
#[allow(unsafe_code)]
unsafe impl Sync for PotaCallbackAdapter {}

impl api::ResiliencyStorage for ResiliencyStorageAdapter {
    #[allow(unsafe_code)]
    fn read(&self, key: &str) -> api::HsmResult<Vec<u8>> {
        let c_key = CString::new(key).map_err(|_| api::HsmError::InvalidArgument)?;

        // First call: query required size (null buffer)
        let mut buf = AzihsmBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };

        // SAFETY: Calling through a valid function pointer (guaranteed non-null
        // by Rust's type system). c_key is a valid null-terminated C string.
        let status: api::HsmError =
            unsafe { (self.ops.read)(self.ctx, c_key.as_ptr(), &mut buf) }.into();

        match status {
            api::HsmError::NotFound => return Err(api::HsmError::NotFound),
            api::HsmError::BufferTooSmall => { /* expected — buf.len now has the required size */
            }
            api::HsmError::Success => {
                // Zero-length data exists
                return Ok(Vec::new());
            }
            err => return Err(err),
        }

        // Second call: read into allocated buffer
        let len = buf.len as usize;
        if len > MAX_STORAGE_READ_SIZE {
            return Err(api::HsmError::InvalidArgument);
        }
        let mut data = vec![0u8; len];
        buf.ptr = data.as_mut_ptr() as *mut c_void;

        // SAFETY: buf.ptr points to a valid allocation of buf.len bytes.
        let status: api::HsmError =
            unsafe { (self.ops.read)(self.ctx, c_key.as_ptr(), &mut buf) }.into();

        if status != api::HsmError::Success {
            return Err(status);
        }

        data.truncate(buf.len as usize);
        Ok(data)
    }

    #[allow(unsafe_code)]
    fn write(&self, key: &str, data: &[u8]) -> api::HsmResult<()> {
        let c_key = CString::new(key).map_err(|_| api::HsmError::InvalidArgument)?;

        // Cast to *mut is safe: the C callback receives this via *const AzihsmBuffer
        // so it will not write through this pointer.
        let buf = AzihsmBuffer {
            ptr: data.as_ptr() as *mut c_void,
            len: data.len() as u32,
        };

        // SAFETY: buf.ptr points to the caller's data slice which remains
        // valid for the duration of this synchronous call.
        let status: api::HsmError =
            unsafe { (self.ops.write)(self.ctx, c_key.as_ptr(), &buf) }.into();

        if status != api::HsmError::Success {
            return Err(status);
        }

        Ok(())
    }

    #[allow(unsafe_code)]
    fn clear(&self, key: &str) -> api::HsmResult<()> {
        let c_key = CString::new(key).map_err(|_| api::HsmError::InvalidArgument)?;

        // SAFETY: c_key is a valid null-terminated C string.
        let status: api::HsmError = unsafe { (self.ops.clear)(self.ctx, c_key.as_ptr()) }.into();

        if status != api::HsmError::Success {
            return Err(status);
        }

        Ok(())
    }
}

impl api::ResiliencyLock for ResiliencyLockAdapter {
    #[allow(unsafe_code)]
    fn lock(&self) -> api::HsmResult<()> {
        // SAFETY: Calling through a valid function pointer.
        let status: api::HsmError = unsafe { (self.ops.lock)(self.ctx) }.into();

        if status != api::HsmError::Success {
            return Err(status);
        }

        Ok(())
    }

    #[allow(unsafe_code)]
    fn unlock(&self) -> api::HsmResult<()> {
        // SAFETY: Calling through a valid function pointer.
        let status: api::HsmError = unsafe { (self.ops.unlock)(self.ctx) }.into();

        if status != api::HsmError::Success {
            return Err(status);
        }

        Ok(())
    }
}

impl api::PotaEndorsementCallback for PotaCallbackAdapter {
    #[allow(unsafe_code)]
    fn endorse(&self, pub_key: &[u8]) -> api::HsmResult<api::HsmPotaEndorsementData> {
        // Cast to *mut is safe: the C callback receives this via *const AzihsmBuffer
        // so it will not write through this pointer.
        let pk_input_buf = AzihsmBuffer {
            ptr: pub_key.as_ptr() as *mut c_void,
            len: pub_key.len() as u32,
        };

        // First call: query required output sizes
        let mut sig_buf = AzihsmBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let mut pk_out_buf = AzihsmBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };

        // SAFETY: pk_input_buf points to valid pub_key data. sig_buf and
        // pk_out_buf are zero-initialized for size query.
        let status: api::HsmError =
            unsafe { (self.ops.endorse)(self.ctx, &pk_input_buf, &mut sig_buf, &mut pk_out_buf) }
                .into();

        match status {
            api::HsmError::BufferTooSmall => { /* expected — sizes now in len fields */ }
            api::HsmError::Success => {
                // Protocol violation: the first (size-query) call must return
                // BufferTooSmall with the required output sizes. Success with
                // null buffers indicates a misbehaving callback.
                return Err(api::HsmError::InvalidArgument);
            }
            err => return Err(err),
        }

        // Second call: fill allocated buffers
        let sig_len = sig_buf.len as usize;
        let pk_len = pk_out_buf.len as usize;
        if sig_len > MAX_POTA_BUFFER_SIZE || pk_len > MAX_POTA_BUFFER_SIZE {
            return Err(api::HsmError::InvalidArgument);
        }
        let mut sig_data = vec![0u8; sig_len];
        let mut pk_data = vec![0u8; pk_len];
        sig_buf.ptr = sig_data.as_mut_ptr() as *mut c_void;
        pk_out_buf.ptr = pk_data.as_mut_ptr() as *mut c_void;

        // SAFETY: Both buffers point to valid Vec allocations of the queried sizes.
        let status: api::HsmError =
            unsafe { (self.ops.endorse)(self.ctx, &pk_input_buf, &mut sig_buf, &mut pk_out_buf) }
                .into();

        if status != api::HsmError::Success {
            return Err(status);
        }

        sig_data.truncate(sig_buf.len as usize);
        pk_data.truncate(pk_out_buf.len as usize);

        Ok(api::HsmPotaEndorsementData::new(&sig_data, &pk_data))
    }
}

impl TryFrom<&AzihsmResiliencyConfig> for api::HsmResiliencyConfig {
    type Error = AzihsmStatus;

    #[allow(unsafe_code)]
    fn try_from(config: &AzihsmResiliencyConfig) -> Result<Self, Self::Error> {
        // Validate that all required function pointers are non-null.
        // The #[repr(C)] structs could have been zero-initialized by a C caller.
        if (config.storage_ops.read as usize) == 0
            || (config.storage_ops.write as usize) == 0
            || (config.storage_ops.clear as usize) == 0
            || (config.lock_ops.lock as usize) == 0
            || (config.lock_ops.unlock as usize) == 0
        {
            return Err(AzihsmStatus::InvalidArgument);
        }

        let storage = Box::new(ResiliencyStorageAdapter {
            ctx: config.ctx,
            ops: config.storage_ops,
        });

        let lock = Arc::new(ResiliencyLockAdapter {
            ctx: config.ctx,
            ops: config.lock_ops,
        });

        let pota_callback = if config.pota_callback_ops.is_null() {
            None
        } else {
            let ops = *deref_ptr(config.pota_callback_ops)?;
            if (ops.endorse as usize) == 0 {
                return Err(AzihsmStatus::InvalidArgument);
            }
            Some(Box::new(PotaCallbackAdapter {
                ctx: config.ctx,
                ops,
            }) as Box<dyn api::PotaEndorsementCallback>)
        };

        Ok(api::HsmResiliencyConfig {
            storage,
            lock,
            pota_callback,
        })
    }
}
