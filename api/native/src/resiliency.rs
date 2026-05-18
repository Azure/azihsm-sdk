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
//!   same partition will deadlock.
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
/// public key is 120 bytes DER.
const MAX_POTA_BUFFER_SIZE: usize = 4 * 1024;

/// OBK (Owner Backup Key) size in bytes per the API contract.
const OBK_SIZE: usize = 48;

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
/// The `endorse` callback re-endorses the device's PID certificate public
/// key with the caller's POTA private key. Uses the two-call buffer pattern:
/// first call with null/zero output buffers to query sizes, second call to
/// fill them.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AzihsmPotaCallbackOps {
    pub endorse: unsafe extern "C" fn(
        ctx: *mut c_void,
        pota_pub_key_der: *const AzihsmBuffer,
        pid_pub_key_der: *const AzihsmBuffer,
        pid_cert_chain_pem: *const AzihsmBuffer,
        signature: *mut AzihsmBuffer,
        endorsement_pub_key: *mut AzihsmBuffer,
    ) -> AzihsmStatus,
}

/// OBK provider callback.
///
/// The `get_obk` callback returns the caller's OBK (owner backup key)
/// during resiliency restore. Uses the two-call buffer pattern: first call
/// with null/zero output buffer to query size, second call to fill it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AzihsmObkCallbackOps {
    pub get_obk: unsafe extern "C" fn(ctx: *mut c_void, obk: *mut AzihsmBuffer) -> AzihsmStatus,
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
/// - `obk_callback_ops`: Pointer to OBK callback ops. NULL when OBK
///   source is TPM. Must be non-null when source is Caller.
#[repr(C)]
pub struct AzihsmResiliencyConfig {
    pub ctx: *mut c_void,
    pub storage_ops: AzihsmResiliencyStorageOps,
    pub lock_ops: AzihsmResiliencyLockOps,
    pub pota_callback_ops: *const AzihsmPotaCallbackOps,
    pub obk_callback_ops: *const AzihsmObkCallbackOps,
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

// SAFETY: See ResiliencyStorageAdapter safety comment.
#[allow(unsafe_code)]
unsafe impl Send for ResiliencyLockAdapter {}

// SAFETY: See ResiliencyStorageAdapter safety comment.
#[allow(unsafe_code)]
unsafe impl Sync for ResiliencyLockAdapter {}

/// Bridge that implements [`api::PotaEndorsementCallback`] by calling
/// through C function pointers.
struct PotaCallbackAdapter {
    ctx: *mut c_void,
    ops: AzihsmPotaCallbackOps,
}

// SAFETY: See ResiliencyStorageAdapter safety comment.
#[allow(unsafe_code)]
unsafe impl Send for PotaCallbackAdapter {}

// SAFETY: See ResiliencyStorageAdapter safety comment.
#[allow(unsafe_code)]
unsafe impl Sync for PotaCallbackAdapter {}

/// Bridge that implements [`api::ObkProviderCallback`] by calling
/// through C function pointers.
struct ObkCallbackAdapter {
    ctx: *mut c_void,
    ops: AzihsmObkCallbackOps,
}

// SAFETY: See ResiliencyStorageBridge safety comment.
#[allow(unsafe_code)]
unsafe impl Send for ObkCallbackAdapter {}

// SAFETY: See ResiliencyStorageBridge safety comment.
#[allow(unsafe_code)]
unsafe impl Sync for ObkCallbackAdapter {}

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
            api::HsmError::BufferTooSmall => {
                // Expected — buf.len should now have the required size.
                // Treat BufferTooSmall with len == 0 as a protocol violation
                // to avoid calling back with an invalid (zero-length) buffer.
                if buf.len == 0 {
                    return Err(api::HsmError::InvalidArgument);
                }
            }
            api::HsmError::Success if buf.len == 0 => {
                // Zero-length data exists
                return Ok(Vec::new());
            }
            api::HsmError::Success => {
                // Protocol violation: callback returned Success with non-zero
                // len instead of BufferTooSmall on the size-query call.
                return Err(api::HsmError::InvalidArgument);
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
    fn endorse(
        &self,
        pota_pub_key_der: &[u8],
        pid_pub_key_der: &[u8],
        pid_cert_chain_pem: &[u8],
    ) -> api::HsmResult<api::HsmPotaEndorsementData> {
        // Cast to *mut is safe: the C callback receives these via *const AzihsmBuffer
        // so it will not write through these pointers.
        let pota_pk_buf = AzihsmBuffer {
            ptr: pota_pub_key_der.as_ptr() as *mut c_void,
            len: pota_pub_key_der.len() as u32,
        };
        let pid_pk_buf = AzihsmBuffer {
            ptr: pid_pub_key_der.as_ptr() as *mut c_void,
            len: pid_pub_key_der.len() as u32,
        };
        let pid_chain_buf = AzihsmBuffer {
            ptr: pid_cert_chain_pem.as_ptr() as *mut c_void,
            len: pid_cert_chain_pem.len() as u32,
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

        // SAFETY: pota_pk_buf, pid_pk_buf, and pid_chain_buf point to valid data.
        // sig_buf and pk_out_buf are zero-initialized for size query.
        let status: api::HsmError = unsafe {
            (self.ops.endorse)(
                self.ctx,
                &pota_pk_buf,
                &pid_pk_buf,
                &pid_chain_buf,
                &mut sig_buf,
                &mut pk_out_buf,
            )
        }
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
        let status: api::HsmError = unsafe {
            (self.ops.endorse)(
                self.ctx,
                &pota_pk_buf,
                &pid_pk_buf,
                &pid_chain_buf,
                &mut sig_buf,
                &mut pk_out_buf,
            )
        }
        .into();

        if status != api::HsmError::Success {
            return Err(status);
        }

        sig_data.truncate(sig_buf.len as usize);
        pk_data.truncate(pk_out_buf.len as usize);

        Ok(api::HsmPotaEndorsementData::new(&sig_data, &pk_data))
    }
}

impl api::ObkProviderCallback for ObkCallbackAdapter {
    #[allow(unsafe_code)]
    fn get_obk(&self) -> api::HsmResult<Vec<u8>> {
        // First call: query required output size
        let mut obk_buf = AzihsmBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };

        // SAFETY: obk_buf is zero-initialized for size query.
        let status: api::HsmError = unsafe { (self.ops.get_obk)(self.ctx, &mut obk_buf) }.into();

        match status {
            api::HsmError::BufferTooSmall => { /* expected — size now in len field */ }
            api::HsmError::Success => {
                return Err(api::HsmError::InvalidArgument);
            }
            err => return Err(err),
        }

        // Second call: fill allocated buffer
        let len = obk_buf.len as usize;
        if len != OBK_SIZE {
            return Err(api::HsmError::InvalidArgument);
        }
        let mut data = vec![0u8; len];
        obk_buf.ptr = data.as_mut_ptr() as *mut c_void;

        // SAFETY: obk_buf.ptr points to a valid Vec allocation of obk_buf.len bytes.
        let status: api::HsmError = unsafe { (self.ops.get_obk)(self.ctx, &mut obk_buf) }.into();

        if status != api::HsmError::Success {
            return Err(status);
        }

        let returned_len = obk_buf.len as usize;
        if returned_len != OBK_SIZE {
            return Err(api::HsmError::InvalidArgument);
        }

        data.truncate(returned_len);
        Ok(data)
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

        let obk_callback = if config.obk_callback_ops.is_null() {
            None
        } else {
            let ops = *deref_ptr(config.obk_callback_ops)?;
            if (ops.get_obk as usize) == 0 {
                return Err(AzihsmStatus::InvalidArgument);
            }
            Some(Box::new(ObkCallbackAdapter {
                ctx: config.ctx,
                ops,
            }) as Box<dyn api::ObkProviderCallback>)
        };

        Ok(api::HsmResiliencyConfig {
            storage,
            lock,
            pota_callback,
            obk_callback,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_safety_doc, clippy::undocumented_unsafe_blocks)]

    use std::ptr;

    use super::*;

    #[derive(Clone, Copy)]
    enum StorageReadMode {
        EmptySuccess,
        ZeroLenBufferTooSmall,
        NonZeroLenSuccess,
        OversizedBufferTooSmall,
        SecondCallFailure,
    }

    struct StorageReadCtx {
        mode: StorageReadMode,
        calls: u32,
    }

    struct StatusCtx {
        status: AzihsmStatus,
    }

    #[allow(unsafe_code)]
    unsafe extern "C" fn storage_read_callback(
        ctx: *mut c_void,
        _key: *const c_char,
        value: *mut AzihsmBuffer,
    ) -> AzihsmStatus {
        let ctx = unsafe { &mut *(ctx as *mut StorageReadCtx) };
        let value = unsafe { &mut *value };
        ctx.calls += 1;

        match ctx.mode {
            StorageReadMode::EmptySuccess => {
                value.len = 0;
                AzihsmStatus::Success
            }
            StorageReadMode::ZeroLenBufferTooSmall => {
                value.len = 0;
                AzihsmStatus::BufferTooSmall
            }
            StorageReadMode::NonZeroLenSuccess => {
                value.len = 1;
                AzihsmStatus::Success
            }
            StorageReadMode::OversizedBufferTooSmall => {
                value.len = (MAX_STORAGE_READ_SIZE + 1) as u32;
                AzihsmStatus::BufferTooSmall
            }
            StorageReadMode::SecondCallFailure => {
                if ctx.calls == 1 {
                    value.len = 3;
                    AzihsmStatus::BufferTooSmall
                } else {
                    AzihsmStatus::InternalError
                }
            }
        }
    }

    #[allow(unsafe_code)]
    unsafe extern "C" fn storage_write_callback(
        ctx: *mut c_void,
        _key: *const c_char,
        _value: *const AzihsmBuffer,
    ) -> AzihsmStatus {
        let ctx = unsafe { &*(ctx as *const StatusCtx) };
        ctx.status
    }

    #[allow(unsafe_code)]
    unsafe extern "C" fn storage_clear_callback(
        ctx: *mut c_void,
        _key: *const c_char,
    ) -> AzihsmStatus {
        let ctx = unsafe { &*(ctx as *const StatusCtx) };
        ctx.status
    }

    #[allow(unsafe_code)]
    unsafe extern "C" fn lock_callback(ctx: *mut c_void) -> AzihsmStatus {
        let ctx = unsafe { &*(ctx as *const StatusCtx) };
        ctx.status
    }

    fn storage_adapter(ctx: *mut c_void) -> ResiliencyStorageAdapter {
        ResiliencyStorageAdapter {
            ctx,
            ops: AzihsmResiliencyStorageOps {
                read: storage_read_callback,
                write: storage_write_callback,
                clear: storage_clear_callback,
            },
        }
    }

    fn lock_adapter(ctx: *mut c_void) -> ResiliencyLockAdapter {
        ResiliencyLockAdapter {
            ctx,
            ops: AzihsmResiliencyLockOps {
                lock: lock_callback,
                unlock: lock_callback,
            },
        }
    }

    #[test]
    fn storage_read_accepts_empty_value() {
        let mut ctx = StorageReadCtx {
            mode: StorageReadMode::EmptySuccess,
            calls: 0,
        };
        let adapter = storage_adapter(&mut ctx as *mut _ as *mut c_void);

        let data = api::ResiliencyStorage::read(&adapter, "key").expect("read should succeed");
        assert!(data.is_empty());
        assert_eq!(ctx.calls, 1);
    }

    #[test]
    fn storage_read_rejects_invalid_size_query_protocols() {
        for mode in [
            StorageReadMode::ZeroLenBufferTooSmall,
            StorageReadMode::NonZeroLenSuccess,
            StorageReadMode::OversizedBufferTooSmall,
        ] {
            let mut ctx = StorageReadCtx { mode, calls: 0 };
            let adapter = storage_adapter(&mut ctx as *mut _ as *mut c_void);

            let err = api::ResiliencyStorage::read(&adapter, "key")
                .expect_err("read should reject invalid callback protocol");
            assert_eq!(err, api::HsmError::InvalidArgument);
        }
    }

    #[test]
    fn storage_read_propagates_second_call_failure() {
        let mut ctx = StorageReadCtx {
            mode: StorageReadMode::SecondCallFailure,
            calls: 0,
        };
        let adapter = storage_adapter(&mut ctx as *mut _ as *mut c_void);

        let err = api::ResiliencyStorage::read(&adapter, "key")
            .expect_err("read should propagate callback failure");
        assert_eq!(err, api::HsmError::InternalError);
        assert_eq!(ctx.calls, 2);
    }

    #[test]
    fn storage_write_and_clear_reject_interior_nul_keys() {
        let mut ctx = StatusCtx {
            status: AzihsmStatus::Success,
        };
        let adapter = storage_adapter(&mut ctx as *mut _ as *mut c_void);

        let write_err = api::ResiliencyStorage::write(&adapter, "a\0b", b"data")
            .expect_err("write should reject interior nul key");
        assert_eq!(write_err, api::HsmError::InvalidArgument);

        let clear_err = api::ResiliencyStorage::clear(&adapter, "a\0b")
            .expect_err("clear should reject interior nul key");
        assert_eq!(clear_err, api::HsmError::InvalidArgument);
    }

    #[test]
    fn storage_write_clear_and_lock_propagate_callback_failures() {
        let mut ctx = StatusCtx {
            status: AzihsmStatus::InternalError,
        };
        let adapter = storage_adapter(&mut ctx as *mut _ as *mut c_void);

        let write_err = api::ResiliencyStorage::write(&adapter, "key", b"data")
            .expect_err("write should propagate callback failure");
        assert_eq!(write_err, api::HsmError::InternalError);

        let clear_err = api::ResiliencyStorage::clear(&adapter, "key")
            .expect_err("clear should propagate callback failure");
        assert_eq!(clear_err, api::HsmError::InternalError);

        let lock = lock_adapter(&mut ctx as *mut _ as *mut c_void);
        let lock_err =
            api::ResiliencyLock::lock(&lock).expect_err("lock should propagate callback failure");
        assert_eq!(lock_err, api::HsmError::InternalError);

        let unlock_err = api::ResiliencyLock::unlock(&lock)
            .expect_err("unlock should propagate callback failure");
        assert_eq!(unlock_err, api::HsmError::InternalError);
    }

    #[derive(Clone, Copy)]
    enum PotaMode {
        QuerySuccess,
        OversizedQuery,
        SecondCallFailure,
    }

    struct PotaCtx {
        mode: PotaMode,
        calls: u32,
    }

    #[allow(unsafe_code)]
    unsafe extern "C" fn pota_callback(
        ctx: *mut c_void,
        _pota_pub_key_der: *const AzihsmBuffer,
        _pid_pub_key_der: *const AzihsmBuffer,
        _pid_cert_chain_pem: *const AzihsmBuffer,
        signature: *mut AzihsmBuffer,
        endorsement_pub_key: *mut AzihsmBuffer,
    ) -> AzihsmStatus {
        let ctx = unsafe { &mut *(ctx as *mut PotaCtx) };
        let signature = unsafe { &mut *signature };
        let endorsement_pub_key = unsafe { &mut *endorsement_pub_key };
        ctx.calls += 1;

        match ctx.mode {
            PotaMode::QuerySuccess => AzihsmStatus::Success,
            PotaMode::OversizedQuery => {
                signature.len = (MAX_POTA_BUFFER_SIZE + 1) as u32;
                endorsement_pub_key.len = 1;
                AzihsmStatus::BufferTooSmall
            }
            PotaMode::SecondCallFailure => {
                if ctx.calls == 1 {
                    signature.len = 1;
                    endorsement_pub_key.len = 1;
                    AzihsmStatus::BufferTooSmall
                } else {
                    AzihsmStatus::InternalError
                }
            }
        }
    }

    fn pota_adapter(ctx: *mut c_void) -> PotaCallbackAdapter {
        PotaCallbackAdapter {
            ctx,
            ops: AzihsmPotaCallbackOps {
                endorse: pota_callback,
            },
        }
    }

    #[test]
    fn pota_callback_rejects_invalid_protocols_and_propagates_failure() {
        for mode in [PotaMode::QuerySuccess, PotaMode::OversizedQuery] {
            let mut ctx = PotaCtx { mode, calls: 0 };
            let adapter = pota_adapter(&mut ctx as *mut _ as *mut c_void);

            let err = api::PotaEndorsementCallback::endorse(&adapter, b"pota", b"pid", b"chain")
                .expect_err("endorse should reject invalid callback protocol");
            assert_eq!(err, api::HsmError::InvalidArgument);
        }

        let mut ctx = PotaCtx {
            mode: PotaMode::SecondCallFailure,
            calls: 0,
        };
        let adapter = pota_adapter(&mut ctx as *mut _ as *mut c_void);

        let err = api::PotaEndorsementCallback::endorse(&adapter, b"pota", b"pid", b"chain")
            .expect_err("endorse should propagate callback failure");
        assert_eq!(err, api::HsmError::InternalError);
        assert_eq!(ctx.calls, 2);
    }

    #[derive(Clone, Copy)]
    enum ObkMode {
        QuerySuccess,
        WrongQueryLen,
        SecondCallFailure,
        WrongReturnedLen,
    }

    struct ObkCtx {
        mode: ObkMode,
        calls: u32,
    }

    #[allow(unsafe_code)]
    unsafe extern "C" fn obk_callback(ctx: *mut c_void, obk: *mut AzihsmBuffer) -> AzihsmStatus {
        let ctx = unsafe { &mut *(ctx as *mut ObkCtx) };
        let obk = unsafe { &mut *obk };
        ctx.calls += 1;

        match ctx.mode {
            ObkMode::QuerySuccess => AzihsmStatus::Success,
            ObkMode::WrongQueryLen => {
                obk.len = (OBK_SIZE - 1) as u32;
                AzihsmStatus::BufferTooSmall
            }
            ObkMode::SecondCallFailure => {
                if ctx.calls == 1 {
                    obk.len = OBK_SIZE as u32;
                    AzihsmStatus::BufferTooSmall
                } else {
                    AzihsmStatus::InternalError
                }
            }
            ObkMode::WrongReturnedLen => {
                if ctx.calls == 1 {
                    obk.len = OBK_SIZE as u32;
                    AzihsmStatus::BufferTooSmall
                } else {
                    obk.len = (OBK_SIZE - 1) as u32;
                    AzihsmStatus::Success
                }
            }
        }
    }

    fn obk_adapter(ctx: *mut c_void) -> ObkCallbackAdapter {
        ObkCallbackAdapter {
            ctx,
            ops: AzihsmObkCallbackOps {
                get_obk: obk_callback,
            },
        }
    }

    #[test]
    fn obk_callback_rejects_invalid_protocols_and_propagates_failure() {
        for mode in [ObkMode::QuerySuccess, ObkMode::WrongQueryLen] {
            let mut ctx = ObkCtx { mode, calls: 0 };
            let adapter = obk_adapter(&mut ctx as *mut _ as *mut c_void);

            let err = api::ObkProviderCallback::get_obk(&adapter)
                .expect_err("get_obk should reject invalid callback protocol");
            assert_eq!(err, api::HsmError::InvalidArgument);
        }

        let mut second_call_ctx = ObkCtx {
            mode: ObkMode::SecondCallFailure,
            calls: 0,
        };
        let adapter = obk_adapter(&mut second_call_ctx as *mut _ as *mut c_void);
        let err = api::ObkProviderCallback::get_obk(&adapter)
            .expect_err("get_obk should propagate callback failure");
        assert_eq!(err, api::HsmError::InternalError);
        assert_eq!(second_call_ctx.calls, 2);

        let mut wrong_len_ctx = ObkCtx {
            mode: ObkMode::WrongReturnedLen,
            calls: 0,
        };
        let adapter = obk_adapter(&mut wrong_len_ctx as *mut _ as *mut c_void);
        let err = api::ObkProviderCallback::get_obk(&adapter)
            .expect_err("get_obk should reject the returned length");
        assert_eq!(err, api::HsmError::InvalidArgument);
        assert_eq!(wrong_len_ctx.calls, 2);
    }

    #[test]
    fn config_allows_null_optional_callbacks() {
        let mut ctx = StatusCtx {
            status: AzihsmStatus::Success,
        };
        let config = AzihsmResiliencyConfig {
            ctx: &mut ctx as *mut _ as *mut c_void,
            storage_ops: AzihsmResiliencyStorageOps {
                read: storage_read_callback,
                write: storage_write_callback,
                clear: storage_clear_callback,
            },
            lock_ops: AzihsmResiliencyLockOps {
                lock: lock_callback,
                unlock: lock_callback,
            },
            pota_callback_ops: ptr::null(),
            obk_callback_ops: ptr::null(),
        };

        let resiliency_config = api::HsmResiliencyConfig::try_from(&config)
            .expect("config should accept null optional callbacks");
        assert!(resiliency_config.pota_callback.is_none());
        assert!(resiliency_config.obk_callback.is_none());
    }
}
