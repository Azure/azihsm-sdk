// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_void;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::ptr::null_mut;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;

use crate::dynamic_fns;
use crate::safeapi::callback::*;
use crate::safeapi::ec::EcKeyMethod;
use crate::safeapi::engine_ctrl::init_defns;
use crate::safeapi::engine_ctrl::EngineCtrlCmds;
use crate::safeapi::engine_ctrl::ENGINE_CTRL_CMDS;
use crate::safeapi::error::OpenSSLError;
use crate::safeapi::error::OpenSSLResult;
use crate::safeapi::rsa::RsaMethod;
use crate::CRYPTO_get_ex_new_index;
use crate::CRYPTO_set_mem_functions;
use crate::ENGINE_free;
use crate::ENGINE_get_ex_data;
use crate::ENGINE_get_static_state;
use crate::ENGINE_new;
use crate::ENGINE_set_EC;
use crate::ENGINE_set_RSA;
use crate::ENGINE_set_ciphers;
use crate::ENGINE_set_cmd_defns;
use crate::ENGINE_set_ctrl_function;
use crate::ENGINE_set_destroy_function;
use crate::ENGINE_set_ex_data;
use crate::ENGINE_set_id;
use crate::ENGINE_set_load_privkey_function;
use crate::ENGINE_set_name;
use crate::ENGINE_set_pkey_meths;
use crate::OPENSSL_init_crypto;
use crate::CRYPTO_EX_INDEX_ENGINE;
use crate::ENGINE;
use crate::OPENSSL_INIT_NO_ATEXIT;

/// The type for a bind function callback
pub type BindCallback = fn(&Engine, &CStr) -> OpenSSLResult<()>;

static ENGINE_DATA_IDX: AtomicI32 = AtomicI32::new(-1);

fn get_or_init_engine_data_idx() -> OpenSSLResult<c_int> {
    let mut data = ENGINE_DATA_IDX.load(Ordering::Relaxed);
    if data == -1 {
        data = unsafe {
            CRYPTO_get_ex_new_index(
                CRYPTO_EX_INDEX_ENGINE as c_int,
                0,
                null_mut(),
                None,
                None,
                None,
            )
        };

        ENGINE_DATA_IDX.store(data, Ordering::Relaxed);
    }

    if data == -1 {
        tracing::error!("get_or_init_engine_data_idx: could not get index");
        Err(OpenSSLError::EngineDataIndexError)?;
    }

    Ok(data)
}

/// Basic engine wrapper type
#[derive(Clone, Debug)]
pub struct Engine {
    engine_ptr: *mut ENGINE,
    is_allocated: bool,
}

unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

impl Engine {
    /// Create a new Engine from a pointer
    ///
    /// # Argument
    /// * `e` - Pointer to the current ENGINE
    ///
    /// # Return
    /// An engine object wrapping the given pointer
    pub fn new_from_ptr(engine_ptr: *mut ENGINE) -> Self {
        debug_assert!(!engine_ptr.is_null());
        Self {
            engine_ptr,
            is_allocated: false,
        }
    }

    /// Create a new engine with ENGINE_new()
    ///
    /// # Return
    /// An engine object wrapping a new engine, or an error
    pub fn new_engine() -> OpenSSLResult<Self> {
        let engine_ptr = unsafe { ENGINE_new() };
        if engine_ptr.is_null() {
            Err(OpenSSLError::AllocationFailed)?;
        }

        let result = Self {
            engine_ptr,
            is_allocated: true,
        };
        Ok(result)
    }

    /// Static method to perform pre-engine init
    /// # Argument
    /// * `fns` - dynamic function table
    fn pre_init(fns: *const dynamic_fns) {
        // SAFETY: standard OpenSSL init, fns should be valid
        unsafe {
            if ENGINE_get_static_state() == (*(fns)).static_state {
                return;
            }

            CRYPTO_set_mem_functions(
                (*(fns)).mem_fns.malloc_fn,
                (*(fns)).mem_fns.realloc_fn,
                (*(fns)).mem_fns.free_fn,
            );

            OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT as u64, null_mut());
        }
    }

    /// Get mutable pointer to engine
    pub fn as_mut_ptr(&self) -> *mut ENGINE {
        self.engine_ptr
    }

    /// Function to perform OpenSSL engine init in Rust
    ///
    /// # Usage
    /// This function should be called from `bind_engine` in a `pub extern "C"`
    /// function, not mangled.
    ///
    /// # Arguments
    /// * `id` - id of the engine
    /// * `fns` - dynamic function table
    /// * `bind_fn` - callback to perform engine init
    ///
    // NOTE: This function is safe for OpenSSL init as we should not get invalid
    // pointers, may not be safe in other contexts
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn bind(
        &self,
        id: *const c_char,
        fns: *const dynamic_fns,
        bind_fn: BindCallback,
    ) -> OpenSSLResult<()> {
        Self::pre_init(fns);

        let id = if id.is_null() {
            // Will not fail
            CStr::from_bytes_until_nul(b"\0").map_err(OpenSSLError::CStringNoNulError)?
        } else {
            // SAFETY: OpenSSL should not pass us an invalid id
            unsafe { CStr::from_ptr(id) }
        };

        (bind_fn)(self, id)
    }

    /// Set ID of OpenSSL engine
    ///
    /// # Argument
    /// * `id` id of the engine
    pub fn set_id(&self, id: &'static CStr) -> OpenSSLResult<()> {
        // SAFETY: id is valid, engine should be valid
        let result = unsafe { ENGINE_set_id(self.as_mut_ptr(), id.as_ptr()) };
        match result {
            1 => Ok(()),
            _ => Err(OpenSSLError::EngineSetIdError),
        }
    }

    /// Set name of OpenSSL engine
    ///
    /// # Argument
    /// * `name` - name of the engine
    pub fn set_name(&self, name: &'static CStr) -> OpenSSLResult<()> {
        // SAFETY: name is valid, engine should be valid
        let result = unsafe { ENGINE_set_name(self.as_mut_ptr(), name.as_ptr()) };
        match result {
            1 => Ok(()),
            _ => Err(OpenSSLError::EngineSetNameError),
        }
    }

    // Set Engine EC key method callbacks
    ///
    /// # Argument
    /// * `ec_key_method` -  EcKeyMethod structure
    pub fn set_ec(&self, ec_key_method: &EcKeyMethod) -> OpenSSLResult<()> {
        let result = unsafe { ENGINE_set_EC(self.as_mut_ptr(), ec_key_method.as_mut_ptr()) };
        match result {
            1 => Ok(()),
            _ => Err(OpenSSLError::EngineSetEcError),
        }
    }

    /// Set Engine destroy callback
    pub fn set_destroy_function(&self, destroy_fn: EngineDestroyFn) -> OpenSSLResult<()> {
        ENGINE_DESTROY.get_or_init(|| destroy_fn);

        let result =
            unsafe { ENGINE_set_destroy_function(self.as_mut_ptr(), Some(c_engine_destroy_cb)) };
        match result {
            1 => Ok(()),
            _ => Err(OpenSSLError::EngineSetDestroyError),
        }
    }

    /// Set Engine ciphers callback
    pub fn set_ciphers(&self, ciphers_fn: EngineCiphersFn) -> OpenSSLResult<()> {
        ENGINE_CIPHERS.get_or_init(|| ciphers_fn);

        let result = unsafe { ENGINE_set_ciphers(self.as_mut_ptr(), Some(c_engine_ciphers_cb)) };
        match result {
            1 => Ok(()),
            _ => Err(OpenSSLError::EngineSetCiphersError),
        }
    }

    /// Set Engine pkey callback
    pub fn set_pkey(&self, pkey_fn: EnginePKeyFn) -> OpenSSLResult<()> {
        ENGINE_PKEY.get_or_init(|| pkey_fn);

        let result = unsafe { ENGINE_set_pkey_meths(self.as_mut_ptr(), Some(c_engine_pkey_cb)) };
        match result {
            1 => Ok(()),
            _ => Err(OpenSSLError::EngineSetPKeyMethsError),
        }
    }

    /// Set Engine RSA callback
    ///
    /// # Argument
    /// `meth` - `RsaMethod` structure
    pub fn set_rsa(&self, meth: &RsaMethod) -> OpenSSLResult<()> {
        let result = unsafe { ENGINE_set_RSA(self.as_mut_ptr(), meth.as_mut_ptr()) };
        match result {
            1 => Ok(()),
            _ => Err(OpenSSLError::EngineSetRsaError),
        }
    }

    /// Set engine ctrl callback
    pub fn set_engine_ctrl(&self, cmds: EngineCtrlCmds) -> OpenSSLResult<()> {
        ENGINE_CTRL_CMDS.get_or_init(|| cmds);
        let defns = init_defns()?;

        let result = unsafe { ENGINE_set_ctrl_function(self.as_mut_ptr(), Some(c_engine_ctrl_cb)) };
        if result != 1 {
            Err(OpenSSLError::EngineSetCtrlFunctionError)?;
        }

        let result = unsafe { ENGINE_set_cmd_defns(self.as_mut_ptr(), defns) };
        if result != 1 {
            Err(OpenSSLError::EngineSetCtrlDefnsError)?;
        }
        Ok(())
    }

    /// Set Engine load privkey callback
    pub fn set_load_private_key(&self, private_key_fn: EngineLoadKeyFn) -> OpenSSLResult<()> {
        ENGINE_PRIVKEY.get_or_init(|| private_key_fn);
        let result = unsafe {
            ENGINE_set_load_privkey_function(self.as_mut_ptr(), Some(c_engine_load_private_key))
        };
        match result {
            1 => Ok(()),
            _ => Err(OpenSSLError::EngineSetLoadPrivKeyError),
        }
    }

    /// Free the Engine object
    pub fn free(&mut self) {
        unsafe {
            // Decreases ENGINE ref count/frees if ref count is 0
            ENGINE_free(self.as_mut_ptr());
        }
        self.engine_ptr = null_mut();
    }
}

pub struct EngineExData<T> {
    engine: Engine,
    _phantom: PhantomData<T>,
}

/// An engine object with extended data, used to work around type limitations in Rust callbacks.
impl<T> EngineExData<T> {
    /// Create a new object from an existing pointer
    ///
    /// # Argument
    /// * `engine` - a pointer to an OpenSSL `ENGINE` object
    ///
    /// # Return
    /// Engine EX data object from allocated pointer. The data will not be freed on drop.
    pub fn new_from_ptr(engine: *mut ENGINE) -> Self {
        Self {
            engine: Engine::new_from_ptr(engine),
            _phantom: PhantomData,
        }
    }

    /// Set data on engine
    ///
    /// # Argument
    /// * `data` - data to set on engine
    ///
    /// # Return
    /// Result of set data
    pub fn set_data(&mut self, data: T) -> OpenSSLResult<()> {
        let data_idx = get_or_init_engine_data_idx()?;

        // Free any existing data
        self.free_data();

        let data_ptr = Box::into_raw(Box::new(data));

        if unsafe {
            ENGINE_set_ex_data(self.engine.as_mut_ptr(), data_idx, data_ptr as *mut c_void)
        } == -1
        {
            // Retake ownership to drop
            let _ = unsafe { Box::from_raw(data_ptr) };
            Err(OpenSSLError::EngineDataIndexError)?;
        }

        Ok(())
    }

    /// Get reference to data in the engine
    ///
    /// # Return
    /// Reference to data in engine
    pub fn get_data(&self) -> OpenSSLResult<Option<&T>> {
        let data_idx = get_or_init_engine_data_idx()?;

        let data = unsafe { ENGINE_get_ex_data(self.engine.as_mut_ptr(), data_idx) } as *const T;
        if data.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { &*data }))
    }

    /// Get pointer to data in the engine
    ///
    /// # Return
    /// Pointer to data in engine
    pub fn get_data_ptr(&self) -> OpenSSLResult<*mut T> {
        let data_idx = get_or_init_engine_data_idx()?;

        Ok(unsafe { ENGINE_get_ex_data(self.engine.as_mut_ptr(), data_idx) as *mut T })
    }

    /// Free the ancillary data attached to this object
    pub fn free_data(&mut self) {
        let data_idx = match get_or_init_engine_data_idx() {
            Ok(idx) => idx,
            Err(_) => return,
        };
        let data_ptr = match self.get_data_ptr() {
            Ok(ptr) => ptr,
            Err(_) => return,
        };
        if data_ptr.is_null() {
            return;
        }

        // Drop the box
        let _: Box<T> = unsafe { Box::from_raw(data_ptr) };

        unsafe {
            ENGINE_set_ex_data(self.engine.as_mut_ptr(), data_idx, null_mut());
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // If we allocated the engine ourself, free it on drop.
        if self.is_allocated {
            self.free();
        }
    }
}
