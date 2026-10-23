// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe wrapper around `*mut ENGINE`.

use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::ptr::null;
use std::ptr::null_mut;

use azihsm_ossl_engine_sys as ffi;

use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::RetCode;
use crate::error::catch_panic;
use crate::error::ossl_check;
use crate::error::result_to_int;
use crate::error::result_to_ptr;

pub struct Engine {
    ptr: *mut ffi::ENGINE,
}

// SAFETY: ENGINE access is serialized by OpenSSL's CRYPTO_LOCK_ENGINE.
#[allow(unsafe_code)]
unsafe impl Send for Engine {}
// SAFETY: Same as above.
#[allow(unsafe_code)]
unsafe impl Sync for Engine {}

impl Engine {
    /// # Safety
    /// `ptr` must point to a valid `ENGINE` for the lifetime of the returned value.
    #[allow(unsafe_code)]
    pub unsafe fn from_ptr(ptr: NonNull<ffi::ENGINE>) -> Self {
        Self { ptr: ptr.as_ptr() }
    }

    /// The raw `*mut ENGINE`, for FFI calls that need the pointer directly.
    pub(crate) fn as_ptr(&self) -> *mut ffi::ENGINE {
        self.ptr
    }

    /// Synchronize memory allocators with the host, then call `f`.
    ///
    /// # Safety
    /// `fns` must point to a valid `dynamic_fns` for the duration of this call.
    /// `id`, if non-null, must be a valid C string.
    #[allow(unsafe_code)]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub unsafe fn bind(
        &mut self,
        id: *const c_char,
        fns: NonNull<ffi::dynamic_fns>,
        f: fn(&mut Engine, &CStr) -> EngineResult<()>,
    ) -> EngineResult<()> {
        let fns_ptr = fns.as_ptr();

        // SAFETY: Caller guarantees fns points to a valid dynamic_fns.
        unsafe {
            if ffi::ENGINE_get_static_state() != (*fns_ptr).static_state {
                ossl_check(
                    ffi::CRYPTO_set_mem_functions(
                        (*fns_ptr).mem_fns.malloc_fn,
                        (*fns_ptr).mem_fns.realloc_fn,
                        (*fns_ptr).mem_fns.free_fn,
                    ),
                    EngineError::CryptoSetMemFunctionsFailed,
                )?;
                ossl_check(
                    ffi::OPENSSL_init_crypto(ffi::OPENSSL_INIT_NO_ATEXIT as u64, null_mut()),
                    EngineError::OpensslInitCryptoFailed,
                )?;
            }
        }

        let id = if id.is_null() {
            c""
        } else {
            // SAFETY: OpenSSL guarantees non-null id is a valid C string.
            unsafe { CStr::from_ptr(id) }
        };

        f(self, id)
    }

    /// Set the engine's id — the short identifier OpenSSL matches against
    /// (e.g. in `ENGINE_by_id`).
    #[allow(unsafe_code)]
    pub fn set_id(&self, id: &CStr) -> EngineResult<()> {
        // SAFETY: self.ptr is valid (from NonNull), id is a valid CStr.
        ossl_check(
            unsafe { ffi::ENGINE_set_id(self.ptr, id.as_ptr()) },
            EngineError::SetIdFailed,
        )
    }

    /// Set the engine's human-readable display name.
    #[allow(unsafe_code)]
    pub fn set_name(&self, name: &CStr) -> EngineResult<()> {
        // SAFETY: self.ptr is valid (from NonNull), name is a valid CStr.
        ossl_check(
            unsafe { ffi::ENGINE_set_name(self.ptr, name.as_ptr()) },
            EngineError::SetNameFailed,
        )
    }

    /// Register a destroy callback. `H::destroy` runs when OpenSSL tears
    /// the engine down (after the last `ENGINE_free`). Each `H` produces a
    /// distinct monomorphized C trampoline, so distinct engines may use
    /// distinct handlers without global state.
    #[allow(unsafe_code)]
    pub fn set_destroy<H: DestroyHandler>(&self) -> EngineResult<()> {
        // SAFETY: self.ptr is valid (from NonNull); c_destroy::<H> has the
        // correct C signature and stays valid for the lifetime of the
        // process (it's a 'static fn item).
        ossl_check(
            unsafe { ffi::ENGINE_set_destroy_function(self.ptr, Some(c_destroy::<H>)) },
            EngineError::SetDestroyFailed,
        )
    }

    /// Register the private-key loader OpenSSL invokes for
    /// `ENGINE_load_private_key` (e.g. `openssl … -keyform engine -inform engine
    /// -in <key_id>`). Like [`set_destroy`](Self::set_destroy), each `H`
    /// monomorphizes a distinct C trampoline.
    #[allow(unsafe_code)]
    pub fn set_load_privkey<H: LoadPrivKeyHandler>(&self) -> EngineResult<()> {
        // SAFETY: self.ptr is valid (from NonNull); c_load_privkey::<H> has the
        // correct ENGINE_LOAD_KEY_PTR signature and is a 'static fn item.
        ossl_check(
            unsafe { ffi::ENGINE_set_load_privkey_function(self.ptr, Some(c_load_privkey::<H>)) },
            EngineError::SetLoadPrivKeyFailed,
        )
    }

    /// Register `H`'s control commands, which `ENGINE_ctrl_cmd_string` and
    /// `openssl engine -t -post CMD:ARG` run by name.
    #[allow(unsafe_code)]
    pub fn set_ctrl<H: CtrlHandler>(&self) -> EngineResult<()> {
        // OpenSSL reads the table up to the first entry without a name.
        if !H::COMMANDS.last().is_some_and(|c| c.cmd_name.is_null()) {
            return Err("ctrl command table must end with CMD_DEFN_END".into());
        }
        // SAFETY: self.ptr is valid (from NonNull); COMMANDS is 'static and
        // terminated (checked above); c_ctrl::<H> has the ENGINE_CTRL_FUNC_PTR
        // signature and is a 'static fn item.
        unsafe {
            ossl_check(
                ffi::ENGINE_set_cmd_defns(self.ptr, H::COMMANDS.as_ptr()),
                "ENGINE_set_cmd_defns failed",
            )?;
            ossl_check(
                ffi::ENGINE_set_ctrl_function(self.ptr, Some(c_ctrl::<H>)),
                "ENGINE_set_ctrl_function failed",
            )
        }
    }

    /// Set the engine's `EC_KEY_METHOD`. Required before
    /// [`new_ec_key`](Self::new_ec_key): `EC_KEY_new_method` fails unless the
    /// engine advertises an EC method, and it adopts this method at creation.
    ///
    /// Registering the method engine-wide (rather than per key via
    /// `EC_KEY_set_method`) is load-bearing: `EC_KEY_set_method` calls
    /// `ENGINE_finish(key->engine)` and NULLs `key->engine`, silently dropping
    /// the functional reference that keeps the engine alive while the key
    /// lives. A method installed here is picked up by `EC_KEY_new_method`
    /// without touching that reference.
    ///
    /// # Safety
    /// `method` must point to a valid `EC_KEY_METHOD` that stays valid for the
    /// engine's lifetime (in practice: the process lifetime — see the caller's
    /// process-global method).
    #[allow(unsafe_code)]
    pub unsafe fn set_ec_method(&self, method: *const ffi::EC_KEY_METHOD) -> EngineResult<()> {
        if method.is_null() {
            return Err(EngineError::NullParam("method"));
        }
        // SAFETY: self.ptr is valid (from NonNull); method is non-null (checked)
        // and, per this fn's contract, outlives the engine. ENGINE_set_EC
        // records the pointer on the engine.
        ossl_check(
            unsafe { ffi::ENGINE_set_EC(self.ptr, method) },
            "ENGINE_set_EC failed",
        )
    }

    /// Create an `EC_KEY` bound to this engine via `EC_KEY_new_method`, which
    /// takes a functional reference on the engine (released on `EC_KEY_free`).
    /// OpenSSL therefore keeps the engine — and any state its destroy handler
    /// owns — alive for as long as the returned key (and any `EVP_PKEY` built
    /// from it) lives. Requires an EC method on the engine (see
    /// [`set_ec_method`](Self::set_ec_method)), which the key adopts. The
    /// returned key has no group or public key set yet.
    #[allow(unsafe_code)]
    pub fn new_ec_key(&self) -> EngineResult<*mut ffi::EC_KEY> {
        // SAFETY: self.ptr is a valid ENGINE; EC_KEY_new_method up-refs it and
        // returns a fresh owned EC_KEY (NULL on allocation failure).
        let ec = unsafe { ffi::EC_KEY_new_method(self.ptr) };
        if ec.is_null() {
            return Err(EngineError::Other("EC_KEY_new_method failed".into()));
        }
        Ok(ec)
    }

    /// Set the engine's `RSA_METHOD`, the RSA analogue of
    /// [`set_ec_method`](Self::set_ec_method). Required before
    /// [`new_rsa_key`](Self::new_rsa_key): `RSA_new_method` adopts the engine's
    /// RSA method, and installing it engine-wide (not per key via
    /// `RSA_set_method`, which drops the engine's functional reference) keeps
    /// the engine alive while a bound key lives.
    ///
    /// # Safety
    /// `method` must point to a valid `RSA_METHOD` that stays valid for the
    /// engine's lifetime (in practice: the process lifetime).
    #[allow(unsafe_code)]
    pub unsafe fn set_rsa_method(&self, method: *const ffi::RSA_METHOD) -> EngineResult<()> {
        if method.is_null() {
            return Err(EngineError::NullParam("method"));
        }
        // SAFETY: self.ptr is valid (from NonNull); method is non-null (checked)
        // and, per this fn's contract, outlives the engine. ENGINE_set_RSA
        // records the pointer on the engine.
        ossl_check(
            unsafe { ffi::ENGINE_set_RSA(self.ptr, method) },
            "ENGINE_set_RSA failed",
        )
    }

    /// Create an `RSA` bound to this engine via `RSA_new_method`, the RSA
    /// analogue of [`new_ec_key`](Self::new_ec_key): it up-refs the engine
    /// (released on `RSA_free`), so OpenSSL keeps the engine and its destroy
    /// state alive for as long as the returned key (and any `EVP_PKEY` built
    /// from it) lives. Requires an RSA method on the engine (see
    /// [`set_rsa_method`](Self::set_rsa_method)). The returned key has no
    /// modulus or exponent set yet.
    #[allow(unsafe_code)]
    pub fn new_rsa_key(&self) -> EngineResult<*mut ffi::RSA> {
        // SAFETY: self.ptr is a valid ENGINE; RSA_new_method up-refs it and
        // returns a fresh owned RSA (NULL on allocation failure).
        let rsa = unsafe { ffi::RSA_new_method(self.ptr) };
        if rsa.is_null() {
            return Err(EngineError::Other("RSA_new_method failed".into()));
        }
        Ok(rsa)
    }
}

/// Caller-supplied destroy logic, invoked by OpenSSL when an `ENGINE` is
/// torn down. Implement this on a zero-sized marker type and pass it as
/// the type parameter to [`Engine::set_destroy`].
///
/// Takes `&mut Engine` so a handler can `take()` ex_data (which requires
/// exclusive access) to drop attached state during teardown.
pub trait DestroyHandler {
    fn destroy(engine: &mut Engine) -> EngineResult<()>;
}

/// C trampoline for `ENGINE_set_destroy_function`. Catches panics and
/// dispatches to `H::destroy`. One instantiation per `H`.
///
/// # Safety
/// Called only by OpenSSL during `ENGINE_free`. `e` is the ENGINE being
/// destroyed (may be NULL on malformed input, handled by the trampoline).
#[allow(unsafe_code)]
unsafe extern "C" fn c_destroy<H: DestroyHandler>(e: *mut ffi::ENGINE) -> c_int {
    catch_panic(
        // SAFETY: `e` is the ENGINE OpenSSL is destroying, per the
        // ENGINE_set_destroy_function callback contract.
        || result_to_int(unsafe { destroy_inner::<H>(e) }),
        RetCode::Fail.into(),
    )
}

/// Inner body of [`c_destroy`]: rebuild a safe [`Engine`] from the raw pointer
/// and run the handler. Split out for readability (see [`c_destroy`]).
///
/// # Safety
/// `e` must be the `ENGINE` OpenSSL is destroying (may be NULL).
#[allow(unsafe_code)]
unsafe fn destroy_inner<H: DestroyHandler>(e: *mut ffi::ENGINE) -> EngineResult<()> {
    let nn = NonNull::new(e).ok_or(EngineError::NullParam("engine"))?;
    // SAFETY: `e` is the ENGINE OpenSSL is destroying; valid for this call.
    let mut engine = unsafe { Engine::from_ptr(nn) };
    H::destroy(&mut engine)
}

/// Caller-supplied private-key loader, invoked by OpenSSL for
/// `ENGINE_load_private_key`. Implement on a marker type and pass it as the
/// type parameter to [`Engine::set_load_privkey`].
pub trait LoadPrivKeyHandler {
    /// Load the key named `key_id` and return an owning `*mut EVP_PKEY`
    /// (ownership transfers to OpenSSL). Return an error to surface a NULL
    /// result plus an ERR-queue entry to the caller.
    fn load(engine: &Engine, key_id: &CStr) -> EngineResult<*mut ffi::EVP_PKEY>;
}

/// C trampoline for `ENGINE_set_load_privkey_function` (`ENGINE_LOAD_KEY_PTR`).
/// Catches panics and dispatches to `H::load`, returning NULL on panic/error.
/// The `UI_METHOD`/`cb_data` params are unused: keys are named by id, no prompt.
///
/// # Safety
/// Called only by OpenSSL. `e` is the loading ENGINE and `key_id` the key
/// identifier string, per the callback contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_load_privkey<H: LoadPrivKeyHandler>(
    e: *mut ffi::ENGINE,
    key_id: *const c_char,
    _ui: *mut ffi::UI_METHOD,
    _cb_data: *mut c_void,
) -> *mut ffi::EVP_PKEY {
    catch_panic(
        // SAFETY: `e` and `key_id` are the pointers OpenSSL passes to the
        // load_privkey callback per ENGINE_set_load_privkey_function.
        || result_to_ptr(unsafe { load_privkey_inner::<H>(e, key_id) }),
        null_mut(),
    )
}

/// Inner body of [`c_load_privkey`]: validate the raw pointers, rebuild a safe
/// [`Engine`], and dispatch to `H::load`.
///
/// # Safety
/// `e` must be the loading `ENGINE` and `key_id` a valid C string (or NULL).
#[allow(unsafe_code)]
unsafe fn load_privkey_inner<H: LoadPrivKeyHandler>(
    e: *mut ffi::ENGINE,
    key_id: *const c_char,
) -> EngineResult<*mut ffi::EVP_PKEY> {
    let nn = NonNull::new(e).ok_or(EngineError::NullParam("engine"))?;
    if key_id.is_null() {
        return Err(EngineError::NullParam("key_id"));
    }
    // SAFETY: `e` is non-null (checked) and the ENGINE OpenSSL is loading from.
    let engine = unsafe { Engine::from_ptr(nn) };
    // SAFETY: `key_id` is non-null (checked) and a valid C string per contract.
    let key_id = unsafe { CStr::from_ptr(key_id) };
    H::load(&engine, key_id)
}

/// A control command taking a string argument (`ENGINE_CMD_FLAG_STRING`), for
/// [`CtrlHandler::COMMANDS`].
pub const fn string_cmd(
    num: c_uint,
    name: &'static CStr,
    desc: &'static CStr,
) -> ffi::ENGINE_CMD_DEFN {
    ffi::ENGINE_CMD_DEFN {
        cmd_num: num,
        cmd_name: name.as_ptr(),
        cmd_desc: desc.as_ptr(),
        cmd_flags: ffi::ENGINE_CMD_FLAG_STRING_CONST,
    }
}

/// The entry that ends a [`CtrlHandler::COMMANDS`] table.
pub const CMD_DEFN_END: ffi::ENGINE_CMD_DEFN = ffi::ENGINE_CMD_DEFN {
    cmd_num: 0,
    cmd_name: null(),
    cmd_desc: null(),
    cmd_flags: 0,
};

/// Engine control commands, all taking a string argument. Implement on a
/// marker type and pass it as the type parameter to [`Engine::set_ctrl`].
pub trait CtrlHandler {
    /// The commands ([`string_cmd`] entries numbered from
    /// `ffi::ENGINE_CMD_BASE`), ended by [`CMD_DEFN_END`].
    const COMMANDS: &'static [ffi::ENGINE_CMD_DEFN];

    /// Run command `cmd`, one of [`COMMANDS`](Self::COMMANDS), with `arg`.
    fn ctrl(engine: &Engine, cmd: c_uint, arg: &CStr) -> EngineResult<()>;
}

/// C trampoline for `ENGINE_set_ctrl_function`. Catches panics and
/// dispatches to `H::ctrl`.
///
/// # Safety
/// Called only by OpenSSL's `ENGINE_ctrl`, per the `ENGINE_CTRL_FUNC_PTR`
/// contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_ctrl<H: CtrlHandler>(
    e: *mut ffi::ENGINE,
    cmd: c_int,
    i: c_long,
    p: *mut c_void,
    f: Option<unsafe extern "C" fn()>,
) -> c_int {
    catch_panic(
        // SAFETY: the arguments are the ones OpenSSL passes to the engine's
        // ctrl function.
        || result_to_int(unsafe { ctrl_inner::<H>(e, cmd, i, p, f) }),
        RetCode::Fail.into(),
    )
}

/// Inner body of [`c_ctrl`]: accept only `H`'s commands, called the way
/// `ENGINE_ctrl_cmd_string` calls a string command (`i` 0, no callback, `p`
/// the argument).
///
/// # Safety
/// `e` must be the `ENGINE` the ctrl runs on and `p` a valid C string (or
/// NULL).
#[allow(unsafe_code)]
unsafe fn ctrl_inner<H: CtrlHandler>(
    e: *mut ffi::ENGINE,
    cmd: c_int,
    i: c_long,
    p: *mut c_void,
    f: Option<unsafe extern "C" fn()>,
) -> EngineResult<()> {
    let nn = NonNull::new(e).ok_or(EngineError::NullParam("engine"))?;
    let cmd = c_uint::try_from(cmd)
        .ok()
        .filter(|&num| {
            H::COMMANDS
                .iter()
                .any(|c| !c.cmd_name.is_null() && c.cmd_num == num)
        })
        .ok_or_else(|| EngineError::Other(format!("unsupported engine ctrl command {cmd}")))?;
    if i != 0 || f.is_some() {
        return Err("a string ctrl command takes no number or callback".into());
    }
    if p.is_null() {
        return Err(EngineError::NullParam("ctrl argument"));
    }
    // SAFETY: `e` is non-null (checked) and the ENGINE the ctrl runs on.
    let engine = unsafe { Engine::from_ptr(nn) };
    // SAFETY: `p` is non-null (checked) and a valid C string per contract.
    let arg = unsafe { CStr::from_ptr(p.cast()) };
    H::ctrl(&engine, cmd, arg)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use super::*;

    static DESTROY_COUNT: AtomicUsize = AtomicUsize::new(0);

    struct CountingDestroy;
    impl DestroyHandler for CountingDestroy {
        fn destroy(_: &mut Engine) -> EngineResult<()> {
            DESTROY_COUNT.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn set_destroy_runs_on_engine_free() {
        // SAFETY: ENGINE_new / ENGINE_free are standard OpenSSL entry points
        // taking no arguments / a valid ENGINE pointer respectively.
        let raw = unsafe { ffi::ENGINE_new() };
        let nn = NonNull::new(raw).expect("ENGINE_new returned NULL");
        // SAFETY: nn is non-null and owned until ENGINE_free below.
        let e = unsafe { Engine::from_ptr(nn) };

        let before = DESTROY_COUNT.load(Ordering::SeqCst);
        e.set_destroy::<CountingDestroy>().unwrap();
        assert_eq!(DESTROY_COUNT.load(Ordering::SeqCst), before);

        // SAFETY: same as above.
        unsafe { ffi::ENGINE_free(e.as_ptr()) };
        assert_eq!(
            DESTROY_COUNT.load(Ordering::SeqCst),
            before + 1,
            "destroy callback should run exactly once on ENGINE_free"
        );
    }

    struct NullLoader;
    impl LoadPrivKeyHandler for NullLoader {
        fn load(_: &Engine, _: &CStr) -> EngineResult<*mut ffi::EVP_PKEY> {
            Ok(null_mut())
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn set_load_privkey_registers_the_hook() {
        // SAFETY: ENGINE_new / ENGINE_free are standard OpenSSL entry points.
        let raw = unsafe { ffi::ENGINE_new() };
        let nn = NonNull::new(raw).expect("ENGINE_new returned NULL");
        // SAFETY: nn is non-null and owned until ENGINE_free below.
        let e = unsafe { Engine::from_ptr(nn) };

        e.set_load_privkey::<NullLoader>().unwrap();
        // SAFETY: e.as_ptr() is a valid ENGINE.
        let f = unsafe { ffi::ENGINE_get_load_privkey_function(e.as_ptr()) };
        assert!(f.is_some(), "load_privkey hook should be registered");

        // SAFETY: same as above.
        unsafe { ffi::ENGINE_free(e.as_ptr()) };
    }

    /// Number of [`OkCtrl`]'s command.
    const TEST_CMD: c_uint = ffi::ENGINE_CMD_BASE;

    /// One command, accepting only the argument `ok`.
    struct OkCtrl;
    impl CtrlHandler for OkCtrl {
        const COMMANDS: &'static [ffi::ENGINE_CMD_DEFN] = &[
            string_cmd(TEST_CMD, c"TEST_CMD", c"test command"),
            CMD_DEFN_END,
        ];

        fn ctrl(_: &Engine, cmd: c_uint, arg: &CStr) -> EngineResult<()> {
            if cmd == TEST_CMD && arg == c"ok" {
                Ok(())
            } else {
                Err("unexpected ctrl call".into())
            }
        }
    }

    /// A command table missing [`CMD_DEFN_END`].
    struct UnterminatedCtrl;
    impl CtrlHandler for UnterminatedCtrl {
        const COMMANDS: &'static [ffi::ENGINE_CMD_DEFN] =
            &[string_cmd(TEST_CMD, c"TEST_CMD", c"test command")];

        fn ctrl(_: &Engine, _: c_uint, _: &CStr) -> EngineResult<()> {
            Ok(())
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn set_ctrl_runs_string_commands() {
        // SAFETY: ENGINE_new / ENGINE_free are standard OpenSSL entry points.
        let raw = unsafe { ffi::ENGINE_new() };
        let nn = NonNull::new(raw).expect("ENGINE_new returned NULL");
        // SAFETY: nn is non-null and owned until ENGINE_free below.
        let e = unsafe { Engine::from_ptr(nn) };
        assert!(e.set_ctrl::<UnterminatedCtrl>().is_err());
        e.set_ctrl::<OkCtrl>().unwrap();

        let ok = RetCode::Success as c_int;
        let num = c_int::try_from(TEST_CMD).unwrap();
        let arg = c"ok".as_ptr().cast_mut().cast::<c_void>();
        // SAFETY: raw is a valid ENGINE; names and arguments are NUL-terminated.
        unsafe {
            // By name, as ENGINE_ctrl_cmd_string and `openssl engine -post` run it.
            let by_name = |name: &CStr, arg: &CStr| {
                ffi::ENGINE_ctrl_cmd_string(raw, name.as_ptr(), arg.as_ptr(), 0)
            };
            assert_eq!(by_name(c"TEST_CMD", c"ok"), ok);
            assert_ne!(by_name(c"TEST_CMD", c"bad"), ok, "handler error");
            assert_ne!(by_name(c"NO_SUCH_CMD", c"ok"), ok, "unknown name");
            // By number: only the command's own, with nothing but a string.
            assert_eq!(ffi::ENGINE_ctrl(raw, num, 0, arg, None), ok);
            let other = num.checked_add(1).unwrap();
            assert_ne!(ffi::ENGINE_ctrl(raw, other, 0, arg, None), ok, "unknown");
            assert_ne!(ffi::ENGINE_ctrl(raw, num, 1, arg, None), ok, "a number");
            assert_ne!(ffi::ENGINE_ctrl(raw, num, 0, null_mut(), None), ok, "NULL");
            ffi::ERR_clear_error();
            ffi::ENGINE_free(raw);
        }
    }
}
