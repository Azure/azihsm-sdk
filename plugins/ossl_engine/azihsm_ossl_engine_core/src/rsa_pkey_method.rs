// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Custom RSA `EVP_PKEY_METHOD` for importing external keys into the HSM.
//!
//! The HSM cannot generate RSA keys natively, so `openssl genpkey -engine
//! azihsm -algorithm RSA` is an **import** pipeline rather than generation:
//! resolved via `ENGINE_get_pkey_meth` through the shared per-engine
//! pkey-method table, its keygen hook lands here when the context was armed
//! with an `azihsm.*` import option. An unarmed context (a plain software
//! keygen that merely reached this method because the engine is the process
//! default) is delegated wholesale to the built-in RSA keygen.
//!
//! Armed options, mirroring the 3.x provider's keymgmt:
//! - `azihsm.input_key` — path to a plaintext DER private key; the engine
//!   wraps it against the HSM's unwrapping key and unwraps it into the HSM.
//! - `azihsm.wrapped_key` — path to a pre-wrapped blob, unwrapped directly
//!   (mutually exclusive with `input_key`).
//! - `azihsm.key_kind` — `RSA` or `RSA-CRT` (default `RSA-CRT`).
//! - `azihsm.key_usage` — `digitalSignature` (default) or `keyWrapping`
//!   (export the HSM's unwrapping public key; requires 2048 bits).
//! - `azihsm.masked_key` — path to write the imported key's masked blob.
//! - `azihsm.session` — only `false` (session keys unimplemented).
//! - `rsa_keygen_bits` — 2048/3072/4096 (standard option, also forwarded to
//!   the built-in so an unarmed keygen still sees it).

use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_void;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::OnceLock;

use azihsm_ossl_engine_sys as ffi;
use parking_lot::Mutex;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::catch_panic;
use crate::error::result_to_int;
use crate::pkey_method::ENGINE_METHODS;

/// Key usage requested via `azihsm.key_usage`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RsaKeyUsage {
    /// Private: sign, public: verify (the default).
    DigitalSignature,
    /// Export the HSM's unwrapping public key (2048-bit only).
    KeyWrapping,
}

/// Parameters an armed context accumulated by the time import runs.
pub struct RsaImportParams {
    /// `rsa_keygen_bits` (2048/3072/4096; validated by the handler).
    pub bits: u32,
    /// `azihsm.key_kind`: true for RSA-CRT (default), false for plain RSA.
    pub crt: bool,
    /// `azihsm.key_usage`.
    pub key_usage: RsaKeyUsage,
    /// `azihsm.session` (default false = persistent).
    pub session: bool,
    /// `azihsm.input_key`: plaintext DER to wrap and import.
    pub input_key: Option<PathBuf>,
    /// `azihsm.wrapped_key`: pre-wrapped blob to import.
    pub wrapped_key: Option<PathBuf>,
    /// `azihsm.masked_key`: where to write the imported key's masked blob.
    pub masked_key_path: Option<PathBuf>,
}

/// Caller-supplied HSM RSA import, invoked through the `EVP_PKEY_METHOD`
/// `keygen` hook when the context was armed. Implement on a marker type and
/// pass it to [`register_rsa_pkey_method`].
pub trait RsaImportHandler {
    /// Import an external RSA key into the HSM per `params` and fill `pkey`
    /// (for `keyWrapping`, fill it with the HSM's unwrapping public key). Write
    /// the masked blob to `params.masked_key_path` when set.
    fn import(
        engine: &Engine,
        params: &RsaImportParams,
        pkey: *mut ffi::EVP_PKEY,
    ) -> EngineResult<()>;
}

/// Per-context state. `armed` is implied by any azihsm-specific field.
#[derive(Clone, Default)]
struct CtxState {
    engine: usize,
    bits: Option<u32>,
    crt: Option<bool>,
    key_usage: Option<RsaKeyUsage>,
    session: Option<bool>,
    input_key: Option<PathBuf>,
    wrapped_key: Option<PathBuf>,
    masked_key_path: Option<PathBuf>,
}

impl CtxState {
    fn armed(&self) -> bool {
        self.crt.is_some()
            || self.key_usage.is_some()
            || self.session.is_some()
            || self.input_key.is_some()
            || self.wrapped_key.is_some()
            || self.masked_key_path.is_some()
    }
}

static CTX_STATE: OnceLock<Mutex<HashMap<usize, CtxState>>> = OnceLock::new();

fn ctx_state() -> &'static Mutex<HashMap<usize, CtxState>> {
    CTX_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Built-in RSA `EVP_PKEY_METHOD` callbacks captured at method build.
#[derive(Clone, Copy, Default)]
struct Defaults {
    init: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX) -> c_int>,
    copy: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX, *mut ffi::EVP_PKEY_CTX) -> c_int>,
    cleanup: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX)>,
    keygen: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX, *mut ffi::EVP_PKEY) -> c_int>,
    ctrl: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX, c_int, c_int, *mut c_void) -> c_int>,
    ctrl_str:
        Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX, *const c_char, *const c_char) -> c_int>,
}

static DEFAULTS: OnceLock<Defaults> = OnceLock::new();

fn defaults() -> EngineResult<Defaults> {
    DEFAULTS.get().copied().ok_or(EngineError::Other(
        "RSA pkey method defaults missing".into(),
    ))
}

/// # Safety
/// Called only by OpenSSL during `EVP_PKEY_CTX` construction.
#[allow(unsafe_code)]
unsafe extern "C" fn c_init(ctx: *mut ffi::EVP_PKEY_CTX) -> c_int {
    catch_panic(
        || {
            let Ok(d) = defaults() else { return 0 };
            if let Some(init) = d.init {
                // SAFETY: delegating the ctx OpenSSL passed us.
                if unsafe { init(ctx) } != 1 {
                    return 0;
                }
            }
            let engine = crate::method_table::take_pending_engine();
            ctx_state().lock().insert(
                ctx as usize,
                CtxState {
                    engine,
                    ..CtxState::default()
                },
            );
            1
        },
        0,
    )
}

/// # Safety
/// Called only by OpenSSL during `EVP_PKEY_CTX_dup`.
#[allow(unsafe_code)]
unsafe extern "C" fn c_copy(dst: *mut ffi::EVP_PKEY_CTX, src: *mut ffi::EVP_PKEY_CTX) -> c_int {
    catch_panic(
        || {
            let Ok(d) = defaults() else { return 0 };
            if let Some(copy) = d.copy {
                // SAFETY: delegating the ctx pair OpenSSL passed us.
                if unsafe { copy(dst, src) } != 1 {
                    return 0;
                }
            }
            let mut table = ctx_state().lock();
            if let Some(dup) = table.get(&(src as usize)).cloned() {
                table.insert(dst as usize, dup);
            }
            1
        },
        0,
    )
}

/// # Safety
/// Called only by OpenSSL during `EVP_PKEY_CTX_free`.
#[allow(unsafe_code)]
unsafe extern "C" fn c_cleanup(ctx: *mut ffi::EVP_PKEY_CTX) {
    catch_panic(
        || {
            ctx_state().lock().remove(&(ctx as usize));
            if let Ok(d) = defaults()
                && let Some(cleanup) = d.cleanup
            {
                // SAFETY: delegating the ctx OpenSSL passed us, exactly once.
                unsafe { cleanup(ctx) };
            }
            0
        },
        0,
    );
}

/// `ctrl` override: delegate every command to the built-in, additionally
/// recording `rsa_keygen_bits` set through the direct ABI
/// (`EVP_PKEY_CTX_set_rsa_keygen_bits`), which dispatches here rather than
/// through `ctrl_str`. Without this an armed import would ignore a direct-ABI
/// bit size and fall back to the 2048 default (and skip the keyWrapping
/// non-2048 check).
///
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_CTX_ctrl`; arguments per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_ctrl(
    ctx: *mut ffi::EVP_PKEY_CTX,
    ctrl_type: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    catch_panic(
        || {
            let Ok(d) = defaults() else { return 0 };
            let Some(ctrl) = d.ctrl else { return 0 };
            // SAFETY: delegating the arguments OpenSSL passed us to the built-in.
            let rc = unsafe { ctrl(ctx, ctrl_type, p1, p2) };
            if rc > 0
                && ctrl_type == ffi::EVP_PKEY_CTRL_RSA_KEYGEN_BITS_CONST
                && let Ok(bits) = u32::try_from(p1)
                && let Some(state) = ctx_state().lock().get_mut(&(ctx as usize))
            {
                state.bits = Some(bits);
            }
            rc
        },
        0,
    )
}

/// `ctrl_str` override: record the `azihsm.*` import options; parse and record
/// `rsa_keygen_bits` while also forwarding it (and any other non-azihsm
/// option) to the built-in, so an unarmed keygen keeps built-in behavior.
///
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_CTX_ctrl_str`; strings per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_ctrl_str(
    ctx: *mut ffi::EVP_PKEY_CTX,
    key: *const c_char,
    value: *const c_char,
) -> c_int {
    catch_panic(|| result_to_int(ctrl_str_inner(ctx, key, value)), 0)
}

#[allow(unsafe_code)]
fn ctrl_str_inner(
    ctx: *mut ffi::EVP_PKEY_CTX,
    key: *const c_char,
    value: *const c_char,
) -> EngineResult<()> {
    if key.is_null() {
        return Err(EngineError::NullParam("ctrl key"));
    }
    // SAFETY: OpenSSL passes NUL-terminated strings to ctrl_str.
    let key_str = unsafe { CStr::from_ptr(key) }
        .to_str()
        .map_err(|_| EngineError::Other("ctrl key is not valid UTF-8".into()))?;

    if let Some(azihsm_key) = key_str.strip_prefix("azihsm.") {
        if value.is_null() {
            return Err(EngineError::NullParam("ctrl value"));
        }
        // SAFETY: as above.
        let value_c = unsafe { CStr::from_ptr(value) };
        let mut table = ctx_state().lock();
        let state = table
            .get_mut(&(ctx as usize))
            .ok_or(EngineError::Other("RSA ctx has no azihsm state".into()))?;
        return match azihsm_key {
            // Paths are byte strings on Unix; no UTF-8 requirement.
            "input_key" => {
                state.input_key = Some(PathBuf::from(OsStr::from_bytes(value_c.to_bytes())));
                Ok(())
            }
            "wrapped_key" => {
                state.wrapped_key = Some(PathBuf::from(OsStr::from_bytes(value_c.to_bytes())));
                Ok(())
            }
            "masked_key" => {
                state.masked_key_path = Some(PathBuf::from(OsStr::from_bytes(value_c.to_bytes())));
                Ok(())
            }
            "key_kind" => {
                let v = value_c
                    .to_str()
                    .map_err(|_| EngineError::Other("key_kind must be UTF-8".into()))?;
                state.crt = Some(match v {
                    "RSA-CRT" => true,
                    "RSA" => false,
                    other => {
                        return Err(EngineError::Other(format!(
                            "azihsm.key_kind must be RSA or RSA-CRT, got: {other}"
                        )));
                    }
                });
                Ok(())
            }
            "key_usage" => {
                let v = value_c
                    .to_str()
                    .map_err(|_| EngineError::Other("key_usage must be UTF-8".into()))?;
                state.key_usage = Some(match v {
                    "digitalSignature" => RsaKeyUsage::DigitalSignature,
                    "keyWrapping" => RsaKeyUsage::KeyWrapping,
                    other => {
                        return Err(EngineError::Other(format!(
                            "azihsm.key_usage must be digitalSignature or keyWrapping, got: {other}"
                        )));
                    }
                });
                Ok(())
            }
            "session" => {
                let v = value_c
                    .to_str()
                    .map_err(|_| EngineError::Other("session must be UTF-8".into()))?;
                state.session = Some(match v {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(EngineError::Other(format!(
                            "azihsm.session must be true or false, got: {other}"
                        )));
                    }
                });
                Ok(())
            }
            other => Err(EngineError::Other(format!(
                "unknown azihsm pkey option: azihsm.{other}"
            ))),
        };
    }

    // rsa_keygen_bits: record for import, and fall through to forward it to the
    // built-in so an unarmed keygen still receives it.
    if key_str == "rsa_keygen_bits" && !value.is_null() {
        // SAFETY: OpenSSL passes a NUL-terminated string to ctrl_str.
        let v = unsafe { CStr::from_ptr(value) };
        if let Ok(bits) = v.to_str().unwrap_or("").parse::<u32>()
            && let Some(state) = ctx_state().lock().get_mut(&(ctx as usize))
        {
            state.bits = Some(bits);
        }
    }

    // Non-azihsm options: delegate to the built-in ctrl_str.
    let d = defaults()?;
    let ctrl_str = d
        .ctrl_str
        .ok_or(EngineError::Other("built-in ctrl_str missing".into()))?;
    // SAFETY: delegating the arguments OpenSSL passed us.
    if unsafe { ctrl_str(ctx, key, value) } <= 0 {
        return Err(EngineError::Other(format!(
            "RSA option rejected: {key_str}"
        )));
    }
    Ok(())
}

/// `keygen` override: delegate an unarmed context to the built-in software
/// keygen; run `H::import` for an armed one.
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_keygen`; arguments per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_keygen<H: RsaImportHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    pkey: *mut ffi::EVP_PKEY,
) -> c_int {
    catch_panic(|| result_to_int(keygen_inner::<H>(ctx, pkey)), 0)
}

#[allow(unsafe_code)]
fn keygen_inner<H: RsaImportHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    pkey: *mut ffi::EVP_PKEY,
) -> EngineResult<()> {
    if pkey.is_null() {
        return Err(EngineError::NullParam("pkey"));
    }
    let state = ctx_state()
        .lock()
        .get(&(ctx as usize))
        .cloned()
        .unwrap_or_default();

    if !state.armed() {
        // Unarmed: a software keygen that merely resolved to our method.
        let d = defaults()?;
        let keygen = d
            .keygen
            .ok_or(EngineError::Other("built-in keygen missing".into()))?;
        // SAFETY: delegating the arguments OpenSSL passed us to the built-in.
        if unsafe { keygen(ctx, pkey) } != 1 {
            return Err(EngineError::Other("software RSA keygen failed".into()));
        }
        return Ok(());
    }

    let engine_ptr = NonNull::new(state.engine as *mut ffi::ENGINE)
        .ok_or(EngineError::Other("pkey ctx has no ENGINE".into()))?;
    // SAFETY: the ctx holds a functional reference on this ENGINE for its
    // lifetime (int_ctx_new), and keygen runs while the ctx is alive.
    let engine = unsafe { Engine::from_ptr(engine_ptr) };

    let params = RsaImportParams {
        bits: state.bits.unwrap_or(2048),
        crt: state.crt.unwrap_or(true),
        key_usage: state.key_usage.unwrap_or(RsaKeyUsage::DigitalSignature),
        session: state.session.unwrap_or(false),
        input_key: state.input_key,
        wrapped_key: state.wrapped_key,
        masked_key_path: state.masked_key_path,
    };
    H::import(&engine, &params, pkey)
}

/// Build the RSA `EVP_PKEY_METHOD`: a copy of the built-in with
/// `init`/`copy`/`cleanup`/`ctrl_str`/`keygen` overridden. Never freed by us —
/// the engine framework owns registered copies.
#[allow(unsafe_code)]
pub fn new_rsa_pkey_method<H: RsaImportHandler>() -> EngineResult<*mut ffi::EVP_PKEY_METHOD> {
    // SAFETY: EVP_PKEY_meth_find returns the built-in const method.
    let builtin = unsafe { ffi::EVP_PKEY_meth_find(ffi::EVP_PKEY_RSA as c_int) };
    if builtin.is_null() {
        return Err(EngineError::Other(
            "built-in RSA pkey method missing".into(),
        ));
    }

    let mut d = Defaults::default();
    let mut keygen_init = None;
    let mut ctrl_dummy = None;
    // SAFETY: builtin is a valid method; the getters write the out-params.
    unsafe {
        ffi::EVP_PKEY_meth_get_init(builtin, &mut d.init);
        ffi::EVP_PKEY_meth_get_copy(builtin, &mut d.copy);
        ffi::EVP_PKEY_meth_get_cleanup(builtin, &mut d.cleanup);
        ffi::EVP_PKEY_meth_get_keygen(builtin, &mut keygen_init, &mut d.keygen);
        ffi::EVP_PKEY_meth_get_ctrl(builtin, &mut ctrl_dummy, &mut d.ctrl_str);
    }
    d.ctrl = ctrl_dummy;
    let _ = DEFAULTS.set(d);

    // SAFETY: fresh method; meth_copy duplicates the built-in callbacks; the
    // setters install our overrides (keeping the built-in keygen_init).
    unsafe {
        let method = ffi::EVP_PKEY_meth_new(ffi::EVP_PKEY_RSA as c_int, 0);
        if method.is_null() {
            return Err(EngineError::Other("EVP_PKEY_meth_new failed".into()));
        }
        ffi::EVP_PKEY_meth_copy(method, builtin);
        ffi::EVP_PKEY_meth_set_init(method, Some(c_init));
        ffi::EVP_PKEY_meth_set_copy(method, Some(c_copy));
        ffi::EVP_PKEY_meth_set_cleanup(method, Some(c_cleanup));
        ffi::EVP_PKEY_meth_set_keygen(method, keygen_init, Some(c_keygen::<H>));
        ffi::EVP_PKEY_meth_set_ctrl(method, Some(c_ctrl), Some(c_ctrl_str));
        Ok(method)
    }
}

/// Register `H` as `engine`'s RSA import handler in the shared pkey-method
/// table. Only one handler type can be registered per process (the first
/// wins). Released together with the EC/HKDF methods via
/// [`release_pkey_methods`](crate::pkey_method::release_pkey_methods).
pub fn register_rsa_pkey_method<H: RsaImportHandler>(engine: &Engine) -> EngineResult<()> {
    ENGINE_METHODS.register(engine, ffi::EVP_PKEY_RSA as c_int, new_rsa_pkey_method::<H>)?;
    crate::pkey_method::install_pkey_meths_callback(engine)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ffi::CString;
    use std::ptr::null_mut;

    use super::*;

    /// Import must never dispatch in these parsing/recording tests.
    struct PanicImport;
    impl RsaImportHandler for PanicImport {
        fn import(
            _engine: &Engine,
            _params: &RsaImportParams,
            _pkey: *mut ffi::EVP_PKEY,
        ) -> EngineResult<()> {
            unreachable!("import must not be dispatched for this context")
        }
    }

    /// Capture DEFAULTS (the method itself is left unregistered), then a built-in
    /// `EVP_PKEY_RSA` keygen ctx with a hand-inserted state entry — the
    /// trampolines run against it directly, no HSM involved.
    #[allow(unsafe_code)]
    fn make_ctx() -> *mut ffi::EVP_PKEY_CTX {
        let method = new_rsa_pkey_method::<PanicImport>().unwrap();
        // SAFETY: ours, unregistered.
        unsafe { ffi::EVP_PKEY_meth_free(method) };
        // SAFETY: a built-in RSA keygen ctx; the state entry is keyed by its ptr.
        unsafe {
            let ctx = ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_RSA as c_int, null_mut());
            assert!(!ctx.is_null());
            assert_eq!(ffi::EVP_PKEY_keygen_init(ctx), 1);
            ctx_state().lock().insert(ctx as usize, CtxState::default());
            ctx
        }
    }

    #[allow(unsafe_code)]
    fn free_ctx(ctx: *mut ffi::EVP_PKEY_CTX) {
        ctx_state().lock().remove(&(ctx as usize));
        // SAFETY: ctx is ours, created in make_ctx.
        unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
    }

    #[allow(unsafe_code)]
    fn set_str(ctx: *mut ffi::EVP_PKEY_CTX, k: &str, v: &str) -> c_int {
        let key = CString::new(k).unwrap();
        let val = CString::new(v).unwrap();
        // SAFETY: NUL-terminated strings; ctx has a state entry (make_ctx).
        unsafe { c_ctrl_str(ctx, key.as_ptr(), val.as_ptr()) }
    }

    fn state_of(ctx: *mut ffi::EVP_PKEY_CTX) -> CtxState {
        ctx_state().lock().get(&(ctx as usize)).unwrap().clone()
    }

    // A direct-ABI keygen-bits setter (the numeric EVP_PKEY_CTRL_RSA_KEYGEN_BITS
    // ctrl, not the string form) must be recorded, so an armed import honors it
    // instead of falling back to the 2048 default.
    #[test]
    #[allow(unsafe_code)]
    fn ctrl_records_direct_keygen_bits() {
        let ctx = make_ctx();
        // SAFETY: ctx is a valid keygen-init'd RSA ctx with a state entry.
        let rc = unsafe {
            c_ctrl(
                ctx,
                ffi::EVP_PKEY_CTRL_RSA_KEYGEN_BITS_CONST,
                3072,
                null_mut(),
            )
        };
        assert_eq!(rc, 1, "built-in must accept keygen_bits");
        assert_eq!(state_of(ctx).bits, Some(3072));
        free_ctx(ctx);
    }

    // The azihsm.* import options are parsed and recorded, and any of them arms
    // the context.
    #[test]
    fn ctrl_str_records_azihsm_options() {
        let ctx = make_ctx();
        assert_eq!(set_str(ctx, "azihsm.key_kind", "RSA-CRT"), 1);
        assert_eq!(set_str(ctx, "azihsm.key_usage", "keyWrapping"), 1);
        assert_eq!(set_str(ctx, "azihsm.session", "false"), 1);
        assert_eq!(set_str(ctx, "azihsm.input_key", "/tmp/in.der"), 1);
        assert_eq!(set_str(ctx, "azihsm.masked_key", "/tmp/out.bin"), 1);

        let s = state_of(ctx);
        assert_eq!(s.crt, Some(true));
        assert_eq!(s.key_usage, Some(RsaKeyUsage::KeyWrapping));
        assert_eq!(s.session, Some(false));
        assert_eq!(
            s.input_key.as_deref(),
            Some(std::path::Path::new("/tmp/in.der"))
        );
        assert_eq!(
            s.masked_key_path.as_deref(),
            Some(std::path::Path::new("/tmp/out.bin"))
        );
        assert!(s.armed(), "azihsm options must arm the context");
        free_ctx(ctx);
    }

    // key_kind maps RSA-CRT/RSA to the crt flag; key_usage maps its two values.
    #[test]
    fn ctrl_str_maps_kind_and_usage() {
        let ctx = make_ctx();
        assert_eq!(set_str(ctx, "azihsm.key_kind", "RSA"), 1);
        assert_eq!(set_str(ctx, "azihsm.key_usage", "digitalSignature"), 1);
        let s = state_of(ctx);
        assert_eq!(s.crt, Some(false));
        assert_eq!(s.key_usage, Some(RsaKeyUsage::DigitalSignature));
        free_ctx(ctx);
    }

    // Invalid option values (and unknown azihsm options) are rejected without a
    // panic.
    #[test]
    fn ctrl_str_rejects_invalid_values() {
        let ctx = make_ctx();
        assert_ne!(set_str(ctx, "azihsm.key_kind", "bogus"), 1);
        assert_ne!(set_str(ctx, "azihsm.key_usage", "bogus"), 1);
        assert_ne!(set_str(ctx, "azihsm.session", "maybe"), 1);
        assert_ne!(set_str(ctx, "azihsm.unknown_option", "x"), 1);
        // The invalid attempts recorded nothing.
        assert!(!state_of(ctx).armed(), "rejected options must not arm");
        free_ctx(ctx);
    }
}
