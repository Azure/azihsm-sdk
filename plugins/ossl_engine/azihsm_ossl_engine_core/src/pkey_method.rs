// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Custom EC `EVP_PKEY_METHOD` for routing key generation through a handler.
//!
//! `openssl genpkey -engine azihsm -algorithm EC` resolves its pkey method via
//! `ENGINE_get_pkey_meth`, never through the `EC_KEY_METHOD` — so HSM key
//! generation needs an `EVP_PKEY_METHOD` registered with
//! [`Engine::set_pkey_meths`](crate::engine::Engine::set_pkey_meths). The
//! method built by [`new_ec_pkey_method`] copies OpenSSL's built-in EC method
//! and overrides only what it must, delegating everything else to the captured
//! built-in callbacks.
//!
//! HSM generation is **opt-in per context**: it runs only when the caller armed
//! the `EVP_PKEY_CTX` with the `azihsm.masked_key:<path>` control string (the
//! same parameter name the OpenSSL 3.x provider uses). An unarmed context —
//! e.g. a software keygen that reached this method because an application made
//! the engine the process default — is delegated wholesale to the built-in
//! keygen. This mirrors the ownership rule of
//! [`ec_method`](crate::ec_method): the engine must never hijack keys or
//! operations it was not explicitly asked to handle.
//!
//! Per-context state (the armed path, the requested curve, the requesting
//! `ENGINE`) lives in a process-global side table keyed by the `EVP_PKEY_CTX`
//! address — OpenSSL 1.1.x offers no ex_data on pkey contexts, and the
//! built-in method owns the context's data slot. Entries are created by the
//! `init` override and removed by the `cleanup` override, so a reused
//! allocation address cannot observe a stale entry.
//!
//! The requesting `ENGINE` is captured through a thread-local handoff: OpenSSL
//! resolves the method via our `pkey_meths` callback (which receives the
//! `ENGINE`) and then runs the method's `init` on the same thread within the
//! same `EVP_PKEY_CTX` construction (`int_ctx_new`), with nothing in between —
//! `init` consumes the thread-local. The context holds a functional engine
//! reference for its lifetime, so the stored pointer stays valid until
//! `cleanup`.

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_void;
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
use crate::method_table::MethodTable;

/// Key usage requested via `azihsm.key_usage`, named as the 3.x provider names
/// them (X.509 keyUsage style).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EcKeyUsage {
    /// Private: sign, public: verify (the default).
    DigitalSignature,
    /// Both halves: derive (ECDH).
    KeyAgreement,
}

/// Parameters a context was armed with by the time keygen runs.
pub struct KeygenParams {
    /// Curve requested via `ec_paramgen_curve` (string) or
    /// `EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID` (int ctrl).
    pub curve_nid: c_int,
    /// Where to write the masked private-key blob (`azihsm.masked_key`).
    pub masked_key_path: PathBuf,
    /// Session key (`azihsm.session`, default false = persistent).
    pub session: bool,
    /// Key usage (`azihsm.key_usage`, default digitalSignature).
    pub key_usage: EcKeyUsage,
}

/// Caller-supplied HSM EC key generation, invoked through the `EVP_PKEY_METHOD`
/// `keygen` hook when the context was armed. Implement on a marker type and
/// pass it to [`new_ec_pkey_method`].
pub trait EcKeygenHandler {
    /// Generate an EC key pair on the HSM for `params` and fill `pkey` (assign
    /// an `EC_KEY` carrying the public half and whatever state later operations
    /// need). `engine` is the ENGINE the context was created with; bind the key
    /// to it so the engine outlives the key. Write the masked blob to
    /// `params.masked_key_path`.
    fn keygen(engine: &Engine, params: &KeygenParams, pkey: *mut ffi::EVP_PKEY)
    -> EngineResult<()>;
}

/// Per-context side-table entry.
#[derive(Clone, Default)]
struct CtxState {
    engine: usize,
    curve_nid: Option<c_int>,
    masked_key_path: Option<PathBuf>,
    session: Option<bool>,
    key_usage: Option<EcKeyUsage>,
}

/// Side table: `EVP_PKEY_CTX` address → state. See the module docs for the
/// lifecycle (created in `init`, dropped in `cleanup`).
static CTX_STATE: OnceLock<Mutex<HashMap<usize, CtxState>>> = OnceLock::new();

fn ctx_state() -> &'static Mutex<HashMap<usize, CtxState>> {
    CTX_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

thread_local! {
    /// The ENGINE that most recently resolved our EC pkey method on this
    /// thread; consumed by the `init` override. See the module docs.
    static PENDING_ENGINE: Cell<usize> = const { Cell::new(0) };
}

/// The built-in EC `EVP_PKEY_METHOD` callbacks captured when the method is
/// built, used for delegation. Fn pointers are `Send + Sync` and the built-in
/// method is a process-lifetime constant.
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
    DEFAULTS
        .get()
        .copied()
        .ok_or(EngineError::Other("EC pkey method defaults missing".into()))
}

/// `init` override: run the built-in init, then create the side-table entry,
/// consuming the thread-local ENGINE handoff.
/// # Safety
/// Called only by OpenSSL during `EVP_PKEY_CTX` construction; `ctx` is the
/// context being initialized.
#[allow(unsafe_code)]
unsafe extern "C" fn c_init(ctx: *mut ffi::EVP_PKEY_CTX) -> c_int {
    catch_panic(
        || {
            let Ok(d) = defaults() else { return 0 };
            if let Some(init) = d.init {
                // SAFETY: delegating the ctx OpenSSL passed us to the built-in
                // init, per the pkey method contract.
                if unsafe { init(ctx) } != 1 {
                    return 0;
                }
            }
            let engine = PENDING_ENGINE.with(|c| c.take());
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

/// `copy` override: run the built-in copy, then duplicate the side-table entry
/// so an armed context stays armed across `EVP_PKEY_CTX_dup`.
/// # Safety
/// Called only by OpenSSL during `EVP_PKEY_CTX_dup`; `dst`/`src` are the
/// contexts being copied.
#[allow(unsafe_code)]
unsafe extern "C" fn c_copy(dst: *mut ffi::EVP_PKEY_CTX, src: *mut ffi::EVP_PKEY_CTX) -> c_int {
    catch_panic(
        || {
            let Ok(d) = defaults() else { return 0 };
            if let Some(copy) = d.copy {
                // SAFETY: delegating the ctx pair OpenSSL passed us to the
                // built-in copy.
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

/// `cleanup` override: drop the side-table entry, then run the built-in
/// cleanup.
/// # Safety
/// Called only by OpenSSL during `EVP_PKEY_CTX_free`; `ctx` is the context
/// being torn down.
#[allow(unsafe_code)]
unsafe extern "C" fn c_cleanup(ctx: *mut ffi::EVP_PKEY_CTX) {
    catch_panic(
        || {
            ctx_state().lock().remove(&(ctx as usize));
            if let Ok(d) = defaults()
                && let Some(cleanup) = d.cleanup
            {
                // SAFETY: delegating the ctx OpenSSL passed us to the built-in
                // cleanup, exactly once.
                unsafe { cleanup(ctx) };
            }
            0
        },
        0,
    );
}

/// `ctrl` override: record a curve set via
/// `EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID`, then delegate to the built-in ctrl.
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_CTX_ctrl`; arguments per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_ctrl(
    ctx: *mut ffi::EVP_PKEY_CTX,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    catch_panic(
        || {
            if cmd == ffi::EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID_CONST {
                if let Some(state) = ctx_state().lock().get_mut(&(ctx as usize)) {
                    state.curve_nid = Some(p1);
                }
            }
            let Ok(d) = defaults() else { return -2 };
            let Some(ctrl) = d.ctrl else { return -2 };
            // SAFETY: delegating the arguments OpenSSL passed us to the
            // built-in ctrl.
            unsafe { ctrl(ctx, cmd, p1, p2) }
        },
        0,
    )
}

/// `ctrl_str` override: handle the `azihsm.*` options (`masked_key` arms the
/// context for HSM keygen) and delegate everything else — so an armed context
/// still configures the built-in state coherently and unknown non-azihsm
/// options keep the built-in error behavior.
///
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_CTX_ctrl_str`; `key`/`value` are NUL-
/// terminated strings (or NULL) per that contract.
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
        let value_str = unsafe { CStr::from_ptr(value) }
            .to_str()
            .map_err(|_| EngineError::Other("ctrl value is not valid UTF-8".into()))?;
        let mut table = ctx_state().lock();
        let state = table
            .get_mut(&(ctx as usize))
            .ok_or(EngineError::Other("pkey ctx has no azihsm state".into()))?;
        return match azihsm_key {
            "masked_key" => {
                state.masked_key_path = Some(PathBuf::from(value_str));
                Ok(())
            }
            "session" => {
                state.session = Some(match value_str {
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
            "key_usage" => {
                state.key_usage = Some(match value_str {
                    "digitalSignature" => EcKeyUsage::DigitalSignature,
                    "keyAgreement" => EcKeyUsage::KeyAgreement,
                    other => {
                        return Err(EngineError::Other(format!(
                            "azihsm.key_usage must be digitalSignature or keyAgreement, got: {other}"
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

    // The curve itself is recorded by the `ctrl` override: the delegated
    // built-in ctrl_str converts the name (including NIST aliases like P-384)
    // and re-enters through EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID.
    let d = defaults()?;
    let ctrl_str = d
        .ctrl_str
        .ok_or(EngineError::Other("built-in ctrl_str missing".into()))?;
    // SAFETY: delegating the arguments OpenSSL passed us to the built-in
    // ctrl_str.
    if unsafe { ctrl_str(ctx, key, value) } <= 0 {
        return Err(EngineError::Other(format!(
            "pkey option rejected: {key_str}"
        )));
    }
    Ok(())
}

/// `keygen` override: delegate an unarmed context to the built-in software
/// keygen; run `H::keygen` for an armed one.
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_keygen`; `ctx` is the keygen context
/// and `pkey` the output key, per the pkey method contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_keygen<H: EcKeygenHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    pkey: *mut ffi::EVP_PKEY,
) -> c_int {
    catch_panic(|| result_to_int(keygen_inner::<H>(ctx, pkey)), 0)
}

#[allow(unsafe_code)]
fn keygen_inner<H: EcKeygenHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    pkey: *mut ffi::EVP_PKEY,
) -> EngineResult<()> {
    if pkey.is_null() {
        return Err(EngineError::NullParam("pkey"));
    }

    let armed = ctx_state()
        .lock()
        .get(&(ctx as usize))
        .filter(|state| state.masked_key_path.is_some())
        .cloned();

    let Some(state) = armed else {
        // Unarmed: a software keygen that merely resolved to our method.
        // Delegate wholesale to the built-in.
        let d = defaults()?;
        let keygen = d
            .keygen
            .ok_or(EngineError::Other("built-in keygen missing".into()))?;
        // SAFETY: delegating the arguments OpenSSL passed us to the built-in
        // keygen.
        if unsafe { keygen(ctx, pkey) } != 1 {
            return Err(EngineError::Other("software EC keygen failed".into()));
        }
        return Ok(());
    };

    let engine_ptr = NonNull::new(state.engine as *mut ffi::ENGINE)
        .ok_or(EngineError::Other("pkey ctx has no ENGINE".into()))?;
    // SAFETY: the ctx holds a functional reference on this ENGINE for its
    // lifetime (int_ctx_new), and keygen runs while the ctx is alive.
    let engine = unsafe { Engine::from_ptr(engine_ptr) };

    let params = KeygenParams {
        curve_nid: state.curve_nid.ok_or(EngineError::Other(
            "azihsm keygen requires a curve (ec_paramgen_curve)".into(),
        ))?,
        masked_key_path: state.masked_key_path.ok_or(EngineError::Other(
            "azihsm keygen requires azihsm.masked_key".into(),
        ))?,
        session: state.session.unwrap_or(false),
        key_usage: state.key_usage.unwrap_or(EcKeyUsage::DigitalSignature),
    };
    H::keygen(&engine, &params, pkey)
}

/// Build the EC `EVP_PKEY_METHOD`: a copy of OpenSSL's built-in EC method with
/// `init`/`copy`/`cleanup`/`ctrl`/`ctrl_str`/`keygen` overridden as described
/// in the module docs. The returned method is heap-allocated and intentionally
/// never freed: the caller registers it for the process lifetime.
#[allow(unsafe_code)]
pub fn new_ec_pkey_method<H: EcKeygenHandler>() -> EngineResult<*mut ffi::EVP_PKEY_METHOD> {
    // SAFETY: EVP_PKEY_meth_find returns the built-in const method for EC.
    let builtin = unsafe { ffi::EVP_PKEY_meth_find(ffi::EVP_PKEY_EC as c_int) };
    if builtin.is_null() {
        return Err(EngineError::Other("built-in EC pkey method missing".into()));
    }

    let mut d = Defaults::default();
    let mut keygen_init = None;
    // SAFETY: builtin is a valid method; the getters write the out-params.
    unsafe {
        ffi::EVP_PKEY_meth_get_init(builtin, &mut d.init);
        ffi::EVP_PKEY_meth_get_copy(builtin, &mut d.copy);
        ffi::EVP_PKEY_meth_get_cleanup(builtin, &mut d.cleanup);
        ffi::EVP_PKEY_meth_get_keygen(builtin, &mut keygen_init, &mut d.keygen);
        ffi::EVP_PKEY_meth_get_ctrl(builtin, &mut d.ctrl, &mut d.ctrl_str);
    }
    let _ = DEFAULTS.set(d);

    // SAFETY: EVP_PKEY_meth_new allocates a fresh method; meth_copy duplicates
    // every callback from the built-in.
    let method = unsafe { ffi::EVP_PKEY_meth_new(ffi::EVP_PKEY_EC as c_int, 0) };
    if method.is_null() {
        return Err(EngineError::Other("EVP_PKEY_meth_new failed".into()));
    }
    // SAFETY: method is fresh and builtin valid; then install our overrides
    // (keeping the built-in keygen_init).
    unsafe {
        ffi::EVP_PKEY_meth_copy(method, builtin);
        ffi::EVP_PKEY_meth_set_init(method, Some(c_init));
        ffi::EVP_PKEY_meth_set_copy(method, Some(c_copy));
        ffi::EVP_PKEY_meth_set_cleanup(method, Some(c_cleanup));
        ffi::EVP_PKEY_meth_set_keygen(method, keygen_init, Some(c_keygen::<H>));
        ffi::EVP_PKEY_meth_set_ctrl(method, Some(c_ctrl), Some(c_ctrl_str));
    }
    Ok(method)
}

/// Record `engine` as the pending ENGINE for this thread — called by the
/// `pkey_meths` callback right before OpenSSL constructs the context (see the
/// module docs for why this handoff is sound).
fn note_pending_engine(engine: *mut ffi::ENGINE) {
    PENDING_ENGINE.with(|c| c.set(engine as usize));
}

/// Per-ENGINE method table (see [`method_table`](crate::method_table) for the
/// ownership rules the engine framework imposes).
static ENGINE_METHODS: MethodTable<ffi::EVP_PKEY_METHOD> = MethodTable::new();

/// `ENGINE_PKEY_METHS_PTR` callback: NID enumeration and per-ENGINE method
/// lookup via [`method_table::dispatch`](crate::method_table::dispatch), with
/// a stored-entry hit additionally recording the ENGINE for the thread-local
/// handoff (a stored entry means a live, registered engine whose lookup
/// precedes an `EVP_PKEY_CTX` construction).
///
/// # Safety
/// Called only by OpenSSL's engine pkey-method lookup; `pmeth`/`nids` are
/// out-params per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_pkey_meths(
    e: *mut ffi::ENGINE,
    pmeth: *mut *mut ffi::EVP_PKEY_METHOD,
    nids: *mut *const c_int,
    nid: c_int,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the out-params OpenSSL passed us.
        || unsafe {
            crate::method_table::dispatch(&ENGINE_METHODS, e, pmeth, nids, nid, note_pending_engine)
        },
        0,
    )
}

/// Register `H` as `engine`'s EC keygen handler, making
/// `EVP_PKEY_CTX_new_id(EVP_PKEY_EC, engine)` — and therefore
/// `openssl genpkey -engine …` — resolve to a method copy owned by this
/// ENGINE. Only one handler type can be registered per process (the first
/// wins). Pair with [`release_ec_pkey_method`] when the ENGINE is destroyed.
pub fn register_ec_pkey_method<H: EcKeygenHandler>(engine: &Engine) -> EngineResult<()> {
    ENGINE_METHODS.register(engine, new_ec_pkey_method::<H>)?;
    // SAFETY: engine's ptr is valid (from NonNull); c_pkey_meths is a 'static
    // fn item with the ENGINE_PKEY_METHS_PTR signature.
    #[allow(unsafe_code)]
    crate::error::ossl_check(
        unsafe { ffi::ENGINE_set_pkey_meths(engine.as_ptr(), Some(c_pkey_meths)) },
        EngineError::Other("ENGINE_set_pkey_meths failed".into()),
    )
}

/// Drop the method-table entry for `engine` (address-only, nothing is
/// dereferenced). Call from the engine's destroy hook, or in tests before
/// `ENGINE_free`: the framework frees the method itself during destruction
/// (`engine_pkey_meths_free`), where a released entry makes the callback hand
/// out a throwaway copy instead.
pub fn release_ec_pkey_method(engine: &Engine) {
    ENGINE_METHODS.release(engine);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ffi::CString;
    use std::ptr::null_mut;

    use super::*;

    /// Stub handler that must never be reached (used where delegation or an
    /// error is expected).
    struct PanicKeygen;
    impl EcKeygenHandler for PanicKeygen {
        fn keygen(
            _engine: &Engine,
            _params: &KeygenParams,
            _pkey: *mut ffi::EVP_PKEY,
        ) -> EngineResult<()> {
            unreachable!("keygen must not be dispatched for this context")
        }
    }

    /// Build the method (capturing the built-in defaults) and a real software
    /// EVP_PKEY_CTX initialized for EC keygen with the given curve set — the
    /// state an unarmed caller would have.
    #[allow(unsafe_code)]
    fn software_keygen_ctx() -> *mut ffi::EVP_PKEY_CTX {
        let method = new_ec_pkey_method::<PanicKeygen>().unwrap();
        // SAFETY: method is ours and registered nowhere.
        unsafe { ffi::EVP_PKEY_meth_free(method) };

        let curve_key = CString::new("ec_paramgen_curve").unwrap();
        let curve_val = CString::new("P-256").unwrap();
        // SAFETY: standard software EVP_PKEY_CTX construction (no engine);
        // every return code is checked.
        unsafe {
            let ctx = ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_EC as c_int, null_mut());
            assert!(!ctx.is_null());
            assert_eq!(ffi::EVP_PKEY_keygen_init(ctx), 1);
            assert_eq!(
                ffi::EVP_PKEY_CTX_ctrl_str(ctx, curve_key.as_ptr(), curve_val.as_ptr()),
                1
            );
            ctx
        }
    }

    // An unarmed context (no azihsm.masked_key, no side-table entry) must be
    // delegated to OpenSSL's software keygen — the situation when an
    // application makes the engine the process default and a plain software
    // keygen resolves to our method.
    #[test]
    #[allow(unsafe_code)]
    fn keygen_inner_delegates_unarmed_ctx_to_software() {
        let ctx = software_keygen_ctx();
        // SAFETY: ctx is a live keygen context; pkey is the out-param.
        unsafe {
            let pkey = ffi::EVP_PKEY_new();
            assert!(!pkey.is_null());
            // The software ctx was built without our init override, so there
            // is no side-table entry — exactly the unarmed shape.
            keygen_inner::<PanicKeygen>(ctx, pkey)
                .expect("unarmed keygen must delegate to software");
            // The software keygen produced a real EC key with a private half.
            let ec = ffi::EVP_PKEY_get0_EC_KEY(pkey);
            assert!(!ec.is_null());
            assert!(
                !ffi::EC_KEY_get0_private_key(ec).is_null(),
                "software keygen must yield a private scalar"
            );
            ffi::EVP_PKEY_free(pkey);
            ffi::EVP_PKEY_CTX_free(ctx);
        }
    }

    // An armed context without a recorded curve must error rather than guess.
    #[test]
    #[allow(unsafe_code)]
    fn keygen_inner_rejects_armed_ctx_without_curve() {
        let ctx = software_keygen_ctx();
        // Arm the ctx by hand (the real arming goes through our ctrl_str).
        ctx_state().lock().insert(
            ctx as usize,
            CtxState {
                engine: 1, // non-zero placeholder; never dereferenced
                masked_key_path: Some(PathBuf::from("/dev/null")),
                ..CtxState::default()
            },
        );
        // SAFETY: ctx is live; EVP_PKEY_new allocates the out-key.
        unsafe {
            let pkey = ffi::EVP_PKEY_new();
            let r = keygen_inner::<PanicKeygen>(ctx, pkey);
            assert!(r.is_err(), "armed keygen without a curve must error");
            ffi::EVP_PKEY_free(pkey);
        }
        ctx_state().lock().remove(&(ctx as usize));
        // SAFETY: ctx is ours.
        unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
    }

    #[test]
    fn keygen_inner_rejects_null_pkey() {
        let r = keygen_inner::<PanicKeygen>(std::ptr::null_mut(), null_mut());
        assert!(matches!(r, Err(EngineError::NullParam("pkey"))));
    }

    // Unknown azihsm.* options must be rejected, not silently ignored or
    // passed to the built-in (which would report a misleading error).
    #[test]
    #[allow(unsafe_code)]
    fn ctrl_str_rejects_unknown_azihsm_option() {
        let ctx = software_keygen_ctx();
        let key = CString::new("azihsm.definitely_unknown").unwrap();
        let value = CString::new("x").unwrap();
        let r = ctrl_str_inner(ctx, key.as_ptr(), value.as_ptr());
        assert!(r.is_err());
        // SAFETY: ctx is ours.
        unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
    }
}
