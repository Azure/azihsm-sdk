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
//! HSM **derive** dispatches on the local key instead: an HSM-backed key
//! ([`EcDeriveHandler::owns`]) derives on the HSM and outputs the secret's
//! masked blob; software keys are delegated to the built-in derive.
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

use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_uchar;
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

/// Caller-supplied HSM ECDH derivation, invoked through the `EVP_PKEY_METHOD`
/// `derive` hook when the local key is HSM-backed. Implement on a marker type
/// and pass it to [`new_ec_pkey_method`].
///
/// The derived shared secret never leaves the HSM in the clear: like the 3.x
/// provider's keyexch, the output of a derive is the **masked key blob** of
/// the derived shared-secret key.
pub trait EcDeriveHandler {
    /// Whether `pkey` is one of the handler's keys (e.g. carries an attached
    /// HSM key handle). Derives on keys not owned are delegated to the
    /// built-in software derive.
    fn owns(pkey: *const ffi::EVP_PKEY) -> bool;

    /// Derive the shared secret between the HSM-backed `pkey` and the software
    /// public key `peer` on the HSM and return its masked blob — or, when
    /// `output_file` is set (the provider's `output_file` parameter), write
    /// the blob there and return `None`.
    fn derive(
        engine: &Engine,
        pkey: *const ffi::EVP_PKEY,
        peer: *const ffi::EVP_PKEY,
        output_file: Option<&std::path::Path>,
    ) -> EngineResult<Option<zeroize::Zeroizing<Vec<u8>>>>;
}

/// Buffer-mode size reported by a derive size query, mirroring the provider's
/// `MASKED_KEY_MAX_BUFFER` (the blob length is unknown until the derive runs).
const MASKED_KEY_MAX_BUFFER: usize = 8192;

/// Per-context side-table entry.
#[derive(Clone, Default)]
struct CtxState {
    engine: usize,
    curve_nid: Option<c_int>,
    masked_key_path: Option<PathBuf>,
    session: Option<bool>,
    key_usage: Option<EcKeyUsage>,
    output_file: Option<PathBuf>,
}

/// Side table: `EVP_PKEY_CTX` address → state. See the module docs for the
/// lifecycle (created in `init`, dropped in `cleanup`).
static CTX_STATE: OnceLock<Mutex<HashMap<usize, CtxState>>> = OnceLock::new();

fn ctx_state() -> &'static Mutex<HashMap<usize, CtxState>> {
    CTX_STATE.get_or_init(|| Mutex::new(HashMap::new()))
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
    derive: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX, *mut c_uchar, *mut usize) -> c_int>,
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

    // `output_file` is the provider's (un-prefixed) keyexch parameter for
    // writing a derive's masked blob to a file; accept it under the same name
    // so pkeyutl invocations port between the plugins.
    if key_str == "output_file" || key_str.starts_with("azihsm.") {
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
        if key_str == "output_file" {
            state.output_file = Some(PathBuf::from(value_str));
            return Ok(());
        }
        let Some(azihsm_key) = key_str.strip_prefix("azihsm.") else {
            return Err(EngineError::Other(format!(
                "unexpected pkey option: {key_str}"
            )));
        };
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

/// `derive` override: software local keys are delegated to the built-in
/// derive; HSM-backed ones get `D::derive` (masked blob to buffer or
/// `output_file`).
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_derive`; arguments per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_derive<D: EcDeriveHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    key: *mut c_uchar,
    keylen: *mut usize,
) -> c_int {
    catch_panic(|| result_to_int(derive_inner::<D>(ctx, key, keylen)), 0)
}

#[allow(unsafe_code)]
fn derive_inner<D: EcDeriveHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    key: *mut c_uchar,
    keylen: *mut usize,
) -> EngineResult<()> {
    if keylen.is_null() {
        return Err(EngineError::NullParam("keylen"));
    }
    // SAFETY: ctx is the derive context; get0 returns a borrowed key or NULL.
    let pkey = unsafe { ffi::EVP_PKEY_CTX_get0_pkey(ctx) };

    if pkey.is_null() || !D::owns(pkey) {
        // Software local key (or none): delegate, size query included —
        // unless the ctx was armed with the HSM-only output_file option,
        // which must fail loudly rather than be silently ignored.
        let output_file_set = ctx_state()
            .lock()
            .get(&(ctx as usize))
            .is_some_and(|s| s.output_file.is_some());
        if output_file_set {
            return Err(EngineError::Other(
                "output_file requires an HSM-backed local key".into(),
            ));
        }
        let d = defaults()?;
        let derive = d
            .derive
            .ok_or(EngineError::Other("built-in derive missing".into()))?;
        // SAFETY: delegating the arguments OpenSSL passed us to the built-in
        // derive.
        if unsafe { derive(ctx, key, keylen) } != 1 {
            return Err(EngineError::Other("software ECDH derive failed".into()));
        }
        return Ok(());
    }

    let state = ctx_state()
        .lock()
        .get(&(ctx as usize))
        .cloned()
        .unwrap_or_default();

    if key.is_null() {
        // Size query: blob length is unknown until the derive runs, so mirror
        // the provider's constants (max in buffer mode, 1 in file mode).
        // SAFETY: keylen is non-null (checked).
        unsafe {
            *keylen = if state.output_file.is_some() {
                1
            } else {
                MASKED_KEY_MAX_BUFFER
            };
        }
        return Ok(());
    }

    let engine_ptr = NonNull::new(state.engine as *mut ffi::ENGINE)
        .ok_or(EngineError::Other("pkey ctx has no ENGINE".into()))?;
    // SAFETY: the ctx holds a functional reference on this ENGINE for its
    // lifetime (int_ctx_new), and derive runs while the ctx is alive.
    let engine = unsafe { Engine::from_ptr(engine_ptr) };

    // SAFETY: ctx is valid; get0 returns the borrowed peer key or NULL.
    let peer = unsafe { ffi::EVP_PKEY_CTX_get0_peerkey(ctx) };
    if peer.is_null() {
        return Err(EngineError::Other(
            "azihsm derive requires a peer key (EVP_PKEY_derive_set_peer)".into(),
        ));
    }

    match D::derive(&engine, pkey, peer, state.output_file.as_deref())? {
        // Blob written to output_file: no bytes in the caller's buffer.
        // SAFETY: keylen is non-null (checked).
        None => unsafe { *keylen = 0 },
        Some(blob) => {
            // SAFETY: keylen is non-null and holds the buffer size on entry.
            let buf_len = unsafe { *keylen };
            if buf_len < blob.len() {
                return Err(EngineError::Other(format!(
                    "output buffer too small for masked key blob ({buf_len} < {})",
                    blob.len()
                )));
            }
            // SAFETY: key points to at least buf_len >= blob.len() writable
            // bytes per the derive contract.
            unsafe {
                std::ptr::copy_nonoverlapping(blob.as_ptr(), key, blob.len());
                *keylen = blob.len();
            }
        }
    }
    Ok(())
}

/// Build the EC `EVP_PKEY_METHOD`: a copy of OpenSSL's built-in EC method with
/// `init`/`copy`/`cleanup`/`ctrl`/`ctrl_str`/`keygen`/`derive` overridden as
/// described in the module docs. The returned method is heap-allocated and
/// intentionally never freed: the caller registers it for the process
/// lifetime.
#[allow(unsafe_code)]
pub fn new_ec_pkey_method<K: EcKeygenHandler, D: EcDeriveHandler>()
-> EngineResult<*mut ffi::EVP_PKEY_METHOD> {
    // SAFETY: EVP_PKEY_meth_find returns the built-in const method for EC.
    let builtin = unsafe { ffi::EVP_PKEY_meth_find(ffi::EVP_PKEY_EC as c_int) };
    if builtin.is_null() {
        return Err(EngineError::Other("built-in EC pkey method missing".into()));
    }

    let mut d = Defaults::default();
    let mut keygen_init = None;
    let mut derive_init = None;
    // SAFETY: builtin is a valid method; the getters write the out-params.
    unsafe {
        ffi::EVP_PKEY_meth_get_init(builtin, &mut d.init);
        ffi::EVP_PKEY_meth_get_copy(builtin, &mut d.copy);
        ffi::EVP_PKEY_meth_get_cleanup(builtin, &mut d.cleanup);
        ffi::EVP_PKEY_meth_get_keygen(builtin, &mut keygen_init, &mut d.keygen);
        ffi::EVP_PKEY_meth_get_derive(builtin, &mut derive_init, &mut d.derive);
        ffi::EVP_PKEY_meth_get_ctrl(builtin, &mut d.ctrl, &mut d.ctrl_str);
    }
    let _ = DEFAULTS.set(d);

    // SAFETY: EVP_PKEY_meth_new allocates a fresh method; meth_copy duplicates
    // every callback from the built-in.
    let method = unsafe { ffi::EVP_PKEY_meth_new(ffi::EVP_PKEY_EC as c_int, 0) };
    if method.is_null() {
        return Err(EngineError::Other("EVP_PKEY_meth_new failed".into()));
    }
    // SAFETY: method is fresh and builtin valid; install our overrides
    // (keeping the built-in keygen_init/derive_init).
    unsafe {
        ffi::EVP_PKEY_meth_copy(method, builtin);
        ffi::EVP_PKEY_meth_set_init(method, Some(c_init));
        ffi::EVP_PKEY_meth_set_copy(method, Some(c_copy));
        ffi::EVP_PKEY_meth_set_cleanup(method, Some(c_cleanup));
        ffi::EVP_PKEY_meth_set_keygen(method, keygen_init, Some(c_keygen::<K>));
        ffi::EVP_PKEY_meth_set_derive(method, derive_init, Some(c_derive::<D>));
        ffi::EVP_PKEY_meth_set_ctrl(method, Some(c_ctrl), Some(c_ctrl_str));
    }
    Ok(method)
}

/// The NIDs this engine's pkey-method callback serves.
static PKEY_NIDS: [c_int; 2] = [ffi::EVP_PKEY_EC as c_int, ffi::NID_hkdf as c_int];

/// Per-`(ENGINE, NID)` method table shared by the EC and HKDF pkey methods
/// (see [`method_table`](crate::method_table) for the ownership rules the
/// engine framework imposes).
pub(crate) static ENGINE_METHODS: MethodTable<ffi::EVP_PKEY_METHOD> = MethodTable::new(&PKEY_NIDS);

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
            crate::method_table::dispatch(
                &ENGINE_METHODS,
                e,
                pmeth,
                nids,
                nid,
                crate::method_table::note_pending_engine,
            )
        },
        0,
    )
}

/// Register `K`/`D` as `engine`'s EC keygen/derive handlers, making
/// `EVP_PKEY_CTX_new_id(EVP_PKEY_EC, engine)` — and therefore
/// `openssl genpkey`/`pkeyutl -engine …` — resolve to a method copy owned by
/// this ENGINE. Only one handler pair can be registered per process (the
/// first wins). Pair with [`release_pkey_methods`] when the ENGINE is
/// destroyed.
pub fn register_ec_pkey_method<K: EcKeygenHandler, D: EcDeriveHandler>(
    engine: &Engine,
) -> EngineResult<()> {
    ENGINE_METHODS.register(
        engine,
        ffi::EVP_PKEY_EC as c_int,
        new_ec_pkey_method::<K, D>,
    )?;
    install_pkey_meths_callback(engine)
}

/// Install the shared pkey-method lookup callback on `engine` (idempotent;
/// called by every per-NID registration).
pub(crate) fn install_pkey_meths_callback(engine: &Engine) -> EngineResult<()> {
    // SAFETY: engine's ptr is valid (from NonNull); c_pkey_meths is a 'static
    // fn item with the ENGINE_PKEY_METHS_PTR signature.
    #[allow(unsafe_code)]
    crate::error::ossl_check(
        unsafe { ffi::ENGINE_set_pkey_meths(engine.as_ptr(), Some(c_pkey_meths)) },
        EngineError::Other("ENGINE_set_pkey_meths failed".into()),
    )
}

/// Drop all of `engine`'s pkey-method entries (address-only, nothing is
/// dereferenced). Call from the engine's destroy hook, or in tests before
/// `ENGINE_free`: the framework frees the methods itself during destruction
/// (`engine_pkey_meths_free`), where a released entry makes the callback hand
/// out a throwaway copy instead.
pub fn release_pkey_methods(engine: &Engine) {
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
    impl EcDeriveHandler for PanicKeygen {
        fn owns(_pkey: *const ffi::EVP_PKEY) -> bool {
            false
        }
        fn derive(
            _engine: &Engine,
            _pkey: *const ffi::EVP_PKEY,
            _peer: *const ffi::EVP_PKEY,
            _output_file: Option<&std::path::Path>,
        ) -> EngineResult<Option<zeroize::Zeroizing<Vec<u8>>>> {
            unreachable!("derive must not be dispatched for this context")
        }
    }

    /// Build the method (capturing the built-in defaults) and a real software
    /// EVP_PKEY_CTX initialized for EC keygen with the given curve set — the
    /// state an unarmed caller would have.
    #[allow(unsafe_code)]
    fn software_keygen_ctx() -> *mut ffi::EVP_PKEY_CTX {
        let method = new_ec_pkey_method::<PanicKeygen, PanicKeygen>().unwrap();
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

    // A software local key must be delegated to the built-in derive: both
    // directions produce the same raw shared secret, and the size query
    // reports the curve's degree bytes (not the masked-blob constant).
    #[test]
    #[allow(unsafe_code)]
    fn derive_inner_delegates_software_keys() {
        let make_key = || {
            let ctx = software_keygen_ctx();
            // SAFETY: ctx is a live keygen context; pkey is the out-param.
            unsafe {
                let mut pkey = null_mut();
                assert_eq!(ffi::EVP_PKEY_keygen(ctx, &mut pkey), 1, "keygen");
                ffi::EVP_PKEY_CTX_free(ctx);
                pkey
            }
        };
        let a = make_key();
        let b = make_key();

        let derive = |local: *mut ffi::EVP_PKEY, peer: *mut ffi::EVP_PKEY| {
            // SAFETY: standard software derive; all return codes checked.
            unsafe {
                let ctx = ffi::EVP_PKEY_CTX_new(local, null_mut());
                assert!(!ctx.is_null());
                assert_eq!(ffi::EVP_PKEY_derive_init(ctx), 1);
                assert_eq!(ffi::EVP_PKEY_derive_set_peer(ctx, peer), 1);
                let mut len = 0usize;
                derive_inner::<PanicKeygen>(ctx, null_mut(), &mut len).expect("size query");
                assert_eq!(len, 32, "P-256 software size query must be 32");
                let mut buf = vec![0u8; len];
                derive_inner::<PanicKeygen>(ctx, buf.as_mut_ptr(), &mut len).expect("derive");
                buf.truncate(len);
                ffi::EVP_PKEY_CTX_free(ctx);
                buf
            }
        };
        let z_ab = derive(a, b);
        let z_ba = derive(b, a);
        assert!(!z_ab.is_empty());
        assert_eq!(z_ab, z_ba, "software ECDH must agree in both directions");

        // SAFETY: a/b are ours.
        unsafe {
            ffi::EVP_PKEY_free(a);
            ffi::EVP_PKEY_free(b);
        }
    }

    // output_file is an HSM-derive option: a delegated software-key derive
    // must reject it loudly, never silently ignore it.
    #[test]
    #[allow(unsafe_code)]
    fn derive_inner_rejects_output_file_for_software_key() {
        let ctx = software_keygen_ctx();
        // SAFETY: ctx is a live keygen context; pkey is the out-param.
        let pkey = unsafe {
            let mut pkey = null_mut();
            assert_eq!(ffi::EVP_PKEY_keygen(ctx, &mut pkey), 1);
            ffi::EVP_PKEY_CTX_free(ctx);
            pkey
        };
        // SAFETY: standard derive ctx on a software key.
        let dctx = unsafe {
            let dctx = ffi::EVP_PKEY_CTX_new(pkey, null_mut());
            assert!(!dctx.is_null());
            assert_eq!(ffi::EVP_PKEY_derive_init(dctx), 1);
            assert_eq!(ffi::EVP_PKEY_derive_set_peer(dctx, pkey), 1);
            dctx
        };
        // Arm output_file by hand (the real arming goes through our ctrl_str).
        ctx_state().lock().insert(
            dctx as usize,
            CtxState {
                output_file: Some(PathBuf::from("/dev/null")),
                ..CtxState::default()
            },
        );
        let mut len = 0usize;
        let r = derive_inner::<PanicKeygen>(dctx, null_mut(), &mut len);
        assert!(
            matches!(&r, Err(EngineError::Other(m)) if m.contains("output_file")),
            "expected output_file rejection, got: {r:?}"
        );
        ctx_state().lock().remove(&(dctx as usize));
        // SAFETY: dctx/pkey are ours.
        unsafe {
            ffi::EVP_PKEY_CTX_free(dctx);
            ffi::EVP_PKEY_free(pkey);
        }
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
