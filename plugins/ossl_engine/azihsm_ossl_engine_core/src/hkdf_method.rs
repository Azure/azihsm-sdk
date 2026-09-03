// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Custom HKDF `EVP_PKEY_METHOD` for deriving HSM keys from masked secrets.
//!
//! `openssl pkeyutl -kdf HKDF -engine azihsm -engine_impl` (and the
//! `EVP_PKEY_derive` ABI on a `NID_hkdf` context) resolve here through the
//! shared per-engine pkey-method table. HSM derivation is **opt-in per
//! context**: it runs only when an `azihsm.*` / provider-parity option armed
//! the context (`azihsm.ikm_file`, `output_file`, `derived_key_type`,
//! `derived_key_bits`). An unarmed context is delegated wholesale to the
//! built-in software HKDF.
//!
//! When armed, the IKM is a masked key blob — the standard `key`/`hexkey`
//! parameter carries the blob bytes, or `azihsm.ikm_file` names its file
//! (mutually exclusive, mirroring the 3.x provider) — and the output is the
//! masked blob of the derived key (AES or HMAC kind), never raw key bytes:
//! into the caller's buffer, or to the `output_file` path.
//!
//! The standard parameters (`md`, `salt`, `info`, `key`, `mode`) are recorded
//! by the `ctrl` override and also delegated, so an unarmed context keeps
//! built-in behavior byte-for-byte.

use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_void;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::OnceLock;

use azihsm_ossl_engine_sys as ffi;
use parking_lot::Mutex;
use zeroize::Zeroizing;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::catch_panic;
use crate::error::result_to_int;
use crate::pkey_method::ENGINE_METHODS;

/// Kind of the derived key, named as the provider names them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DerivedKeyType {
    /// AES key (encrypt/decrypt), the default.
    Aes,
    /// HMAC key (sign/verify); bits select the SHA-2 kind.
    Hmac,
}

/// The IKM for an armed derivation: a masked key blob, by value or by file.
pub enum IkmSource {
    /// Blob bytes from the standard `key`/`hexkey` parameter.
    Bytes(Zeroizing<Vec<u8>>),
    /// Blob file from `azihsm.ikm_file` (read by the handler, hardened).
    File(PathBuf),
}

/// Parameters an armed context accumulated by the time derive runs.
pub struct HkdfParams {
    /// Digest NID from the `md` parameter.
    pub md_nid: c_int,
    /// Optional salt (replace semantics, like the built-in).
    pub salt: Option<Vec<u8>>,
    /// Optional info (append semantics, like the built-in).
    pub info: Option<Vec<u8>>,
    /// The masked IKM.
    pub ikm: IkmSource,
    /// `derived_key_type` (default AES).
    pub derived_key_type: DerivedKeyType,
    /// `derived_key_bits` (default 256).
    pub derived_key_bits: u32,
}

/// Caller-supplied HSM HKDF derivation. Implement on a marker type and pass
/// it to [`register_hkdf_pkey_method`].
pub trait HkdfHandler {
    /// Derive a key on the HSM per `params` and return its masked blob — or,
    /// when `output_file` is set, write the blob there and return `None`.
    fn derive(
        engine: &Engine,
        params: &HkdfParams,
        output_file: Option<&Path>,
    ) -> EngineResult<Option<Zeroizing<Vec<u8>>>>;
}

/// Buffer-mode size reported by an armed size query (blob length is unknown
/// until the derive runs; mirrors the keyexch constant).
const MASKED_KEY_MAX_BUFFER: usize = 8192;

/// Per-context state. `armed` is implied by any azihsm-specific field.
#[derive(Clone, Default)]
struct HkdfState {
    engine: usize,
    md_nid: Option<c_int>,
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
    key: Option<Zeroizing<Vec<u8>>>,
    mode: c_int,
    ikm_file: Option<PathBuf>,
    output_file: Option<PathBuf>,
    derived_key_type: Option<DerivedKeyType>,
    derived_key_bits: Option<u32>,
}

impl HkdfState {
    fn armed(&self) -> bool {
        self.ikm_file.is_some()
            || self.output_file.is_some()
            || self.derived_key_type.is_some()
            || self.derived_key_bits.is_some()
    }
}

static CTX_STATE: OnceLock<Mutex<HashMap<usize, HkdfState>>> = OnceLock::new();

fn ctx_state() -> &'static Mutex<HashMap<usize, HkdfState>> {
    CTX_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Built-in HKDF `EVP_PKEY_METHOD` callbacks captured at method build.
#[derive(Clone, Copy, Default)]
struct Defaults {
    init: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX) -> c_int>,
    copy: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX, *mut ffi::EVP_PKEY_CTX) -> c_int>,
    cleanup: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX)>,
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
        .ok_or(EngineError::Other("HKDF method defaults missing".into()))
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
                HkdfState {
                    engine,
                    ..HkdfState::default()
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

/// `ctrl` override: record the standard HKDF parameters for direct-ABI
/// callers (the EVP_PKEY_CTX_set_hkdf_* macros), then delegate. String
/// parameters are recorded by our ctrl_str instead, which forwards to the
/// built-in ctrl directly — never through this override.
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
            {
                let mut table = ctx_state().lock();
                if let Some(state) = table.get_mut(&(ctx as usize)) {
                    // SAFETY: p1/p2 shapes per the HKDF ctrl contract; byte
                    // parameters are length-p1 buffers.
                    unsafe {
                        if cmd == ffi::EVP_PKEY_CTRL_HKDF_MD_CONST && !p2.is_null() {
                            state.md_nid = Some(ffi::EVP_MD_type(p2.cast_const().cast()));
                        } else if cmd == ffi::EVP_PKEY_CTRL_HKDF_MODE_CONST {
                            state.mode = p1;
                        } else if !p2.is_null()
                            && let Ok(len) = usize::try_from(p1)
                        {
                            let bytes = std::slice::from_raw_parts(p2.cast::<u8>(), len);
                            if cmd == ffi::EVP_PKEY_CTRL_HKDF_SALT_CONST {
                                state.salt = Some(bytes.to_vec());
                            } else if cmd == ffi::EVP_PKEY_CTRL_HKDF_KEY_CONST {
                                state.key = Some(Zeroizing::new(bytes.to_vec()));
                            } else if cmd == ffi::EVP_PKEY_CTRL_HKDF_INFO_CONST {
                                // Append, matching the built-in.
                                state.info.get_or_insert_with(Vec::new).extend(bytes);
                            }
                        }
                    }
                }
            }
            let Ok(d) = defaults() else { return -2 };
            let Some(ctrl) = d.ctrl else { return -2 };
            // SAFETY: delegating the arguments OpenSSL passed us.
            unsafe { ctrl(ctx, cmd, p1, p2) }
        },
        0,
    )
}

/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_CTX_ctrl_str`; strings per that
/// contract.
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

    let ours = matches!(
        key_str,
        "azihsm.ikm_file" | "output_file" | "derived_key_type" | "derived_key_bits"
    );
    if ours {
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
            .ok_or(EngineError::Other("HKDF ctx has no azihsm state".into()))?;
        return match key_str {
            "azihsm.ikm_file" => {
                state.ikm_file = Some(PathBuf::from(value_str));
                Ok(())
            }
            "output_file" => {
                state.output_file = Some(PathBuf::from(value_str));
                Ok(())
            }
            "derived_key_type" => {
                state.derived_key_type = Some(match value_str {
                    "aes" => DerivedKeyType::Aes,
                    "hmac" => DerivedKeyType::Hmac,
                    other => {
                        return Err(EngineError::Other(format!(
                            "derived_key_type must be aes or hmac, got: {other}"
                        )));
                    }
                });
                Ok(())
            }
            "derived_key_bits" => {
                let bits: u32 = value_str.parse().map_err(|_| {
                    EngineError::Other(format!("invalid derived_key_bits: {value_str}"))
                })?;
                if bits == 0 || !bits.is_multiple_of(8) {
                    return Err(EngineError::Other(format!(
                        "derived_key_bits must be positive and divisible by 8, got: {bits}"
                    )));
                }
                state.derived_key_bits = Some(bits);
                Ok(())
            }
            _ => Err(EngineError::Other("unreachable ctrl key".into())),
        };
    }

    // Standard parameters: parse and record here, then forward to the
    // built-in's ctrl directly. Do not rely on the built-in ctrl_str
    // re-entering our ctrl override — patched 1.1.1 builds (e.g. RHEL's
    // FIPS-reworked 1.1.1k) dispatch internally without it.
    if value.is_null() {
        return Err(EngineError::NullParam("ctrl value"));
    }
    // SAFETY: as above.
    let value_str = unsafe { CStr::from_ptr(value) }
        .to_str()
        .map_err(|_| EngineError::Other("ctrl value is not valid UTF-8".into()))?;
    let d = defaults()?;
    match key_str {
        "md" => {
            // SAFETY: value is a NUL-terminated digest name; the returned
            // EVP_MD is a process-lifetime constant (or NULL, checked).
            let md = unsafe { ffi::EVP_get_digestbyname(value) };
            if md.is_null() {
                return Err(EngineError::Other(format!("unknown digest: {value_str}")));
            }
            // SAFETY: md is a valid EVP_MD (checked).
            let nid = unsafe { ffi::EVP_MD_type(md) };
            record(ctx, |state| state.md_nid = Some(nid))?;
            builtin_ctrl(
                &d,
                ctx,
                ffi::EVP_PKEY_CTRL_HKDF_MD_CONST,
                0,
                md.cast_mut().cast(),
                "md",
            )
        }
        "salt" | "hexsalt" | "key" | "hexkey" | "info" | "hexinfo" => {
            let bytes = if key_str.starts_with("hex") {
                hex_decode(value_str)?
            } else {
                Zeroizing::new(value_str.as_bytes().to_vec())
            };
            let (cmd, is_info) = match key_str {
                "salt" | "hexsalt" => (ffi::EVP_PKEY_CTRL_HKDF_SALT_CONST, false),
                "key" | "hexkey" => (ffi::EVP_PKEY_CTRL_HKDF_KEY_CONST, false),
                _ => (ffi::EVP_PKEY_CTRL_HKDF_INFO_CONST, true),
            };
            record(ctx, |state| {
                if cmd == ffi::EVP_PKEY_CTRL_HKDF_SALT_CONST {
                    state.salt = Some(bytes.to_vec());
                } else if is_info {
                    // Append, matching the built-in.
                    state.info.get_or_insert_with(Vec::new).extend(bytes.iter());
                } else {
                    state.key = Some(Zeroizing::new(bytes.to_vec()));
                }
            })?;
            let len = c_int::try_from(bytes.len())
                .map_err(|_| EngineError::Other(format!("{key_str} too large")))?;
            builtin_ctrl(&d, ctx, cmd, len, bytes.as_ptr().cast_mut().cast(), key_str)
        }
        "mode" => {
            // 0 = EXTRACT_AND_EXPAND (kdf.h); only that mode works armed.
            let mode: c_int = match value_str {
                "EXTRACT_AND_EXPAND" => 0,
                "EXTRACT_ONLY" => 1,
                "EXPAND_ONLY" => 2,
                other => {
                    return Err(EngineError::Other(format!("unknown HKDF mode: {other}")));
                }
            };
            record(ctx, |state| state.mode = mode)?;
            builtin_ctrl(
                &d,
                ctx,
                ffi::EVP_PKEY_CTRL_HKDF_MODE_CONST,
                mode,
                std::ptr::null_mut(),
                "mode",
            )
        }
        // Anything else: the built-in's ctrl_str decides.
        _ => {
            let ctrl_str = d
                .ctrl_str
                .ok_or(EngineError::Other("built-in ctrl_str missing".into()))?;
            // SAFETY: delegating the arguments OpenSSL passed us.
            if unsafe { ctrl_str(ctx, key, value) } <= 0 {
                return Err(EngineError::Other(format!(
                    "HKDF option rejected: {key_str}"
                )));
            }
            Ok(())
        }
    }
}

/// Update this ctx's recorded state.
fn record(ctx: *mut ffi::EVP_PKEY_CTX, f: impl FnOnce(&mut HkdfState)) -> EngineResult<()> {
    let mut table = ctx_state().lock();
    let state = table
        .get_mut(&(ctx as usize))
        .ok_or(EngineError::Other("HKDF ctx has no azihsm state".into()))?;
    f(state);
    Ok(())
}

/// Forward one parsed parameter to the built-in's ctrl.
#[allow(unsafe_code)]
fn builtin_ctrl(
    d: &Defaults,
    ctx: *mut ffi::EVP_PKEY_CTX,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
    what: &str,
) -> EngineResult<()> {
    let ctrl = d
        .ctrl
        .ok_or(EngineError::Other("built-in ctrl missing".into()))?;
    // SAFETY: forwarding a well-formed HKDF ctrl to the built-in.
    if unsafe { ctrl(ctx, cmd, p1, p2) } <= 0 {
        return Err(EngineError::Other(format!("HKDF option rejected: {what}")));
    }
    Ok(())
}

/// Decode a hex string (as the built-in's hex parameters accept).
fn hex_decode(s: &str) -> EngineResult<Zeroizing<Vec<u8>>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(EngineError::Other("odd-length hex value".into()));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or(EngineError::Other("invalid hex value".into()))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or(EngineError::Other("invalid hex value".into()))?;
        #[allow(clippy::cast_possible_truncation)]
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// `derive` override: unarmed contexts delegate to the built-in software
/// HKDF; armed ones derive on the HSM (masked blob to buffer or
/// `output_file`).
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_derive`; arguments per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_derive<H: HkdfHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    key: *mut c_uchar,
    keylen: *mut usize,
) -> c_int {
    catch_panic(|| result_to_int(derive_inner::<H>(ctx, key, keylen)), 0)
}

#[allow(unsafe_code)]
fn derive_inner<H: HkdfHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    key: *mut c_uchar,
    keylen: *mut usize,
) -> EngineResult<()> {
    if keylen.is_null() {
        return Err(EngineError::NullParam("keylen"));
    }
    let state = ctx_state()
        .lock()
        .get(&(ctx as usize))
        .cloned()
        .unwrap_or_default();

    if !state.armed() {
        // Software HKDF: delegate wholesale, size query included.
        let d = defaults()?;
        let derive = d
            .derive
            .ok_or(EngineError::Other("built-in derive missing".into()))?;
        // SAFETY: delegating the arguments OpenSSL passed us.
        if unsafe { derive(ctx, key, keylen) } != 1 {
            return Err(EngineError::Other("software HKDF derive failed".into()));
        }
        return Ok(());
    }

    if key.is_null() {
        // Size query: blob length is unknown until the derive runs.
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

    if state.mode != 0 {
        return Err(EngineError::Other(
            "azihsm HKDF supports only the extract-and-expand mode".into(),
        ));
    }
    let ikm = match (state.key, &state.ikm_file) {
        (Some(_), Some(_)) => {
            return Err(EngineError::Other(
                "key/hexkey and azihsm.ikm_file are mutually exclusive".into(),
            ));
        }
        (Some(bytes), None) => IkmSource::Bytes(bytes),
        (None, Some(path)) => IkmSource::File(path.clone()),
        (None, None) => {
            return Err(EngineError::Other(
                "azihsm HKDF requires an IKM (key, hexkey, or azihsm.ikm_file)".into(),
            ));
        }
    };
    let params = HkdfParams {
        md_nid: state
            .md_nid
            .ok_or(EngineError::Other("azihsm HKDF requires md".into()))?,
        salt: state.salt,
        info: state.info,
        ikm,
        derived_key_type: state.derived_key_type.unwrap_or(DerivedKeyType::Aes),
        derived_key_bits: state.derived_key_bits.unwrap_or(256),
    };

    let engine_ptr = NonNull::new(state.engine as *mut ffi::ENGINE)
        .ok_or(EngineError::Other("HKDF ctx has no ENGINE".into()))?;
    // SAFETY: the ctx holds a functional reference on this ENGINE for its
    // lifetime (int_ctx_new), and derive runs while the ctx is alive.
    let engine = unsafe { Engine::from_ptr(engine_ptr) };

    match H::derive(&engine, &params, state.output_file.as_deref())? {
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
            // SAFETY: key points to at least buf_len writable bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(blob.as_ptr(), key, blob.len());
                *keylen = blob.len();
            }
        }
    }
    Ok(())
}

/// Build the HKDF `EVP_PKEY_METHOD`: a copy of the built-in with
/// `init`/`copy`/`cleanup`/`ctrl`/`ctrl_str`/`derive` overridden. Never
/// freed by us — the engine framework owns registered copies.
#[allow(unsafe_code)]
pub fn new_hkdf_pkey_method<H: HkdfHandler>() -> EngineResult<*mut ffi::EVP_PKEY_METHOD> {
    // SAFETY: EVP_PKEY_meth_find returns the built-in const method.
    let builtin = unsafe { ffi::EVP_PKEY_meth_find(ffi::NID_hkdf as c_int) };
    if builtin.is_null() {
        return Err(EngineError::Other("built-in HKDF method missing".into()));
    }

    let mut d = Defaults::default();
    let mut derive_init = None;
    // SAFETY: builtin is a valid method; the getters write the out-params.
    unsafe {
        ffi::EVP_PKEY_meth_get_init(builtin, &mut d.init);
        ffi::EVP_PKEY_meth_get_copy(builtin, &mut d.copy);
        ffi::EVP_PKEY_meth_get_cleanup(builtin, &mut d.cleanup);
        ffi::EVP_PKEY_meth_get_derive(builtin, &mut derive_init, &mut d.derive);
        ffi::EVP_PKEY_meth_get_ctrl(builtin, &mut d.ctrl, &mut d.ctrl_str);
    }
    let _ = DEFAULTS.set(d);

    // SAFETY: fresh method; meth_copy duplicates the built-in callbacks; the
    // setters install our overrides (keeping the built-in derive_init).
    unsafe {
        let method = ffi::EVP_PKEY_meth_new(ffi::NID_hkdf as c_int, 0);
        if method.is_null() {
            return Err(EngineError::Other("EVP_PKEY_meth_new failed".into()));
        }
        ffi::EVP_PKEY_meth_copy(method, builtin);
        ffi::EVP_PKEY_meth_set_init(method, Some(c_init));
        ffi::EVP_PKEY_meth_set_copy(method, Some(c_copy));
        ffi::EVP_PKEY_meth_set_cleanup(method, Some(c_cleanup));
        ffi::EVP_PKEY_meth_set_derive(method, derive_init, Some(c_derive::<H>));
        ffi::EVP_PKEY_meth_set_ctrl(method, Some(c_ctrl), Some(c_ctrl_str));
        Ok(method)
    }
}

/// Register `H` as `engine`'s HKDF handler in the shared pkey-method table.
/// Only one handler type can be registered per process (the first wins).
/// Released together with the EC methods via
/// [`release_pkey_methods`](crate::pkey_method::release_pkey_methods).
pub fn register_hkdf_pkey_method<H: HkdfHandler>(engine: &Engine) -> EngineResult<()> {
    ENGINE_METHODS.register(engine, ffi::NID_hkdf as c_int, new_hkdf_pkey_method::<H>)?;
    crate::pkey_method::install_pkey_meths_callback(engine)
}
