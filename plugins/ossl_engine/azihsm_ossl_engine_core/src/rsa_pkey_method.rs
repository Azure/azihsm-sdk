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
use std::ffi::c_uchar;
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

/// Caller-supplied RSA-PSS signing, invoked through the `EVP_PKEY_METHOD` `sign`
/// slot when the context requests PSS padding on an HSM-backed key. Implement on
/// a marker type and pass it to [`register_rsa_pkey_method`].
///
/// PKCS#1 v1.5 signing does not come here — it stays on the `RSA_METHOD` sign
/// slot (`RSA_sign`); only PSS, which 1.1.1 handles by padding in software and
/// calling the raw `rsa_priv_enc` the HSM cannot back, needs this higher-level
/// hook. A PSS request on a key the handler does not [`own`](Self::owns) is
/// rejected, not delegated: the engine's sign path must never produce a software
/// signature. Non-PSS paddings delegate to the built-in `sign` (PKCS#1 v1.5 then
/// reaches the `RSA_METHOD` hook, which likewise rejects non-HSM keys).
pub trait RsaPssSignHandler {
    /// Whether `pkey` is one of the handler's keys (carries an HSM key handle).
    fn owns(pkey: *const ffi::EVP_PKEY) -> bool;

    /// PSS-sign the pre-computed digest `m` (digest NID `md_nid`, salt length
    /// `salt_len` bytes, MGF1 digest equal to `md_nid`) with `pkey`'s HSM key,
    /// returning a signature of exactly the modulus size.
    fn pss_sign(
        pkey: *const ffi::EVP_PKEY,
        md_nid: c_int,
        salt_len: usize,
        m: &[u8],
    ) -> EngineResult<Vec<u8>>;
}

/// OpenSSL PSS salt-length sentinels (negative `rsa_pss_saltlen` values).
const RSA_PSS_SALTLEN_DIGEST: c_int = -1;
const RSA_PSS_SALTLEN_AUTO: c_int = -2;
const RSA_PSS_SALTLEN_MAX: c_int = -3;

/// Resolve an explicitly-set `rsa_pss_saltlen` value to a concrete byte length,
/// matching the 3.x provider: `DIGEST` → the digest length, `MAX` → `max_salt`
/// (modulus − digest − 2), a non-negative value as-is. An explicit `AUTO` is
/// rejected (the provider refuses it), as is any other sentinel. An *unset* salt
/// length is handled by the caller (it defaults to the digest length), so `AUTO`
/// here only ever means the caller set it explicitly.
fn resolve_salt_len(raw: c_int, md_size: usize, max_salt: usize) -> EngineResult<usize> {
    match raw {
        RSA_PSS_SALTLEN_DIGEST => Ok(md_size),
        RSA_PSS_SALTLEN_MAX => Ok(max_salt),
        RSA_PSS_SALTLEN_AUTO => Err(EngineError::Other(
            "rsa_pss_saltlen:auto is not supported; use digest, max, or an explicit length".into(),
        )),
        n if n >= 0 => Ok(n as usize),
        other => Err(EngineError::Other(format!(
            "unsupported RSA-PSS salt length ({other}); use digest, max, or a non-negative value"
        ))),
    }
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
    /// The `rsa_pss_saltlen` value if the caller set it explicitly (via the
    /// numeric ctrl or the string form, which the built-in routes through ctrl).
    /// `None` means unset — a sign then defaults to the digest length, matching
    /// the 3.x provider. Not an arming field (it does not imply an import).
    pss_saltlen: Option<c_int>,
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
    sign: Option<
        unsafe extern "C" fn(
            *mut ffi::EVP_PKEY_CTX,
            *mut c_uchar,
            *mut usize,
            *const c_uchar,
            usize,
        ) -> c_int,
    >,
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
/// recording `rsa_keygen_bits` (for an armed import) and an explicitly-set
/// `rsa_pss_saltlen` (for the PSS sign path). Both the direct numeric ABIs and
/// the string forms reach here — the built-in `ctrl_str` routes those options
/// back through `EVP_PKEY_CTX_ctrl`.
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
            // Record an explicitly-set PSS salt length so the sign path can tell
            // it apart from the unset default (and reject an explicit `auto`).
            if rc > 0
                && ctrl_type == ffi::EVP_PKEY_CTRL_RSA_PSS_SALTLEN_CONST
                && let Some(state) = ctx_state().lock().get_mut(&(ctx as usize))
            {
                state.pss_saltlen = Some(p1);
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

/// Read an integer `EVP_PKEY_CTX_ctrl` getter (e.g. padding, salt length).
/// # Safety
/// `ctx` must be a valid signing `EVP_PKEY_CTX`.
#[allow(unsafe_code)]
unsafe fn ctrl_get_int(
    ctx: *mut ffi::EVP_PKEY_CTX,
    optype: c_int,
    cmd: c_int,
) -> EngineResult<c_int> {
    let mut out: c_int = 0;
    // SAFETY: ctx is valid; the getter writes an int into `out` via p2.
    let rc = unsafe {
        ffi::EVP_PKEY_CTX_ctrl(
            ctx,
            ffi::EVP_PKEY_RSA as c_int,
            optype,
            cmd,
            0,
            (&mut out as *mut c_int).cast(),
        )
    };
    if rc <= 0 {
        return Err(EngineError::Other("EVP_PKEY_CTX_ctrl getter failed".into()));
    }
    Ok(out)
}

/// Read an `EVP_MD *` `EVP_PKEY_CTX_ctrl` getter, returning NULL when unset.
/// # Safety
/// `ctx` must be a valid signing `EVP_PKEY_CTX`.
#[allow(unsafe_code)]
unsafe fn ctrl_get_md(
    ctx: *mut ffi::EVP_PKEY_CTX,
    keytype: c_int,
    cmd: c_int,
) -> *const ffi::EVP_MD {
    let mut md: *const ffi::EVP_MD = std::ptr::null();
    // SAFETY: ctx is valid; the getter writes an EVP_MD* into `md` via p2.
    let rc = unsafe {
        ffi::EVP_PKEY_CTX_ctrl(
            ctx,
            keytype,
            ffi::EVP_PKEY_OP_TYPE_SIG_CONST,
            cmd,
            0,
            (&mut md as *mut *const ffi::EVP_MD).cast(),
        )
    };
    if rc <= 0 { std::ptr::null() } else { md }
}

/// C trampoline for the `EVP_PKEY_METHOD` `sign` slot: PSS on an HSM-backed key
/// goes to `S::pss_sign`; a PSS request on a key the engine does not own is
/// rejected (never software-signed); every non-PSS request — including PKCS#1
/// v1.5, which reaches the `RSA_METHOD` sign slot via `RSA_sign` — delegates to
/// the built-in `sign`.
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_sign`; arguments per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_sign<S: RsaPssSignHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    sig: *mut c_uchar,
    siglen: *mut usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the arguments OpenSSL passed to this sign callback.
        || result_to_int(unsafe { sign_inner::<S>(ctx, sig, siglen, tbs, tbslen) }),
        0,
    )
}

/// Inner body of [`c_sign`]: PSS on an owned HSM key dispatches to `S::pss_sign`;
/// anything else delegates to the built-in `sign`.
///
/// # Safety
/// `ctx` is the signing context; `sig`/`siglen` the output buffer (or NULL for a
/// size query) and `tbs`/`tbslen` the digest, per the `sign` contract.
#[allow(unsafe_code)]
unsafe fn sign_inner<S: RsaPssSignHandler>(
    ctx: *mut ffi::EVP_PKEY_CTX,
    sig: *mut c_uchar,
    siglen: *mut usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> EngineResult<()> {
    // SAFETY: ctx is the signing context OpenSSL passed us; get0 borrows its key.
    let pkey = unsafe { ffi::EVP_PKEY_CTX_get0_pkey(ctx) };
    // PSS is the only padding handled here. Everything else — the size query
    // (sig == NULL, already short-circuited by AUTOARGLEN) and PKCS#1 v1.5, which
    // reaches the RSA_METHOD sign slot via RSA_sign — delegates to the built-in.
    // SAFETY: ctx is a valid signing ctx.
    let is_pss = !sig.is_null()
        && !pkey.is_null()
        && unsafe { ctrl_get_int(ctx, -1, ffi::EVP_PKEY_CTRL_GET_RSA_PADDING_CONST) }
            .map(|p| p == ffi::RSA_PKCS1_PSS_PADDING_CONST)
            .unwrap_or(false);

    if !is_pss {
        let d = defaults()?;
        let sign = d
            .sign
            .ok_or(EngineError::Other("built-in RSA sign missing".into()))?;
        // SAFETY: delegating the arguments OpenSSL passed us to the built-in.
        if unsafe { sign(ctx, sig, siglen, tbs, tbslen) } != 1 {
            return Err(EngineError::Other("RSA sign failed".into()));
        }
        return Ok(());
    }

    // PSS: the engine signs on the HSM and never falls back to software. A key
    // the engine does not own carries no HSM handle, so it is rejected rather
    // than signed in software (mirroring the PKCS#1 v1.5 RSA_METHOD hook) — the
    // engine's sign path must never produce a software signature.
    if !S::owns(pkey) {
        return Err(EngineError::Other(
            "RSA-PSS signing through the engine requires an HSM-backed key \
             (software RSA signing through the engine is not supported)"
                .into(),
        ));
    }

    // PSS on an HSM key: resolve digest, MGF1, and salt length from the ctx.
    // SAFETY: ctx is a valid signing ctx.
    let md = unsafe { ctrl_get_md(ctx, -1, ffi::EVP_PKEY_CTRL_GET_MD_CONST) };
    if md.is_null() {
        return Err(EngineError::Other(
            "RSA-PSS signing requires a signature digest".into(),
        ));
    }
    // SAFETY: md is a valid EVP_MD returned by the getter.
    let md_nid = unsafe { ffi::EVP_MD_type(md) };
    // MGF1 must equal the signing digest: the SDK's PSS encoder (RsaPadPssAlgo)
    // uses one hash for both the message digest and MGF1. On a valid PSS ctx the
    // getter always reports a non-null digest (the explicit MGF1, or the signing
    // md when unset), so a NULL means the getter failed — fail closed rather than
    // silently signing with a different MGF1.
    // SAFETY: ctx is valid.
    let mgf1 = unsafe {
        ctrl_get_md(
            ctx,
            ffi::EVP_PKEY_RSA as c_int,
            ffi::EVP_PKEY_CTRL_GET_RSA_MGF1_MD_CONST,
        )
    };
    if mgf1.is_null() {
        return Err(EngineError::Other(
            "could not read the RSA-PSS MGF1 digest".into(),
        ));
    }
    // SAFETY: mgf1 is a valid EVP_MD (checked non-null).
    if unsafe { ffi::EVP_MD_type(mgf1) } != md_nid {
        return Err(EngineError::Other(
            "RSA-PSS MGF1 digest must equal the signing digest".into(),
        ));
    }
    // SAFETY: md is a valid EVP_MD; the size is non-negative.
    let md_size = usize::try_from(unsafe { ffi::EVP_MD_size(md) })
        .map_err(|_| EngineError::Other("negative digest size".into()))?;
    // The pre-computed digest must be non-null (a null pointer with any length is
    // undefined behavior for slice::from_raw_parts) and its length must match the
    // signature digest, as the built-in pkey_rsa_sign enforces — reject a null or
    // mismatched pre-hashed input cleanly rather than forwarding it to the HSM.
    if tbs.is_null() {
        return Err(EngineError::NullParam("tbs"));
    }
    if tbslen != md_size {
        return Err(EngineError::Other(format!(
            "digest length ({tbslen}) does not match the signature digest ({md_size})"
        )));
    }
    // Modulus size, and the maximum PSS salt (modulus − digest − 2) the provider
    // uses for saltlen:max.
    // SAFETY: pkey is a valid RSA key (owned, checked).
    let cap = usize::try_from(unsafe { ffi::EVP_PKEY_size(pkey) })
        .map_err(|_| EngineError::Other("negative EVP_PKEY_size".into()))?;
    // Validate the output descriptor BEFORE the HSM private-key operation so a
    // null or undersized buffer does not consume a signing op. AUTOARGLEN already
    // makes EVP_PKEY_sign reject *siglen < EVP_PKEY_size before dispatch; this
    // check makes the copy locally sound regardless of that flag.
    if siglen.is_null() {
        return Err(EngineError::NullParam("siglen"));
    }
    // SAFETY: siglen is non-null (checked); it holds the caller's buffer capacity.
    let buf_cap = unsafe { *siglen };
    if buf_cap < cap {
        return Err(EngineError::Other(format!(
            "output buffer too small for RSA-PSS signature ({buf_cap} < {cap})"
        )));
    }
    let max_salt = cap
        .checked_sub(md_size)
        .and_then(|v| v.checked_sub(2))
        .ok_or(EngineError::Other("RSA modulus too small for PSS".into()))?;
    // Salt length from the caller's explicitly-set value (recorded in c_ctrl):
    // an unset context defaults to the digest length (the provider's default),
    // while an explicit value — including `auto`, which is rejected — is resolved.
    let explicit_salt = ctx_state()
        .lock()
        .get(&(ctx as usize))
        .and_then(|s| s.pss_saltlen);
    let salt_len = match explicit_salt {
        None => md_size,
        Some(v) => resolve_salt_len(v, md_size, max_salt)?,
    };

    // SAFETY: tbs is valid for tbslen bytes per the sign contract.
    let digest = unsafe { std::slice::from_raw_parts(tbs, tbslen) };
    let out = S::pss_sign(pkey, md_nid, salt_len, digest)?;

    // A PSS signature is exactly the modulus size (== cap, already validated to
    // fit the buffer); a shorter vector would be malformed.
    if out.len() != cap {
        return Err(EngineError::Other(format!(
            "RSA-PSS signature is {} bytes, expected modulus size ({cap})",
            out.len()
        )));
    }
    // SAFETY: sig is non-null (PSS path requires it) and valid for buf_cap >= cap
    // == out.len() bytes; siglen is writable (checked non-null).
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), sig, out.len());
        *siglen = out.len();
    }
    Ok(())
}

/// Build the RSA `EVP_PKEY_METHOD`: a copy of the built-in with
/// `init`/`copy`/`cleanup`/`ctrl_str`/`keygen`/`sign` overridden. Never freed by
/// us — the engine framework owns registered copies.
#[allow(unsafe_code)]
pub fn new_rsa_pkey_method<H: RsaImportHandler, S: RsaPssSignHandler>()
-> EngineResult<*mut ffi::EVP_PKEY_METHOD> {
    // SAFETY: EVP_PKEY_meth_find returns the built-in const method.
    let builtin = unsafe { ffi::EVP_PKEY_meth_find(ffi::EVP_PKEY_RSA as c_int) };
    if builtin.is_null() {
        return Err(EngineError::Other(
            "built-in RSA pkey method missing".into(),
        ));
    }

    let mut d = Defaults::default();
    let mut keygen_init = None;
    let mut sign_init = None;
    let mut ctrl_dummy = None;
    // SAFETY: builtin is a valid method; the getters write the out-params.
    unsafe {
        ffi::EVP_PKEY_meth_get_init(builtin, &mut d.init);
        ffi::EVP_PKEY_meth_get_copy(builtin, &mut d.copy);
        ffi::EVP_PKEY_meth_get_cleanup(builtin, &mut d.cleanup);
        ffi::EVP_PKEY_meth_get_keygen(builtin, &mut keygen_init, &mut d.keygen);
        ffi::EVP_PKEY_meth_get_sign(builtin, &mut sign_init, &mut d.sign);
        ffi::EVP_PKEY_meth_get_ctrl(builtin, &mut ctrl_dummy, &mut d.ctrl_str);
    }
    d.ctrl = ctrl_dummy;
    let _ = DEFAULTS.set(d);

    // Create with EVP_PKEY_FLAG_AUTOARGLEN: EVP_PKEY_meth_copy copies the
    // callbacks but not the flags, and the inherited built-in encrypt/decrypt/
    // sign ops rely on it to short-circuit the out==NULL size query. Without it
    // that query reaches e.g. pkey_rsa_encrypt with a NULL buffer and segfaults
    // (hit once the engine is the process default, e.g. the import's RSA wrap).
    // SAFETY: fresh method; meth_copy duplicates the built-in callbacks; the
    // setters install our overrides (keeping the built-in keygen_init).
    unsafe {
        let method = ffi::EVP_PKEY_meth_new(
            ffi::EVP_PKEY_RSA as c_int,
            ffi::EVP_PKEY_FLAG_AUTOARGLEN_CONST,
        );
        if method.is_null() {
            return Err(EngineError::Other("EVP_PKEY_meth_new failed".into()));
        }
        ffi::EVP_PKEY_meth_copy(method, builtin);
        ffi::EVP_PKEY_meth_set_init(method, Some(c_init));
        ffi::EVP_PKEY_meth_set_copy(method, Some(c_copy));
        ffi::EVP_PKEY_meth_set_cleanup(method, Some(c_cleanup));
        ffi::EVP_PKEY_meth_set_keygen(method, keygen_init, Some(c_keygen::<H>));
        ffi::EVP_PKEY_meth_set_sign(method, sign_init, Some(c_sign::<S>));
        ffi::EVP_PKEY_meth_set_ctrl(method, Some(c_ctrl), Some(c_ctrl_str));
        Ok(method)
    }
}

/// Register `H` as `engine`'s RSA import handler in the shared pkey-method
/// table. Only one handler type can be registered per process (the first
/// wins). Released together with the EC/HKDF methods via
/// [`release_pkey_methods`](crate::pkey_method::release_pkey_methods).
pub fn register_rsa_pkey_method<H: RsaImportHandler, S: RsaPssSignHandler>(
    engine: &Engine,
) -> EngineResult<()> {
    ENGINE_METHODS.register(
        engine,
        ffi::EVP_PKEY_RSA as c_int,
        new_rsa_pkey_method::<H, S>,
    )?;
    crate::pkey_method::install_pkey_meths_callback(engine)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ffi::CString;
    use std::ptr::null_mut;

    use super::*;

    /// Import/PSS-sign must never dispatch in these parsing/recording tests.
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
    impl RsaPssSignHandler for PanicImport {
        fn owns(_pkey: *const ffi::EVP_PKEY) -> bool {
            false
        }
        fn pss_sign(
            _pkey: *const ffi::EVP_PKEY,
            _md_nid: c_int,
            _salt_len: usize,
            _m: &[u8],
        ) -> EngineResult<Vec<u8>> {
            unreachable!("pss_sign must not be dispatched for this context")
        }
    }

    #[test]
    fn resolve_salt_len_maps_digest_max_explicit_and_rejects_auto() {
        // DIGEST (-1) resolves to the digest length; MAX (-3) to the max salt.
        assert_eq!(
            resolve_salt_len(RSA_PSS_SALTLEN_DIGEST, 32, 222).unwrap(),
            32
        );
        assert_eq!(resolve_salt_len(RSA_PSS_SALTLEN_MAX, 32, 222).unwrap(), 222);
        // An explicit non-negative length is used as-is.
        assert_eq!(resolve_salt_len(20, 32, 222).unwrap(), 20);
        assert_eq!(resolve_salt_len(0, 32, 222).unwrap(), 0);
        // An explicit AUTO (-2) is rejected, matching the provider.
        assert!(resolve_salt_len(RSA_PSS_SALTLEN_AUTO, 32, 222).is_err());
        // Any other sentinel is rejected.
        assert!(resolve_salt_len(-99, 32, 222).is_err());
    }

    #[test]
    #[allow(unsafe_code)]
    fn method_installs_sign_slot() {
        let method = new_rsa_pkey_method::<PanicImport, PanicImport>().unwrap();
        let mut sign = None;
        let mut sign_init = None;
        // SAFETY: method is our fresh method; the getter writes the out-params.
        unsafe { ffi::EVP_PKEY_meth_get_sign(method, &mut sign_init, &mut sign) };
        assert!(sign.is_some(), "sign slot must be installed");
        // SAFETY: method is ours and unregistered.
        unsafe { ffi::EVP_PKEY_meth_free(method) };
    }

    /// Capture DEFAULTS (the method itself is left unregistered), then a built-in
    /// `EVP_PKEY_RSA` keygen ctx with a hand-inserted state entry — the
    /// trampolines run against it directly, no HSM involved.
    #[allow(unsafe_code)]
    fn make_ctx() -> *mut ffi::EVP_PKEY_CTX {
        let method = new_rsa_pkey_method::<PanicImport, PanicImport>().unwrap();
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

    // The method must carry EVP_PKEY_FLAG_AUTOARGLEN (dropped by
    // EVP_PKEY_meth_copy) so the out==NULL size query is short-circuited instead
    // of segfaulting in the inherited built-in ops.
    #[test]
    #[allow(unsafe_code)]
    fn method_advertises_autoarglen() {
        let method = new_rsa_pkey_method::<PanicImport, PanicImport>().unwrap();
        let mut flags: c_int = 0;
        // SAFETY: method is our fresh method; the getter writes the out-params
        // (NULL for the ones we don't want).
        unsafe { ffi::EVP_PKEY_meth_get0_info(null_mut(), &mut flags, method) };
        assert_ne!(
            flags & ffi::EVP_PKEY_FLAG_AUTOARGLEN_CONST,
            0,
            "RSA pkey method must carry EVP_PKEY_FLAG_AUTOARGLEN"
        );
        // SAFETY: method is ours and unregistered.
        unsafe { ffi::EVP_PKEY_meth_free(method) };
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
