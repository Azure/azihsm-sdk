// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Engine-supplied AES-CBC `EVP_CIPHER`s for HSM-backed keys.
//!
//! OpenSSL 1.1.x has no opaque symmetric keys, so an HSM AES key is attached
//! to a cipher context with [`AZIHSM_CTRL_SET_KEY_URI`] (usage in
//! `inc/azihsm_ossl_engine.h`). The last key set wins: an attached key stays
//! across inits that keep the cipher until a raw-key init or another attach
//! replaces it.
//!
//! Each cipher is a copy of the built-in AES-CBC cipher with
//! `init`/`do_cipher`/`ctrl`/`cleanup` overridden. An attached key runs raw
//! CBC on the HSM while the EVP layer still buffers and pads; a raw key runs
//! the built-in unchanged, so the engine stays usable as the process default.
//! The key lives in a side table keyed by the context address. The framework
//! never frees engine ciphers: [`release_aes_cbc_ciphers`] does, from the
//! destroy hook.

use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_ulong;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::OnceLock;

use azihsm_ossl_engine_sys as ffi;
use parking_lot::Mutex;
use zeroize::Zeroizing;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::RetCode;
use crate::error::catch_panic;
use crate::error::ossl_check;
use crate::error::result_to_int;

/// `EVP_CIPHER_CTX_ctrl` type that attaches an HSM AES key to an AES-CBC
/// context: `ptr` is a NUL-terminated `azihsm://<masked-key-file>;type=aes`
/// URI and `arg` must be 0. "AZ" (0x415A) in the high half keeps it clear of
/// OpenSSL's own `EVP_CTRL_*` values.
pub const AZIHSM_CTRL_SET_KEY_URI: c_int = 0x415A_0001;

/// AES block (and CBC IV) size in bytes.
pub const AES_BLOCK: usize = 16;

/// Most bytes one [`AesCbcKey::cbc`] call gets: the device's per-request AES
/// limit, so a retried request restarts from its own IV. Also bounds the input
/// copy.
pub const HSM_CBC_REQUEST: usize = 1024;

/// `ctrl` return for a control type the cipher does not implement
/// (`EVP_CIPHER_CTX_ctrl` reports it as a failure).
const CTRL_NOT_IMPLEMENTED: c_int = -1;

/// An HSM AES key attached to a cipher context (and its copies). Dropping the
/// last reference releases the key.
pub trait AesCbcKey: Send + Sync {
    /// Raw AES-CBC (no padding) over `input` (whole blocks, at most
    /// [`HSM_CBC_REQUEST`] bytes) into `output` (same length). `iv` is the
    /// chaining value, updated in place to the one the next call continues
    /// from.
    fn cbc(
        &self,
        encrypt: bool,
        iv: &mut [u8; AES_BLOCK],
        input: &[u8],
        output: &mut [u8],
    ) -> EngineResult<()>;
}

/// Caller-supplied loader for [`AZIHSM_CTRL_SET_KEY_URI`]. Implement on a
/// marker type and pass it to [`register_aes_cbc_ciphers`].
pub trait AesCbcKeyLoader {
    /// Load the AES key named by `uri` for a cipher of `key_bits`; a key of any
    /// other size is an error. `engine` is the ENGINE the cipher belongs to.
    fn load_key(engine: &Engine, uri: &str, key_bits: u32) -> EngineResult<Arc<dyn AesCbcKey>>;
}

/// The key a context runs with.
#[derive(Clone)]
enum CtxKey {
    /// A raw key, set up by the built-in init: the built-in cipher runs.
    Software,
    /// An HSM key attached with [`AZIHSM_CTRL_SET_KEY_URI`].
    Hsm(Arc<dyn AesCbcKey>),
}

/// Side table: `EVP_CIPHER_CTX` address → its key. Entries are created by
/// init/ctrl and dropped by cleanup.
static CTX_KEYS: OnceLock<Mutex<HashMap<usize, CtxKey>>> = OnceLock::new();

/// The context key table, created on first use.
fn ctx_keys() -> &'static Mutex<HashMap<usize, CtxKey>> {
    CTX_KEYS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The NIDs these ciphers serve.
static NIDS: [c_int; 3] = [
    ffi::NID_aes_128_cbc as c_int,
    ffi::NID_aes_192_cbc as c_int,
    ffi::NID_aes_256_cbc as c_int,
];

/// One of our cipher copies.
#[derive(Clone, Copy)]
struct CipherEntry {
    /// The ENGINE that owns it.
    engine: usize,
    /// The cipher's NID.
    nid: c_int,
}

/// Cipher table: our `EVP_CIPHER` address → its entry.
static CIPHERS: OnceLock<Mutex<HashMap<usize, CipherEntry>>> = OnceLock::new();

/// The cipher table, created on first use.
fn ciphers() -> &'static Mutex<HashMap<usize, CipherEntry>> {
    CIPHERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The built-in AES-CBC cipher for `nid`, which our copy for `nid` delegates
/// to. Resolved without a lock: it runs for every AES-CBC operation in the
/// process when the engine is the default.
#[allow(unsafe_code)]
fn builtin_cipher(nid: c_int) -> EngineResult<*const ffi::EVP_CIPHER> {
    let accessor: unsafe extern "C" fn() -> *const ffi::EVP_CIPHER = match u32::try_from(nid) {
        Ok(ffi::NID_aes_128_cbc) => ffi::EVP_aes_128_cbc,
        Ok(ffi::NID_aes_192_cbc) => ffi::EVP_aes_192_cbc,
        Ok(ffi::NID_aes_256_cbc) => ffi::EVP_aes_256_cbc,
        _ => return Err(EngineError::Other(format!("not an AES-CBC NID: {nid}"))),
    };
    // SAFETY: the EVP_aes_*_cbc accessors return process-lifetime constants.
    let cipher = unsafe { accessor() };
    if cipher.is_null() {
        return Err(EngineError::Other(format!(
            "built-in AES-CBC {nid} missing"
        )));
    }
    Ok(cipher)
}

/// The built-in cipher behind the context `ctx` (see [`builtin_cipher`]).
#[allow(unsafe_code)]
fn builtin_for(ctx: *const ffi::EVP_CIPHER_CTX) -> EngineResult<*const ffi::EVP_CIPHER> {
    // SAFETY: ctx is the live context OpenSSL passed a callback; the getter
    // only reads its cipher's NID.
    builtin_cipher(unsafe { ffi::EVP_CIPHER_CTX_nid(ctx) })
}

/// `init` override: set up a raw key with the built-in init.
///
/// # Safety
/// Called only by `EVP_CipherInit_ex`; arguments per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_init(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    key: *const c_uchar,
    iv: *const c_uchar,
    enc: c_int,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the arguments OpenSSL passed us.
        || result_to_int(unsafe { init_inner(ctx, key, iv, enc) }),
        0,
    )
}

/// Run the built-in init with the raw `key`; it replaces an attached HSM key
/// (the last key set wins).
///
/// # Safety
/// As [`c_init`].
#[allow(unsafe_code)]
unsafe fn init_inner(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    key: *const c_uchar,
    iv: *const c_uchar,
    enc: c_int,
) -> EngineResult<()> {
    // OpenSSL calls init only with a key (the ciphers do not set
    // EVP_CIPH_ALWAYS_CALL_INIT).
    if key.is_null() {
        return Err(EngineError::NullParam("cipher key"));
    }
    // SAFETY: builtin_for returns a valid built-in cipher.
    let init = unsafe { ffi::EVP_CIPHER_meth_get_init(builtin_for(ctx)?) }
        .ok_or(EngineError::Other("built-in AES-CBC init missing".into()))?;
    // SAFETY: delegating the arguments OpenSSL passed us to the built-in, whose
    // cipher data layout our copy shares.
    let rc = unsafe { init(ctx, key, iv, enc) };
    ossl_check(rc, EngineError::Other("AES key setup failed".into()))?;
    // A replaced HSM key is released outside the lock.
    let replaced = ctx_keys().lock().insert(ctx as usize, CtxKey::Software);
    drop(replaced);
    Ok(())
}

/// `do_cipher` override: the HSM for an attached key, the built-in for a raw
/// one, an error for neither.
///
/// # Safety
/// Called only by the EVP update/final functions; `out`/`input` hold `inl`
/// bytes (whole blocks for this non-custom cipher) and are either the same
/// buffer or disjoint.
#[allow(unsafe_code)]
unsafe extern "C" fn c_do_cipher(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the arguments OpenSSL passed us.
        || result_to_int(unsafe { do_cipher_inner(ctx, out, input, inl) }),
        0,
    )
}

/// Dispatch `inl` bytes to the context's key (see [`c_do_cipher`]).
///
/// # Safety
/// As [`c_do_cipher`].
#[allow(unsafe_code)]
unsafe fn do_cipher_inner(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> EngineResult<()> {
    if inl == 0 {
        return Ok(());
    }
    let key = ctx_keys().lock().get(&(ctx as usize)).cloned();
    match key {
        Some(CtxKey::Software) => {
            // SAFETY: builtin_for returns a valid built-in cipher.
            let do_cipher = unsafe { ffi::EVP_CIPHER_meth_get_do_cipher(builtin_for(ctx)?) }
                .ok_or(EngineError::Other("built-in AES-CBC cipher missing".into()))?;
            // SAFETY: delegating the arguments OpenSSL passed us.
            let rc = unsafe { do_cipher(ctx, out, input, inl) };
            ossl_check(rc, EngineError::Other("AES-CBC failed".into()))
        }
        // SAFETY: as this function's contract.
        Some(CtxKey::Hsm(key)) => unsafe { hsm_cbc(ctx, key.as_ref(), out, input, inl) },
        None => Err(EngineError::Other(
            "no key set on this AES-CBC context (attach an HSM key with \
             AZIHSM_CTRL_SET_KEY_URI or initialize it with a key)"
                .into(),
        )),
    }
}

/// Run `inl` bytes through the HSM key, one [`HSM_CBC_REQUEST`]-sized request
/// at a time, chaining the IV through the context's IV buffer as the built-in
/// does. The IV is written back only once every request succeeded.
///
/// # Safety
/// As [`c_do_cipher`].
#[allow(unsafe_code)]
unsafe fn hsm_cbc(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    key: &dyn AesCbcKey,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> EngineResult<()> {
    if out.is_null() || input.is_null() {
        return Err(EngineError::NullParam("cipher buffer"));
    }
    if !inl.is_multiple_of(AES_BLOCK) {
        return Err(EngineError::Other(format!(
            "AES-CBC input of {inl} bytes is not whole blocks"
        )));
    }
    // SAFETY: ctx is the live context; a CBC context's IV buffer holds one
    // block.
    let (encrypt, ivp) = unsafe {
        (
            ffi::EVP_CIPHER_CTX_encrypting(ctx) != 0,
            ffi::EVP_CIPHER_CTX_iv_noconst(ctx),
        )
    };
    if ivp.is_null() {
        return Err(EngineError::NullParam("cipher IV"));
    }
    // SAFETY: ivp holds AES_BLOCK bytes (see above); this reads a copy.
    let mut iv = unsafe { ivp.cast::<[u8; AES_BLOCK]>().read_unaligned() };
    // Each request's input is copied before its output is written, as OpenSSL
    // may run in place (out == input). It may be plaintext, so the copy is
    // scrubbed on drop.
    let mut request = Zeroizing::new([0u8; HSM_CBC_REQUEST]);
    for start in (0..inl).step_by(HSM_CBC_REQUEST) {
        let len = HSM_CBC_REQUEST.min(inl.saturating_sub(start));
        let data = &mut request[..len];
        // SAFETY: input and out hold inl bytes and start + len <= inl; the
        // input slice is gone before the output slice over the same request
        // (when in place) is created.
        let output = unsafe {
            data.copy_from_slice(std::slice::from_raw_parts(input.add(start), len));
            std::slice::from_raw_parts_mut(out.add(start), len)
        };
        key.cbc(encrypt, &mut iv, data, output)?;
    }
    // SAFETY: as for the read above.
    unsafe { std::ptr::copy_nonoverlapping(iv.as_ptr(), ivp, AES_BLOCK) };
    Ok(())
}

/// `ctrl` override: [`AZIHSM_CTRL_SET_KEY_URI`] attaches an HSM key, the copy
/// control duplicates a context's key, anything else goes to the built-in.
///
/// # Safety
/// Called only by `EVP_CIPHER_CTX_ctrl`/`EVP_CIPHER_CTX_copy`; arguments per
/// that contract (for the key URI: `ptr` is NULL or a NUL-terminated string).
#[allow(unsafe_code)]
unsafe extern "C" fn c_ctrl<L: AesCbcKeyLoader>(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    typ: c_int,
    arg: c_int,
    ptr: *mut c_void,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the arguments OpenSSL passed us.
        || match unsafe { ctrl_inner::<L>(ctx, typ, arg, ptr) } {
            Ok(rc) => rc,
            Err(e) => result_to_int::<()>(Err(e)),
        },
        0,
    )
}

/// Handle one control (see [`c_ctrl`]), returning the `ctrl` result.
///
/// # Safety
/// As [`c_ctrl`].
#[allow(unsafe_code)]
unsafe fn ctrl_inner<L: AesCbcKeyLoader>(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    typ: c_int,
    arg: c_int,
    ptr: *mut c_void,
) -> EngineResult<c_int> {
    if typ == AZIHSM_CTRL_SET_KEY_URI {
        // SAFETY: as this function's contract.
        unsafe { attach_key::<L>(ctx, arg, ptr) }?;
        return Ok(RetCode::Success.into());
    }
    let copy = typ == ffi::EVP_CTRL_COPY as c_int;
    // SAFETY: builtin_for returns a valid built-in cipher.
    let rc = match unsafe { ffi::EVP_CIPHER_meth_get_ctrl(builtin_for(ctx)?) } {
        // SAFETY: delegating the arguments OpenSSL passed us.
        Some(ctrl) => unsafe { ctrl(ctx, typ, arg, ptr) },
        // The copy needs nothing from the built-in; anything else is
        // unsupported.
        None if copy => RetCode::Success.into(),
        None => CTRL_NOT_IMPLEMENTED,
    };
    // Only a successful copy shares the key: a failed one leaves the copy
    // without a cipher, so its cleanup would never drop an entry.
    if copy && rc == RetCode::Success as c_int {
        copy_key(ctx, ptr.cast())?;
    }
    Ok(rc)
}

/// [`AZIHSM_CTRL_SET_KEY_URI`]: load the key `ptr` names for this cipher's
/// size and attach it to `ctx`, replacing a raw key (whose schedule is wiped)
/// or an attached key. A failed attach leaves the context unchanged.
///
/// # Safety
/// `ctx` is a live context of one of our ciphers; `ptr` is NULL or a
/// NUL-terminated string.
#[allow(unsafe_code)]
unsafe fn attach_key<L: AesCbcKeyLoader>(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    arg: c_int,
    ptr: *mut c_void,
) -> EngineResult<()> {
    if arg != 0 {
        return Err(EngineError::Other(format!(
            "AZIHSM_CTRL_SET_KEY_URI takes arg 0, got {arg}"
        )));
    }
    if ptr.is_null() {
        return Err(EngineError::NullParam("key URI"));
    }
    // SAFETY: ptr is a NUL-terminated string per this control's contract.
    let uri = unsafe { CStr::from_ptr(ptr.cast::<c_char>()) }
        .to_str()
        .map_err(|_| EngineError::Other("key URI is not valid UTF-8".into()))?;
    // SAFETY: ctx is the live context; the getter only reads its cipher.
    let cipher = unsafe { ffi::EVP_CIPHER_CTX_cipher(ctx) };
    let entry = ciphers()
        .lock()
        .get(&(cipher as usize))
        .copied()
        .ok_or(EngineError::Other(
            "cipher context is not an azihsm AES-CBC context".into(),
        ))?;
    let engine_ptr = NonNull::new(entry.engine as *mut ffi::ENGINE)
        .ok_or(EngineError::Other("cipher has no ENGINE".into()))?;
    // SAFETY: the ENGINE owns this cipher and outlives every context that uses
    // it (see the module docs).
    let engine = unsafe { Engine::from_ptr(engine_ptr) };
    // SAFETY: ctx is the live context.
    let key_len = unsafe { ffi::EVP_CIPHER_CTX_key_length(ctx) };
    let key_bits = u32::try_from(key_len)
        .ok()
        .and_then(|bytes| bytes.checked_mul(u8::BITS))
        .ok_or(EngineError::Other("invalid cipher key length".into()))?;
    let key = L::load_key(&engine, uri, key_bits)?;
    // SAFETY: ctx is the live context.
    unsafe { wipe_cipher_data(ctx) };
    // A replaced key is released outside the lock.
    let replaced = ctx_keys().lock().insert(ctx as usize, CtxKey::Hsm(key));
    drop(replaced);
    Ok(())
}

/// Scrub the built-in's cipher data (a raw key's schedule) before an HSM key
/// takes over the context.
///
/// # Safety
/// `ctx` is a live cipher context.
#[allow(unsafe_code)]
unsafe fn wipe_cipher_data(ctx: *mut ffi::EVP_CIPHER_CTX) {
    // SAFETY: ctx is live; its cipher data, when present, is the cipher's
    // ctx_size bytes.
    unsafe {
        let data = ffi::EVP_CIPHER_CTX_get_cipher_data(ctx);
        let size = ffi::EVP_CIPHER_impl_ctx_size(ffi::EVP_CIPHER_CTX_cipher(ctx));
        if !data.is_null()
            && let Ok(size) = usize::try_from(size)
        {
            ffi::OPENSSL_cleanse(data, size);
        }
    }
}

/// `EVP_CTRL_COPY`: give the copy `out` the key of `ctx`.
fn copy_key(ctx: *mut ffi::EVP_CIPHER_CTX, out: *mut ffi::EVP_CIPHER_CTX) -> EngineResult<()> {
    if out.is_null() {
        return Err(EngineError::NullParam("copy destination"));
    }
    let key = ctx_keys().lock().get(&(ctx as usize)).cloned();
    if let Some(key) = key {
        // The copy was reset first, so nothing should be replaced; whatever is
        // gets released outside the lock.
        let replaced = ctx_keys().lock().insert(out as usize, key);
        drop(replaced);
    }
    Ok(())
}

/// `cleanup` override: drop the context's key, then the built-in cleanup.
///
/// # Safety
/// Called only by `EVP_CIPHER_CTX_reset`; `ctx` is the context being reset.
#[allow(unsafe_code)]
unsafe extern "C" fn c_cleanup(ctx: *mut ffi::EVP_CIPHER_CTX) -> c_int {
    catch_panic(
        || {
            // Released outside the lock: deleting an HSM key is a device call.
            let key = ctx_keys().lock().remove(&(ctx as usize));
            drop(key);
            let cleanup = builtin_for(ctx).ok().and_then(|builtin| {
                // SAFETY: builtin_for returns a valid built-in cipher.
                unsafe { ffi::EVP_CIPHER_meth_get_cleanup(builtin) }
            });
            match cleanup {
                // SAFETY: delegating the context OpenSSL passed us.
                Some(cleanup) => unsafe { cleanup(ctx) },
                None => RetCode::Success.into(),
            }
        },
        // A failed cleanup stops EVP_CIPHER_CTX_reset before it frees the
        // cipher data and the ENGINE reference.
        RetCode::Success.into(),
    )
}

/// Build our copy of the built-in `builtin` cipher (same sizes, flags and
/// ASN.1 handlers) with our overrides and `EVP_CIPH_CUSTOM_COPY` installed.
#[allow(unsafe_code)]
fn new_cipher<L: AesCbcKeyLoader>(
    builtin: *const ffi::EVP_CIPHER,
) -> EngineResult<*mut ffi::EVP_CIPHER> {
    // SAFETY: builtin is a valid built-in cipher; meth_dup copies every field.
    let cipher = unsafe { ffi::EVP_CIPHER_meth_dup(builtin) };
    if cipher.is_null() {
        return Err(EngineError::Other("EVP_CIPHER_meth_dup failed".into()));
    }
    // SAFETY: cipher is our fresh copy; the callbacks are 'static fn items with
    // the EVP_CIPHER method signatures.
    let rcs = unsafe {
        let flags = ffi::EVP_CIPHER_flags(builtin) | ffi::EVP_CIPH_CUSTOM_COPY as c_ulong;
        [
            ffi::EVP_CIPHER_meth_set_flags(cipher, flags),
            ffi::EVP_CIPHER_meth_set_init(cipher, Some(c_init)),
            ffi::EVP_CIPHER_meth_set_do_cipher(cipher, Some(c_do_cipher)),
            ffi::EVP_CIPHER_meth_set_ctrl(cipher, Some(c_ctrl::<L>)),
            ffi::EVP_CIPHER_meth_set_cleanup(cipher, Some(c_cleanup)),
        ]
    };
    let set = rcs.into_iter().try_for_each(|rc| {
        ossl_check(
            rc,
            EngineError::Other("EVP_CIPHER_meth_set_* failed".into()),
        )
    });
    if let Err(e) = set {
        // SAFETY: cipher is our unpublished copy.
        unsafe { ffi::EVP_CIPHER_meth_free(cipher) };
        return Err(e);
    }
    Ok(cipher)
}

/// `ENGINE_CIPHERS_PTR` callback: NID enumeration and per-ENGINE lookup.
///
/// # Safety
/// Called only by OpenSSL's engine cipher lookup; out-params per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_ciphers(
    e: *mut ffi::ENGINE,
    cipher: *mut *const ffi::EVP_CIPHER,
    nids: *mut *const c_int,
    nid: c_int,
) -> c_int {
    catch_panic(
        || {
            if cipher.is_null() {
                if !nids.is_null() {
                    // SAFETY: nids is a valid out-param when non-null.
                    unsafe { *nids = NIDS.as_ptr() };
                }
                return c_int::try_from(NIDS.len()).unwrap_or(0);
            }
            let found = ciphers()
                .lock()
                .iter()
                .find(|(_, v)| v.engine == e as usize && v.nid == nid)
                .map(|(k, _)| *k);
            // SAFETY: cipher is a valid out-param (checked non-null).
            unsafe { *cipher = found.map_or(std::ptr::null(), |c| c as *const ffi::EVP_CIPHER) };
            if found.is_some() {
                RetCode::Success.into()
            } else {
                RetCode::Fail.into()
            }
        },
        0,
    )
}

/// Create `engine`'s AES-128/192/256-CBC ciphers with `L` loading HSM keys,
/// and install them with `ENGINE_set_ciphers`. Pair with
/// [`release_aes_cbc_ciphers`] in the engine's destroy hook. A second
/// registration on the same ENGINE is refused: its contexts may still use the
/// first one's ciphers.
#[allow(unsafe_code)]
pub fn register_aes_cbc_ciphers<L: AesCbcKeyLoader>(engine: &Engine) -> EngineResult<()> {
    let e = engine.as_ptr() as usize;
    if ciphers().lock().values().any(|v| v.engine == e) {
        return Err(EngineError::Other(
            "AES-CBC ciphers are already registered on this ENGINE".into(),
        ));
    }
    for nid in NIDS {
        let cipher = new_cipher::<L>(builtin_cipher(nid)?)?;
        ciphers().lock().insert(
            cipher as usize,
            CipherEntry {
                engine: engine.as_ptr() as usize,
                nid,
            },
        );
    }
    // SAFETY: engine's ptr is valid (from NonNull); c_ciphers is a 'static fn
    // item with the ENGINE_CIPHERS_PTR signature.
    let rc = unsafe { ffi::ENGINE_set_ciphers(engine.as_ptr(), Some(c_ciphers)) };
    ossl_check(rc, EngineError::Other("ENGINE_set_ciphers failed".into()))
}

/// Free `engine`'s cipher copies; the framework never frees engine ciphers.
///
/// # Safety
/// No cipher context may still use them: call from the engine's destroy hook,
/// which runs once every context's functional reference on the ENGINE is gone
/// (or, in tests, once their contexts are freed).
#[allow(unsafe_code)]
pub unsafe fn release_aes_cbc_ciphers(engine: &Engine) {
    let e = engine.as_ptr() as usize;
    let mut table = ciphers().lock();
    let mine: Vec<usize> = table
        .iter()
        .filter(|(_, v)| v.engine == e)
        .map(|(k, _)| *k)
        .collect();
    for cipher in mine {
        table.remove(&cipher);
        // SAFETY: cipher is our own EVP_CIPHER_meth_dup copy, no longer listed;
        // no context still uses it (this function's contract).
        unsafe { ffi::EVP_CIPHER_meth_free(cipher as *mut ffi::EVP_CIPHER) };
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;
    use std::ffi::CString;
    use std::ptr::null;
    use std::ptr::null_mut;

    use super::*;

    thread_local! {
        /// Keys released (dropped) on this test thread.
        static RELEASED: Cell<usize> = const { Cell::new(0) };
        /// The key size the loader was last asked for on this thread.
        static LAST_BITS: Cell<u32> = const { Cell::new(0) };
        /// The longest input one `cbc` call got on this thread.
        static LONGEST_INPUT: Cell<usize> = const { Cell::new(0) };
    }

    /// OpenSSL's success return code.
    const OK: c_int = RetCode::Success as c_int;

    /// The URI [`ToyLoader`] knows; any other is an unknown key.
    const TOY_URI: &str = "toy";

    /// CBC with an identity block cipher: enough to check the dispatch, the
    /// chaining and the EVP layer's padding without an HSM.
    fn toy_cbc(encrypt: bool, iv: &mut [u8; AES_BLOCK], input: &[u8], output: &mut [u8]) {
        for (block, out) in input.chunks(AES_BLOCK).zip(output.chunks_mut(AES_BLOCK)) {
            for ((o, b), v) in out.iter_mut().zip(block).zip(iv.iter()) {
                *o = b ^ v;
            }
            iv.copy_from_slice(if encrypt { &out[..] } else { block });
        }
    }

    /// The toy encryption of `msg` under `iv`, PKCS#7-padded as by EVP.
    fn toy_encrypt(iv: &[u8; AES_BLOCK], msg: &[u8]) -> Vec<u8> {
        let padded_len = msg.len().saturating_add(1).next_multiple_of(AES_BLOCK);
        let pad = u8::try_from(padded_len.saturating_sub(msg.len())).unwrap();
        let mut padded = msg.to_vec();
        padded.resize(padded_len, pad);
        let mut out = vec![0u8; padded_len];
        toy_cbc(true, &mut iv.clone(), &padded, &mut out);
        out
    }

    /// `len` bytes of a repeating 0..=255 pattern.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i & usize::from(u8::MAX)).unwrap())
            .collect()
    }

    /// A key running [`toy_cbc`] that records its input sizes and release.
    struct ToyKey;

    impl Drop for ToyKey {
        fn drop(&mut self) {
            RELEASED.with(|c| c.set(c.get().saturating_add(1)));
        }
    }

    impl AesCbcKey for ToyKey {
        fn cbc(
            &self,
            encrypt: bool,
            iv: &mut [u8; AES_BLOCK],
            input: &[u8],
            output: &mut [u8],
        ) -> EngineResult<()> {
            LONGEST_INPUT.with(|c| c.set(c.get().max(input.len())));
            toy_cbc(encrypt, iv, input, output);
            Ok(())
        }
    }

    /// Loads a [`ToyKey`] for [`TOY_URI`], recording the size asked for.
    struct ToyLoader;

    impl AesCbcKeyLoader for ToyLoader {
        fn load_key(
            _engine: &Engine,
            uri: &str,
            key_bits: u32,
        ) -> EngineResult<Arc<dyn AesCbcKey>> {
            LAST_BITS.with(|c| c.set(key_bits));
            if uri != TOY_URI {
                return Err(EngineError::Other(format!("no such key: {uri}")));
            }
            Ok(Arc::new(ToyKey))
        }
    }

    /// A fresh ENGINE with our ciphers registered; free with [`teardown`].
    #[allow(unsafe_code)]
    fn engine_with_ciphers() -> (Engine, *mut ffi::ENGINE) {
        // SAFETY: ENGINE_new returns a fresh structural ref (freed by teardown).
        unsafe {
            let raw = ffi::ENGINE_new();
            assert!(!raw.is_null());
            let engine = Engine::from_ptr(NonNull::new(raw).unwrap());
            register_aes_cbc_ciphers::<ToyLoader>(&engine).unwrap();
            (engine, raw)
        }
    }

    /// Free the ciphers and the ENGINE from [`engine_with_ciphers`], once the
    /// test's contexts are freed.
    #[allow(unsafe_code)]
    fn teardown(engine: &Engine, raw: *mut ffi::ENGINE) {
        // SAFETY: the test freed every context it created; raw is the
        // ENGINE_new ref from engine_with_ciphers.
        unsafe {
            release_aes_cbc_ciphers(engine);
            ffi::ENGINE_free(raw);
            ffi::ERR_clear_error();
        }
    }

    /// The ENGINE `raw`'s cipher for `nid`.
    #[allow(unsafe_code)]
    fn our_cipher(raw: *mut ffi::ENGINE, nid: c_int) -> *const ffi::EVP_CIPHER {
        // SAFETY: raw is a live ENGINE with our cipher callback installed.
        let cipher = unsafe { ffi::ENGINE_get_cipher(raw, nid) };
        assert!(!cipher.is_null());
        cipher
    }

    /// A raw key of the right length for `nid`.
    #[allow(unsafe_code)]
    fn raw_key(nid: c_int) -> Vec<u8> {
        // SAFETY: builtin_cipher returns a valid cipher.
        let len = unsafe { ffi::EVP_CIPHER_key_length(builtin_cipher(nid).unwrap()) };
        vec![7u8; usize::try_from(len).unwrap()]
    }

    /// A fresh cipher context, initialized with `init`; free with [`free`].
    #[allow(unsafe_code)]
    fn new_ctx() -> *mut ffi::EVP_CIPHER_CTX {
        // SAFETY: plain allocation.
        let ctx = unsafe { ffi::EVP_CIPHER_CTX_new() };
        assert!(!ctx.is_null());
        ctx
    }

    /// Free a context from [`new_ctx`].
    #[allow(unsafe_code)]
    fn free(ctx: *mut ffi::EVP_CIPHER_CTX) {
        // SAFETY: ctx is a live context, not used afterwards.
        unsafe { ffi::EVP_CIPHER_CTX_free(ctx) };
    }

    /// `EVP_CipherInit_ex` on `ctx` with `engine` (NULL for a built-in) and
    /// optional key and IV; true on success.
    #[allow(unsafe_code)]
    fn init(
        ctx: *mut ffi::EVP_CIPHER_CTX,
        cipher: *const ffi::EVP_CIPHER,
        engine: *mut ffi::ENGINE,
        key: Option<&[u8]>,
        iv: Option<&[u8]>,
        encrypt: bool,
    ) -> bool {
        let ptr = |bytes: Option<&[u8]>| bytes.map_or(null(), <[u8]>::as_ptr);
        let enc = c_int::from(encrypt);
        // SAFETY: ctx is live; a key or IV holds the cipher's key or IV length.
        unsafe { ffi::EVP_CipherInit_ex(ctx, cipher, engine, ptr(key), ptr(iv), enc) == OK }
    }

    /// [`AZIHSM_CTRL_SET_KEY_URI`] on `ctx` with `uri` (NULL for `None`) and
    /// `arg`; true on success.
    #[allow(unsafe_code)]
    fn attach(ctx: *mut ffi::EVP_CIPHER_CTX, uri: Option<&str>, arg: c_int) -> bool {
        let uri = uri.map(|u| CString::new(u).unwrap());
        let ptr = uri
            .as_ref()
            .map_or(null_mut(), |u| u.as_ptr().cast_mut().cast::<c_void>());
        // SAFETY: ctx is live; ptr is NULL or a NUL-terminated string.
        unsafe { ffi::EVP_CIPHER_CTX_ctrl(ctx, AZIHSM_CTRL_SET_KEY_URI, arg, ptr) == OK }
    }

    /// Feed `data` through `ctx` in `chunk`-byte updates plus the final; `None`
    /// if any step fails.
    #[allow(unsafe_code)]
    fn run(ctx: *mut ffi::EVP_CIPHER_CTX, data: &[u8], chunk: usize) -> Option<Vec<u8>> {
        // Room for every byte plus a block of buffering and a block of padding.
        let mut out = vec![0u8; data.len().saturating_add(AES_BLOCK.saturating_mul(2))];
        let mut total = 0usize;
        let mut n: c_int = 0;
        // SAFETY: standard update/final calls on a live context; out has room
        // for everything they write.
        unsafe {
            for piece in data.chunks(chunk) {
                let len = c_int::try_from(piece.len()).unwrap();
                let rc = ffi::EVP_CipherUpdate(
                    ctx,
                    out[total..].as_mut_ptr(),
                    &mut n,
                    piece.as_ptr(),
                    len,
                );
                if rc != OK {
                    return None;
                }
                total = total.saturating_add(usize::try_from(n).unwrap());
            }
            if ffi::EVP_CipherFinal_ex(ctx, out[total..].as_mut_ptr(), &mut n) != OK {
                return None;
            }
        }
        out.truncate(total.saturating_add(usize::try_from(n).unwrap()));
        Some(out)
    }

    /// One-shot `cipher` (with `engine`, NULL for a built-in) under a raw key.
    fn raw_crypt(
        cipher: *const ffi::EVP_CIPHER,
        engine: *mut ffi::ENGINE,
        key: &[u8],
        iv: &[u8],
        encrypt: bool,
        data: &[u8],
    ) -> Vec<u8> {
        let ctx = new_ctx();
        assert!(init(ctx, cipher, engine, Some(key), Some(iv), encrypt));
        let out = run(ctx, data, 7).unwrap();
        free(ctx);
        out
    }

    /// A fresh context of `raw`'s `nid` cipher with the toy key attached and
    /// `iv` set, per the documented sequence.
    fn hsm_ctx(
        raw: *mut ffi::ENGINE,
        nid: c_int,
        encrypt: bool,
        iv: &[u8; AES_BLOCK],
    ) -> *mut ffi::EVP_CIPHER_CTX {
        let ctx = new_ctx();
        assert!(init(ctx, our_cipher(raw, nid), raw, None, None, encrypt));
        assert!(attach(ctx, Some(TOY_URI), 0));
        assert!(init(ctx, null(), null_mut(), None, Some(iv), encrypt));
        ctx
    }

    // The C header publishes the same control value.
    #[test]
    fn header_matches_ctrl_constant() {
        let header = include_str!("../../inc/azihsm_ossl_engine.h");
        let define = format!("#define AZIHSM_CTRL_SET_KEY_URI 0x{AZIHSM_CTRL_SET_KEY_URI:X}");
        assert!(header.contains(&define), "header must contain `{define}`");
    }

    // Our copies keep the built-ins' sizes and mode and add CUSTOM_COPY; a
    // second registration is refused; the lookup stops after release.
    #[test]
    #[allow(unsafe_code)]
    fn ciphers_mirror_the_builtins() {
        let (engine, raw) = engine_with_ciphers();
        // SAFETY: called on valid ciphers only.
        let props = |c| unsafe {
            (
                ffi::EVP_CIPHER_key_length(c),
                ffi::EVP_CIPHER_iv_length(c),
                ffi::EVP_CIPHER_block_size(c),
                ffi::EVP_CIPHER_flags(c),
            )
        };
        for nid in NIDS {
            let (key_len, iv_len, block, flags) = props(builtin_cipher(nid).unwrap());
            let custom_copy = flags | ffi::EVP_CIPH_CUSTOM_COPY as c_ulong;
            assert_eq!(
                props(our_cipher(raw, nid)),
                (key_len, iv_len, block, custom_copy)
            );
        }
        assert!(register_aes_cbc_ciphers::<ToyLoader>(&engine).is_err());
        // SAFETY: no context was created on these ciphers.
        unsafe { release_aes_cbc_ciphers(&engine) };
        let mut cipher: *const ffi::EVP_CIPHER = null();
        // SAFETY: calling our callback directly with valid out-params (the
        // ENGINE is still alive, so its address cannot be reused meanwhile).
        let rc = unsafe { c_ciphers(raw, &mut cipher, null_mut(), NIDS[2]) };
        assert!(
            rc != OK && cipher.is_null(),
            "a released ENGINE has no ciphers"
        );
        teardown(&engine, raw);
    }

    // A raw key runs the built-in: byte-identical to OpenSSL's own AES-CBC.
    #[test]
    fn raw_key_runs_the_builtin() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [9u8; AES_BLOCK];
        for nid in NIDS {
            let (builtin, ours, key) = (
                builtin_cipher(nid).unwrap(),
                our_cipher(raw, nid),
                raw_key(nid),
            );
            for len in [0usize, 1, 15, 16, 17, 47] {
                let msg = pattern(len);
                let ct = raw_crypt(ours, raw, &key, &iv, true, &msg);
                assert_eq!(
                    ct,
                    raw_crypt(builtin, null_mut(), &key, &iv, true, &msg),
                    "nid {nid}, len {len}"
                );
                assert_eq!(raw_crypt(ours, raw, &key, &iv, false, &ct), msg);
            }
        }
        teardown(&engine, raw);
    }

    // An attached key runs per whole block with the IV chained through the
    // context and the EVP layer padding, whatever the update sizes; the loader
    // is asked for each cipher's key size.
    #[test]
    fn attached_key_chains_and_pads_through_evp() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [3u8; AES_BLOCK];
        let msg = pattern(37);
        let expected = toy_encrypt(&iv, &msg);
        for nid in NIDS {
            let bits = u32::try_from(raw_key(nid).len())
                .unwrap()
                .checked_mul(u8::BITS);
            for chunk in [1, 5, 16, 100] {
                let ctx = hsm_ctx(raw, nid, true, &iv);
                assert_eq!(Some(LAST_BITS.with(Cell::get)), bits, "nid {nid}");
                assert_eq!(run(ctx, &msg, chunk).unwrap(), expected, "chunk {chunk}");
                free(ctx);
            }
            let ctx = hsm_ctx(raw, nid, false, &iv);
            assert_eq!(run(ctx, &expected, 7).unwrap(), msg);
            free(ctx);
        }
        teardown(&engine, raw);
    }

    // A long update reaches the key one HSM request at a time, with the IV
    // chained across the requests.
    #[test]
    fn long_input_is_split_per_hsm_request() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [4u8; AES_BLOCK];
        let msg = pattern(HSM_CBC_REQUEST.saturating_mul(3).saturating_add(37));
        let expected = toy_encrypt(&iv, &msg);
        for chunk in [HSM_CBC_REQUEST.saturating_add(5), msg.len()] {
            LONGEST_INPUT.with(|c| c.set(0));
            let ctx = hsm_ctx(raw, NIDS[2], true, &iv);
            assert_eq!(run(ctx, &msg, chunk).unwrap(), expected, "chunk {chunk}");
            free(ctx);
            assert_eq!(
                LONGEST_INPUT.with(Cell::get),
                HSM_CBC_REQUEST,
                "chunk {chunk}"
            );
        }
        let ctx = hsm_ctx(raw, NIDS[2], false, &iv);
        assert_eq!(run(ctx, &expected, expected.len()).unwrap(), msg);
        free(ctx);
        teardown(&engine, raw);
    }

    // A copied context runs like the original: it shares an attached key,
    // released with the last of them, or carries the raw key's schedule.
    #[test]
    #[allow(unsafe_code)]
    fn copies_keep_the_key() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [5u8; AES_BLOCK];
        let msg = pattern(40);
        let key = raw_key(NIDS[2]);
        let software = raw_crypt(
            builtin_cipher(NIDS[2]).unwrap(),
            null_mut(),
            &key,
            &iv,
            true,
            &msg,
        );
        let raw_ctx = new_ctx();
        assert!(init(
            raw_ctx,
            our_cipher(raw, NIDS[2]),
            raw,
            Some(&key),
            Some(&iv),
            true
        ));
        RELEASED.with(|c| c.set(0));
        for (ctx, expected) in [
            (hsm_ctx(raw, NIDS[2], true, &iv), toy_encrypt(&iv, &msg)),
            (raw_ctx, software),
        ] {
            let dup = new_ctx();
            // SAFETY: copying a live context into a fresh one.
            assert_eq!(unsafe { ffi::EVP_CIPHER_CTX_copy(dup, ctx) }, OK);
            assert_eq!(run(ctx, &msg, 16).unwrap(), expected);
            assert_eq!(run(dup, &msg, 16).unwrap(), expected);
            let released = RELEASED.with(Cell::get);
            free(ctx);
            assert_eq!(
                RELEASED.with(Cell::get),
                released,
                "the copy still holds the key"
            );
            free(dup);
        }
        assert_eq!(RELEASED.with(Cell::get), 1);
        teardown(&engine, raw);
    }

    // The last key set wins. An attached key survives an init that names the
    // cipher again with the ENGINE (OpenSSL skips the reset then) and takes the
    // new IV; a raw key replaces it, releasing it; attaching again replaces the
    // raw key and wipes its schedule.
    #[test]
    #[allow(unsafe_code)]
    fn last_key_set_wins() {
        let (engine, raw) = engine_with_ciphers();
        let (iv, iv2) = ([1u8; AES_BLOCK], [2u8; AES_BLOCK]);
        let key = raw_key(NIDS[2]);
        let msg = pattern(40);
        RELEASED.with(|c| c.set(0));

        let ctx = hsm_ctx(raw, NIDS[2], true, &iv);
        assert_eq!(run(ctx, &msg, 16).unwrap(), toy_encrypt(&iv, &msg));
        assert!(init(
            ctx,
            our_cipher(raw, NIDS[2]),
            raw,
            None,
            Some(&iv2),
            true
        ));
        assert_eq!(run(ctx, &msg, 16).unwrap(), toy_encrypt(&iv2, &msg));
        assert_eq!(RELEASED.with(Cell::get), 0, "the key must stay attached");

        assert!(init(ctx, null(), null_mut(), Some(&key), Some(&iv), true));
        assert_eq!(
            RELEASED.with(Cell::get),
            1,
            "the replaced key must be released"
        );
        let software = raw_crypt(
            builtin_cipher(NIDS[2]).unwrap(),
            null_mut(),
            &key,
            &iv,
            true,
            &msg,
        );
        assert_eq!(run(ctx, &msg, 16).unwrap(), software);

        assert!(attach(ctx, Some(TOY_URI), 0));
        // SAFETY: ctx is live; its cipher data is the cipher's ctx_size bytes.
        let wiped = unsafe {
            let size = ffi::EVP_CIPHER_impl_ctx_size(ffi::EVP_CIPHER_CTX_cipher(ctx));
            let data = ffi::EVP_CIPHER_CTX_get_cipher_data(ctx).cast::<u8>();
            std::slice::from_raw_parts(data, usize::try_from(size).unwrap())
                .iter()
                .all(|&b| b == 0)
        };
        assert!(wiped, "the raw key schedule must be wiped");
        assert!(init(ctx, null(), null_mut(), None, Some(&iv), true));
        assert_eq!(run(ctx, &msg, 16).unwrap(), toy_encrypt(&iv, &msg));
        free(ctx);
        assert_eq!(RELEASED.with(Cell::get), 2);
        teardown(&engine, raw);
    }

    // No key, an unknown or NULL key URI, a nonzero arg and an unsupported
    // control all fail cleanly; a failed attach leaves the context as it was.
    #[test]
    #[allow(unsafe_code)]
    fn misuse_fails_cleanly() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [1u8; AES_BLOCK];
        let block = [0u8; AES_BLOCK];
        let msg = pattern(40);

        let ctx = new_ctx();
        assert!(init(
            ctx,
            our_cipher(raw, NIDS[2]),
            raw,
            None,
            Some(&iv),
            true
        ));
        assert!(run(ctx, &block, AES_BLOCK).is_none(), "no key must fail");
        assert!(!attach(ctx, Some("bogus"), 0), "unknown key URI");
        assert!(!attach(ctx, None, 0), "NULL key URI");
        assert!(!attach(ctx, Some(TOY_URI), 1), "nonzero arg");
        assert!(init(ctx, null(), null_mut(), None, Some(&iv), true));
        assert!(run(ctx, &block, AES_BLOCK).is_none(), "still no key");
        let (set_tag, tag_len) = (
            ffi::EVP_CTRL_AEAD_SET_TAG as c_int,
            c_int::try_from(AES_BLOCK).unwrap(),
        );
        // SAFETY: ctx is live; the control is refused before ptr is used.
        let rc = unsafe { ffi::EVP_CIPHER_CTX_ctrl(ctx, set_tag, tag_len, null_mut()) };
        assert_ne!(rc, OK, "unsupported control");
        free(ctx);

        let ctx = hsm_ctx(raw, NIDS[2], true, &iv);
        assert!(!attach(ctx, Some("bogus"), 0));
        assert!(init(ctx, null(), null_mut(), None, Some(&iv), true));
        assert_eq!(run(ctx, &msg, 16).unwrap(), toy_encrypt(&iv, &msg));
        free(ctx);
        teardown(&engine, raw);
    }
}
