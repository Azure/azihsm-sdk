// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `ENGINE_load_private_key` implementation: resolve an `azihsm://` URI to an
//! HSM key and return an `EVP_PKEY`.
//!
//! The returned key carries the real public key (rebuilt from the SDK's DER via
//! the safe `openssl` crate). The live HSM private-key wrapper is owned by
//! [`EngineData`], which deletes it from the HSM when the engine is destroyed;
//! a non-owning pointer to it is stashed in the underlying `EC_KEY` ex_data for
//! later sign/derive callbacks. Deletion runs from the engine's destroy handler
//! (while this `.so` is loaded), never from a libcrypto ex_data free callback —
//! such a callback holds a function pointer into this `.so` and can be invoked
//! after the `.so` is unloaded (see [`azihsm_ossl_engine_core::exdata`]).
//!
//! The returned `EC_KEY` is bound to the engine (`EC_KEY_new_method`), which
//! takes a functional reference OpenSSL releases on `EC_KEY_free`. So the engine
//! — hence `EngineData` and this `.so` — cannot be torn down while any loaded
//! key is alive, and the stashed HSM-key pointer can never dangle even if an
//! `EVP_PKEY` outlives the caller's `ENGINE` handle.
//!
//! ECDSA signing on a loaded key routes through the HSM (see [`crate::sign`]);
//! `-pubout` and other public-key operations use the public key on the
//! `EVP_PKEY`. Key derivation is not wired yet.
//!
//! Only EC keys are supported here; RSA loading (an HSM import + unmask path)
//! lands in a follow-up together with its test coverage.

use std::ffi::c_int;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::OnceLock;

use azihsm_api::HsmEccKeyUnmaskAlgo;
use azihsm_api::HsmEccPrivateKey;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyManager;
use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;
use foreign_types::ForeignTypeRef;
use openssl::pkey::PKey;
use parking_lot::Mutex;

use crate::context::EngineData;
use crate::uri;
use crate::uri::KeyType;

/// Load the private key named by `key_id` (an `azihsm://…` URI) and return an
/// owning `*mut EVP_PKEY`. `engine` binds the returned key to the engine so it
/// stays loaded while the key is alive (see [`build_ec_pkey`]).
pub fn load_key(
    engine: &Engine,
    data: &EngineData,
    key_id: &str,
) -> EngineResult<*mut ffi::EVP_PKEY> {
    let parsed = uri::parse(key_id)?;

    // Reject unsupported key types before any HSM open or file I/O, so they
    // fail with a clear error instead of a misleading environment/filesystem
    // one. RSA loading lands in a follow-up (it needs an HSM import path plus
    // test coverage).
    match parsed.key_type {
        KeyType::Ec => {}
        KeyType::Rsa | KeyType::RsaPss => {
            return Err(EngineError::Other(
                "RSA key loading is not yet supported".into(),
            ));
        }
    }

    // First real caller of the lazy HSM open (idempotent).
    data.open_hsm_from_env()?;
    let masked = read_masked_key(&parsed.masked_key_path)?;
    load_ec(engine, data, &masked)
}

/// Upper bound on a masked-key blob. A masked EC/RSA key is far smaller; this
/// bounds allocation against a caller-supplied path pointing at a very large or
/// unbounded file. Mirrors `MAX_STORAGE_FILE_SIZE` in
/// azihsm_ossl_engine_resiliency.
const MAX_MASKED_KEY_SIZE: u64 = 64 * 1024;

/// Read a masked-key blob with the same hardening the rest of the engine
/// applies to key-material files: `O_NOFOLLOW` refuses a symlink at `path`,
/// `O_NONBLOCK` avoids blocking on a FIFO/device before the regular-file check,
/// `O_CLOEXEC` keeps the fd from leaking across exec, a non-regular file is
/// rejected outright, and the read is capped at [`MAX_MASKED_KEY_SIZE`].
/// Mirrors `read_regular_hardened` in azihsm_ossl_engine_resiliency.
fn read_masked_key(path: &Path) -> EngineResult<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| EngineError::wrap(format!("open masked key {}", path.display()), e))?;

    let meta = file
        .metadata()
        .map_err(|e| EngineError::wrap(format!("stat masked key {}", path.display()), e))?;
    if !meta.is_file() {
        return Err(EngineError::Other(format!(
            "masked key {} is not a regular file",
            path.display()
        )));
    }
    if meta.len() > MAX_MASKED_KEY_SIZE {
        return Err(EngineError::Other(format!(
            "masked key {} is too large ({} bytes, max {MAX_MASKED_KEY_SIZE})",
            path.display(),
            meta.len()
        )));
    }

    // Cap the read too: metadata can under-report (a growing or virtual file),
    // so bound the bytes actually read and reject anything over the limit.
    let mut buf = Vec::new();
    file.take(MAX_MASKED_KEY_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| EngineError::wrap(format!("read masked key {}", path.display()), e))?;
    if buf.len() as u64 > MAX_MASKED_KEY_SIZE {
        return Err(EngineError::Other(format!(
            "masked key {} exceeds {MAX_MASKED_KEY_SIZE} bytes",
            path.display()
        )));
    }
    Ok(buf)
}

fn load_ec(engine: &Engine, data: &EngineData, masked: &[u8]) -> EngineResult<*mut ffi::EVP_PKEY> {
    let priv_key = data.with_session(|session| {
        let mut algo = HsmEccKeyUnmaskAlgo {};
        HsmKeyManager::unmask_key_pair(session, &mut algo, masked)
            .map(|(private, _public)| private)
            .map_err(|e| EngineError::wrap("EC key unmask", e))
    })?;

    let der = priv_key
        .pub_key_der_vec()
        .map_err(|e| EngineError::wrap("read EC public key DER", e))?;

    build_ec_pkey(engine, data, &der, priv_key)
}

/// Build an engine-bound `EC_KEY` (via [`Engine::new_ec_key`] — see the module
/// docs for why the binding matters) carrying the public key from `der`, with
/// the live HSM key attached to its ex_data and retained by `data`. Returns an
/// owning `*mut EC_KEY`. Shared by the loader and the keygen handler.
#[allow(unsafe_code)]
pub(crate) fn build_bound_ec_key(
    engine: &Engine,
    data: &EngineData,
    der: &[u8],
    key: HsmEccPrivateKey,
) -> EngineResult<*mut ffi::EC_KEY> {
    // Parse the SPKI DER into a temporary key just to recover the curve group
    // and public point.
    let parsed =
        PKey::public_key_from_der(der).map_err(|e| EngineError::wrap("parse public key DER", e))?;
    // SAFETY: parsed is a valid EC public-key EVP_PKEY; the get0 accessors
    // return borrowed pointers valid while `parsed` lives.
    let (group, point) = unsafe {
        let parsed_ec = ffi::EVP_PKEY_get0_EC_KEY(parsed.as_ptr().cast::<ffi::EVP_PKEY>());
        if parsed_ec.is_null() {
            return Err(EngineError::Other("parsed EVP_PKEY has no EC_KEY".into()));
        }
        (
            ffi::EC_KEY_get0_group(parsed_ec),
            ffi::EC_KEY_get0_public_key(parsed_ec),
        )
    };
    if group.is_null() || point.is_null() {
        return Err(EngineError::Other(
            "parsed EC_KEY missing group or public key".into(),
        ));
    }

    // Engine-bound EC_KEY (up-refs the engine; see the fn doc).
    let ec = engine.new_ec_key()?;
    // SAFETY: ec is a fresh EC_KEY; set_group/set_public_key dup the borrowed
    // group/point out of `parsed`.
    let set_ok = unsafe {
        ffi::EC_KEY_set_group(ec, group) == 1 && ffi::EC_KEY_set_public_key(ec, point) == 1
    };
    // `group`/`point` borrow into `parsed`; keep it alive until here (they are
    // raw pointers, so the borrow checker won't do it for us) — they were dup'd
    // into `ec` above and are no longer needed.
    drop(parsed);
    if !set_ok {
        // SAFETY: ec is ours and not yet handed out.
        unsafe { ffi::EC_KEY_free(ec) };
        return Err(EngineError::Other(
            "failed to set EC group/public key".into(),
        ));
    }

    // Stash the HSM key in the ex_data (attach_ec rolls the retain back on
    // failure).
    if let Err(e) = attach_ec(data, ec, key) {
        // SAFETY: ec is ours and not yet handed out.
        unsafe { ffi::EC_KEY_free(ec) };
        return Err(e);
    }
    Ok(ec)
}

/// Free a bound `EC_KEY` from [`build_bound_ec_key`] that could not be handed
/// out, rolling back the HSM-key retain so the failed call does not leave the
/// key parked in the HSM until engine teardown.
///
/// # Safety
/// `ec` must be the caller's own never-handed-out `EC_KEY` from
/// [`build_bound_ec_key`].
#[allow(unsafe_code)]
pub(crate) unsafe fn free_bound_ec_key(data: &EngineData, ec: *mut ffi::EC_KEY) {
    let key_ptr = ec_key_hsm_key(ec);
    if !key_ptr.is_null() {
        data.release_loaded_key(key_ptr);
    }
    // SAFETY: ec is valid and owned by the caller per this function's contract.
    unsafe { ffi::EC_KEY_free(ec) };
}

/// Build the returned `EVP_PKEY` around an engine-bound `EC_KEY` from
/// [`build_bound_ec_key`].
#[allow(unsafe_code)]
fn build_ec_pkey(
    engine: &Engine,
    data: &EngineData,
    der: &[u8],
    key: HsmEccPrivateKey,
) -> EngineResult<*mut ffi::EVP_PKEY> {
    let ec = build_bound_ec_key(engine, data, der, key)?;

    // Wrap the EC_KEY in an EVP_PKEY. EVP_PKEY_set1_EC_KEY up-refs `ec`, so drop
    // our own reference afterwards; the EVP_PKEY (and its engine ref) then owns
    // the key. The OOM-only failure paths free the bound key with its HSM-key
    // retain rolled back.
    // SAFETY: standard EVP_PKEY construction; every return code is checked and
    // `ec` is freed on each path.
    unsafe {
        let pkey = ffi::EVP_PKEY_new();
        if pkey.is_null() {
            free_bound_ec_key(data, ec);
            return Err(EngineError::Other("EVP_PKEY_new failed".into()));
        }
        if ffi::EVP_PKEY_set1_EC_KEY(pkey, ec) != 1 {
            ffi::EVP_PKEY_free(pkey);
            free_bound_ec_key(data, ec);
            return Err(EngineError::Other("EVP_PKEY_set1_EC_KEY failed".into()));
        }
        ffi::EC_KEY_free(ec);
        Ok(pkey)
    }
}

#[allow(unsafe_code)]
fn attach_ec(data: &EngineData, ec: *mut ffi::EC_KEY, key: HsmEccPrivateKey) -> EngineResult<()> {
    if ec.is_null() {
        return Err(EngineError::Other("EVP_PKEY has no EC_KEY".into()));
    }
    let idx = ec_key_ex_index()?;

    // Hand the key to EngineData, which owns it and deletes it from the HSM when
    // the engine is destroyed (while this `.so` is loaded). Stash the non-owning
    // pointer it returns for later sign/derive retrieval. The ex_data slot has
    // no free callback (see ec_key_ex_index), so libcrypto never calls back into
    // this `.so` for cleanup.
    let key_ptr = data.retain_loaded_key(key);
    // SAFETY: ec is valid (checked), idx is a registered EC_KEY ex_data slot,
    // and key_ptr is a non-owning pointer into a key EngineData keeps alive for
    // the engine's lifetime; the slot has no free callback, so no ownership is
    // transferred.
    let rc = unsafe { ffi::EC_KEY_set_ex_data(ec, idx, key_ptr.cast_mut().cast::<c_void>()) };
    if rc != 1 {
        // Roll back the retain so the failed load doesn't leave the key in the
        // HSM until engine teardown.
        data.release_loaded_key(key_ptr);
        return Err(EngineError::Other("EC_KEY_set_ex_data failed".into()));
    }

    // Signing on this key already routes through the HSM: the EC_KEY adopted
    // the engine's ECDSA EC_KEY_METHOD at creation (EC_KEY_new_method; see
    // crate::sign). It is not attached per key — EC_KEY_set_method would drop
    // the engine reference that keeps EngineData (and this HSM key) alive.
    Ok(())
}

/// Recover the `HsmEccPrivateKey` [`attach_ec`] stashed in `ec_key`'s ex_data,
/// or null if none is set. The pointer is owned by `EngineData` and valid for
/// the engine's lifetime; the sign path dereferences it while the key is live.
#[allow(unsafe_code)]
pub(crate) fn ec_key_hsm_key(ec_key: *mut ffi::EC_KEY) -> *const HsmEccPrivateKey {
    let Ok(idx) = ec_key_ex_index() else {
        return std::ptr::null();
    };
    // SAFETY: ec_key is the EC_KEY OpenSSL passed to the sign callback; idx is
    // our registered slot (returns NULL if nothing was stored).
    unsafe { ffi::EC_KEY_get_ex_data(ec_key, idx) }.cast::<HsmEccPrivateKey>()
}

/// Process-global EC_KEY ex_data slot index, registered once **without** a free
/// callback: the stored pointer is non-owning (the key is owned by
/// [`EngineData`]), and a libcrypto-held free callback into this `.so` would be
/// unsafe across `.so` unload (see [`azihsm_ossl_engine_core::exdata`]).
#[allow(unsafe_code)]
fn ec_key_ex_index() -> EngineResult<c_int> {
    static IDX: OnceLock<c_int> = OnceLock::new();
    static INIT: Mutex<()> = Mutex::new(());

    if let Some(i) = IDX.get() {
        return Ok(*i);
    }
    let _guard = INIT.lock();
    if let Some(i) = IDX.get() {
        return Ok(*i);
    }
    // EC_KEY_get_ex_new_index is a macro in 1.1.x, so call the underlying
    // CRYPTO_get_ex_new_index with the EC_KEY class directly.
    // SAFETY: standard ex_data index registration with no new/dup/free callbacks.
    let idx = unsafe {
        ffi::CRYPTO_get_ex_new_index(
            ffi::CRYPTO_EX_INDEX_EC_KEY as c_int,
            0,
            null_mut(),
            None,
            None,
            None,
        )
    };
    if idx < 0 {
        return Err(EngineError::ExDataRegisterFailed);
    }
    let _ = IDX.set(idx);
    Ok(idx)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::ptr::NonNull;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use super::*;

    /// Unique scratch directory, removed on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let dir =
                std::env::temp_dir().join(format!("engine-keyload-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn read_masked_key_reads_regular_file() {
        let s = Scratch::new();
        let p = s.0.join("blob.bin");
        fs::write(&p, b"masked-bytes").unwrap();
        assert_eq!(read_masked_key(&p).unwrap(), b"masked-bytes");
    }

    #[test]
    fn read_masked_key_rejects_symlink() {
        let s = Scratch::new();
        let target = s.0.join("real.bin");
        fs::write(&target, b"x").unwrap();
        let link = s.0.join("link.bin");
        symlink(&target, &link).unwrap();
        // O_NOFOLLOW must refuse to open the symlink itself.
        assert!(read_masked_key(&link).is_err());
    }

    #[test]
    fn read_masked_key_rejects_non_regular_file() {
        let s = Scratch::new();
        // A directory opens but is not a regular file, so is_file() rejects it.
        assert!(read_masked_key(&s.0).is_err());
    }

    #[test]
    fn read_masked_key_rejects_oversized_file() {
        let s = Scratch::new();
        let p = s.0.join("big.bin");
        let oversize = usize::try_from(MAX_MASKED_KEY_SIZE + 1).unwrap();
        fs::write(&p, vec![0u8; oversize]).unwrap();
        assert!(read_masked_key(&p).is_err());
    }

    /// `load_key` rejects RSA/RSA-PSS before opening the HSM, so this needs no
    /// device — only a throwaway ENGINE to satisfy the signature.
    #[test]
    #[allow(unsafe_code)]
    fn load_key_rejects_rsa_before_hsm_open() {
        // SAFETY: ENGINE_new returns a fresh structural ref, freed below; the
        // Engine wrapper is only used to satisfy the signature (the RSA arm
        // returns before touching it).
        unsafe {
            let raw = ffi::ENGINE_new();
            assert!(!raw.is_null(), "ENGINE_new");
            let engine = Engine::from_ptr(NonNull::new(raw).unwrap());
            let data = EngineData::new();
            let err =
                load_key(&engine, &data, "azihsm:///tmp/does-not-matter;type=rsa").unwrap_err();
            assert!(
                format!("{err}").contains("RSA key loading is not yet supported"),
                "unexpected error: {err}"
            );
            ffi::ENGINE_free(raw);
        }
    }
}
