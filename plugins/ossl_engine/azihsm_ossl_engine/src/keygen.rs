// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM EC key generation for `openssl genpkey -engine azihsm` (and the
//! equivalent `EVP_PKEY_keygen` ABI path).
//!
//! The engine registers an EC `EVP_PKEY_METHOD` (see
//! [`azihsm_ossl_engine_core::pkey_method`]) whose keygen hook lands here when
//! the context was armed with `azihsm.masked_key:<path>` — the same parameter
//! the OpenSSL 3.x provider uses. The handler generates a persistent signing
//! key pair on the HSM, writes the masked private-key blob (owner-only) to the
//! given path, and returns an `EVP_PKEY` that is immediately usable for ECDSA
//! signing: the same engine-bound `EC_KEY` + retained-HSM-key plumbing the
//! loader produces, so generate→sign works without a reload, and the blob
//! reloads later via `ENGINE_load_private_key`.
//!
//! The provider's companion options are accepted with validated values:
//! `azihsm.session` (only `false` — session keys are not implemented yet) and
//! `azihsm.key_usage` (only `digitalSignature` — `keyAgreement` needs ECDH
//! derive, which lands separately). Unsupported values fail keygen with a
//! clear error instead of minting keys the engine cannot use.
//!
//! Unarmed keygen contexts never reach this module — the toolkit delegates
//! them to OpenSSL's software keygen (see the pkey_method module docs).

use std::ffi::c_int;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use azihsm_api::HsmEccCurve;
use azihsm_api::HsmEccKeyGenAlgo;
use azihsm_api::HsmKeyClass;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyKind;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmKeyPropsBuilder;
use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;
use azihsm_ossl_engine_core::pkey_method::EcKeyUsage;
use azihsm_ossl_engine_core::pkey_method::EcKeygenHandler;
use azihsm_ossl_engine_core::pkey_method::KeygenParams;

use crate::SECRET_FILE_MODE;
use crate::engine_impl::engine_data_slot;

/// Marker type carrying the engine's EC keygen logic (see [`EcKeygenHandler`]).
pub(crate) struct AzihsmEcKeygen;

/// Map an OpenSSL curve NID to the HSM curve, rejecting curves the HSM does
/// not implement.
fn curve_from_nid(nid: c_int) -> EngineResult<HsmEccCurve> {
    #[allow(clippy::cast_possible_wrap)]
    match nid as u32 {
        ffi::NID_X9_62_prime256v1 => Ok(HsmEccCurve::P256),
        ffi::NID_secp384r1 => Ok(HsmEccCurve::P384),
        ffi::NID_secp521r1 => Ok(HsmEccCurve::P521),
        _ => Err(EngineError::Other(format!(
            "unsupported curve for azihsm keygen (NID {nid}); supported: P-256, P-384, P-521"
        ))),
    }
}

/// Write the masked blob with the engine's secret-file hardening, mirroring
/// the resiliency crate's write path: staged to an owner-only (0600) temp file
/// in the destination directory (`O_NOFOLLOW` refuses a pre-planted symlink),
/// fsynced, then atomically renamed into place — so a crash cannot leave a
/// torn blob, a pre-existing destination (symlink or wrong permissions) is
/// replaced rather than reused, and the result is always a fresh 0600 file.
fn write_masked_blob(path: &Path, blob: &[u8]) -> EngineResult<()> {
    let file_name = path.file_name().ok_or_else(|| {
        EngineError::Other(format!(
            "masked key path {} has no file name",
            path.display()
        ))
    })?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    // Unique staging name (pid + per-process counter) so concurrent keygens
    // cannot collide; a leftover from a crashed run is removed so create_new
    // below always creates a fresh file with the 0600 mode actually applied
    // (OpenOptions::mode only takes effect on creation).
    static STAGING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = parent.join(format!(
        ".{}.azihsm-tmp.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        STAGING.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&tmp);

    let staged = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(SECRET_FILE_MODE)
            .open(&tmp)
            .map_err(|e| EngineError::wrap(format!("open masked key {}", tmp.display()), e))?;
        f.write_all(blob)
            .map_err(|e| EngineError::wrap(format!("write masked key {}", tmp.display()), e))?;
        f.sync_all()
            .map_err(|e| EngineError::wrap(format!("sync masked key {}", tmp.display()), e))?;
        // rename(2) replaces a pre-existing destination inode (including a
        // symlink itself, never its target) atomically; fsync the directory so
        // the rename itself is durable, like the resiliency crate's writes.
        std::fs::rename(&tmp, path)
            .map_err(|e| EngineError::wrap(format!("persist masked key {}", path.display()), e))?;
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| EngineError::wrap(format!("sync directory {}", parent.display()), e))
    })();
    if staged.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    staged
}

impl EcKeygenHandler for AzihsmEcKeygen {
    #[allow(unsafe_code)]
    fn keygen(
        engine: &Engine,
        params: &KeygenParams,
        pkey: *mut ffi::EVP_PKEY,
    ) -> EngineResult<()> {
        let curve = curve_from_nid(params.curve_nid)?;

        // Provider-parity options are accepted at the parameter surface, but
        // only their defaults are implemented so far; the rest fail loudly
        // here rather than minting keys the engine cannot use yet.
        if params.session {
            return Err(EngineError::Other(
                "azihsm.session:true (session keys) is not yet supported by the engine".into(),
            ));
        }
        if params.key_usage == EcKeyUsage::KeyAgreement {
            return Err(EngineError::Other(
                "azihsm.key_usage:keyAgreement is not yet supported by the engine \
                 (requires ECDH derive)"
                    .into(),
            ));
        }

        let slot = engine_data_slot()?;
        let data = slot
            .get(engine)
            .ok_or(EngineError::NullParam("engine_data"))?;
        // First caller may be the keygen itself (idempotent open).
        data.open_hsm_from_env()?;

        // Generate a persistent signing key pair on the HSM and export the
        // masked blob + public-key DER.
        let (priv_key, masked, pub_der) = data.with_session(|session| {
            let priv_props = HsmKeyPropsBuilder::default()
                .class(HsmKeyClass::Private)
                .key_kind(HsmKeyKind::Ecc)
                .ecc_curve(curve)
                .is_session(false)
                .can_sign(true)
                .build()
                .map_err(|e| EngineError::wrap("build private key props", e))?;
            let pub_props = HsmKeyPropsBuilder::default()
                .class(HsmKeyClass::Public)
                .key_kind(HsmKeyKind::Ecc)
                .ecc_curve(curve)
                .is_session(false)
                .can_verify(true)
                .build()
                .map_err(|e| EngineError::wrap("build public key props", e))?;
            let mut algo = HsmEccKeyGenAlgo::default();
            let (priv_key, _pub) =
                HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
                    .map_err(|e| EngineError::wrap("generate EC key pair", e))?;
            let masked = priv_key
                .masked_key_vec()
                .map_err(|e| EngineError::wrap("export masked key", e))?;
            let pub_der = priv_key
                .pub_key_der_vec()
                .map_err(|e| EngineError::wrap("read public key DER", e))?;
            Ok((priv_key, masked, pub_der))
        })?;

        // Persist the blob before touching `pkey`, so a write failure surfaces
        // cleanly. (The blob stays valid independently of this key handle: a
        // later unmask imports it as a fresh handle.)
        write_masked_blob(&params.masked_key_path, &masked)?;

        // Same engine-bound EC_KEY + retained-HSM-key construction as the
        // loader, then hand it to the caller's EVP_PKEY. set1 up-refs `ec`.
        let ec = crate::keyload::build_bound_ec_key(engine, data, &pub_der, priv_key)?;
        // SAFETY: pkey is the keygen out-key OpenSSL passed us; ec is our fresh
        // engine-bound EC_KEY, freed after set1 takes its own reference (the
        // OOM failure path also rolls back the HSM-key retain).
        unsafe {
            if ffi::EVP_PKEY_set1_EC_KEY(pkey, ec) != 1 {
                crate::keyload::free_bound_ec_key(data, ec);
                return Err(EngineError::Other("EVP_PKEY_set1_EC_KEY failed".into()));
            }
            ffi::EC_KEY_free(ec);
        }
        Ok(())
    }
}
