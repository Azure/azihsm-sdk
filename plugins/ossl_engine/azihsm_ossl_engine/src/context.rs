// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Engine context parked in `ENGINE` ex_data.
//!
//! [`EngineData`] is the per-engine state stored in the `ENGINE`'s ex_data
//! and retrieved via `ENGINE_get_ex_data`. It owns one lazily-populated
//! [`HsmEngineContext`] (partition + session).

use std::path::Path;

use azihsm_api::HsmCredentials;
use azihsm_api::HsmEccPrivateKey;
use azihsm_api::HsmError;
use azihsm_api::HsmOwnerBackupKey;
use azihsm_api::HsmOwnerBackupKeyConfig;
use azihsm_api::HsmOwnerBackupKeySource;
use azihsm_api::HsmPartition;
use azihsm_api::HsmPartitionManager;
use azihsm_api::HsmPotaEndorsement;
use azihsm_api::HsmPotaEndorsementData;
use azihsm_api::HsmPotaEndorsementSource;
use azihsm_api::HsmSession;
use azihsm_api::MobkProviderCallback;
use azihsm_api::PotaEndorsementCallback;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_resiliency::FileMobkCallback;
use azihsm_ossl_engine_resiliency::FilePotaCallback;
use azihsm_ossl_engine_resiliency::ResiliencySettings;
use parking_lot::Mutex;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::SECRET_FILE_MODE;

/// Test-only credentials. Match the values used throughout the API test
/// suite (`api/tests/src/utils/partition.rs`), so the mock DDI accepts
/// the engine out of the box. Compiled in **only** for `mock` builds: a
/// production build has no default, so an unset `AZIHSM_CREDENTIALS_*` is a
/// hard error rather than a silent authentication with a well-known PIN.
#[cfg(feature = "mock")]
const DEFAULT_CRED_ID: [u8; 16] = [1u8; 16];
#[cfg(feature = "mock")]
const DEFAULT_CRED_PIN: [u8; 16] = [2u8; 16];

const ENV_CREDENTIALS_ID: &str = "AZIHSM_CREDENTIALS_ID";
const ENV_CREDENTIALS_PIN: &str = "AZIHSM_CREDENTIALS_PIN";

/// Per-engine state stored in `ENGINE` ex_data.
pub struct EngineData {
    /// HSM private keys loaded via the engine's `load_private_key` path. Owned
    /// here — never via an `EC_KEY` ex_data free callback, which would leave a
    /// libcrypto-held function pointer into this `.so` (see the module docs of
    /// [`azihsm_ossl_engine_core::exdata`]). Each key's `Drop` deletes it from
    /// the HSM; that runs when this `EngineData` is dropped by the destroy
    /// handler, while the `.so` is loaded. Declared before `hsm` so it drops
    /// first, while the session is still open.
    ///
    /// Keys therefore accumulate for the engine's lifetime: repeated loads (even
    /// of the same URI) each retain a handle. That is fine for the usual load-key-
    /// once pattern; a URI-keyed dedupe cache could bound it if a workload ever
    /// loads keys repeatedly.
    //
    // `Box` gives each key a stable heap address: keyload stashes a raw pointer
    // to it in EC_KEY ex_data, which must stay valid across `Vec` growth — so
    // the `vec_box` suggestion to drop the `Box` does not apply.
    #[allow(clippy::vec_box)]
    loaded_keys: Mutex<Vec<Box<HsmEccPrivateKey>>>,
    hsm: Mutex<Option<HsmEngineContext>>,
}

impl Default for EngineData {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineData {
    pub fn new() -> Self {
        Self {
            loaded_keys: Mutex::new(Vec::new()),
            hsm: Mutex::new(None),
        }
    }

    /// True once an `HsmEngineContext` has been installed via `open_hsm_*`.
    pub fn is_hsm_open(&self) -> bool {
        self.hsm.lock().is_some()
    }

    /// Open the HSM using `settings` (already parsed) and `creds`.
    /// Idempotent: subsequent calls return `Ok(())` without re-opening.
    ///
    /// The lock is held across `HsmEngineContext::open` so concurrent first-use
    /// callers serialize on the open instead of racing two sessions open
    /// and discarding one.
    pub fn open_hsm_with(
        &self,
        settings: ResiliencySettings,
        creds: HsmCredentials,
    ) -> EngineResult<()> {
        let mut guard = self.hsm.lock();
        if guard.is_some() {
            return Ok(());
        }
        *guard = Some(HsmEngineContext::open(settings, creds)?);
        Ok(())
    }

    /// Open the HSM by reading settings + credentials from the process
    /// environment.
    ///
    /// Idempotent: if the HSM is already open (e.g. opened earlier via
    /// [`open_hsm_with`]) this returns `Ok` without touching the environment,
    /// so a caller like the key loader can invoke it unconditionally.
    pub fn open_hsm_from_env(&self) -> EngineResult<()> {
        if self.is_hsm_open() {
            return Ok(());
        }
        let settings = ResiliencySettings::from_env()
            .map_err(|e| EngineError::wrap("resiliency settings", e))?;
        let creds = credentials_from_env()?;
        self.open_hsm_with(settings, creds)
    }

    /// Run `f` with the open HSM session. The lock is held across `f`, so key
    /// operations serialize with each other and with the open. Errors if the
    /// HSM has not been opened.
    ///
    /// Crate-internal: it hands out a raw `HsmSession`, so it is used only by
    /// the key loader (and tests), not exposed as public engine API.
    pub(crate) fn with_session<F, R>(&self, f: F) -> EngineResult<R>
    where
        F: FnOnce(&HsmSession) -> EngineResult<R>,
    {
        let guard = self.hsm.lock();
        let ctx = guard
            .as_ref()
            .ok_or_else(|| EngineError::Other("HSM session not open".into()))?;
        f(&ctx.session)
    }

    /// Take ownership of a loaded HSM private key so it lives until the engine
    /// is destroyed (its `Drop` deletes it from the HSM), and return a stable
    /// non-owning pointer to it for stashing in `EC_KEY` ex_data. Boxing keeps
    /// the address stable across `Vec` growth; the returned pointer stays valid
    /// until this `EngineData` is dropped by the destroy handler, or until
    /// [`release_loaded_key`](Self::release_loaded_key) drops it early.
    ///
    /// Crate-internal: an implementation detail of the key loader.
    pub(crate) fn retain_loaded_key(&self, key: HsmEccPrivateKey) -> *const HsmEccPrivateKey {
        let boxed = Box::new(key);
        let ptr: *const HsmEccPrivateKey = boxed.as_ref();
        self.loaded_keys.lock().push(boxed);
        ptr
    }

    /// Drop a key previously handed to [`retain_loaded_key`](Self::retain_loaded_key),
    /// identified by the pointer it returned. Used to roll back on a partial
    /// load failure (e.g. if stashing the ex_data pointer fails) so the key
    /// doesn't linger in the HSM until engine teardown. A no-op if the pointer
    /// isn't currently retained. Dropping the box deletes the key from the HSM.
    pub(crate) fn release_loaded_key(&self, ptr: *const HsmEccPrivateKey) {
        let mut keys = self.loaded_keys.lock();
        if let Some(pos) = keys.iter().position(|k| std::ptr::eq(k.as_ref(), ptr)) {
            keys.remove(pos);
        }
    }
}

/// Live HSM partition + session.
///
/// Both fields are RAII holders: dropping them closes the session and
/// releases the partition. They are held (not currently read) to keep the
/// session open for the lifetime of the `EngineData`.
struct HsmEngineContext {
    #[allow(dead_code)]
    partition: HsmPartition,
    #[allow(dead_code)]
    session: HsmSession,
}

impl HsmEngineContext {
    fn open(settings: ResiliencySettings, creds: HsmCredentials) -> EngineResult<Self> {
        let info = HsmPartitionManager::partition_info_list()
            .into_iter()
            .next()
            .ok_or_else(|| EngineError::Other("no HSM partitions found".into()))?;

        let api_rev_range = info
            .api_rev_range
            .ok_or_else(|| EngineError::Other(format!("partition {} has no API rev", info.path)))?;
        let api_rev = api_rev_range.max();

        let partition = HsmPartitionManager::open_partition(&info.path, api_rev)
            .map_err(|e| EngineError::wrap(format!("open_partition({})", info.path), e))?;

        // With resiliency off the SDK wants a clean partition. reset() is a
        // no-op on a freshly opened one and does NOT clear BK3 (one-shot per
        // power cycle) — the warm-device case is handled by the OBK→MOBK
        // fallback below.
        if !settings.enabled {
            partition
                .reset()
                .map_err(|e| EngineError::wrap("partition reset", e))?;
        }

        // Mirror the provider (azihsm_ossl_hsm.c): always attempt init with
        // the plaintext OBK first. On a cold device `init_bk3` runs and
        // derives a fresh MOBK; on a warm device the SDK returns
        // Bk3AlreadyInitialized and we retry with the MOBK a previous init
        // persisted.
        let caller_obk = matches!(settings.obk_source, HsmOwnerBackupKeySource::Caller);
        let pota = build_pota_endorsement(&partition, &settings)?;
        let first = partition.init(
            creds,
            None,
            None,
            build_obk_config(&settings)?,
            pota.clone(),
            build_resiliency_config(&settings)?,
        );

        match first {
            Ok(()) => {}
            Err(HsmError::Bk3AlreadyInitialized) if caller_obk => {
                reinit_with_cached_mobk(&partition, creds, &settings, pota)?;
            }
            Err(e) => return Err(EngineError::wrap("partition init", e)),
        }

        // Persist the device's MOBK so a later warm re-init can recover
        // (mirrors the provider). `mobk_vec()` is populated only when this
        // init actually derived the MOBK — the cold-device `init_bk3` path.
        // On a warm re-init the SDK reports credentials already established
        // and returns no MOBK; the file persisted by the original cold init
        // is still valid, so there is nothing new to write. Caller source
        // only; TPM re-derives the MOBK each init.
        if caller_obk {
            let mobk = Zeroizing::new(partition.mobk_vec());
            if !mobk.is_empty() {
                persist_secret_file(&settings.mobk_path, mobk.as_slice()).map_err(|e| {
                    EngineError::wrap(
                        format!("persist MOBK to '{}'", settings.mobk_path.display()),
                        e,
                    )
                })?;
            }
        }

        let session = partition
            .open_session(api_rev, &creds, None)
            .map_err(|e| EngineError::wrap("open_session", e))?;

        Ok(Self { partition, session })
    }
}

/// Warm-device re-init: the plaintext OBK was rejected with
/// `Bk3AlreadyInitialized`, so re-init from the MOBK a previous cold init
/// persisted at `settings.mobk_path`. Caller-OBK source only.
fn reinit_with_cached_mobk(
    partition: &HsmPartition,
    creds: HsmCredentials,
    settings: &ResiliencySettings,
    pota: HsmPotaEndorsement,
) -> EngineResult<()> {
    let mobk = Zeroizing::new(
        FileMobkCallback::new(settings.mobk_path.clone())
            .get_mobk()
            .map_err(|e| {
                EngineError::wrap(
                    format!(
                        "device reports BK3 already initialized but cached MOBK \
                         '{}' is unusable — restore it or reset/power-cycle the \
                         device",
                        settings.mobk_path.display()
                    ),
                    e,
                )
            })?,
    );
    let obk_config = HsmOwnerBackupKeyConfig::new(
        HsmOwnerBackupKeySource::Caller,
        HsmOwnerBackupKey::from_masked_key(mobk.as_slice()),
    );
    partition
        .init(
            creds,
            None,
            None,
            obk_config,
            pota,
            build_resiliency_config(settings)?,
        )
        .map_err(|e| EngineError::wrap("partition init (MOBK retry)", e))
}

/// Persist key material to `path` durably: write a `0600` temp file, flush it,
/// then atomically rename into place, so a torn write can't leave a corrupt
/// MOBK that would break a later warm re-init.
fn persist_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    // PID plus a per-call counter, so two engines in one process writing the
    // same target path can't collide on the temp name.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut tmp_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?
        .to_os_string();
    tmp_name.push(format!(".tmp.{}.{seq}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);

    // Exclusive-create (O_EXCL via create_new): if a file already exists at
    // this temp name — a crash leftover or a planted file in a shared dir —
    // fail instead of truncating it, so secret material is never written into
    // a file we did not just create with 0600.
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(SECRET_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;

    // We own `tmp` now, so on any later failure remove it (and only it) so a
    // partial copy of key material is not left behind.
    if let Err(e) = (|| -> std::io::Result<()> {
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // fsync the directory so the rename itself survives a crash.
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Assemble the resiliency config for one `partition.init` attempt.
///
/// `HsmResiliencyConfig` is consumed by `init` and holds non-`Clone` callback
/// boxes, so each attempt rebuilds it from a `settings` clone.
fn build_resiliency_config(
    settings: &ResiliencySettings,
) -> EngineResult<Option<azihsm_api::HsmResiliencyConfig>> {
    settings
        .clone()
        .into_resiliency_config()
        .map_err(|e| EngineError::wrap("resiliency config", e))
}

/// Build the initial POTA endorsement OpenSSL hands to `partition.init`.
/// When source is `Caller` we use [`FilePotaCallback`] to sign the
/// partition's PID public key; when source is `Tpm` we pass `None`.
fn build_pota_endorsement(
    partition: &HsmPartition,
    settings: &ResiliencySettings,
) -> EngineResult<HsmPotaEndorsement> {
    match settings.pota_source {
        HsmPotaEndorsementSource::Caller => {
            let priv_path = settings.pota_priv_path.clone().ok_or_else(|| {
                EngineError::Other(
                    "AZIHSM_POTA_PRIVATE_KEY_PATH is required for caller POTA".into(),
                )
            })?;
            let pub_path = settings.pota_pub_path.clone().ok_or_else(|| {
                EngineError::Other("AZIHSM_POTA_PUBLIC_KEY_PATH is required for caller POTA".into())
            })?;
            let pid_pub = partition
                .pub_key()
                .map_err(|e| EngineError::wrap("partition pub_key", e))?;
            let cb = FilePotaCallback::new(priv_path, pub_path);
            let data = cb
                .endorse(&[], &pid_pub, &[])
                .map_err(|e| EngineError::wrap("POTA endorse", e))?;
            let endorsement = HsmPotaEndorsementData::new(data.signature(), data.pub_key());
            Ok(HsmPotaEndorsement::new(
                HsmPotaEndorsementSource::Caller,
                Some(endorsement),
            ))
        }
        _ => Ok(HsmPotaEndorsement::new(settings.pota_source, None)),
    }
}

/// Build the OBK config for the *first* `partition.init` attempt: Caller
/// source supplies the plaintext OBK (which runs `init_bk3`); Tpm supplies an
/// empty key. The warm-device MOBK retry is handled in [`HsmEngineContext::open`].
fn build_obk_config(settings: &ResiliencySettings) -> EngineResult<HsmOwnerBackupKeyConfig> {
    match settings.obk_source {
        HsmOwnerBackupKeySource::Caller => {
            // Plaintext OBK (BK3); our copy is scrubbed on drop.
            let cb = FileMobkCallback::new(settings.obk_path.clone());
            let obk = Zeroizing::new(
                cb.get_mobk()
                    .map_err(|e| EngineError::wrap("OBK load", e))?,
            );
            Ok(HsmOwnerBackupKeyConfig::new(
                HsmOwnerBackupKeySource::Caller,
                HsmOwnerBackupKey::from_obk(obk.as_slice()),
            ))
        }
        _ => Ok(HsmOwnerBackupKeyConfig::new(
            settings.obk_source,
            HsmOwnerBackupKey::default(),
        )),
    }
}

fn credentials_from_env() -> EngineResult<HsmCredentials> {
    // Defaults exist only in mock builds; a production build requires the
    // env vars (see DEFAULT_CRED_* above).
    #[cfg(feature = "mock")]
    let (def_id, def_pin) = (Some(DEFAULT_CRED_ID), Some(DEFAULT_CRED_PIN));
    #[cfg(not(feature = "mock"))]
    let (def_id, def_pin): (Option<[u8; 16]>, Option<[u8; 16]>) = (None, None);

    let mut id = cred_field(ENV_CREDENTIALS_ID, def_id)?;
    let mut pin = cred_field(ENV_CREDENTIALS_PIN, def_pin)?;
    let creds = HsmCredentials::new(&id, &pin);
    // Scrub our decoded copies; HsmCredentials holds its own.
    id.zeroize();
    pin.zeroize();
    Ok(creds)
}

/// Read a 16-byte credential from `var` (32 hex chars). Falls back to
/// `default` when the var is unset; in non-mock builds `default` is `None`,
/// so a missing credential is a hard error rather than a silent well-known PIN.
fn cred_field(var: &'static str, default: Option<[u8; 16]>) -> EngineResult<[u8; 16]> {
    match std::env::var(var) {
        Ok(s) => {
            // The source hex string holds the secret; scrub it on drop.
            let s = Zeroizing::new(s);
            hex_decode_16(&s, var)
        }
        // Only a truly-unset var falls back to the default; a present but
        // non-UTF-8 value is an error, not "unset".
        Err(std::env::VarError::NotPresent) => {
            default.ok_or_else(|| EngineError::Other(format!("{var} must be set (32 hex chars)")))
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(EngineError::Other(format!("{var} is not valid UTF-8")))
        }
    }
}

fn hex_decode_16(s: &str, var: &'static str) -> EngineResult<[u8; 16]> {
    if s.len() != 32 {
        return Err(EngineError::Other(format!(
            "{var} must be 32 hex chars (16 bytes), got {}",
            s.len()
        )));
    }
    let mut out = [0u8; 16];
    for (dst, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        let pair_str = std::str::from_utf8(pair)
            .map_err(|_| EngineError::Other(format!("{var} has non-ASCII byte")))?;
        *dst = u8::from_str_radix(pair_str, 16)
            .map_err(|_| EngineError::Other(format!("{var} has non-hex byte")))?;
    }
    Ok(out)
}

// Imports for the shared test helpers below. Kept at module scope (not in the
// function bodies) and gated on `test` so they serve both the `mock` unit tests
// and the hardware tests, which have opposite `mock` gates.
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(test)]
use std::ptr::NonNull;

#[cfg(test)]
use azihsm_ossl_engine_core::engine::Engine;
#[cfg(test)]
use azihsm_ossl_engine_core::ffi;

/// Test helper: write key-material bytes to `path` with owner-only permissions
/// and the same open hardening the engine uses for secret files — create a new
/// file (`O_EXCL`, no clobber) mode 0600 and refuse a symlink at the path
/// (`O_NOFOLLOW`). Used by the round-trip tests to stage a masked-key blob.
#[cfg(test)]
fn write_key_material(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(SECRET_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(data)
}

/// Test helper: a throwaway ENGINE for driving `keyload::load_key` in-process.
/// The loader binds returned keys to it (`EC_KEY_new_method`), so it must
/// outlive the loaded `EVP_PKEY`; the raw structural ref is returned so the
/// caller frees it with `ENGINE_free` after dropping the key.
#[cfg(test)]
#[allow(unsafe_code)]
#[allow(clippy::unwrap_used)]
fn new_test_engine() -> (Engine, *mut ffi::ENGINE) {
    // SAFETY: ENGINE_new returns a fresh structural ref; wrapping it in Engine
    // is sound for the test, and the caller ENGINE_free's the returned raw ref.
    unsafe {
        let raw = ffi::ENGINE_new();
        assert!(!raw.is_null(), "ENGINE_new");
        let engine = Engine::from_ptr(NonNull::new(raw).unwrap());
        // The loader binds keys via EC_KEY_new_method, which needs an EC method
        // on the engine (bind_helper does this in production).
        engine.set_default_ec_method().unwrap();
        (engine, raw)
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use azihsm_api::HsmEccCurve;
    use azihsm_api::HsmEccKeyGenAlgo;
    use azihsm_api::HsmKeyClass;
    use azihsm_api::HsmKeyCommonProps;
    use azihsm_api::HsmKeyKind;
    use azihsm_api::HsmKeyManager;
    use azihsm_api::HsmKeyPropsBuilder;
    use azihsm_ossl_engine_core::ffi;
    use foreign_types::ForeignType;
    use openssl::ec::EcGroup;
    use openssl::ec::EcKey;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::pkey::Public;
    use openssl::sign::Verifier;
    use serial_test::serial;

    use super::*;

    /// Shared per-process MOBK path. The mock device's BK3 is global to the
    /// process: the first test establishes it (plaintext OBK) and the engine
    /// persists the MOBK here; later tests re-init from that MOBK (re-running
    /// init_bk3 fails). Shared across tests so the second open sees the first
    /// open's persisted MOBK.
    fn shared_mobk_path() -> PathBuf {
        std::env::temp_dir().join(format!("engine-test-mobk-{}.bin", std::process::id()))
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let pid = std::process::id();
            let dir = std::env::temp_dir().join(format!("engine-ctx-{tag}-{pid}-{n}"));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Materialize a fresh P-384 key pair on disk + a 48-byte OBK, return
    /// settings pointing at them with resiliency enabled.
    fn caller_settings(scratch: &Scratch) -> ResiliencySettings {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec).unwrap();
        // PKCS#8: FilePotaCallback signs via azihsm_crypto, which accepts only
        // that private-key format.
        let priv_der = pkey.private_key_to_pkcs8().unwrap();
        let pub_der = pkey.public_key_to_der().unwrap();

        let priv_path = scratch.0.join("pota_priv.der");
        let pub_path = scratch.0.join("pota_pub.der");
        let obk_path = scratch.0.join("obk.bin");
        fs::write(&priv_path, &priv_der).unwrap();
        fs::write(&pub_path, &pub_der).unwrap();
        fs::write(&obk_path, vec![0u8; 48]).unwrap();

        ResiliencySettings {
            enabled: true,
            storage_dir: scratch.0.join("res"),
            obk_source: HsmOwnerBackupKeySource::Caller,
            obk_path,
            mobk_path: shared_mobk_path(),
            pota_source: HsmPotaEndorsementSource::Caller,
            pota_priv_path: Some(priv_path),
            pota_pub_path: Some(pub_path),
        }
    }

    // `#[serial]`: these share the process-global mock device (BK3 state),
    // so they must not run concurrently.
    #[test]
    #[serial]
    fn open_hsm_with_resiliency_succeeds() {
        let scratch = Scratch::new("open");
        // The storage dir is created by the open path (setup_storage_dir) with
        // mode 0700; pre-creating it here would inherit the umask and could be
        // rejected, so leave it to the open path to stay umask-independent.
        let settings = caller_settings(&scratch);
        let creds = HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN);

        let data = EngineData::new();
        assert!(!data.is_hsm_open());
        data.open_hsm_with(settings, creds).unwrap();
        assert!(data.is_hsm_open());
    }

    /// Full engine key-load round trip: generate an EC key + its masked blob in
    /// the HSM, write the blob to disk, load it back through the engine's
    /// `load_private_key` path, and verify the returned EVP_PKEY's public key
    /// matches. Dropping the EVP_PKEY (no ex_data free callback) and then the
    /// EngineData (which deletes the loaded key from the HSM) must not crash.
    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn load_ec_key_round_trips_through_engine() {
        let scratch = Scratch::new("load");
        // Leave the `res` storage dir to the open path (setup_storage_dir),
        // which creates it mode 0700; pre-creating it here would inherit the
        // umask and be rejected as insecure (see open_hsm_with_resiliency_succeeds).
        let data = EngineData::new();
        data.open_hsm_with(
            caller_settings(&scratch),
            HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN),
        )
        .unwrap();

        // Generate a persistent EC P-384 key in the HSM and export its masked
        // blob (the form the engine loads).
        let (masked, expected_pub_der) = data
            .with_session(|session| {
                let priv_props = HsmKeyPropsBuilder::default()
                    .class(HsmKeyClass::Private)
                    .key_kind(HsmKeyKind::Ecc)
                    .ecc_curve(HsmEccCurve::P384)
                    .is_session(false)
                    .can_sign(true)
                    .build()
                    .unwrap();
                let pub_props = HsmKeyPropsBuilder::default()
                    .class(HsmKeyClass::Public)
                    .key_kind(HsmKeyKind::Ecc)
                    .ecc_curve(HsmEccCurve::P384)
                    .is_session(false)
                    .can_verify(true)
                    .build()
                    .unwrap();
                let mut algo = HsmEccKeyGenAlgo::default();
                let (priv_key, _pub) =
                    HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
                        .unwrap();
                Ok((
                    priv_key.masked_key_vec().unwrap(),
                    priv_key.pub_key_der_vec().unwrap(),
                ))
            })
            .unwrap();

        let blob_path = scratch.0.join("ec_key.bin");
        write_key_material(&blob_path, &masked).unwrap();

        let (engine, engine_raw) = new_test_engine();
        let uri = format!("azihsm://{};type=ec", blob_path.display());
        let raw = crate::keyload::load_key(&engine, &data, &uri).unwrap();
        assert!(!raw.is_null());

        // Take ownership of the returned EVP_PKEY, confirm its public key, then
        // drop it. The EC_KEY ex_data slot has no free callback, so this frees
        // only the OpenSSL objects; the HSM key is deleted when `data` drops.
        // SAFETY: raw is an owning *mut EVP_PKEY returned by load_key.
        let loaded: PKey<Public> = unsafe { PKey::from_ptr(raw.cast()) };
        assert_eq!(loaded.public_key_to_der().unwrap(), expected_pub_der);
        drop(loaded);

        // Release the test engine's structural ref; the loaded key already
        // released its functional ref when dropped above.
        // SAFETY: engine_raw is the ENGINE_new ref from new_test_engine.
        unsafe { azihsm_ossl_engine_core::ffi::ENGINE_free(engine_raw) };
    }

    // A signature produced through a loaded key (HSM sign via our EC_KEY_METHOD,
    // reached the same way the ABI and CLI do — EVP_DigestSign*) must verify
    // against the key's public half in software.
    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn sign_through_loaded_key_verifies() {
        let scratch = Scratch::new("sign");
        let data = EngineData::new();
        data.open_hsm_with(
            caller_settings(&scratch),
            HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN),
        )
        .unwrap();

        // Generate a persistent EC P-384 key and export its masked blob.
        let (masked, expected_pub_der) = data
            .with_session(|session| {
                let priv_props = HsmKeyPropsBuilder::default()
                    .class(HsmKeyClass::Private)
                    .key_kind(HsmKeyKind::Ecc)
                    .ecc_curve(HsmEccCurve::P384)
                    .is_session(false)
                    .can_sign(true)
                    .build()
                    .unwrap();
                let pub_props = HsmKeyPropsBuilder::default()
                    .class(HsmKeyClass::Public)
                    .key_kind(HsmKeyKind::Ecc)
                    .ecc_curve(HsmEccCurve::P384)
                    .is_session(false)
                    .can_verify(true)
                    .build()
                    .unwrap();
                let mut algo = HsmEccKeyGenAlgo::default();
                let (priv_key, _pub) =
                    HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
                        .unwrap();
                Ok((
                    priv_key.masked_key_vec().unwrap(),
                    priv_key.pub_key_der_vec().unwrap(),
                ))
            })
            .unwrap();

        let blob_path = scratch.0.join("ec_key.bin");
        write_key_material(&blob_path, &masked).unwrap();
        let (engine, engine_raw) = new_test_engine();
        let uri = format!("azihsm://{};type=ec", blob_path.display());
        let raw = crate::keyload::load_key(&engine, &data, &uri).unwrap();
        assert!(!raw.is_null());

        // Sign through the loaded key, then take ownership of the EVP_PKEY so it
        // is freed below.
        let msg = b"engine ecdsa signing over the EVP/ABI path";
        let sig = evp_digest_sign_sha384(raw, msg);
        assert!(!sig.is_empty(), "engine produced an empty signature");
        // SAFETY: raw is an owning *mut EVP_PKEY returned by load_key.
        let loaded: PKey<Public> = unsafe { PKey::from_ptr(raw.cast()) };

        // Verify in software against the public key: proves the HSM signed the
        // right digest with the matching private key.
        let pubkey = PKey::public_key_from_der(&expected_pub_der).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha384(), &pubkey).unwrap();
        verifier.update(msg).unwrap();
        assert!(
            verifier.verify(&sig).unwrap(),
            "engine ECDSA signature must verify against the public key"
        );

        // Drop the loaded key (releases its functional engine ref), then release
        // the test engine's structural ref.
        drop(loaded);
        // SAFETY: engine_raw is the ENGINE_new ref from new_test_engine.
        unsafe { azihsm_ossl_engine_core::ffi::ENGINE_free(engine_raw) };
    }

    /// Sign `msg` (SHA-384) through `pkey` via OpenSSL's EVP interface — the same
    /// path the ABI and `openssl dgst -sign` take. Exercises the loaded key's
    /// `EC_KEY_METHOD` `sign_sig` (→ HSM).
    #[allow(unsafe_code)]
    fn evp_digest_sign_sha384(pkey: *mut ffi::EVP_PKEY, msg: &[u8]) -> Vec<u8> {
        // SAFETY: pkey is a valid EVP_PKEY; the calls follow the EVP_DigestSign
        // contract and every return code is checked.
        unsafe {
            let ctx = ffi::EVP_MD_CTX_new();
            assert!(!ctx.is_null());
            let md = ffi::EVP_sha384();
            assert_eq!(
                ffi::EVP_DigestSignInit(ctx, std::ptr::null_mut(), md, std::ptr::null_mut(), pkey),
                1,
                "EVP_DigestSignInit"
            );
            assert_eq!(
                ffi::EVP_DigestUpdate(ctx, msg.as_ptr().cast(), msg.len()),
                1,
                "EVP_DigestUpdate"
            );
            let mut siglen: usize = 0;
            assert_eq!(
                ffi::EVP_DigestSignFinal(ctx, std::ptr::null_mut(), &mut siglen),
                1,
                "EVP_DigestSignFinal (size query)"
            );
            let mut sig = vec![0u8; siglen];
            assert_eq!(
                ffi::EVP_DigestSignFinal(ctx, sig.as_mut_ptr(), &mut siglen),
                1,
                "EVP_DigestSignFinal"
            );
            sig.truncate(siglen);
            ffi::EVP_MD_CTX_free(ctx);
            sig
        }
    }

    #[test]
    #[serial]
    fn open_hsm_is_idempotent() {
        let scratch = Scratch::new("idem");
        // See open_hsm_with_resiliency_succeeds: let the open path create the
        // storage dir at 0700 rather than depending on the umask here.
        let data = EngineData::new();
        let creds = HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN);

        data.open_hsm_with(
            caller_settings(&scratch),
            HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN),
        )
        .unwrap();
        // Second call must not panic, must not re-open, must succeed.
        data.open_hsm_with(caller_settings(&scratch), creds)
            .unwrap();
        assert!(data.is_hsm_open());
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert!(hex_decode_16("abcd", "X").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        let s = "g".repeat(32);
        assert!(hex_decode_16(&s, "X").is_err());
    }

    #[test]
    fn hex_decode_round_trip() {
        let s = "000102030405060708090a0b0c0d0e0f";
        assert_eq!(
            hex_decode_16(s, "X").unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    // An unset credential with no default must be a hard error, not a silent
    // fallback. (In production builds cred_field is called with None.)
    #[test]
    fn cred_field_missing_without_default_errors() {
        let r = cred_field("AZIHSM_CRED_FIELD_DEFINITELY_UNSET_XYZ", None);
        assert!(matches!(r, Err(EngineError::Other(_))));
    }

    #[test]
    fn cred_field_missing_with_default_uses_default() {
        let def = [7u8; 16];
        let got = cred_field("AZIHSM_CRED_FIELD_DEFINITELY_UNSET_XYZ", Some(def)).unwrap();
        assert_eq!(got, def);
    }
}

/// Hardware smoke test. Drives the full device open (`open_hsm_from_env`:
/// partition open → init → session) using the ambient `AZIHSM_*` environment,
/// so a real HSM host can validate a configuration end to end — e.g. the TPM
/// OBK/POTA sources, which the mock cannot exercise.
///
/// Compiled only in non-mock builds and `#[ignore]`d, so it never runs in the
/// normal (mock) CI cell — invoke it explicitly on a provisioned host:
///
/// ```text
/// export AZIHSM_CREDENTIALS_ID=<32 hex>  AZIHSM_CREDENTIALS_PIN=<32 hex>
/// export AZIHSM_RESILIENCY_ENABLED=1        # turns on resiliency persistence (storage dir + MOBK/POTA callbacks)
/// export AZIHSM_OBK_SOURCE=tpm  AZIHSM_POTA_SOURCE=tpm  # source selection applies regardless of the flag above
/// # Storage dir must already exist, be mode 0700, and be owned by you. The
/// # default is /var/lib/azihsm/resiliency; create it once (override with
/// # AZIHSM_RESILIENCY_STORAGE_DIR to use e.g. a path under $HOME):
/// sudo install -d -m 700 -o "$USER" /var/lib/azihsm/resiliency
/// umask 0077
/// cargo test -p azihsm_ossl_engine --features engine open_from_env_smoke -- --ignored --nocapture
/// ```
#[cfg(all(test, not(feature = "mock")))]
mod hw_tests {
    use azihsm_api::HsmEccCurve;
    use azihsm_api::HsmEccKeyGenAlgo;
    use azihsm_api::HsmKeyClass;
    use azihsm_api::HsmKeyCommonProps;
    use azihsm_api::HsmKeyKind;
    use azihsm_api::HsmKeyManager;
    use azihsm_api::HsmKeyPropsBuilder;
    use foreign_types::ForeignType;
    use openssl::pkey::PKey;
    use openssl::pkey::Public;

    use super::*;

    #[test]
    #[ignore = "requires a provisioned HSM host; configure AZIHSM_* env first"]
    fn open_from_env_smoke() -> EngineResult<()> {
        let data = EngineData::new();
        data.open_hsm_from_env()?;
        assert!(
            data.is_hsm_open(),
            "HSM should be open after open_hsm_from_env"
        );
        Ok(())
    }

    /// Hardware key-loading round trip. Generates a persistent EC P-384 key on
    /// the device, exports its masked blob, loads it back through the engine's
    /// `load_private_key` path, and verifies the returned EVP_PKEY's public key
    /// matches. Dropping the EVP_PKEY, then the EngineData (which deletes the
    /// loaded key from the HSM), must not crash.
    /// `tests::load_ec_key_round_trips_through_engine` covers this against the
    /// mock; this runs the same cycle on a real device.
    ///
    /// Same env setup as `open_from_env_smoke` (configure `AZIHSM_*` first):
    ///
    /// ```text
    /// cargo test -p azihsm_ossl_engine --features engine load_ec_key_from_env_smoke -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires a provisioned HSM host; configure AZIHSM_* env first"]
    #[allow(unsafe_code)]
    fn load_ec_key_from_env_smoke() -> EngineResult<()> {
        let data = EngineData::new();
        data.open_hsm_from_env()?;

        // Generate a persistent EC P-384 key on the device and export the masked
        // blob (the form the engine loads).
        let (masked, expected_pub_der) = data.with_session(|session| {
            let priv_props = HsmKeyPropsBuilder::default()
                .class(HsmKeyClass::Private)
                .key_kind(HsmKeyKind::Ecc)
                .ecc_curve(HsmEccCurve::P384)
                .is_session(false)
                .can_sign(true)
                .build()
                .map_err(|e| EngineError::wrap("build private key props", e))?;
            let pub_props = HsmKeyPropsBuilder::default()
                .class(HsmKeyClass::Public)
                .key_kind(HsmKeyKind::Ecc)
                .ecc_curve(HsmEccCurve::P384)
                .is_session(false)
                .can_verify(true)
                .build()
                .map_err(|e| EngineError::wrap("build public key props", e))?;
            let mut algo = HsmEccKeyGenAlgo::default();
            let (priv_key, _pub) =
                HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
                    .map_err(|e| EngineError::wrap("generate EC key pair", e))?;
            Ok((
                priv_key
                    .masked_key_vec()
                    .map_err(|e| EngineError::wrap("export masked key", e))?,
                priv_key
                    .pub_key_der_vec()
                    .map_err(|e| EngineError::wrap("read public key DER", e))?,
            ))
        })?;

        let blob_path =
            std::env::temp_dir().join(format!("engine-hw-ec-{}.bin", std::process::id()));
        // Clear any leftover from a prior crashed run so the O_EXCL create in
        // write_key_material succeeds.
        let _ = std::fs::remove_file(&blob_path);
        write_key_material(&blob_path, &masked).map_err(|e| {
            EngineError::wrap(format!("write masked blob {}", blob_path.display()), e)
        })?;

        let (engine, engine_raw) = new_test_engine();
        let uri = format!("azihsm://{};type=ec", blob_path.display());
        let raw = crate::keyload::load_key(&engine, &data, &uri)?;
        assert!(!raw.is_null(), "load_key returned a NULL EVP_PKEY");

        // Take ownership of the returned key, confirm its public half, then drop
        // it. The ex_data slot has no free callback; the HSM key is deleted when
        // `data` drops at the end of the test.
        // SAFETY: raw is an owning *mut EVP_PKEY returned by load_key.
        let loaded: PKey<Public> = unsafe { PKey::from_ptr(raw.cast()) };
        let loaded_der = loaded
            .public_key_to_der()
            .map_err(|e| EngineError::wrap("encode loaded public key", e))?;
        assert_eq!(loaded_der, expected_pub_der, "loaded public key mismatch");
        drop(loaded);

        // Release the test engine's structural ref (the loaded key released its
        // functional ref when dropped above).
        // SAFETY: engine_raw is the ENGINE_new ref from new_test_engine.
        unsafe { azihsm_ossl_engine_core::ffi::ENGINE_free(engine_raw) };

        let _ = std::fs::remove_file(&blob_path);
        Ok(())
    }
}
