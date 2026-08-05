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

#[cfg(test)]
mod tests;
