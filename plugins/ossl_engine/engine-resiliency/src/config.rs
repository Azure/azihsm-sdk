// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Environment-variable-driven resiliency configuration.
//!
//! The engine reads its resiliency settings from `AZIHSM_*` environment
//! variables and captures them into [`ResiliencySettings`].
//! [`ResiliencySettings::into_resiliency_config`] turns the relevant subset
//! (storage dir, lock, and the POTA / MOBK callbacks) into an SDK
//! [`HsmResiliencyConfig`] for the 6th argument of `HsmPartition::init`.
//!
//! Not every field feeds that config: the plaintext-OBK input (`obk_path`)
//! is consumed by the engine's init/lifecycle layer to build the
//! `HsmOwnerBackupKeyConfig` for cold init, not by `into_resiliency_config`.
//!
//! # Environment variables
//!
//! | Var                              | Default                          | Notes |
//! |----------------------------------|----------------------------------|-------|
//! | `AZIHSM_RESILIENCY_ENABLED`      | unset (off)                      | `1` / `true` → on |
//! | `AZIHSM_RESILIENCY_STORAGE_DIR`  | `/var/lib/azihsm/resiliency`     | storage dir |
//! | `AZIHSM_OBK_SOURCE`              | `caller`                         | `caller` or `tpm` |
//! | `AZIHSM_OBK_PATH`                | `./obk.bin`                      | plaintext OBK, first init; used when `OBK_SOURCE=caller` |
//! | `AZIHSM_MOBK_PATH`               | `./mobk.bin`                     | cached MOBK, written after init / read to re-init a warm device |
//! | `AZIHSM_POTA_SOURCE`             | `caller`                         | `caller` or `tpm` |
//! | `AZIHSM_POTA_PRIVATE_KEY_PATH`   | none                             | required when `POTA_SOURCE=caller` and resiliency enabled |
//! | `AZIHSM_POTA_PUBLIC_KEY_PATH`    | none                             | same |

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use azihsm_api::HsmOwnerBackupKeySource;
use azihsm_api::HsmPotaEndorsementSource;
use azihsm_api::HsmResiliencyConfig;

use crate::FileLock;
use crate::FileMobkCallback;
use crate::FilePotaCallback;
use crate::FileStorage;

const ENV_ENABLED: &str = "AZIHSM_RESILIENCY_ENABLED";
const ENV_STORAGE_DIR: &str = "AZIHSM_RESILIENCY_STORAGE_DIR";
const ENV_OBK_SOURCE: &str = "AZIHSM_OBK_SOURCE";
const ENV_OBK_PATH: &str = "AZIHSM_OBK_PATH";
const ENV_MOBK_PATH: &str = "AZIHSM_MOBK_PATH";
const ENV_POTA_SOURCE: &str = "AZIHSM_POTA_SOURCE";
const ENV_POTA_PRIV: &str = "AZIHSM_POTA_PRIVATE_KEY_PATH";
const ENV_POTA_PUB: &str = "AZIHSM_POTA_PUBLIC_KEY_PATH";

const DEFAULT_STORAGE_DIR: &str = "/var/lib/azihsm/resiliency";
const DEFAULT_OBK_PATH: &str = "./obk.bin";
const DEFAULT_MOBK_PATH: &str = "./mobk.bin";

/// Error from reading the engine's resiliency environment variables.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("env var {0} contains invalid value {1:?} (expected one of {2})")]
    InvalidValue(&'static str, String, &'static str),

    #[error("env var {0} is required but unset")]
    Missing(&'static str),

    #[error("resiliency storage directory {0:?} could not be created or is insecure")]
    StorageDir(PathBuf),

    #[error("env var {0} has unsafe path {1:?} (must be non-empty and contain no \"..\")")]
    UnsafePath(&'static str, PathBuf),
}

/// Parsed view of the engine's resiliency-related environment variables.
#[derive(Debug, Clone)]
pub struct ResiliencySettings {
    pub enabled: bool,
    pub storage_dir: PathBuf,
    pub obk_source: HsmOwnerBackupKeySource,
    /// Plaintext OBK (BK3) used for the *first* `init` on a power cycle.
    pub obk_path: PathBuf,
    /// Caller-persisted MOBK (masked OBK): written after each successful init
    /// and read back to re-init a warm device, since re-running `init_bk3`
    /// fails with `Bk3AlreadyInitialized`. Mirrors the provider's
    /// `azihsm-mobk-path`.
    pub mobk_path: PathBuf,
    pub pota_source: HsmPotaEndorsementSource,
    pub pota_priv_path: Option<PathBuf>,
    pub pota_pub_path: Option<PathBuf>,
}

impl ResiliencySettings {
    /// Read settings from the process environment, applying defaults from
    /// the module docs. An empty value is treated as unset (falls back to the
    /// default, or `None` for optional vars). Returns an error for malformed
    /// values or unsafe paths (empty or containing `..`).
    pub fn from_env() -> Result<Self, ConfigError> {
        let enabled = parse_bool(ENV_ENABLED, &std::env::var(ENV_ENABLED).unwrap_or_default())?;
        let storage_dir = env_nonempty(ENV_STORAGE_DIR)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STORAGE_DIR));
        // Sources parse (and can error on a bad value) only when enabled; a
        // disabled engine must not fail over a var it will never use.
        let obk_source = if enabled {
            parse_obk_source(&std::env::var(ENV_OBK_SOURCE).unwrap_or_default())?
        } else {
            HsmOwnerBackupKeySource::Caller
        };
        let obk_path = env_nonempty(ENV_OBK_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_OBK_PATH));
        let mobk_path = env_nonempty(ENV_MOBK_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MOBK_PATH));
        let pota_source = if enabled {
            parse_pota_source(&std::env::var(ENV_POTA_SOURCE).unwrap_or_default())?
        } else {
            HsmPotaEndorsementSource::Caller
        };
        let pota_priv_path = env_nonempty(ENV_POTA_PRIV).map(PathBuf::from);
        let pota_pub_path = env_nonempty(ENV_POTA_PUB).map(PathBuf::from);

        // Reject unsafe paths up front (mirrors the provider's path_is_safe),
        // but only those that will actually be used: a disabled engine, or a
        // `tpm` source whose file paths are ignored, must not fail to start
        // over a path it will never read.
        if enabled {
            validate_path(ENV_STORAGE_DIR, &storage_dir)?;
            if matches!(obk_source, HsmOwnerBackupKeySource::Caller) {
                validate_path(ENV_OBK_PATH, &obk_path)?;
                validate_path(ENV_MOBK_PATH, &mobk_path)?;
            }
            if matches!(pota_source, HsmPotaEndorsementSource::Caller) {
                if let Some(p) = &pota_priv_path {
                    validate_path(ENV_POTA_PRIV, p)?;
                }
                if let Some(p) = &pota_pub_path {
                    validate_path(ENV_POTA_PUB, p)?;
                }
            }
        }

        Ok(Self {
            enabled,
            storage_dir,
            obk_source,
            obk_path,
            mobk_path,
            pota_source,
            pota_priv_path,
            pota_pub_path,
        })
    }

    /// Assemble an `HsmResiliencyConfig`, or `None` if resiliency is off.
    ///
    /// When `pota_source` is `Caller`, both `pota_priv_path` and
    /// `pota_pub_path` must be set.
    pub fn into_resiliency_config(self) -> Result<Option<HsmResiliencyConfig>, ConfigError> {
        if !self.enabled {
            return Ok(None);
        }

        let pota_callback = match self.pota_source {
            HsmPotaEndorsementSource::Caller => {
                let priv_path = self
                    .pota_priv_path
                    .ok_or(ConfigError::Missing(ENV_POTA_PRIV))?;
                let pub_path = self
                    .pota_pub_path
                    .ok_or(ConfigError::Missing(ENV_POTA_PUB))?;
                Some(Box::new(FilePotaCallback::new(priv_path, pub_path)) as _)
            }
            _ => None,
        };

        // The restore-time MOBK provider reads the caller-persisted MOBK.
        let mobk_callback = match self.obk_source {
            HsmOwnerBackupKeySource::Caller => {
                Some(Box::new(FileMobkCallback::new(self.mobk_path)) as _)
            }
            _ => None,
        };

        setup_storage_dir(&self.storage_dir)?;
        let lock_path = self.storage_dir.join(crate::LOCK_FILE_NAME);

        Ok(Some(HsmResiliencyConfig {
            storage: Box::new(FileStorage::new(self.storage_dir)),
            lock: Arc::new(FileLock::new(lock_path)),
            pota_callback,
            mobk_callback,
        }))
    }
}

/// Parse a boolean env value (`1`/`true`/`yes`/`on` vs `0`/`false`/`no`/`off`,
/// case-insensitive); empty parses as `false`.
fn parse_bool(var: &'static str, raw: &str) -> Result<bool, ConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => Ok(false),
        "1" | "true" | "yes" | "on" => Ok(true),
        _ => Err(ConfigError::InvalidValue(
            var,
            raw.to_owned(),
            "1/true/yes/on or 0/false/no/off",
        )),
    }
}

/// Parse the OBK source env value: `caller` (or empty, the default) or `tpm`.
fn parse_obk_source(raw: &str) -> Result<HsmOwnerBackupKeySource, ConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "caller" => Ok(HsmOwnerBackupKeySource::Caller),
        "tpm" => Ok(HsmOwnerBackupKeySource::Tpm),
        _ => Err(ConfigError::InvalidValue(
            ENV_OBK_SOURCE,
            raw.to_owned(),
            "caller or tpm",
        )),
    }
}

/// Parse the POTA source env value: `caller` (or empty, the default) or `tpm`.
fn parse_pota_source(raw: &str) -> Result<HsmPotaEndorsementSource, ConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "caller" => Ok(HsmPotaEndorsementSource::Caller),
        "tpm" => Ok(HsmPotaEndorsementSource::Tpm),
        _ => Err(ConfigError::InvalidValue(
            ENV_POTA_SOURCE,
            raw.to_owned(),
            "caller or tpm",
        )),
    }
}

/// Read an env var, treating unset or empty as "not provided" (mirrors the
/// provider's `dir_env[0] != '\0'` check).
fn env_nonempty(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Reject an empty path or one containing `..`. Mirrors the provider's
/// `azihsm_path_is_safe` so a configured path can't escape its intended tree.
fn validate_path(var: &'static str, path: &Path) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains("..") {
        return Err(ConfigError::UnsafePath(var, path.to_path_buf()));
    }
    Ok(())
}

/// Current process UID; `getuid(2)` takes no arguments and cannot fail.
#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: getuid() has no preconditions and always succeeds.
    unsafe { libc::getuid() }
}

/// Create `dir` with mode `0700`, or, if it already exists, require it to be a
/// real directory owned by us with no group/other permissions. Mirrors the
/// provider's storage-directory setup so misconfiguration fails up front
/// rather than as a generic IO error on the first write.
fn setup_storage_dir(dir: &Path) -> Result<(), ConfigError> {
    let err = || ConfigError::StorageDir(dir.to_path_buf());
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // symlink_metadata (lstat) so a symlink at `dir` is rejected here
            // rather than silently followed.
            let meta = fs::symlink_metadata(dir).map_err(|_| err())?;
            // Require exactly owner-rwx, no group/other (i.e. mode 0700, what
            // we create above): rejecting too-loose perms protects the key
            // material, and rejecting too-tight owner perms surfaces the
            // misconfig here rather than as a generic IO error on first write.
            if !meta.is_dir() || meta.uid() != current_uid() || meta.mode() & 0o777 != 0o700 {
                return Err(err());
            }
            Ok(())
        }
        Err(_) => Err(err()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::test_util::Scratch;

    fn caller_caller_settings(storage: PathBuf) -> ResiliencySettings {
        ResiliencySettings {
            enabled: true,
            storage_dir: storage,
            obk_source: HsmOwnerBackupKeySource::Caller,
            obk_path: PathBuf::from("./obk.bin"),
            mobk_path: PathBuf::from("./mobk.bin"),
            pota_source: HsmPotaEndorsementSource::Caller,
            pota_priv_path: Some(PathBuf::from("priv.der")),
            pota_pub_path: Some(PathBuf::from("pub.der")),
        }
    }

    #[test]
    fn disabled_yields_none() {
        let mut s = caller_caller_settings(PathBuf::from("/tmp/x"));
        s.enabled = false;
        assert!(s.into_resiliency_config().unwrap().is_none());
    }

    #[test]
    fn caller_sources_get_both_callbacks() {
        let scratch = Scratch::new("cfg-both");
        let s = caller_caller_settings(scratch.0.join("store"));
        let cfg = s.into_resiliency_config().unwrap().unwrap();
        assert!(cfg.pota_callback.is_some());
        assert!(cfg.mobk_callback.is_some());
    }

    #[test]
    fn tpm_obk_drops_obk_callback() {
        let scratch = Scratch::new("cfg-tpmobk");
        let mut s = caller_caller_settings(scratch.0.join("store"));
        s.obk_source = HsmOwnerBackupKeySource::Tpm;
        let cfg = s.into_resiliency_config().unwrap().unwrap();
        assert!(cfg.mobk_callback.is_none());
        assert!(cfg.pota_callback.is_some());
    }

    #[test]
    fn tpm_pota_drops_pota_callback() {
        let scratch = Scratch::new("cfg-tpmpota");
        let mut s = caller_caller_settings(scratch.0.join("store"));
        s.pota_source = HsmPotaEndorsementSource::Tpm;
        let cfg = s.into_resiliency_config().unwrap().unwrap();
        assert!(cfg.pota_callback.is_none());
        assert!(cfg.mobk_callback.is_some());
    }

    #[test]
    fn creates_storage_dir_with_owner_only_perms() {
        let scratch = Scratch::new("cfg-mk");
        let dir = scratch.0.join("store");
        let s = caller_caller_settings(dir.clone());
        assert!(s.into_resiliency_config().is_ok());
        let mode = fs::symlink_metadata(&dir).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700, "created storage dir must be 0700");
    }

    #[test]
    fn rejects_group_or_other_accessible_storage_dir() {
        let scratch = Scratch::new("cfg-perm");
        let dir = scratch.0.join("store");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let s = caller_caller_settings(dir);
        assert!(matches!(
            s.into_resiliency_config(),
            Err(ConfigError::StorageDir(_))
        ));
    }

    #[test]
    fn rejects_storage_dir_with_too_tight_owner_perms() {
        // An existing dir missing owner write/exec passes the group/other
        // check but would fail later on first write; reject it up front.
        let scratch = Scratch::new("cfg-tight");
        let dir = scratch.0.join("store");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o400)).unwrap();
        let s = caller_caller_settings(dir);
        assert!(matches!(
            s.into_resiliency_config(),
            Err(ConfigError::StorageDir(_))
        ));
    }

    #[test]
    fn caller_pota_without_priv_path_errors() {
        let mut s = caller_caller_settings(PathBuf::from("/tmp/x"));
        s.pota_priv_path = None;
        assert!(matches!(
            s.into_resiliency_config(),
            Err(ConfigError::Missing(ENV_POTA_PRIV))
        ));
    }

    #[test]
    fn parse_bool_accepts_common_truthy_values() {
        for v in ["1", "true", "TRUE", "yes", "on"] {
            assert!(parse_bool("X", v).unwrap(), "expected {v} to parse true");
        }
        for v in ["", "0", "false", "no", "off"] {
            assert!(!parse_bool("X", v).unwrap(), "expected {v} to parse false");
        }
        assert!(matches!(
            parse_bool("X", "maybe"),
            Err(ConfigError::InvalidValue("X", _, _))
        ));
    }

    #[test]
    fn validate_path_rejects_unsafe_and_empty() {
        assert!(validate_path("X", Path::new("")).is_err());
        assert!(validate_path("X", Path::new("..")).is_err());
        assert!(validate_path("X", Path::new("../escape")).is_err());
        assert!(validate_path("X", Path::new("/var/lib/azihsm/../x")).is_err());
        assert!(validate_path("X", Path::new("/var/lib/azihsm/resiliency")).is_ok());
        assert!(validate_path("X", Path::new("./obk.bin")).is_ok());
    }

    #[test]
    fn parse_obk_source_handles_known_values() {
        assert_eq!(
            parse_obk_source("").unwrap(),
            HsmOwnerBackupKeySource::Caller
        );
        assert_eq!(
            parse_obk_source("caller").unwrap(),
            HsmOwnerBackupKeySource::Caller
        );
        assert_eq!(
            parse_obk_source("TPM").unwrap(),
            HsmOwnerBackupKeySource::Tpm
        );
        assert!(matches!(
            parse_obk_source("hardware"),
            Err(ConfigError::InvalidValue(_, _, _))
        ));
    }
}
