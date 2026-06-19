// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Environment-variable-driven assembly of [`HsmResiliencyConfig`].
//!
//! The engine reads its resiliency configuration from `AZIHSM_*` environment
//! variables, captures them into [`ResiliencySettings`], and turns them into
//! an SDK [`HsmResiliencyConfig`] for the 6th argument of
//! `HsmPartition::init`.
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
const LOCK_FILE_NAME: &str = ".lock";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("env var {0} contains invalid value {1:?} (expected one of {2})")]
    InvalidValue(&'static str, String, &'static str),

    #[error("env var {0} is required but unset")]
    Missing(&'static str),
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
    /// the module docs. Returns an error for malformed values; missing
    /// optional vars fall back to their defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        let enabled = parse_bool(ENV_ENABLED, &std::env::var(ENV_ENABLED).unwrap_or_default())?;
        let storage_dir = std::env::var(ENV_STORAGE_DIR)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_STORAGE_DIR));
        let obk_source = parse_obk_source(&std::env::var(ENV_OBK_SOURCE).unwrap_or_default())?;
        let obk_path = std::env::var(ENV_OBK_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_OBK_PATH));
        let mobk_path = std::env::var(ENV_MOBK_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_MOBK_PATH));
        let pota_source = parse_pota_source(&std::env::var(ENV_POTA_SOURCE).unwrap_or_default())?;
        let pota_priv_path = std::env::var(ENV_POTA_PRIV).ok().map(PathBuf::from);
        let pota_pub_path = std::env::var(ENV_POTA_PUB).ok().map(PathBuf::from);

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

        let lock_path = self.storage_dir.join(LOCK_FILE_NAME);

        Ok(Some(HsmResiliencyConfig {
            storage: Box::new(FileStorage::new(self.storage_dir)),
            lock: Arc::new(FileLock::new(lock_path)),
            pota_callback,
            mobk_callback,
        }))
    }
}

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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

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
        let s = caller_caller_settings(PathBuf::from("/tmp/x"));
        let cfg = s.into_resiliency_config().unwrap().unwrap();
        assert!(cfg.pota_callback.is_some());
        assert!(cfg.mobk_callback.is_some());
    }

    #[test]
    fn tpm_obk_drops_obk_callback() {
        let mut s = caller_caller_settings(PathBuf::from("/tmp/x"));
        s.obk_source = HsmOwnerBackupKeySource::Tpm;
        let cfg = s.into_resiliency_config().unwrap().unwrap();
        assert!(cfg.mobk_callback.is_none());
        assert!(cfg.pota_callback.is_some());
    }

    #[test]
    fn tpm_pota_drops_pota_callback() {
        let mut s = caller_caller_settings(PathBuf::from("/tmp/x"));
        s.pota_source = HsmPotaEndorsementSource::Tpm;
        let cfg = s.into_resiliency_config().unwrap().unwrap();
        assert!(cfg.pota_callback.is_none());
        assert!(cfg.mobk_callback.is_some());
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
