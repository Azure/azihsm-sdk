// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The engine is Linux-only; gate the whole crate so non-Linux targets (the
// workspace `build_windows` clippy) don't pull `openssl-sys`.
#![cfg(target_os = "linux")]

//! File-backed resiliency primitives for the engine:
//! [`FileStorage`] / [`FileLock`] for SDK-internal state and
//! [`FilePotaCallback`] / [`FileMobkCallback`] for caller-side material.
//!
//! Writes through `FileStorage` go via temp file + `fsync` + `rename(2)`
//! + directory fsync, so the on-disk state is crash-consistent.

mod callbacks;
mod config;
#[cfg(test)]
mod test_util;

use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use azihsm_api::HsmError;
use azihsm_api::HsmResult;
use azihsm_api::ResiliencyLock;
use azihsm_api::ResiliencyStorage;
pub use callbacks::FileMobkCallback;
pub use callbacks::FilePotaCallback;
pub use config::ConfigError;
pub use config::ResiliencySettings;
use fs2::FileExt;
use parking_lot::Mutex;

/// File-backed storage: one file per key under `dir`. Writes are durable.
pub struct FileStorage {
    dir: PathBuf,
}

impl FileStorage {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl ResiliencyStorage for FileStorage {
    fn read(&self, key: &str) -> HsmResult<Vec<u8>> {
        let mut file = fs::File::open(self.dir.join(key)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                HsmError::NotFound
            } else {
                HsmError::InternalError
            }
        })?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|_| HsmError::InternalError)?;
        Ok(buf)
    }

    fn write(&self, key: &str, data: &[u8]) -> HsmResult<()> {
        let path = self.dir.join(key);
        let tmp_path = self.dir.join(format!(".{key}.tmp"));

        let result = (|| -> HsmResult<()> {
            let mut file = fs::File::create(&tmp_path).map_err(|_| HsmError::InternalError)?;
            file.write_all(data).map_err(|_| HsmError::InternalError)?;
            file.sync_all().map_err(|_| HsmError::InternalError)?;
            rename_atomic(&tmp_path, &path).map_err(|_| HsmError::InternalError)?;
            let dir = fs::File::open(&self.dir).map_err(|_| HsmError::InternalError)?;
            dir.sync_all().map_err(|_| HsmError::InternalError)
        })();

        if result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        result
    }

    fn clear(&self, key: &str) -> HsmResult<()> {
        let _ = fs::remove_file(self.dir.join(key));
        Ok(())
    }
}

/// Atomically replace `to` with `from`. On Linux `rename(2)` is atomic and
/// replaces an existing target.
fn rename_atomic(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)
}

/// Cross-process / cross-thread lock backed by `flock(2)` on a lock file.
///
/// Opens a new file descriptor per [`lock`](Self::lock) call: `flock(2)`
/// operates per open-file-description, so reusing a single descriptor
/// would let a second thread acquire the same lock immediately. Reentrant
/// lock() on the same instance is rejected; the OS lock from the second
/// `open` is released before returning.
pub struct FileLock {
    path: PathBuf,
    active: Mutex<Option<fs::File>>,
}

impl FileLock {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            active: Mutex::new(None),
        }
    }
}

impl ResiliencyLock for FileLock {
    fn lock(&self) -> HsmResult<()> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .map_err(|_| HsmError::InternalError)?;
        file.lock_exclusive().map_err(|_| HsmError::InternalError)?;

        let mut guard = self.active.lock();
        if guard.is_some() {
            let _ = file.unlock();
            return Err(HsmError::InternalError);
        }
        *guard = Some(file);
        Ok(())
    }

    fn unlock(&self) -> HsmResult<()> {
        match self.active.lock().take() {
            Some(file) => file.unlock().map_err(|_| HsmError::InternalError),
            None => Err(HsmError::InternalError),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::test_util::Scratch;

    #[test]
    fn write_then_read_round_trip() {
        let scratch = Scratch::new("rw");
        let s = FileStorage::new(scratch.0.clone());

        s.write("k", b"value").unwrap();
        assert_eq!(s.read("k").unwrap(), b"value");
    }

    #[test]
    fn write_overwrites_atomically() {
        let scratch = Scratch::new("ow");
        let s = FileStorage::new(scratch.0.clone());

        s.write("k", b"first").unwrap();
        s.write("k", b"second").unwrap();
        assert_eq!(s.read("k").unwrap(), b"second");
    }

    #[test]
    fn read_missing_returns_not_found() {
        let scratch = Scratch::new("miss");
        let s = FileStorage::new(scratch.0.clone());

        assert!(matches!(s.read("absent"), Err(HsmError::NotFound)));
    }

    #[test]
    fn clear_is_idempotent() {
        let scratch = Scratch::new("clr");
        let s = FileStorage::new(scratch.0.clone());

        s.clear("never-existed").unwrap();
        s.write("k", b"x").unwrap();
        s.clear("k").unwrap();
        assert!(matches!(s.read("k"), Err(HsmError::NotFound)));
    }

    #[test]
    fn lock_unlock_round_trip() {
        let scratch = Scratch::new("lk");
        let l = FileLock::new(scratch.0.join("lock"));

        l.lock().unwrap();
        l.unlock().unwrap();
        l.lock().unwrap();
        l.unlock().unwrap();
    }

    #[test]
    fn unlock_without_lock_errors() {
        let scratch = Scratch::new("ul");
        let l = FileLock::new(scratch.0.join("lock"));

        assert!(l.unlock().is_err());
    }
}
