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
use std::os::unix::fs::OpenOptionsExt;
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

/// Max length of a storage key, mirroring the provider's `MAX_KEY_NAME_LEN`.
const MAX_KEY_NAME_LEN: usize = 256;

/// Cap on a single resiliency file, mirroring the provider's
/// `MAX_STORAGE_FILE_SIZE`. Bounds reads/writes against disk-fill and runaway
/// allocation on subsequent reads.
const MAX_STORAGE_FILE_SIZE: u64 = 64 * 1024;

/// Reject empty, over-long, or path-traversal keys, as well as keys with a
/// separator or interior NUL, so `dir.join(key)` can never escape the storage
/// directory and an invalid key always maps to `InvalidArgument` (not a later
/// `InternalError`). Mirrors the provider's `build_storage_path` validation.
fn validate_key(key: &str) -> HsmResult<()> {
    if key.is_empty() || key.len() > MAX_KEY_NAME_LEN {
        return Err(HsmError::InvalidArgument);
    }
    if key.contains('/') || key.contains('\0') || key == ".." || key.contains("../") {
        return Err(HsmError::InvalidArgument);
    }
    Ok(())
}

/// Map a file IO error to an `HsmError`, preserving "not found".
pub(crate) fn io_to_hsm(e: std::io::Error) -> HsmError {
    if e.kind() == std::io::ErrorKind::NotFound {
        HsmError::NotFound
    } else {
        HsmError::InternalError
    }
}

/// Open `path` for reading without following a final-component symlink
/// (`O_NOFOLLOW`) and without blocking on special files (`O_NONBLOCK`),
/// require it to be a regular file, and read at most [`MAX_STORAGE_FILE_SIZE`]
/// bytes. Mirrors the provider's hardened secret-material loads.
pub(crate) fn read_regular_hardened(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    let too_large =
        || std::io::Error::new(std::io::ErrorKind::InvalidInput, "file exceeds size cap");
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if meta.len() > MAX_STORAGE_FILE_SIZE {
        return Err(too_large());
    }
    // Bound the read independently of the stat, in case the file grew.
    let mut buf = Vec::new();
    file.take(MAX_STORAGE_FILE_SIZE + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_STORAGE_FILE_SIZE {
        return Err(too_large());
    }
    Ok(buf)
}

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
        validate_key(key)?;
        read_regular_hardened(&self.dir.join(key)).map_err(io_to_hsm)
    }

    fn write(&self, key: &str, data: &[u8]) -> HsmResult<()> {
        validate_key(key)?;
        if data.len() as u64 > MAX_STORAGE_FILE_SIZE {
            return Err(HsmError::InvalidArgument);
        }
        let path = self.dir.join(key);
        let tmp_path = self.dir.join(format!(".{key}.tmp"));

        // Closure so any step's failure funnels to the temp-file cleanup below.
        let result = (|| -> HsmResult<()> {
            // O_NOFOLLOW + 0600: the temp file may hold key material, so refuse
            // a pre-planted symlink and keep it owner-only.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|_| HsmError::InternalError)?;
            file.write_all(data).map_err(|_| HsmError::InternalError)?;
            file.sync_all().map_err(|_| HsmError::InternalError)?;
            rename_atomic(&tmp_path, &path).map_err(|_| HsmError::InternalError)?;
            let dir = fs::File::open(&self.dir).map_err(|_| HsmError::InternalError)?;
            dir.sync_all().map_err(|_| HsmError::InternalError)
        })();

        if result.is_err() {
            // Best-effort: the write already failed, so a failed cleanup of
            // the temp file must not mask the original error.
            let _ = fs::remove_file(&tmp_path);
        }
        result
    }

    fn clear(&self, key: &str) -> HsmResult<()> {
        validate_key(key)?;
        match fs::remove_file(self.dir.join(key)) {
            Ok(()) => Ok(()),
            // Already absent counts as cleared (clear is idempotent); any
            // other error (e.g. permission denied) is surfaced.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(HsmError::InternalError),
        }
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
        // O_NOFOLLOW + 0600: refuse a symlinked lock path and keep it
        // owner-only, matching the provider's hardened lock file.
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600)
            .open(&self.path)
            .map_err(|_| HsmError::InternalError)?;
        // Reject a FIFO/device/etc. at the lock path (O_NOFOLLOW only blocks
        // symlinks); flock on a special file could hang or misbehave.
        if !file
            .metadata()
            .map_err(|_| HsmError::InternalError)?
            .is_file()
        {
            return Err(HsmError::InternalError);
        }
        file.lock_exclusive().map_err(|_| HsmError::InternalError)?;

        let mut guard = self.active.lock();
        if guard.is_some() {
            // Release the OS lock just acquired before rejecting the reentrant
            // call; best-effort, since we are already returning an error.
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
    fn rejects_invalid_keys() {
        let scratch = Scratch::new("trav");
        let s = FileStorage::new(scratch.0.clone());
        for bad in ["", "..", "../escape", "a/b", "/abs", "a\0b"] {
            assert!(
                matches!(s.write(bad, b"x"), Err(HsmError::InvalidArgument)),
                "write {bad:?} should be rejected"
            );
            assert!(
                matches!(s.read(bad), Err(HsmError::InvalidArgument)),
                "read {bad:?} should be rejected"
            );
            assert!(
                matches!(s.clear(bad), Err(HsmError::InvalidArgument)),
                "clear {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn write_rejects_oversize_value() {
        let scratch = Scratch::new("big");
        let s = FileStorage::new(scratch.0.clone());
        let huge = vec![0u8; MAX_STORAGE_FILE_SIZE as usize + 1];
        assert!(matches!(
            s.write("k", &huge),
            Err(HsmError::InvalidArgument)
        ));
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
    #[allow(unsafe_code)]
    fn lock_rejects_non_regular_file() {
        use std::ffi::CString;

        let scratch = Scratch::new("lkfifo");
        let fifo = scratch.0.join("fifo");
        let c = CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path and 0o600 is a valid mode.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed");

        let l = FileLock::new(fifo);
        assert!(l.lock().is_err(), "lock on a FIFO must be rejected");
    }

    #[test]
    fn unlock_without_lock_errors() {
        let scratch = Scratch::new("ul");
        let l = FileLock::new(scratch.0.join("lock"));

        assert!(l.unlock().is_err());
    }
}
