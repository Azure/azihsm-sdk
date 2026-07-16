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
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::thread::ThreadId;

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

/// Reserved storage-dir filename for the [`FileLock`] lock file. Rejected as a
/// storage key so storage operations can't clobber the lock.
pub(crate) const LOCK_FILE_NAME: &str = ".lock";

/// Mode for files the resiliency layer creates (state + lock): owner
/// read/write only, since they can hold or guard key material.
const SECRET_FILE_MODE: u32 = 0o600;

/// Reject empty, over-long, or path-traversal keys, keys with a separator or
/// interior NUL, and the reserved lock-file name, so `dir.join(key)` can never
/// escape the storage directory or clobber the lock file, and an invalid key
/// always maps to `InvalidArgument` (not a later `InternalError`). Mirrors the
/// provider's `build_storage_path` validation.
fn validate_key(key: &str) -> HsmResult<()> {
    if key.is_empty() || key.len() > MAX_KEY_NAME_LEN {
        return Err(HsmError::InvalidArgument);
    }
    if key.contains('/') || key.contains('\0') || key == ".." || key.contains("../") {
        return Err(HsmError::InvalidArgument);
    }
    if key == LOCK_FILE_NAME {
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

    /// Durably write `data` to `tmp_path` (fsync), then atomically rename it
    /// onto `dest` and fsync the directory. Returns the raw IO error so the
    /// single caller can map it once.
    fn write_durable(&self, tmp_path: &Path, dest: &Path, data: &[u8]) -> std::io::Result<()> {
        // O_NOFOLLOW + 0600: the temp file may hold key material, so refuse a
        // pre-planted symlink and keep it owner-only.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(SECRET_FILE_MODE)
            .open(tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        rename_atomic(tmp_path, dest)?;
        let dir = fs::File::open(&self.dir)?;
        dir.sync_all()
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
        // Per-write unique staging file so concurrent writes to the same key
        // don't race on a shared temp path: the PID distinguishes processes and
        // the atomic counter distinguishes writers within a process. The name
        // is independent of `key` so it stays well under NAME_MAX and doesn't
        // leak key names into directory listings.
        static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp_path = self.dir.join(format!(
            ".staging.{}.{}.tmp",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed),
        ));

        let result = self
            .write_durable(&tmp_path, &path, data)
            .map_err(|_| HsmError::InternalError);
        if result.is_err() {
            // Best-effort: the write already failed, so a failed cleanup of the
            // temp file must not mask the original error.
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
/// Opens a fresh file descriptor per [`lock`](Self::lock) call: `flock(2)`
/// operates per open-file-description, so distinct fds — even within one
/// process — contend at the OS level, giving the cross-thread / cross-process
/// blocking the `ResiliencyLock` contract requires. The in-process `active`
/// slot records the holding thread so a *reentrant* `lock()` from that same
/// thread is rejected (it would otherwise deadlock on its own held lock);
/// other threads simply block on the OS lock until it is released.
pub struct FileLock {
    path: PathBuf,
    active: Mutex<Option<(fs::File, ThreadId)>>,
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
        // Reject only *true* (same-thread) reentrancy: a reentrant flock on a
        // fresh fd would deadlock against our own held lock (flock is per
        // open-file-description). Drop the guard before the OS lock so other
        // threads block on flock rather than erroring.
        let this = std::thread::current().id();
        {
            let guard = self.active.lock();
            if let Some((_, holder)) = guard.as_ref()
                && *holder == this
            {
                return Err(HsmError::InternalError);
            }
        }

        // O_NOFOLLOW + 0600: refuse a symlinked lock path and keep it
        // owner-only, matching the provider's hardened lock file.
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(SECRET_FILE_MODE)
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
        // Blocks until the lock is available (cross-thread / cross-process).
        file.lock_exclusive().map_err(|_| HsmError::InternalError)?;

        *self.active.lock() = Some((file, this));
        Ok(())
    }

    fn unlock(&self) -> HsmResult<()> {
        match self.active.lock().take() {
            Some((file, _)) => file.unlock().map_err(|_| HsmError::InternalError),
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
        for bad in ["", "..", "../escape", "a/b", "/abs", "a\0b", LOCK_FILE_NAME] {
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
    fn reentrant_lock_is_rejected() {
        let scratch = Scratch::new("reent");
        let l = FileLock::new(scratch.0.join("lock"));

        l.lock().unwrap();
        // A second lock() from the same thread must be rejected, not deadlock.
        assert!(l.lock().is_err(), "reentrant lock must be rejected");
        l.unlock().unwrap();
        // Once released, locking again succeeds.
        l.lock().unwrap();
        l.unlock().unwrap();
    }

    #[test]
    fn other_thread_blocks_until_unlock() {
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::time::Duration;

        let scratch = Scratch::new("xthread");
        let l = Arc::new(FileLock::new(scratch.0.join("lock")));
        l.lock().unwrap();

        let l2 = Arc::clone(&l);
        let (tx, rx) = mpsc::channel();
        let h = std::thread::spawn(move || {
            // Blocks here until the main thread releases the lock.
            l2.lock().unwrap();
            tx.send(()).unwrap();
            l2.unlock().unwrap();
        });

        // While we hold the lock the other thread cannot acquire it (it blocks
        // on flock rather than erroring).
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "other thread acquired the lock while it was held"
        );
        l.unlock().unwrap();
        // After release it proceeds.
        rx.recv_timeout(Duration::from_secs(5))
            .expect("other thread should acquire after unlock");
        h.join().unwrap();
    }

    #[test]
    fn unlock_without_lock_errors() {
        let scratch = Scratch::new("ul");
        let l = FileLock::new(scratch.0.join("lock"));

        assert!(l.unlock().is_err());
    }
}
