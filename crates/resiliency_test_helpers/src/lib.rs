// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! File-backed [`ResiliencyStorage`] and [`ResiliencyLock`] implementations
//! shared between integration tests and the resiliency stress tool.

use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

use azihsm_api::*;
use fs2::FileExt;
use parking_lot::Mutex;

/// File-backed [`ResiliencyStorage`]: one file per key under `dir`.
pub struct FileStorage {
    dir: PathBuf,
    sync_on_write: bool,
}

impl FileStorage {
    /// Creates a new `FileStorage` backed by the given directory.
    ///
    /// Writes are **not** synced to disk (`fsync`); this is suitable for
    /// tests where durability is not required.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            sync_on_write: false,
        }
    }

    /// Creates a new `FileStorage` that calls `sync_all()` after every
    /// write, ensuring data is flushed to disk before the rename.
    ///
    /// Use this in tools or scenarios where crash-consistency matters.
    pub fn new_with_sync(dir: PathBuf) -> Self {
        Self {
            dir,
            sync_on_write: true,
        }
    }

    fn key_path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }
}

impl ResiliencyStorage for FileStorage {
    fn read(&self, key: &str) -> HsmResult<Vec<u8>> {
        let path = self.key_path(key);
        let mut file = fs::File::open(&path).map_err(|e| {
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
        let path = self.key_path(key);
        let tmp_path = self.dir.join(format!(".{key}.tmp"));
        let mut file = fs::File::create(&tmp_path).map_err(|_| HsmError::InternalError)?;
        file.write_all(data).map_err(|_| HsmError::InternalError)?;
        if self.sync_on_write {
            file.sync_all().map_err(|_| HsmError::InternalError)?;
        }
        // On Linux, rename(2) atomically replaces an existing target.
        // On Windows, std::fs::rename fails if the target exists, so
        // fall back to a remove+rename sequence.  The remove+rename is
        // safe without an additional lock because all callers hold the
        // cross-process ResiliencyLock (via ResiliencyLockGuard).
        if let Err(e) = fs::rename(&tmp_path, &path) {
            // Only handle the "destination already exists" case with a
            // remove+rename fallback. For other errors, avoid deleting
            // the existing file and return an internal error instead.
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                // Rename failed (likely Windows — target exists).
                // Remove the destination and retry.
                let _ = fs::remove_file(&path);
                fs::rename(&tmp_path, &path).map_err(|_| HsmError::InternalError)?;
            } else {
                return Err(HsmError::InternalError);
            }
        }
        if self.sync_on_write {
            // Sync the directory to make the rename durable on POSIX.
            // Without this, a crash after rename could revert the
            // directory entry, leaving the old file (or no file).
            if let Ok(dir) = fs::File::open(&self.dir) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    fn clear(&self, key: &str) -> HsmResult<()> {
        let path = self.key_path(key);
        // No error if key doesn't exist (matches trait contract).
        let _ = fs::remove_file(&path);
        Ok(())
    }
}

/// Cross-process and cross-thread [`ResiliencyLock`] backed by `fs2`
/// file locking.
///
/// Opens a new file descriptor on each [`lock()`] call and acquires an
/// exclusive `flock` on it.  This is critical because `flock(2)` on Linux
/// operates per *open file description* (kernel-level fd): two threads
/// calling `flock(LOCK_EX)` on the **same** fd see a single lock and the
/// second call silently succeeds instead of blocking.  By opening a fresh
/// fd each time, each caller gets its own independent lock that truly
/// serializes both cross-thread and cross-process.
///
/// On Windows the underlying `LockFileEx` has the same per-handle
/// semantics, so the same approach applies.
pub struct FileLock {
    /// Path to the lock file (opened anew on each [`lock()`] call).
    path: PathBuf,
    /// The currently-held file descriptor, if any.
    ///
    /// The `Mutex` is required solely for interior mutability: the
    /// [`ResiliencyLock`] trait methods take `&self`, so a bare
    /// `Option<File>` cannot be mutated.  It is never contended at
    /// runtime — `flock(LOCK_EX)` guarantees that only one thread holds
    /// the OS lock at a time, so writes to this field are inherently
    /// serialized.
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
        // Open a new fd and block on the OS-level exclusive lock
        // before touching `self.active`.  This ensures concurrent
        // callers block at `flock(LOCK_EX)` rather than failing.
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .map_err(|_| HsmError::InternalError)?;
        file.lock_exclusive().map_err(|_| HsmError::InternalError)?;

        // Only the flock holder reaches here; store the fd for unlock.
        *self.active.lock() = Some(file);
        Ok(())
    }

    fn unlock(&self) -> HsmResult<()> {
        match self.active.lock().take() {
            Some(file) => {
                file.unlock().map_err(|_| HsmError::InternalError)?;
                Ok(())
            }
            None => Err(HsmError::InternalError),
        }
    }
}
