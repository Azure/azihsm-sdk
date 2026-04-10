// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! File-backed [`ResiliencyStorage`] and [`ResiliencyLock`] implementations
//! shared between integration tests and the resiliency stress tool.

use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Path;
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
        if file.write_all(data).is_err() {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(HsmError::InternalError);
        }
        if self.sync_on_write && file.sync_all().is_err() {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(HsmError::InternalError);
        }
        // Atomically rename the temp file to the target, replacing it if
        // it already exists.  On Linux rename(2) does this natively; on
        // Windows we use MoveFileExW with MOVEFILE_REPLACE_EXISTING to
        // avoid the non-atomic remove+rename sequence.
        rename_with_replace(&tmp_path, &path).map_err(|_| {
            let _ = fs::remove_file(&tmp_path);
            HsmError::InternalError
        })?;
        if self.sync_on_write {
            // Sync the directory to make the rename durable on POSIX.
            // Without this, a crash after rename could revert the
            // directory entry, leaving the old file (or no file).
            let dir = fs::File::open(&self.dir).map_err(|_| HsmError::InternalError)?;
            dir.sync_all().map_err(|_| HsmError::InternalError)?;
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

/// Atomically rename `from` to `to`, replacing `to` if it exists.
///
/// On Unix, `std::fs::rename` already replaces the target atomically.
/// On Windows, `std::fs::rename` fails when the target exists, so we
/// call `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` instead.
fn rename_with_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fs::rename(from, to)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;

        // SAFETY: Declaring a well-known Win32 API with correct signature.
        #[allow(unsafe_code)]
        unsafe extern "system" {
            fn MoveFileExW(
                existing_file_name: *const u16,
                new_file_name: *const u16,
                flags: u32,
            ) -> i32;
        }

        let from_wide: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to_wide: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();

        // SAFETY: Both pointers are valid null-terminated wide strings.
        #[allow(unsafe_code)]
        let ret = unsafe {
            MoveFileExW(
                from_wide.as_ptr(),
                to_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING,
            )
        };
        if ret == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
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

        // Detect reentrant lock(): flock(LOCK_EX) operates per open-file-
        // description, so a second lock() on the same thread opens a new
        // fd and succeeds immediately instead of blocking. Without this
        // check the old fd in `active` would be silently dropped (releasing
        // the first OS lock), breaking mutual exclusion.
        let mut guard = self.active.lock();
        if guard.is_some() {
            // Release the OS lock we just acquired before returning.
            let _ = file.unlock();
            return Err(HsmError::InternalError);
        }
        *guard = Some(file);
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
