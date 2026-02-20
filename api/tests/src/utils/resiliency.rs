// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency test helpers.
//!
//! Provides file-backed implementations of [`ResiliencyStorage`],
//! cross-process [`ResiliencyLock`] (via `fs2` file locking), and a dummy
//! [`PotaEndorsementCallback`] for use in integration tests.
//!
//! All callers share a single well-known directory under the system
//! temp dir. Storage uses one file per key inside that directory.
//!
//! # Usage
//!
//! **Single-thread / single-process tests** — use [`make_resiliency_config`]:
//! ```ignore
//! let (config, _ctx) = make_resiliency_config();
//! // _ctx cleans up the directory on drop.
//! ```
//!
//! **Multi-thread / multi-process tests** — create the context once in
//! setup, then call [`make_resiliency_config_in`] from each thread or
//! process:
//! ```ignore
//! let ctx = ResiliencyTestCtx::new();
//! // spawn threads / processes, each calls:
//! let config = make_resiliency_config_in(ctx.dir());
//! // after all join, ctx drops and cleans up.
//! ```

use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use azihsm_api::*;
use fs2::FileExt;

/// Well-known directory name for resiliency test data.
const RESILIENCY_DIR_NAME: &str = "azihsm_resiliency_test";

/// Monotonic counter for unique directory names across all threads.
static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// File-backed [`ResiliencyStorage`]: one file per key under `dir`.
struct FileStorage {
    dir: PathBuf,
}

impl FileStorage {
    fn key_path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }
}

impl ResiliencyStorage for FileStorage {
    fn read(&self, key: &str) -> HsmResult<Vec<u8>> {
        let path = self.key_path(key);
        let mut file = fs::File::open(&path).map_err(|_| HsmError::NotFound)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|_| HsmError::InternalError)?;
        Ok(buf)
    }

    fn write(&self, key: &str, data: &[u8]) -> HsmResult<()> {
        let path = self.key_path(key);
        let mut file = fs::File::create(&path).map_err(|_| HsmError::InternalError)?;
        file.write_all(data).map_err(|_| HsmError::InternalError)?;
        Ok(())
    }

    fn clear(&self, key: &str) -> HsmResult<()> {
        let path = self.key_path(key);
        // No error if key doesn't exist (matches trait contract).
        let _ = fs::remove_file(&path);
        Ok(())
    }
}

/// Cross-process [`ResiliencyLock`] backed by `fs2` file locking.
///
/// Uses `flock(2)` on Linux and `LockFileEx` on Windows under the hood.
/// The lock file lives inside the shared test directory. Multiple
/// threads and processes coordinate by blocking on an exclusive file lock.
/// The underlying `File` is closed automatically when dropped.
struct FileLock {
    file: fs::File,
}

impl ResiliencyLock for FileLock {
    fn lock(&self) -> HsmResult<()> {
        self.file
            .lock_exclusive()
            .map_err(|_| HsmError::InternalError)
    }

    fn unlock(&self) -> HsmResult<()> {
        self.file.unlock().map_err(|_| HsmError::InternalError)
    }
}

/// Dummy POTA callback that returns zeroed signature and public key.
struct DummyPotaCallback;

impl PotaEndorsementCallback for DummyPotaCallback {
    fn endorse(&self, _pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData> {
        Ok(HsmPotaEndorsementData::new(&[0u8; 96], &[0u8; 120]))
    }
}

/// RAII context that owns the resiliency test directory.
///
/// Create this once in test setup (before spawning threads or
/// child processes). Pass [`dir()`](Self::dir) to
/// [`make_resiliency_config_in`] from each thread / process. The
/// directory is removed when this context is dropped.
pub(crate) struct ResiliencyTestCtx {
    temp_dir: PathBuf,
}

impl ResiliencyTestCtx {
    /// Creates a unique resiliency test directory.
    ///
    /// Each invocation gets its own subdirectory under the system temp dir,
    /// so parallel tests never interfere with each other. The directory is
    /// removed when this context is dropped.
    pub(crate) fn new() -> Self {
        let id = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_dir = std::env::temp_dir().join(RESILIENCY_DIR_NAME).join(format!(
            "{}_{}",
            std::process::id(),
            id
        ));
        // Wipe any stale data, then recreate empty.
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).expect("Failed to create resiliency test dir");
        Self { temp_dir }
    }

    /// Returns the shared directory path.
    pub(crate) fn dir(&self) -> &Path {
        &self.temp_dir
    }
}

impl Drop for ResiliencyTestCtx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

/// Creates a [`HsmResiliencyConfig`] backed by the given directory.
///
/// The directory must already exist (created by [`ResiliencyTestCtx::new`]).
/// Each thread or process should call this to get its own config handle
/// pointing at the shared storage and lock file.
pub(crate) fn make_resiliency_config_in(dir: &Path) -> HsmResiliencyConfig {
    let lock_path = dir.join(".lock");
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("Failed to open lock file");

    HsmResiliencyConfig {
        storage: Box::new(FileStorage {
            dir: dir.to_path_buf(),
        }),
        lock: Box::new(FileLock { file: lock_file }),
        pota_callback: Some(Box::new(DummyPotaCallback)),
    }
}

/// Convenience wrapper: creates the shared directory, builds a
/// [`HsmResiliencyConfig`], and returns the RAII context.
///
/// For multi-thread or multi-process tests, use
/// [`ResiliencyTestCtx::new`] + [`make_resiliency_config_in`] instead.
///
/// The returned `ResiliencyTestCtx` must outlive the config.
pub(crate) fn make_resiliency_config() -> (HsmResiliencyConfig, ResiliencyTestCtx) {
    let ctx = ResiliencyTestCtx::new();
    let config = make_resiliency_config_in(ctx.dir());
    (config, ctx)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;

    use super::*;

    /// Per-process counter to give every test a unique directory,
    /// avoiding interference when nextest runs tests in parallel
    /// (each `#[test]` is a separate process).
    static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

    /// RAII helper that creates a unique temp directory for a single
    /// unit test and removes it on drop.
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Self {
            let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let path = std::env::temp_dir().join(format!("azihsm_resiliency_ut_{pid}_{seq}"));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("Failed to create test dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn storage_write_then_read() {
        let dir = TestDir::new();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };

        storage.write("key1", b"hello").unwrap();
        let data = storage.read("key1").unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn storage_read_nonexistent_returns_not_found() {
        let dir = TestDir::new();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };

        let err = storage.read("missing").unwrap_err();
        assert_eq!(err, HsmError::NotFound);
    }

    #[test]
    fn storage_write_overwrites() {
        let dir = TestDir::new();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };

        storage.write("key1", b"first").unwrap();
        storage.write("key1", b"second").unwrap();
        let data = storage.read("key1").unwrap();
        assert_eq!(data, b"second");
    }

    #[test]
    fn storage_clear_removes_key() {
        let dir = TestDir::new();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };

        storage.write("key1", b"data").unwrap();
        storage.clear("key1").unwrap();
        let err = storage.read("key1").unwrap_err();
        assert_eq!(err, HsmError::NotFound);
    }

    #[test]
    fn storage_clear_nonexistent_succeeds() {
        let dir = TestDir::new();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };

        // Should not error — matches trait contract.
        storage.clear("missing").unwrap();
    }

    #[test]
    fn storage_write_empty_data() {
        let dir = TestDir::new();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };

        storage.write("empty", b"").unwrap();
        let data = storage.read("empty").unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn lock_and_unlock() {
        let dir = TestDir::new();
        let config = make_resiliency_config_in(dir.path());

        config.lock.lock().unwrap();
        config.lock.unlock().unwrap();
    }

    #[test]
    fn pota_callback_returns_expected_sizes() {
        let callback = DummyPotaCallback;
        let result = callback.endorse(&[0u8; 32]).unwrap();
        assert_eq!(result.signature().len(), 96);
        assert_eq!(result.pub_key().len(), 120);
    }

    #[test]
    fn make_resiliency_config_returns_valid_config() {
        let dir = TestDir::new();
        let config = make_resiliency_config_in(dir.path());

        // Storage should work
        config.storage.write("test", b"value").unwrap();
        let data = config.storage.read("test").unwrap();
        assert_eq!(data, b"value");

        // Lock should work
        config.lock.lock().unwrap();
        config.lock.unlock().unwrap();

        // POTA callback should be present
        assert!(config.pota_callback.is_some());
    }

    #[test]
    fn lock_protects_across_threads() {
        let dir = TestDir::new();
        let dir_path = dir.path().to_path_buf();

        let num_threads = 128;
        let increments_per_thread = 50;

        // Initialize counter file to "0"
        let storage = FileStorage {
            dir: dir_path.clone(),
        };
        storage.write("counter", b"0").unwrap();

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let dir = dir_path.clone();
                std::thread::spawn(move || {
                    let config = make_resiliency_config_in(&dir);
                    let storage = FileStorage { dir: dir.clone() };

                    for _ in 0..increments_per_thread {
                        config.lock.lock().unwrap();

                        let data = storage.read("counter").unwrap();
                        let value: u32 = String::from_utf8(data).unwrap().parse().unwrap();
                        storage
                            .write("counter", (value + 1).to_string().as_bytes())
                            .unwrap();

                        config.lock.unlock().unwrap();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let data = storage.read("counter").unwrap();
        let final_value: u32 = String::from_utf8(data).unwrap().parse().unwrap();
        assert_eq!(final_value, num_threads * increments_per_thread);
    }

    #[test]
    fn storage_large_data() {
        let dir = TestDir::new();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };

        let large = vec![0xABu8; 64 * 1024]; // 64 KiB
        storage.write("large", &large).unwrap();
        let data = storage.read("large").unwrap();
        assert_eq!(data.len(), large.len());
        assert_eq!(data, large);
    }

    #[test]
    fn storage_multiple_keys_independent() {
        let dir = TestDir::new();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };

        storage.write("key_a", b"alpha").unwrap();
        storage.write("key_b", b"bravo").unwrap();
        storage.write("key_c", b"charlie").unwrap();

        assert_eq!(storage.read("key_a").unwrap(), b"alpha");
        assert_eq!(storage.read("key_b").unwrap(), b"bravo");
        assert_eq!(storage.read("key_c").unwrap(), b"charlie");

        // Clearing one key doesn't affect others
        storage.clear("key_b").unwrap();
        assert_eq!(storage.read("key_a").unwrap(), b"alpha");
        assert_eq!(storage.read("key_b").unwrap_err(), HsmError::NotFound);
        assert_eq!(storage.read("key_c").unwrap(), b"charlie");
    }

    #[test]
    fn pota_callback_ignores_input_pub_key() {
        let callback = DummyPotaCallback;

        // Call with different input keys — output should be the same
        let result1 = callback.endorse(&[0xAAu8; 64]).unwrap();
        let result2 = callback.endorse(&[0xBBu8; 32]).unwrap();
        let result3 = callback.endorse(&[]).unwrap();

        assert_eq!(result1.signature(), result2.signature());
        assert_eq!(result2.signature(), result3.signature());
        assert_eq!(result1.pub_key(), result2.pub_key());
        assert_eq!(result2.pub_key(), result3.pub_key());
    }

    #[test]
    fn make_resiliency_config_convenience_creates_valid_config() {
        let (config, _ctx) = make_resiliency_config();

        // Storage should work
        config.storage.write("conv_test", b"data").unwrap();
        let data = config.storage.read("conv_test").unwrap();
        assert_eq!(data, b"data");

        // Lock should work
        config.lock.lock().unwrap();
        config.lock.unlock().unwrap();

        // POTA callback should be present
        assert!(config.pota_callback.is_some());
    }

    #[test]
    fn resiliency_test_ctx_cleanup_on_drop() {
        let dir_path;
        {
            let ctx = ResiliencyTestCtx::new();
            dir_path = ctx.dir().to_path_buf();

            // Directory exists while ctx is alive
            assert!(dir_path.exists());

            // Write a file to verify it gets cleaned up
            let storage = FileStorage {
                dir: dir_path.clone(),
            };
            storage.write("cleanup_test", b"data").unwrap();
        }
        // After ctx drops, directory should be removed
        assert!(!dir_path.exists());
    }
}
