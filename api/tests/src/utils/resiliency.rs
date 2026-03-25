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
//! let (config, _ctx) = make_resiliency_config(&part);
//! // _ctx cleans up the directory on drop.
//! ```
//!
//! **Multi-thread / multi-process tests** — create the context once in
//! setup, then call [`make_resiliency_config_in`] from each thread or
//! process:
//! ```ignore
//! let ctx = ResiliencyTestCtx::new();
//! // spawn threads / processes, each calls:
//! let config = make_resiliency_config_in(ctx.dir(), &part);
//! // after all join, ctx drops and cleans up.
//! ```

use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use azihsm_api::*;
use azihsm_crypto::*;
#[cfg(feature = "res-test")]
use azihsm_res_test_dev::DdiOp;
use fs2::FileExt;
use parking_lot::Mutex;

use crate::utils::partition::*;

/// Returns the BK3-related DDI op used by `init_part` / `restore_partition`:
/// `GetSealedBk3` on the TPM path, `InitBk3` on the Caller path.
#[cfg(feature = "res-test")]
pub(crate) fn bk3_op() -> DdiOp {
    if use_tpm() {
        DdiOp::GetSealedBk3
    } else {
        DdiOp::InitBk3
    }
}

/// Well-known directory name for resiliency test data.
const RESILIENCY_DIR_NAME: &str = "azihsm_resiliency_test";

/// Monotonic counter for unique directory names across all threads.
static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

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
        // Remove existing destination before rename — on Windows,
        // fs::rename fails if the target already exists (Linux rename(2)
        // atomically replaces, but std::fs::rename is not guaranteed to).
        // The remove+rename sequence is safe without an additional lock
        // because all callers hold the cross-process ResiliencyLock
        // (via ResiliencyLockGuard) before writing to storage.
        let _ = fs::remove_file(&path);
        fs::rename(&tmp_path, &path).map_err(|_| HsmError::InternalError)?;
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
/// Opens a **new file descriptor** on each [`lock()`] call and acquires an
/// exclusive `flock` on it.  This is critical because `flock(2)` on Linux
/// operates per *open file description* (kernel-level fd): two threads
/// calling `flock(LOCK_EX)` on the **same** fd see a single lock and the
/// second call silently succeeds instead of blocking.  By opening a fresh
/// fd each time, each caller gets its own independent lock that truly
/// serializes both cross-thread and cross-process.
///
/// On Windows the underlying `LockFileEx` has the same per-handle
/// semantics, so the same approach applies.
struct FileLock {
    /// Path to the lock file (opened anew on each [`lock()`] call).
    path: PathBuf,
    /// The currently-held file descriptor, if any.
    active: Mutex<Option<fs::File>>,
}

impl FileLock {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            active: Mutex::new(None),
        }
    }
}

impl ResiliencyLock for FileLock {
    fn lock(&self) -> HsmResult<()> {
        let mut guard = self.active.lock();
        if guard.is_some() {
            return Err(HsmError::InternalError);
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .map_err(|_| HsmError::InternalError)?;
        file.lock_exclusive().map_err(|_| HsmError::InternalError)?;
        *guard = Some(file);
        Ok(())
    }

    fn unlock(&self) -> HsmResult<()> {
        let mut guard = self.active.lock();
        match guard.take() {
            Some(file) => {
                file.unlock().map_err(|_| HsmError::InternalError)?;
                Ok(())
            }
            None => Err(HsmError::InternalError),
        }
    }
}

/// Test POTA callback that retrieves the PID public key from the
/// partition's certificate and signs it using the hardcoded test
/// ECC P-384 key pair (same as [`super::partition::generate_pota_endorsement`]).
///
/// The `pub_key` parameter (caller's original endorsement key) is
/// ignored — this callback always re-derives the endorsement from the
/// current device's PID cert.
///
/// Opens a separate partition handle to avoid deadlocking with the
/// caller's partition RwLock (held during init / restore).
struct TestPotaCallback {
    path: String,
}

impl PotaEndorsementCallback for TestPotaCallback {
    fn endorse(&self, _pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData> {
        // Open a separate partition handle.
        let part = HsmPartitionManager::open_partition(&self.path)?;
        let pid_pub_key_der = part.pub_key()?;

        let pub_key_obj =
            DerEccPublicKey::from_der(&pid_pub_key_der).map_err(|_| HsmError::InternalError)?;
        let mut uncompressed = vec![0x04u8];
        uncompressed.extend_from_slice(pub_key_obj.x());
        uncompressed.extend_from_slice(pub_key_obj.y());

        let priv_key = EccPrivateKey::from_bytes(&super::partition::TEST_POTA_PRIVATE_KEY)
            .map_err(|_| HsmError::InternalError)?;
        let hash_algo = HashAlgo::sha384();
        let mut ecdsa = EcdsaAlgo::new(hash_algo);
        let signature = Signer::sign_vec(&mut ecdsa, &priv_key, &uncompressed)
            .map_err(|_| HsmError::InternalError)?;

        Ok(HsmPotaEndorsementData::new(
            &signature,
            &super::partition::TEST_POTA_PUBLIC_KEY_DER,
        ))
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
pub(crate) fn make_resiliency_config_in(dir: &Path, part: &HsmPartition) -> HsmResiliencyConfig {
    let lock_path = dir.join(".lock");

    // When TPM is used, the POTA source is Tpm and no callback is needed
    // (validate_config rejects TPM + callback). When Caller is used, the
    // callback re-signs the POTA endorsement on retry.
    let pota_callback: Option<Box<dyn PotaEndorsementCallback>> = if use_tpm() {
        None
    } else {
        Some(Box::new(TestPotaCallback { path: part.path() }))
    };

    HsmResiliencyConfig {
        storage: Box::new(FileStorage {
            dir: dir.to_path_buf(),
        }),
        lock: Arc::new(FileLock::new(lock_path)),
        pota_callback,
    }
}

/// Convenience wrapper: creates the shared directory, builds a
/// [`HsmResiliencyConfig`], and returns the RAII context.
///
/// For multi-thread or multi-process tests, use
/// [`ResiliencyTestCtx::new`] + [`make_resiliency_config_in`] instead.
///
/// The returned `ResiliencyTestCtx` must outlive the config.
pub(crate) fn make_resiliency_config(
    part: &HsmPartition,
) -> (HsmResiliencyConfig, ResiliencyTestCtx) {
    let ctx = ResiliencyTestCtx::new();
    let config = make_resiliency_config_in(ctx.dir(), part);
    (config, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-process counter to give every test a unique directory,
    /// avoiding interference when nextest runs tests in parallel
    /// (each `#[test]` is a separate process).
    static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

    /// Dummy POTA callback for unit tests that don't exercise the
    /// actual POTA signing flow.
    struct DummyPotaCallback;

    impl PotaEndorsementCallback for DummyPotaCallback {
        fn endorse(&self, _pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData> {
            // Use non-trivial byte pattern for signature and the real test
            // public key so that any endianness or byte-order issues are caught.
            let sig: [u8; 96] = core::array::from_fn(|i| (i + 1) as u8);
            Ok(HsmPotaEndorsementData::new(&sig, &TEST_POTA_PUBLIC_KEY_DER))
        }
    }

    /// Build a resiliency config for unit tests that exercise storage
    /// and locking without interacting with a partition. Uses
    /// [`DummyPotaCallback`] since the POTA callback is not exercised.
    fn make_unit_test_config(dir: &Path) -> HsmResiliencyConfig {
        let lock_path = dir.join(".lock");

        HsmResiliencyConfig {
            storage: Box::new(FileStorage {
                dir: dir.to_path_buf(),
            }),
            lock: Arc::new(FileLock::new(lock_path)),
            pota_callback: Some(Box::new(DummyPotaCallback)),
        }
    }

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
        let config = make_unit_test_config(dir.path());

        config.lock.lock().unwrap();
        config.lock.unlock().unwrap();
    }

    #[test]
    fn pota_dummy_callback_returns_expected_sizes() {
        let callback = DummyPotaCallback;
        let result = callback.endorse(&[0u8; 32]).unwrap();
        assert_eq!(result.signature().len(), 96);
        assert_eq!(result.pub_key().len(), 120);
    }

    #[test]
    fn make_resiliency_config_returns_valid_config() {
        let dir = TestDir::new();
        let config = make_unit_test_config(dir.path());

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
                    let config = make_unit_test_config(&dir);
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
        let part_infos = HsmPartitionManager::partition_info_list();
        assert!(!part_infos.is_empty(), "No partitions found.");
        let part = HsmPartitionManager::open_partition(&part_infos[0].path)
            .expect("Failed to open partition");

        let (config, _ctx) = make_resiliency_config(&part);

        // Storage should work
        config.storage.write("conv_test", b"data").unwrap();
        let data = config.storage.read("conv_test").unwrap();
        assert_eq!(data, b"data");

        // Lock should work
        config.lock.lock().unwrap();
        config.lock.unlock().unwrap();

        // POTA callback should match the source: present for Caller, absent for TPM.
        assert_eq!(config.pota_callback.is_some(), !use_tpm());
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
