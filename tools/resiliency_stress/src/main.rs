// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency stress tool for AZIHSM SDK.
//!
//! Continuously runs crypto operations across multiple threads while a
//! dedicated thread triggers device resets at configurable intervals.
//! Stops immediately on any unexpected error, printing the failing
//! scenario and aggregated stats.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use azihsm_api::*;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::KeyGenerationOp;
use clap::Parser;
use parking_lot::deadlock;
use parking_lot::Mutex;
use rand::Rng;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Resiliency stress tool — continuous crypto ops under device resets.
#[derive(Parser, Debug)]
#[command(name = "resiliency_stress", version, about)]
struct Args {
    // -- Process & thread configuration --
    /// Number of separate OS processes, each with its own partition/session.
    /// Resets are triggered from the parent process only.
    #[arg(short = 'p', long, default_value_t = 1)]
    processes: usize,

    /// Number of worker threads performing crypto operations (per process).
    #[arg(short = 'w', long, default_value_t = 4)]
    workers: usize,

    // -- Timing --
    /// Duration to run in seconds (0 = run until Ctrl-C).
    #[arg(short = 'd', long, default_value_t = 60)]
    duration_secs: u64,

    /// Reset interval in milliseconds.
    #[arg(short = 'r', long, default_value_t = 200)]
    reset_interval_ms: u64,

    /// Stats reporting interval in seconds.
    #[arg(short = 's', long, default_value_t = 5)]
    stats_interval_secs: u64,

    /// Stall detection timeout in seconds. If no operations complete
    /// within this duration the tool treats it as a deadlock, dumps
    /// diagnostics, and exits. 0 disables stall detection.
    #[arg(long, default_value_t = 30)]
    stall_timeout_secs: u64,

    // -- Operations --
    /// Comma-separated list of operations to include.
    /// Available: aes-cbc,aes-xts*,aes-gcm*,ecc-sign,hmac-sign,rsa-sign,rsa-decrypt,rsa,ecdh,hkdf,
    /// aes-keygen,ecc-keygen,aes-xts-keygen,unwrapping-keygen,aes-unwrap,ecc-unwrap,
    /// xts-unwrap,unwrap,aes-unmask,ecc-unmask,xts-unmask,unmask,
    /// ecc-key-report,rsa-key-report,key-report,cert-chain,
    /// aes-keygen-delete,ecc-keygen-delete,xts-keygen-delete,keygen-delete,all
    /// Note: standalone keygen ops (aes-keygen, ecc-keygen, aes-xts-keygen) are NOT
    /// included in 'all' — use keygen-delete variants instead.
    /// *aes-xts and aes-gcm enc/dec are currently enabled only with mock.
    #[arg(short = 'o', long, default_value = "all")]
    ops: String,

    // -- Error handling --
    /// Maximum number of operation errors before stopping.
    /// 0 = stop on first error (legacy behavior).
    /// -1 = never stop on errors (infinite tolerance).
    #[arg(short = 'e', long, default_value_t = 10, allow_hyphen_values = true)]
    max_errors: i64,

    // -- Behavior flags --
    /// Enable verbose logging (shows retry/restore warnings).
    #[arg(short = 'v', long, default_value_t = false)]
    verbose: bool,

    /// Disable resiliency support (no resiliency config, no resets).
    /// Useful for baseline performance comparison.
    #[arg(long, default_value_t = false)]
    no_resiliency: bool,

    /// Keep resiliency enabled but do not trigger resets.
    /// Useful for measuring resiliency overhead without disruption.
    #[arg(long, default_value_t = false)]
    no_reset: bool,

    /// Inject random NSSR faults on DDI operations instead of using
    /// timer-based resets. Requires the `res-test` feature.
    /// This provides better race coverage by triggering resets
    /// mid-DDI-call rather than between operations.
    #[arg(long, default_value_t = false)]
    random_fault: bool,

    // -- Internal (hidden) --
    /// (Internal) Child process ID — set automatically by the parent.
    #[arg(long, hide = true)]
    child_id: Option<usize>,

    /// (Internal) Path to shared memory file — set automatically by the parent.
    #[arg(long, hide = true)]
    shmem_path: Option<String>,

    /// (Internal) Path to shared resiliency storage directory — set automatically by the parent.
    #[arg(long, hide = true)]
    storage_dir: Option<String>,
}

// ---------------------------------------------------------------------------
// Cross-process shared memory (multi-process mode)
// ---------------------------------------------------------------------------

/// Maximum number of child processes supported.
const MAX_PROCS: usize = 16;

/// Human-readable labels for each operation slot.
const LABELS: [&str; 26] = [
    "AES-CBC enc+dec:  ",
    "ECC sign:         ",
    "HMAC sign:        ",
    "RSA sign:         ",
    "RSA decrypt:      ",
    "ECDH derive:      ",
    "HKDF derive:      ",
    "AES key gen:      ",
    "ECC key gen:      ",
    "AES-XTS keygen:   ",
    "Unwrapping keygen:",
    "AES unwrap:       ",
    "ECC unwrap:       ",
    "XTS unwrap:       ",
    "AES unmask:       ",
    "ECC unmask:       ",
    "XTS unmask:       ",
    "ECC key report:   ",
    "RSA key report:   ",
    "Unwrap key report:",
    "Cert chain:       ",
    "AES keygen+del:   ",
    "ECC keygen+del:   ",
    "XTS keygen+del:   ",
    "AES-XTS enc+dec:  ",
    "AES-GCM enc+dec:  ",
];

/// Number of per-op counter slots.
const NUM_OPS: usize = LABELS.len();

/// Per-process stats stored in shared memory.
///
/// Uses `repr(C)` to ensure deterministic layout across processes.
#[repr(C)]
struct ProcessStats {
    total_ops: AtomicU64,
    total_errors: AtomicU64,
    op_counts: [AtomicU64; NUM_OPS],
    op_errors: [AtomicU64; NUM_OPS],
    /// Set to 1 when this process hits max errors.
    failed: AtomicBool,
    _pad0: [u8; 7], // align next field
    failed_op: AtomicU32,
    failed_error: AtomicI32,
    failed_thread: AtomicU32,
}

/// Shared memory layout mapped into all processes.
#[repr(C)]
struct SharedMem {
    /// Parent sets this to signal all children to stop.
    stop: AtomicBool,
    _pad: [u8; 7],
    /// Reset counters (parent only).
    total_resets: AtomicU64,
    reset_failures: AtomicU64,
    /// Number of child processes that have finished setup and are ready
    /// for resets. The reset thread waits for this to reach `num_procs`
    /// before firing the first reset.
    children_ready: AtomicU32,
    _pad2: [u8; 4],
    /// Per-process stats slots.
    procs: [ProcessStats; MAX_PROCS],
}

impl SharedMem {
    /// Total size in bytes.
    #[cfg(all(target_os = "linux", not(feature = "mock")))]
    fn size() -> usize {
        std::mem::size_of::<Self>()
    }
}

impl ProcessStats {
    fn increment_op(&self, op_idx: usize) {
        self.op_counts[op_idx].fetch_add(1, Ordering::Relaxed);
        self.total_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_error(&self, op_idx: usize) {
        self.op_errors[op_idx].fetch_add(1, Ordering::Relaxed);
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Create a shared memory file and return its path and mmap.
#[cfg(all(target_os = "linux", not(feature = "mock")))]
#[allow(unsafe_code)]
fn create_shared_mem() -> (String, memmap2::MmapMut) {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let path = format!("/dev/shm/azihsm_stress_{}", std::process::id());
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .expect("Failed to create shared memory file");
    file.set_len(SharedMem::size() as u64)
        .expect("Failed to set shared memory size");

    // SAFETY: The file is freshly created and zero-initialized by set_len.
    // AtomicU64/AtomicBool are valid when zero-initialized.
    // SAFETY: Shared memory pointer is valid for the lifetime of the process.
    let mmap = unsafe {
        memmap2::MmapOptions::new()
            .len(SharedMem::size())
            .map_mut(&file)
            .expect("Failed to mmap shared memory")
    };

    (path, mmap)
}

#[cfg(all(target_os = "windows", not(feature = "mock")))]
fn create_shared_mem() -> (String, memmap2::MmapMut) {
    // TODO: Windows implementation using CreateFileMappingW
    unimplemented!("Multi-process mode is not yet supported on Windows")
}

/// Open an existing shared memory file (child process).
#[cfg(all(target_os = "linux", not(feature = "mock")))]
#[allow(unsafe_code)]
fn open_shared_mem(path: &str) -> memmap2::MmapMut {
    use std::fs::OpenOptions;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("Failed to open shared memory file");

    // SAFETY: The parent created and zero-initialized this file.
    unsafe {
        memmap2::MmapOptions::new()
            .len(SharedMem::size())
            .map_mut(&file)
            .expect("Failed to mmap shared memory")
    }
}

#[cfg(all(target_os = "windows", not(feature = "mock")))]
fn open_shared_mem(_path: &str) -> memmap2::MmapMut {
    unimplemented!("Multi-process mode is not yet supported on Windows")
}

/// Get a reference to `SharedMem` from a mutable mmap.
///
/// # Safety
/// The mmap must be at least `SharedMem::size()` bytes and
/// zero-initialized (all atomics start at 0/false).
#[cfg(not(feature = "mock"))]
#[allow(unsafe_code)]
unsafe fn shmem_ref(mmap: &memmap2::MmapMut) -> &SharedMem {
    // SAFETY: Shared memory pointer is valid for the lifetime of the process.
    unsafe { &*(mmap.as_ptr() as *const SharedMem) }
}
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum OpKind {
    AesCbcEncDec = 1,
    EccSign = 2,
    HmacSign = 3,
    RsaSign = 4,
    RsaDecrypt = 5,
    EcdhDerive = 6,
    HkdfDerive = 7,
    AesKeyGen = 8,
    EccKeyGen = 9,
    AesXtsKeyGen = 10,
    UnwrappingKeyGen = 11,
    AesUnwrap = 12,
    EccUnwrap = 13,
    XtsUnwrap = 14,
    AesUnmask = 15,
    EccUnmask = 16,
    XtsUnmask = 17,
    EccKeyReport = 18,
    RsaKeyReport = 19,
    UnwrappingKeyReport = 20,
    CertChain = 21,
    AesKeyGenDelete = 22,
    EccKeyGenDelete = 23,
    AesXtsKeyGenDelete = 24,
    #[cfg(feature = "mock")]
    AesXtsEncDec = 25,
    #[cfg(feature = "mock")]
    AesGcmEncDec = 26,
}

impl OpKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::AesCbcEncDec),
            2 => Some(Self::EccSign),
            3 => Some(Self::HmacSign),
            4 => Some(Self::RsaSign),
            5 => Some(Self::RsaDecrypt),
            6 => Some(Self::EcdhDerive),
            7 => Some(Self::HkdfDerive),
            8 => Some(Self::AesKeyGen),
            9 => Some(Self::EccKeyGen),
            10 => Some(Self::AesXtsKeyGen),
            11 => Some(Self::UnwrappingKeyGen),
            12 => Some(Self::AesUnwrap),
            13 => Some(Self::EccUnwrap),
            14 => Some(Self::XtsUnwrap),
            15 => Some(Self::AesUnmask),
            16 => Some(Self::EccUnmask),
            17 => Some(Self::XtsUnmask),
            18 => Some(Self::EccKeyReport),
            19 => Some(Self::RsaKeyReport),
            20 => Some(Self::UnwrappingKeyReport),
            21 => Some(Self::CertChain),
            22 => Some(Self::AesKeyGenDelete),
            23 => Some(Self::EccKeyGenDelete),
            24 => Some(Self::AesXtsKeyGenDelete),
            #[cfg(feature = "mock")]
            25 => Some(Self::AesXtsEncDec),
            #[cfg(feature = "mock")]
            26 => Some(Self::AesGcmEncDec),
            _ => None,
        }
    }
}

impl std::fmt::Display for OpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AesCbcEncDec => write!(f, "AES-CBC enc+dec"),
            Self::EccSign => write!(f, "ECC sign"),
            Self::HmacSign => write!(f, "HMAC sign"),
            Self::RsaSign => write!(f, "RSA sign"),
            Self::RsaDecrypt => write!(f, "RSA decrypt"),
            Self::EcdhDerive => write!(f, "ECDH derive"),
            Self::HkdfDerive => write!(f, "HKDF derive"),
            Self::AesKeyGen => write!(f, "AES key gen"),
            Self::EccKeyGen => write!(f, "ECC key gen"),
            Self::AesXtsKeyGen => write!(f, "AES-XTS key gen"),
            Self::UnwrappingKeyGen => write!(f, "unwrapping key gen"),
            Self::AesUnwrap => write!(f, "AES unwrap"),
            Self::EccUnwrap => write!(f, "ECC unwrap"),
            Self::XtsUnwrap => write!(f, "XTS unwrap"),
            Self::AesUnmask => write!(f, "AES unmask"),
            Self::EccUnmask => write!(f, "ECC unmask"),
            Self::XtsUnmask => write!(f, "XTS unmask"),
            Self::EccKeyReport => write!(f, "ECC key report"),
            Self::RsaKeyReport => write!(f, "RSA key report"),
            Self::UnwrappingKeyReport => write!(f, "unwrapping key report"),
            Self::CertChain => write!(f, "cert chain"),
            Self::AesKeyGenDelete => write!(f, "AES keygen+delete"),
            Self::EccKeyGenDelete => write!(f, "ECC keygen+delete"),
            Self::AesXtsKeyGenDelete => write!(f, "AES-XTS keygen+delete"),
            #[cfg(feature = "mock")]
            Self::AesXtsEncDec => write!(f, "AES-XTS enc+dec"),
            #[cfg(feature = "mock")]
            Self::AesGcmEncDec => write!(f, "AES-GCM enc+dec"),
        }
    }
}

// ---------------------------------------------------------------------------
// Partition + session setup
// ---------------------------------------------------------------------------

fn open_and_init_partition(
    enable_resiliency: bool,
    skip_reset: bool,
    storage_dir: Option<PathBuf>,
) -> (HsmPartition, HsmCredentials) {
    use azihsm_crypto::*;

    const TEST_POTA_PRIVATE_KEY: [u8; 185] = [
        0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b,
        0x02, 0x01, 0x01, 0x04, 0x30, 0x17, 0xe9, 0x1c, 0xac, 0xf7, 0xb7, 0x21, 0xd7, 0x75, 0x20,
        0x02, 0x07, 0xbc, 0xaa, 0x94, 0x2c, 0xe3, 0xb5, 0x5b, 0x78, 0x13, 0xcc, 0x8b, 0xde, 0x87,
        0x65, 0x6b, 0xe1, 0x7b, 0xc2, 0xa8, 0xcc, 0x89, 0x33, 0x4e, 0xcd, 0xaa, 0x9d, 0x1d, 0x09,
        0xf1, 0xc7, 0x01, 0x1b, 0x64, 0xeb, 0x78, 0x5b, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x1f,
        0x42, 0x0d, 0x73, 0xeb, 0xf0, 0x67, 0xc2, 0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6,
        0x53, 0x19, 0xb7, 0x57, 0xe0, 0xa9, 0x20, 0xce, 0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c,
        0x93, 0x45, 0xf1, 0xea, 0xd9, 0x5f, 0xe5, 0x90, 0xab, 0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06,
        0xef, 0x21, 0xa2, 0xad, 0x10, 0xd3, 0x17, 0x6e, 0x99, 0xc8, 0x22, 0x26, 0x23, 0x08, 0x57,
        0xa7, 0x56, 0x08, 0x45, 0xe3, 0xda, 0x12, 0xc7, 0xdc, 0x3a, 0xee, 0x01, 0xfc, 0x37, 0xab,
        0x1c, 0x8d, 0xc6, 0xd0, 0x64, 0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02, 0x7d, 0x8d, 0xa3, 0xc8,
        0x01, 0x4b, 0xa4, 0x0d, 0x98,
    ];
    const TEST_POTA_PUBLIC_KEY_DER: [u8; 120] = [
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0,
        0x67, 0xc2, 0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0,
        0xa9, 0x20, 0xce, 0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9,
        0x5f, 0xe5, 0x90, 0xab, 0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10,
        0xd3, 0x17, 0x6e, 0x99, 0xc8, 0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3,
        0xda, 0x12, 0xc7, 0xdc, 0x3a, 0xee, 0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64,
        0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02, 0x7d, 0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98,
    ];
    const TEST_OBK: [u8; 48] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
        0x2E, 0x2F, 0x30,
    ];

    /// Generate POTA endorsement by signing the device's PID public key.
    fn generate_pota(part: &HsmPartition) -> (Vec<u8>, Vec<u8>) {
        let pid_der = part.pub_key().expect("Failed to get PID public key");
        let pid_pub = DerEccPublicKey::from_der(&pid_der).expect("Failed to parse PID public key");
        let mut uncompressed = vec![0x04u8];
        uncompressed.extend_from_slice(pid_pub.x());
        uncompressed.extend_from_slice(pid_pub.y());

        let priv_key = EccPrivateKey::from_bytes(&TEST_POTA_PRIVATE_KEY)
            .expect("Failed to load POTA private key");
        let hash_algo = HashAlgo::sha384();
        let mut ecdsa = EcdsaAlgo::new(hash_algo);
        let sig =
            Signer::sign_vec(&mut ecdsa, &priv_key, &uncompressed).expect("Failed to sign PID key");
        (sig, TEST_POTA_PUBLIC_KEY_DER.to_vec())
    }

    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No HSM partitions found.");
    let part =
        HsmPartitionManager::open_partition(&list[0].path).expect("Failed to open partition");
    if !skip_reset {
        part.reset().expect("Failed to reset partition");
    }

    let creds = HsmCredentials::new(&[0xAA; 16], &[0xBB; 16]);

    // Select OBK and POTA source based on AZIHSM_USE_TPM env variable,
    // matching the test infrastructure convention.
    let use_tpm = std::env::var("AZIHSM_USE_TPM").is_ok();
    let (obk, pota) = if use_tpm {
        (
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Tpm, None),
            HsmPotaEndorsement::new(HsmPotaEndorsementSource::Tpm, None),
        )
    } else {
        let (sig, pubkey_der) = generate_pota(&part);
        (
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK)),
            HsmPotaEndorsement::new(
                HsmPotaEndorsementSource::Caller,
                Some(HsmPotaEndorsementData::new(&sig, &pubkey_der)),
            ),
        )
    };

    // File-backed resiliency storage: one file per key under a shared directory.
    // All processes (parent + children) use the same directory.
    struct FileStorage {
        dir: PathBuf,
    }
    impl ResiliencyStorage for FileStorage {
        fn read(&self, key: &str) -> HsmResult<Vec<u8>> {
            let path = self.dir.join(key);
            let mut file = fs::File::open(&path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    HsmError::NotFound
                } else {
                    HsmError::InternalError
                }
            })?;
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut buf).map_err(|_| HsmError::InternalError)?;
            Ok(buf)
        }
        fn write(&self, key: &str, data: &[u8]) -> HsmResult<()> {
            let path = self.dir.join(key);
            let tmp_path = self.dir.join(format!(".{key}.tmp"));
            let mut file = fs::File::create(&tmp_path).map_err(|_| HsmError::InternalError)?;
            std::io::Write::write_all(&mut file, data).map_err(|_| HsmError::InternalError)?;
            file.sync_all().map_err(|_| HsmError::InternalError)?;
            fs::rename(&tmp_path, &path).map_err(|_| HsmError::InternalError)?;
            Ok(())
        }
        fn clear(&self, key: &str) -> HsmResult<()> {
            let path = self.dir.join(key);
            let _ = fs::remove_file(&path);
            Ok(())
        }
    }

    // File-backed cross-process lock using flock.
    struct FileLock {
        path: PathBuf,
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
            fs2::FileExt::lock_exclusive(&file).map_err(|_| HsmError::InternalError)?;
            *guard = Some(file);
            Ok(())
        }
        fn unlock(&self) -> HsmResult<()> {
            let mut guard = self.active.lock();
            match guard.take() {
                Some(file) => {
                    fs2::FileExt::unlock(&file).map_err(|_| HsmError::InternalError)?;
                    Ok(())
                }
                None => Err(HsmError::InternalError),
            }
        }
    }

    /// POTA re-endorsement callback for resiliency restore.
    /// Opens a separate partition handle to avoid deadlock — the callback
    /// is invoked while the caller's partition RwLock is held.
    struct StressPotaCallback {
        path: String,
    }
    impl PotaEndorsementCallback for StressPotaCallback {
        fn endorse(&self, _pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData> {
            let part = HsmPartitionManager::open_partition(&self.path)?;
            let (sig, pubkey_der) = generate_pota(&part);
            Ok(HsmPotaEndorsementData::new(&sig, &pubkey_der))
        }
    }

    let resiliency_config = if enable_resiliency {
        let storage_path = storage_dir.unwrap_or_else(|| {
            let dir = std::env::temp_dir().join(format!("azihsm_stress_{}", std::process::id()));
            fs::create_dir_all(&dir).expect("Failed to create storage directory");
            dir
        });
        fs::create_dir_all(&storage_path).ok(); // ok if already exists
        eprintln!(
            "[pid={}] Resiliency storage path: {}",
            std::process::id(),
            storage_path.display()
        );

        // POTA callback is only needed for Caller source (not TPM).
        let pota_callback: Option<Box<dyn PotaEndorsementCallback>> = if !use_tpm {
            Some(Box::new(StressPotaCallback { path: part.path() }))
        } else {
            None
        };

        Some(HsmResiliencyConfig {
            storage: Box::new(FileStorage {
                dir: storage_path.clone(),
            }),
            lock: Arc::new(FileLock::new(storage_path.join(".lock"))),
            pota_callback,
        })
    } else {
        None
    };

    part.init(creds, None, None, obk, pota, resiliency_config)
        .expect("Failed to init partition");

    (part, creds)
}

fn open_session(part: &HsmPartition, creds: &HsmCredentials) -> HsmSession {
    part.open_session(part.api_rev_range().max(), creds, None)
        .expect("Failed to open session")
}

// ---------------------------------------------------------------------------
// Key creation helpers
// ---------------------------------------------------------------------------

fn gen_aes_key(session: &HsmSession) -> HsmAesKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("AES key props");
    let mut algo = HsmAesKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props).expect("AES key gen")
}

fn gen_ecc_key_pair(session: &HsmSession) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("ECC priv props");
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("ECC pub props");
    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
        .expect("ECC key gen")
}

fn gen_ecc_derive_key_pair(session: &HsmSession) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("ECC derive priv props");
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("ECC derive pub props");
    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
        .expect("ECC derive key gen")
}

fn gen_hmac_key(session: &HsmSession) -> HsmHmacKey {
    // ECDH needs two different key pairs with can_derive.
    let (priv_a, _) = gen_ecc_derive_key_pair(session);
    let (_, pub_b) = gen_ecc_derive_key_pair(session);
    let pub_der = pub_b.pub_key_der_vec().expect("ECC pub DER");
    let mut ecdh_algo = EcdhAlgo::new(&pub_der);
    let secret_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("secret props");
    let shared_secret = HsmKeyManager::derive_key(session, &mut ecdh_algo, &priv_a, secret_props)
        .expect("ECDH derive");

    let hmac_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("HMAC props");
    let mut hkdf =
        HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(b"salt"), Some(b"info")).expect("HKDF algo");
    let derived = HsmKeyManager::derive_key(session, &mut hkdf, &shared_secret, hmac_props)
        .expect("HKDF derive");
    derived.try_into().expect("convert to HmacKey")
}

fn gen_rsa_unwrapping_key_pair(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("RSA unwrap priv props");
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("RSA unwrap pub props");
    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
        .expect("RSA unwrap keygen")
}

fn import_rsa_sign_key(
    _session: &HsmSession,
    unwrap_priv: &HsmRsaPrivateKey,
    unwrap_pub: &HsmRsaPublicKey,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let sw_key = azihsm_crypto::RsaPrivateKey::generate(256).expect("SW RSA key gen");
    let der = sw_key.to_vec().expect("RSA DER export");

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap_algo, unwrap_pub, &der).expect("RSA key wrap");

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("RSA sign priv props");
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("RSA sign pub props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .expect("RSA sign key unwrap")
}

fn import_rsa_enc_key(
    _session: &HsmSession,
    unwrap_priv: &HsmRsaPrivateKey,
    unwrap_pub: &HsmRsaPublicKey,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let sw_key = azihsm_crypto::RsaPrivateKey::generate(256).expect("SW RSA key gen");
    let der = sw_key.to_vec().expect("RSA DER export");

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap_algo, unwrap_pub, &der).expect("RSA key wrap");

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("RSA dec priv props");
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .is_session(true)
        .build()
        .expect("RSA enc pub props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .expect("RSA enc key unwrap")
}

fn prepare_wrapped_aes_key(
    _session: &HsmSession,
    _unwrap_priv: &HsmRsaPrivateKey,
    unwrap_pub: &HsmRsaPublicKey,
) -> Vec<u8> {
    let aes_key_data = vec![0x42u8; 32];
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    HsmEncrypter::encrypt_vec(&mut wrap_algo, unwrap_pub, &aes_key_data).expect("AES key wrap")
}

fn prepare_wrapped_ecc_key(_session: &HsmSession, unwrap_pub: &HsmRsaPublicKey) -> Vec<u8> {
    let sw_key = azihsm_crypto::EccPrivateKey::from_curve(azihsm_crypto::EccCurve::P256)
        .expect("SW ECC key gen");
    let der = sw_key.to_vec().expect("ECC DER export");

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    HsmEncrypter::encrypt_vec(&mut wrap_algo, unwrap_pub, &der).expect("ECC key wrap")
}

fn build_xts_wrapped_blob(
    wrapping_pub_key: &HsmRsaPublicKey,
    hash: HsmHashAlgo,
    key1_plain: &[u8],
    key2_plain: &[u8],
) -> Vec<u8> {
    const WRAP_BLOB_MAGIC: u64 = 0x5354_584D_5348_5A41;
    const WRAP_BLOB_VERSION: u16 = 1;

    let mut wrap1 = HsmRsaAesWrapAlgo::new(hash, key1_plain.len());
    let key1_wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap1, wrapping_pub_key, key1_plain).expect("XTS key1 wrap");
    let mut wrap2 = HsmRsaAesWrapAlgo::new(hash, key2_plain.len());
    let key2_wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap2, wrapping_pub_key, key2_plain).expect("XTS key2 wrap");

    let key1_len = u16::try_from(key1_wrapped.len()).expect("XTS key1 len");
    let key2_len = u16::try_from(key2_wrapped.len()).expect("XTS key2 len");

    let mut hdr = [0u8; 16];
    hdr[0..8].copy_from_slice(&WRAP_BLOB_MAGIC.to_le_bytes());
    hdr[8..10].copy_from_slice(&WRAP_BLOB_VERSION.to_le_bytes());
    hdr[10..12].copy_from_slice(&key1_len.to_le_bytes());
    hdr[12..14].copy_from_slice(&key2_len.to_le_bytes());

    let mut blob = Vec::with_capacity(hdr.len() + key1_wrapped.len() + key2_wrapped.len());
    blob.extend_from_slice(&hdr);
    blob.extend_from_slice(&key1_wrapped);
    blob.extend_from_slice(&key2_wrapped);
    blob
}

fn prepare_wrapped_xts_key(_session: &HsmSession, unwrap_pub: &HsmRsaPublicKey) -> Vec<u8> {
    let key1 = vec![0x11u8; 32];
    let key2 = vec![0x22u8; 32];
    build_xts_wrapped_blob(unwrap_pub, HsmHashAlgo::Sha256, &key1, &key2)
}

fn gen_aes_xts_key(session: &HsmSession) -> HsmAesXtsKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("AES-XTS key props");
    let mut algo = HsmAesXtsKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props).expect("AES-XTS key gen")
}

// ---------------------------------------------------------------------------
// Operation executors
// ---------------------------------------------------------------------------

fn exec_aes_cbc_enc_dec(key: &HsmAesKey) -> HsmResult<()> {
    let iv = [0u8; 16];
    let data = b"stress test data for encryption!"; // 32 bytes
                                                    // Encrypt
    let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
    let len = HsmEncrypter::encrypt(&mut algo, key, data, None)?;
    let mut ct = vec![0u8; len];
    let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
    HsmEncrypter::encrypt(&mut algo, key, data, Some(&mut ct))?;
    // Decrypt
    let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
    let len = HsmDecrypter::decrypt(&mut algo, key, &ct, None)?;
    let mut pt = vec![0u8; len];
    let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
    HsmDecrypter::decrypt(&mut algo, key, &ct, Some(&mut pt))?;
    Ok(())
}

fn exec_ecc_sign(key: &HsmEccPrivateKey, hash: &[u8]) -> HsmResult<()> {
    let mut algo = HsmEccSignAlgo::default();
    let len = HsmSigner::sign(&mut algo, key, hash, None)?;
    let mut sig = vec![0u8; len];
    HsmSigner::sign(&mut algo, key, hash, Some(&mut sig))?;
    Ok(())
}

fn exec_hmac_sign(key: &HsmHmacKey) -> HsmResult<()> {
    let data = b"stress test data for HMAC signing";
    let mut algo = HsmHmacAlgo::new();
    let len = HsmSigner::sign(&mut algo, key, data, None)?;
    let mut sig = vec![0u8; len];
    HsmSigner::sign(&mut algo, key, data, Some(&mut sig))?;
    Ok(())
}

fn exec_aes_keygen(session: &HsmSession) -> HsmResult<()> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let mut algo = HsmAesKeyGenAlgo::default();
    let _key = HsmKeyManager::generate_key(session, &mut algo, props)?;
    Ok(())
}

fn exec_ecdh_derive(
    session: &HsmSession,
    priv_key: &HsmEccPrivateKey,
    peer_pub_key: &HsmEccPublicKey,
) -> HsmResult<()> {
    let pub_der = peer_pub_key
        .pub_key_der_vec()
        .map_err(|_| HsmError::InternalError)?;
    let mut algo = EcdhAlgo::new(&pub_der);
    let bits = priv_key
        .ecc_curve()
        .ok_or(HsmError::InternalError)?
        .key_size_bits() as u32;
    let secret_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(bits)
        .can_derive(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let _secret = HsmKeyManager::derive_key(session, &mut algo, priv_key, secret_props)?;
    Ok(())
}

fn exec_hkdf_derive(session: &HsmSession, shared_secret: &HsmGenericSecretKey) -> HsmResult<()> {
    let hmac_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let mut hkdf = HsmHkdfAlgo::new(
        HsmHashAlgo::Sha256,
        Some(b"stress_salt"),
        Some(b"stress_info"),
    )
    .map_err(|_| HsmError::InternalError)?;
    let _key = HsmKeyManager::derive_key(session, &mut hkdf, shared_secret, hmac_props)?;
    Ok(())
}

fn exec_rsa_sign(key: &HsmRsaPrivateKey, hash: &[u8]) -> HsmResult<()> {
    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let len = HsmSigner::sign(&mut algo, key, hash, None)?;
    let mut sig = vec![0u8; len];
    HsmSigner::sign(&mut algo, key, hash, Some(&mut sig))?;
    Ok(())
}

fn exec_rsa_decrypt(key: &HsmRsaPrivateKey, ciphertext: &[u8]) -> HsmResult<()> {
    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    let len = HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?;
    let mut out = vec![0u8; len];
    let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
    HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut out))?;
    Ok(())
}

fn exec_aes_unwrap(unwrapping_key: &HsmRsaPrivateKey, wrapped: &[u8]) -> HsmResult<()> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let mut algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let _key: HsmAesKey = HsmKeyManager::unwrap_key(&mut algo, unwrapping_key, wrapped, props)?;
    Ok(())
}

fn exec_ecc_unwrap(unwrapping_key: &HsmRsaPrivateKey, wrapped: &[u8]) -> HsmResult<()> {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let mut algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (_priv, _pub): (HsmEccPrivateKey, HsmEccPublicKey) =
        HsmKeyManager::unwrap_key_pair(&mut algo, unwrapping_key, wrapped, priv_props, pub_props)?;
    Ok(())
}

fn exec_xts_unwrap(unwrapping_key: &HsmRsaPrivateKey, wrapped: &[u8]) -> HsmResult<()> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let mut algo = HsmAesXtsKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let _key: HsmAesXtsKey = HsmKeyManager::unwrap_key(&mut algo, unwrapping_key, wrapped, props)?;
    Ok(())
}

fn exec_aes_unmask(session: &HsmSession, masked: &[u8]) -> HsmResult<()> {
    let mut algo = HsmAesKeyUnmaskAlgo::default();
    let _key: HsmAesKey = HsmKeyManager::unmask_key(session, &mut algo, masked)?;
    Ok(())
}

fn exec_ecc_unmask(session: &HsmSession, masked: &[u8]) -> HsmResult<()> {
    let mut algo = HsmEccKeyUnmaskAlgo::default();
    let (_priv, _pub): (HsmEccPrivateKey, HsmEccPublicKey) =
        HsmKeyManager::unmask_key_pair(session, &mut algo, masked)?;
    Ok(())
}

fn exec_xts_unmask(session: &HsmSession, masked: &[u8]) -> HsmResult<()> {
    let mut algo = HsmAesXtsKeyUnmaskAlgo::default();
    let _key: HsmAesXtsKey = HsmKeyManager::unmask_key(session, &mut algo, masked)?;
    Ok(())
}

fn exec_ecc_keygen(session: &HsmSession) -> HsmResult<()> {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let mut algo = HsmEccKeyGenAlgo::default();
    let (_priv, _pub) =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)?;
    Ok(())
}

fn exec_aes_xts_keygen(session: &HsmSession) -> HsmResult<()> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let _key: HsmAesXtsKey = HsmKeyManager::generate_key(session, &mut algo, props)?;
    Ok(())
}

fn exec_unwrapping_keygen(session: &HsmSession) -> HsmResult<()> {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .map_err(|_| HsmError::InvalidArgument)?;
    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    let (_priv, _pub) =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)?;
    Ok(())
}

fn exec_ecc_key_report(key: &HsmEccPrivateKey, report_data: &[u8]) -> HsmResult<()> {
    let report_size = HsmKeyManager::generate_key_report(key, report_data, None)?;
    let mut report_buffer = vec![0u8; report_size];
    HsmKeyManager::generate_key_report(key, report_data, Some(&mut report_buffer))?;
    Ok(())
}

fn exec_rsa_key_report(key: &HsmRsaPrivateKey, report_data: &[u8]) -> HsmResult<()> {
    let report_size = HsmKeyManager::generate_key_report(key, report_data, None)?;
    let mut report_buffer = vec![0u8; report_size];
    HsmKeyManager::generate_key_report(key, report_data, Some(&mut report_buffer))?;
    Ok(())
}

fn exec_cert_chain(partition: &HsmPartition) -> HsmResult<()> {
    let _chain = partition.cert_chain(0)?;
    Ok(())
}

fn exec_aes_keygen_delete(session: &HsmSession) -> HsmResult<()> {
    let key = gen_aes_key(session);
    HsmKeyManager::delete_key(key)?;
    Ok(())
}

fn exec_ecc_keygen_delete(session: &HsmSession) -> HsmResult<()> {
    let (priv_key, _pub_key) = gen_ecc_key_pair(session);
    HsmKeyManager::delete_key(priv_key)?;
    Ok(())
}

fn exec_aes_xts_keygen_delete(session: &HsmSession) -> HsmResult<()> {
    let key = gen_aes_xts_key(session);
    HsmKeyManager::delete_key(key)?;
    Ok(())
}

#[cfg(feature = "mock")]
fn exec_aes_xts_enc_dec(key: &HsmAesXtsKey) -> HsmResult<()> {
    let tweak = [0u8; 16];
    let plaintext = [0x42u8; 512]; // DUL-aligned
                                   // Encrypt
    let mut algo = HsmAesXtsAlgo::new(&tweak, 512).map_err(|_| HsmError::InternalError)?;
    let len = HsmEncrypter::encrypt(&mut algo, key, &plaintext, None)?;
    let mut ct = vec![0u8; len];
    let mut algo = HsmAesXtsAlgo::new(&tweak, 512).map_err(|_| HsmError::InternalError)?;
    HsmEncrypter::encrypt(&mut algo, key, &plaintext, Some(&mut ct))?;
    // Decrypt
    let mut algo = HsmAesXtsAlgo::new(&tweak, 512).map_err(|_| HsmError::InternalError)?;
    let len = HsmDecrypter::decrypt(&mut algo, key, &ct, None)?;
    let mut pt = vec![0u8; len];
    let mut algo = HsmAesXtsAlgo::new(&tweak, 512).map_err(|_| HsmError::InternalError)?;
    HsmDecrypter::decrypt(&mut algo, key, &ct, Some(&mut pt))?;
    Ok(())
}

#[cfg(feature = "mock")]
fn gen_aes_gcm_key(session: &HsmSession) -> HsmAesGcmKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("AES-GCM key props");
    let mut algo = HsmAesGcmKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props).expect("AES-GCM key gen")
}

#[cfg(feature = "mock")]
fn exec_aes_gcm_enc_dec(key: &HsmAesGcmKey) -> HsmResult<()> {
    let iv = [0u8; 12];
    let plaintext = b"stress test data for GCM!padding";
    // Encrypt
    let mut algo = HsmAesGcmAlgo::new_for_encryption(iv.to_vec(), None)
        .map_err(|_| HsmError::InternalError)?;
    let len = HsmEncrypter::encrypt(&mut algo, key, plaintext.as_slice(), None)?;
    let mut ct = vec![0u8; len];
    let mut algo = HsmAesGcmAlgo::new_for_encryption(iv.to_vec(), None)
        .map_err(|_| HsmError::InternalError)?;
    HsmEncrypter::encrypt(&mut algo, key, plaintext.as_slice(), Some(&mut ct))?;
    let tag = algo.tag().ok_or(HsmError::InternalError)?;
    // Decrypt
    let mut algo = HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), tag.to_vec(), None)
        .map_err(|_| HsmError::InternalError)?;
    let len = HsmDecrypter::decrypt(&mut algo, key, &ct, None)?;
    let mut pt = vec![0u8; len];
    let mut algo = HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), tag.to_vec(), None)
        .map_err(|_| HsmError::InternalError)?;
    HsmDecrypter::decrypt(&mut algo, key, &ct, Some(&mut pt))?;
    Ok(())
}

fn parse_ops(ops_str: &str) -> Vec<OpKind> {
    if ops_str == "all" {
        return vec![
            OpKind::AesCbcEncDec,
            OpKind::EccSign,
            OpKind::HmacSign,
            OpKind::RsaSign,
            OpKind::RsaDecrypt,
            OpKind::EcdhDerive,
            OpKind::HkdfDerive,
            // Standalone keygen ops (AesKeyGen, EccKeyGen, AesXtsKeyGen) excluded
            // from 'all' — their keygen+delete variants below exercise the same
            // code path without leaking session key slots.
            OpKind::AesUnwrap,
            OpKind::EccUnwrap,
            OpKind::XtsUnwrap,
            OpKind::AesUnmask,
            OpKind::EccUnmask,
            OpKind::XtsUnmask,
            OpKind::EccKeyReport,
            OpKind::RsaKeyReport,
            OpKind::UnwrappingKeyReport,
            OpKind::CertChain,
            OpKind::AesKeyGenDelete,
            OpKind::EccKeyGenDelete,
            OpKind::AesXtsKeyGenDelete,
            #[cfg(feature = "mock")]
            OpKind::AesXtsEncDec,
            #[cfg(feature = "mock")]
            OpKind::AesGcmEncDec,
        ];
    }
    let mut ops = Vec::new();
    for op in ops_str.split(',') {
        match op.trim() {
            "aes-cbc" => ops.push(OpKind::AesCbcEncDec),
            #[cfg(feature = "mock")]
            "aes-xts" => ops.push(OpKind::AesXtsEncDec),
            #[cfg(not(feature = "mock"))]
            "aes-xts" => {
                eprintln!("aes-xts enc/dec requires mock feature.");
                std::process::exit(1);
            }
            #[cfg(feature = "mock")]
            "aes-gcm" => ops.push(OpKind::AesGcmEncDec),
            #[cfg(not(feature = "mock"))]
            "aes-gcm" => {
                eprintln!("aes-gcm enc/dec requires mock feature.");
                std::process::exit(1);
            }
            "ecc-sign" => ops.push(OpKind::EccSign),
            "hmac-sign" => ops.push(OpKind::HmacSign),
            "rsa-sign" => ops.push(OpKind::RsaSign),
            "rsa-decrypt" => ops.push(OpKind::RsaDecrypt),
            "rsa" => {
                ops.push(OpKind::RsaSign);
                ops.push(OpKind::RsaDecrypt);
            }
            "aes-keygen" => ops.push(OpKind::AesKeyGen),
            "ecc-keygen" => ops.push(OpKind::EccKeyGen),
            "aes-xts-keygen" => ops.push(OpKind::AesXtsKeyGen),
            "ecdh" => ops.push(OpKind::EcdhDerive),
            "hkdf" => ops.push(OpKind::HkdfDerive),
            "unwrapping-keygen" => ops.push(OpKind::UnwrappingKeyGen),
            "aes-unwrap" => ops.push(OpKind::AesUnwrap),
            "ecc-unwrap" => ops.push(OpKind::EccUnwrap),
            "xts-unwrap" => ops.push(OpKind::XtsUnwrap),
            "unwrap" => {
                ops.push(OpKind::AesUnwrap);
                ops.push(OpKind::EccUnwrap);
                ops.push(OpKind::XtsUnwrap);
            }
            "aes-unmask" => ops.push(OpKind::AesUnmask),
            "ecc-unmask" => ops.push(OpKind::EccUnmask),
            "xts-unmask" => ops.push(OpKind::XtsUnmask),
            "unmask" => {
                ops.push(OpKind::AesUnmask);
                ops.push(OpKind::EccUnmask);
                ops.push(OpKind::XtsUnmask);
            }
            "ecc-key-report" => ops.push(OpKind::EccKeyReport),
            "rsa-key-report" => ops.push(OpKind::RsaKeyReport),
            "unwrapping-key-report" => ops.push(OpKind::UnwrappingKeyReport),
            "key-report" => {
                ops.push(OpKind::EccKeyReport);
                ops.push(OpKind::RsaKeyReport);
                ops.push(OpKind::UnwrappingKeyReport);
            }
            "cert-chain" => ops.push(OpKind::CertChain),
            "aes-keygen-delete" => ops.push(OpKind::AesKeyGenDelete),
            "ecc-keygen-delete" => ops.push(OpKind::EccKeyGenDelete),
            "xts-keygen-delete" => ops.push(OpKind::AesXtsKeyGenDelete),
            "keygen-delete" => {
                ops.push(OpKind::AesKeyGenDelete);
                ops.push(OpKind::EccKeyGenDelete);
                ops.push(OpKind::AesXtsKeyGenDelete);
            }
            other => {
                eprintln!("Unknown operation: {other}");
                std::process::exit(1);
            }
        }
    }
    ops
}

fn main() {
    let args = Args::parse();

    // Child process dispatch: if --child-id is set, we are a child process.
    #[cfg(not(feature = "mock"))]
    if let Some(child_id) = args.child_id {
        run_as_child(args, child_id);
        return;
    }

    // Mock builds use single-process mode (in-process sim doesn't support
    // cross-process resets). Multi-process is supported for sim-service
    // and hardware.
    #[cfg(feature = "mock")]
    {
        if args.processes > 1 {
            eprintln!("Multi-process mode (-p > 1) is not supported with mock feature.");
            eprintln!("Use -p 1 or build with --features sim-service for multi-process testing.");
            std::process::exit(1);
        }
        run_single_process(args);
        return;
    }

    #[cfg(not(feature = "mock"))]
    run_as_parent(args);
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn print_config(args: &Args, ops: &[OpKind]) {
    eprintln!("\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
    eprintln!("\u{2551}    Resiliency Stress Tool        \u{2551}");
    eprintln!("\u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}");
    eprintln!("Processes:      {}", args.processes);
    eprintln!("Workers/proc:   {}", args.workers);
    eprintln!("Reset interval: {}ms", args.reset_interval_ms);
    eprintln!(
        "Duration:       {}",
        if args.duration_secs == 0 {
            "infinite (Ctrl-C to stop)".to_string()
        } else {
            format!("{}s", args.duration_secs)
        }
    );
    eprintln!(
        "Max errors:     {}",
        if args.max_errors < 0 {
            "unlimited".to_string()
        } else {
            format!("{}", args.max_errors)
        }
    );

    eprintln!("Operations:     {} ops", ops.len());
    let mut enc_dec = Vec::new();
    let mut sign = Vec::new();
    let mut decrypt = Vec::new();
    let mut derive = Vec::new();
    let mut unwrap = Vec::new();
    let mut unmask = Vec::new();
    let mut key_report = Vec::new();
    let mut keygen_del = Vec::new();
    let mut keygen = Vec::new();
    let mut other = Vec::new();
    for op in ops {
        match op {
            OpKind::AesCbcEncDec => enc_dec.push("AES-CBC"),
            #[cfg(feature = "mock")]
            OpKind::AesXtsEncDec => enc_dec.push("AES-XTS"),
            #[cfg(feature = "mock")]
            OpKind::AesGcmEncDec => enc_dec.push("AES-GCM"),
            OpKind::EccSign => sign.push("ECC"),
            OpKind::HmacSign => sign.push("HMAC"),
            OpKind::RsaSign => sign.push("RSA"),
            OpKind::RsaDecrypt => decrypt.push("RSA"),
            OpKind::EcdhDerive => derive.push("ECDH"),
            OpKind::HkdfDerive => derive.push("HKDF"),
            OpKind::AesUnwrap => unwrap.push("AES"),
            OpKind::EccUnwrap => unwrap.push("ECC"),
            OpKind::XtsUnwrap => unwrap.push("XTS"),
            OpKind::AesUnmask => unmask.push("AES"),
            OpKind::EccUnmask => unmask.push("ECC"),
            OpKind::XtsUnmask => unmask.push("XTS"),
            OpKind::EccKeyReport => key_report.push("ECC"),
            OpKind::RsaKeyReport => key_report.push("RSA"),
            OpKind::UnwrappingKeyReport => key_report.push("unwrapping"),
            OpKind::AesKeyGenDelete => keygen_del.push("AES"),
            OpKind::EccKeyGenDelete => keygen_del.push("ECC"),
            OpKind::AesXtsKeyGenDelete => keygen_del.push("AES-XTS"),
            OpKind::AesKeyGen => keygen.push("AES"),
            OpKind::EccKeyGen => keygen.push("ECC"),
            OpKind::AesXtsKeyGen => keygen.push("AES-XTS"),
            OpKind::UnwrappingKeyGen => keygen.push("unwrapping"),
            OpKind::CertChain => other.push("cert chain"),
        }
    }
    let groups: [(&str, &[&str]); 10] = [
        ("Encrypt/Decrypt:", &enc_dec),
        ("Sign:           ", &sign),
        ("Decrypt:        ", &decrypt),
        ("Derive:         ", &derive),
        ("Unwrap:         ", &unwrap),
        ("Unmask:         ", &unmask),
        ("Key Report:     ", &key_report),
        ("KeyGen+Delete:  ", &keygen_del),
        ("KeyGen:         ", &keygen),
        ("Other:          ", &other),
    ];
    for (label, items) in &groups {
        if !items.is_empty() {
            eprintln!("  {label} {}", items.join(", "));
        }
    }
    eprintln!();
}

fn print_final_stats(shmem: &SharedMem, num_procs: usize, elapsed: Duration) {
    let total_resets = shmem.total_resets.load(Ordering::Relaxed);
    let reset_fails = shmem.reset_failures.load(Ordering::Relaxed);

    let mut grand_ops: u64 = 0;
    let mut grand_errors: u64 = 0;
    let mut grand_op_counts = [0u64; NUM_OPS];
    let mut grand_op_errors = [0u64; NUM_OPS];

    for p in 0..num_procs {
        let ps = &shmem.procs[p];
        grand_ops += ps.total_ops.load(Ordering::Relaxed);
        grand_errors += ps.total_errors.load(Ordering::Relaxed);
        for j in 0..NUM_OPS {
            grand_op_counts[j] += ps.op_counts[j].load(Ordering::Relaxed);
            grand_op_errors[j] += ps.op_errors[j].load(Ordering::Relaxed);
        }
    }

    eprintln!("\n");
    eprintln!("=== Final Stats ===");
    eprintln!(
        "Elapsed:        {:02}:{:02}:{:02}",
        elapsed.as_secs() / 3600,
        (elapsed.as_secs() % 3600) / 60,
        elapsed.as_secs() % 60,
    );
    eprintln!("Total ops:      {grand_ops}");
    eprintln!("Op errors:      {grand_errors}");
    eprintln!("Resets:         {total_resets}");
    eprintln!("Reset failures: {reset_fails}");
    eprintln!(
        "Ops/sec:        {:.0}",
        grand_ops as f64 / elapsed.as_secs_f64().max(0.001)
    );

    eprintln!();

    // Header with per-process columns.
    eprint!("                    ");
    for p in 0..num_procs {
        eprint!("{:>8}", format!("P{p}"));
    }
    eprintln!("{:>9}", "Total");

    for (i, label) in LABELS.iter().enumerate() {
        if grand_op_counts[i] == 0 && grand_op_errors[i] == 0 {
            continue;
        }
        eprint!("  {label}");
        for p in 0..num_procs {
            eprint!("{:>8}", shmem.procs[p].op_counts[i].load(Ordering::Relaxed));
        }
        let errs = grand_op_errors[i];
        if errs > 0 {
            eprintln!("{:>9}  !! {errs} fail", grand_op_counts[i]);
        } else {
            eprintln!("{:>9}", grand_op_counts[i]);
        }
    }

    for p in 0..num_procs {
        let ps = &shmem.procs[p];
        if ps.failed.load(Ordering::Relaxed) {
            let op_u8 = ps.failed_op.load(Ordering::Relaxed) as u8;
            let op = OpKind::from_u8(op_u8)
                .map(|o| format!("{o}"))
                .unwrap_or_else(|| format!("unknown({})", op_u8));
            let err = ps.failed_error.load(Ordering::Relaxed);
            let tid = ps.failed_thread.load(Ordering::Relaxed);
            eprintln!();
            eprintln!("=== FAILURE (P{p}) ===");
            eprintln!("Thread:    {tid}");
            eprintln!("Operation: {op}");
            eprintln!("Error:     {err}");
        }
    }

    if grand_errors > 0 {
        eprintln!();
        eprintln!("Completed with {grand_errors} error(s) (within budget).");
    } else {
        eprintln!();
        eprintln!("All operations completed successfully.");
    }
}

// ---------------------------------------------------------------------------
// Single-process mode (mock builds)
// ---------------------------------------------------------------------------

/// Runs everything in a single process: partition, session, workers, and
/// reset thread all share the same in-process mock simulator.
#[cfg(feature = "mock")]
#[allow(unsafe_code)]
fn run_single_process(args: Args) {
    if args.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(std::io::stderr)
            .init();
    } else {
        let log_path = "resiliency_stress.log";
        let log_file = fs::File::create(log_path).expect("Failed to create log file");
        #[allow(clippy::disallowed_types)]
        let writer = std::sync::Mutex::new(log_file);
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(writer)
            .with_ansi(false)
            .init();
    }

    let ops = parse_ops(&args.ops);
    if !args.verbose {
        eprintln!("Trace log:      resiliency_stress.log");
    }
    print_config(&args, &ops);

    // Heap-allocate SharedMem (zero-initialized = all atomics start at 0/false).
    let shmem: Box<SharedMem> = unsafe { Box::new(std::mem::zeroed()) };
    let shmem: &'static SharedMem = Box::leak(shmem);
    let proc_stats = &shmem.procs[0];

    // Open and init partition with resiliency.
    let enable_resiliency = !args.no_resiliency;
    let enable_resets = enable_resiliency && !args.no_reset;
    let (part, creds) = open_and_init_partition(enable_resiliency, false, None);
    let session = open_session(&part, &creds);
    let shared_unwrap_keys = Arc::new(gen_rsa_unwrapping_key_pair(&session));

    let max_errors = args.max_errors;
    let num_workers = args.workers;
    let barrier = Arc::new(Barrier::new(num_workers));
    let reset_interval = Duration::from_millis(args.reset_interval_ms);

    // Spawn reset thread (in-process, shares the mock sim).
    let reset_handle = {
        let list = HsmPartitionManager::partition_info_list();
        let path = list[0].path.clone();
        thread::spawn(move || {
            let partition = HsmPartitionManager::open_partition(&path)
                .expect("Failed to open partition for reset thread");

            if !enable_resets {
                while !shmem.stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                }
                return;
            }

            // Wait for workers to finish setup.
            eprintln!("Reset thread: waiting for workers to be ready...");
            while shmem.children_ready.load(Ordering::Acquire) < 1 {
                if shmem.stop.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            eprintln!("Reset thread: workers ready, starting resets.");

            loop {
                thread::sleep(reset_interval);
                if shmem.stop.load(Ordering::Relaxed) {
                    break;
                }
                match partition.reset() {
                    Ok(()) => {
                        shmem.total_resets.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        shmem.reset_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
    };

    // Stats display thread.
    let stats_interval = Duration::from_secs(args.stats_interval_secs);
    let stall_timeout = Duration::from_secs(args.stall_timeout_secs);
    let start = Instant::now();
    let stats_handle =
        thread::spawn(move || multiproc_stats_loop(shmem, 1, stats_interval, start, stall_timeout));

    // Duration timer.
    if args.duration_secs > 0 {
        let dur = Duration::from_secs(args.duration_secs);
        thread::spawn(move || {
            thread::sleep(dur);
            shmem.stop.store(true, Ordering::SeqCst);
        });
    }

    // Deadlock detection thread.
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        let deadlocks = deadlock::check_deadlock();
        if !deadlocks.is_empty() {
            eprintln!("=== DEADLOCK DETECTED ({} cycles) ===", deadlocks.len());
            for (i, threads) in deadlocks.iter().enumerate() {
                eprintln!("--- Cycle {} ({} threads) ---", i + 1, threads.len());
                for t in threads {
                    eprintln!("Thread {:?}: {:#?}", t.thread_id(), t.backtrace());
                }
            }
            shmem.stop.store(true, Ordering::SeqCst);
            break;
        }
        if shmem.stop.load(Ordering::Relaxed) {
            break;
        }
    });

    // Spawn worker threads.
    let mut worker_handles = Vec::new();
    for i in 0..num_workers {
        let partition = part.clone();
        let session = session.clone();
        let ops = ops.clone();
        let barrier_clone = Arc::clone(&barrier);
        let unwrap_keys = Arc::clone(&shared_unwrap_keys);
        let handle = thread::spawn(move || {
            child_worker_thread(
                i,
                partition,
                session,
                ops,
                proc_stats,
                shmem,
                barrier_clone,
                max_errors,
                unwrap_keys,
            )
        });
        worker_handles.push(handle);
    }

    // Wait for completion.
    let stalled = stats_handle.join().unwrap_or(false);

    // Stop everything.
    shmem.stop.store(true, Ordering::SeqCst);
    let _ = reset_handle.join();

    let mut any_failed = false;
    for handle in worker_handles {
        if let Ok(true) = handle.join() {
            any_failed = true;
        }
    }

    let elapsed = start.elapsed();
    print_final_stats(shmem, 1, elapsed);

    if any_failed {
        std::process::exit(1);
    } else if stalled {
        eprintln!();
        eprintln!("Exiting due to stall (possible deadlock).");
        std::process::exit(2);
    }
}

// ---------------------------------------------------------------------------
// Multi-process: parent orchestrator
// ---------------------------------------------------------------------------

#[cfg(not(feature = "mock"))]
#[allow(unsafe_code)]
fn run_as_parent(args: Args) {
    use std::process::Command;

    if args.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(std::io::stderr)
            .init();
    } else {
        let log_path = "resiliency_stress_parent.log";
        let log_file = fs::File::create(log_path).expect("Failed to create log file");
        // tracing_subscriber requires std::sync::Mutex, not parking_lot::Mutex.
        #[allow(clippy::disallowed_types)]
        let writer = std::sync::Mutex::new(log_file);
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(writer)
            .with_ansi(false)
            .init();
    }

    let num_procs = args.processes;
    assert!((1..=MAX_PROCS).contains(&num_procs));

    let ops = parse_ops(&args.ops);
    if !args.verbose {
        if num_procs == 1 {
            eprintln!("Trace log:      resiliency_stress_child_0.log");
        } else {
            eprintln!(
                "Trace log:      resiliency_stress_parent.log (+ child_0..{} logs)",
                num_procs - 1
            );
        }
    }
    print_config(&args, &ops);

    // Create shared memory.
    let (shmem_path, mmap) = create_shared_mem();
    // SAFETY: Shared memory pointer is valid for the lifetime of the process.
    let shmem: &SharedMem = unsafe { shmem_ref(&mmap) };

    // Create shared resiliency storage directory for all processes.
    let storage_dir = std::env::temp_dir().join(format!("azihsm_stress_{}", std::process::id()));
    fs::create_dir_all(&storage_dir).expect("Failed to create shared storage directory");
    eprintln!(
        "[pid={}] Shared resiliency storage path: {}",
        std::process::id(),
        storage_dir.display()
    );

    // Reset the partition once before spawning children.
    // Children will each call init() — the first succeeds, subsequent ones
    // get VaultAppLimitReached and read the BMK from shared FileStorage.
    // The cross-process FileLock serializes children's init calls.
    {
        let list = HsmPartitionManager::partition_info_list();
        assert!(!list.is_empty(), "No partitions found");
        let part = HsmPartitionManager::open_partition(&list[0].path)
            .expect("Failed to open partition for reset");
        part.reset().expect("Failed to reset partition");
    }

    // Build the self-exe path for child re-exec.
    let self_exe = std::env::current_exe().expect("Failed to get current executable path");

    // Spawn child processes.
    let mut children = Vec::new();
    for i in 0..num_procs {
        let mut cmd = Command::new(&self_exe);

        // Forward all relevant args to child.
        cmd.arg("--child-id").arg(i.to_string());
        cmd.arg("--shmem-path").arg(&shmem_path);
        cmd.arg("--storage-dir").arg(
            storage_dir
                .to_str()
                .expect("storage dir path is valid UTF-8"),
        );
        cmd.arg("-w").arg(args.workers.to_string());
        cmd.arg("-d").arg(args.duration_secs.to_string());
        cmd.arg("-o").arg(&args.ops);
        cmd.arg("-e").arg(args.max_errors.to_string());
        cmd.arg("--stall-timeout-secs")
            .arg(args.stall_timeout_secs.to_string());
        if args.verbose {
            cmd.arg("-v");
        }
        if args.no_resiliency {
            cmd.arg("--no-resiliency");
        }
        if args.no_reset {
            cmd.arg("--no-reset");
        }

        // Redirect child stderr to its log file so panics/backtraces
        // don't pollute the parent's console output.
        let child_log = fs::File::create(format!("resiliency_stress_child_{i}.log"))
            .expect("Failed to create child log file");
        let child = cmd
            .env("RUST_BACKTRACE", "full")
            .stderr(std::process::Stdio::from(child_log))
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to spawn child process {i}: {e}"));
        children.push(child);
    }

    // Setup partition for reset thread (parent only).
    let enable_resiliency = !args.no_resiliency;
    let enable_resets = enable_resiliency && !args.no_reset;
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found");
    let path = list[0].path.clone();
    let reset_interval = Duration::from_millis(args.reset_interval_ms);

    // Spawn reset thread using SharedMem atomics.
    let shmem_ptr = shmem as *const SharedMem as usize;
    let num_procs_for_reset = num_procs as u32;
    let reset_handle = thread::spawn(move || {
        // SAFETY: Shared memory pointer is valid for the lifetime of the process.
        let shmem = unsafe { &*(shmem_ptr as *const SharedMem) };
        let partition = HsmPartitionManager::open_partition(&path)
            .expect("Failed to open partition for reset thread");

        if !enable_resets {
            while !shmem.stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
            }
            return;
        }

        // Wait for all children to finish setup before firing resets.
        eprintln!("Reset thread: waiting for {num_procs_for_reset} child(ren) to be ready...");
        while shmem.children_ready.load(Ordering::Acquire) < num_procs_for_reset {
            if shmem.stop.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        eprintln!("Reset thread: all children ready, starting resets.");

        loop {
            thread::sleep(reset_interval);
            if shmem.stop.load(Ordering::Relaxed) {
                break;
            }
            match partition.reset() {
                Ok(()) => {
                    shmem.total_resets.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    shmem.reset_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });

    // Stats display thread.
    let stats_interval = Duration::from_secs(args.stats_interval_secs);
    let stall_timeout = Duration::from_secs(args.stall_timeout_secs);
    let start = Instant::now();
    let shmem_ptr2 = shmem as *const SharedMem as usize;
    let stats_handle = thread::spawn(move || {
        // SAFETY: Shared memory pointer is valid for the lifetime of the process.
        let shmem = unsafe { &*(shmem_ptr2 as *const SharedMem) };
        multiproc_stats_loop(shmem, num_procs, stats_interval, start, stall_timeout)
    });

    // Duration timer.
    if args.duration_secs > 0 {
        let shmem_ptr3 = shmem as *const SharedMem as usize;
        let dur = Duration::from_secs(args.duration_secs);
        thread::spawn(move || {
            // SAFETY: Shared memory pointer is valid for the lifetime of the process.
            let shmem = unsafe { &*(shmem_ptr3 as *const SharedMem) };
            thread::sleep(dur);
            shmem.stop.store(true, Ordering::SeqCst);
        });
    }

    // Wait for all children.
    let mut any_failed = false;
    let stalled = stats_handle.join().unwrap_or(false);

    // If stalled, send SIGUSR1 to children to dump thread backtraces.
    #[cfg(target_os = "linux")]
    if stalled {
        eprintln!();
        eprintln!("Sending SIGUSR1 to child processes for backtrace dump...");
        for child in children.iter() {
            let pid = child.id();
            // SAFETY: Shared memory pointer is valid for the lifetime of the process.
            unsafe {
                libc::kill(pid as i32, libc::SIGUSR1);
            }
        }
        // Give children time to dump backtraces.
        thread::sleep(Duration::from_secs(3));

        // Force-kill children that are stuck (e.g., blocked in DDI calls
        // or sleeping). They won't exit on their own since the worker
        // threads may never reach the `shmem.stop` check.
        for child in children.iter() {
            // SAFETY: child.id() is a valid PID of a process we spawned.
            // SIGKILL is always safe to send to a known child process.
            unsafe {
                libc::kill(child.id() as i32, libc::SIGKILL);
            }
        }
    }

    for (i, mut child) in children.into_iter().enumerate() {
        let status = child.wait().expect("Failed to wait for child");
        if !status.success() && !stalled {
            eprintln!("Child P{i} exited with {status}");
            any_failed = true;
        }
    }

    // Stop helper threads.
    shmem.stop.store(true, Ordering::SeqCst);
    let _ = reset_handle.join();

    // Final summary.
    let elapsed = start.elapsed();
    print_final_stats(shmem, num_procs, elapsed);

    // Cleanup shared memory file and storage directory.
    let _ = std::fs::remove_file(&shmem_path);
    let _ = std::fs::remove_dir_all(&storage_dir);

    if any_failed {
        std::process::exit(1);
    } else if stalled {
        eprintln!();
        eprintln!("Exiting due to stall (possible deadlock).");
        std::process::exit(2);
    }
}

fn multiproc_stats_loop(
    shmem: &SharedMem,
    num_procs: usize,
    interval: Duration,
    start: Instant,
    stall_timeout: Duration,
) -> bool {
    use std::fmt::Write as _;
    let mut first = true;
    let mut prev_total: u64 = 0;
    let mut last_progress_ops: u64 = 0;
    let mut last_progress_time = Instant::now();
    // Tracks how many lines were printed last iteration for cursor-up.
    let mut lines_to_clear: usize = 0;

    while !shmem.stop.load(Ordering::Relaxed) {
        thread::sleep(interval);

        let elapsed = start.elapsed();
        let resets = shmem.total_resets.load(Ordering::Relaxed);
        let reset_fails = shmem.reset_failures.load(Ordering::Relaxed);

        let mut total_ops: u64 = 0;
        let mut total_errors: u64 = 0;
        let mut agg_counts = [0u64; NUM_OPS];
        let mut agg_errors = [0u64; NUM_OPS];
        for p in 0..num_procs {
            let ps = &shmem.procs[p];
            total_ops += ps.total_ops.load(Ordering::Relaxed);
            total_errors += ps.total_errors.load(Ordering::Relaxed);
            for j in 0..NUM_OPS {
                agg_counts[j] += ps.op_counts[j].load(Ordering::Relaxed);
                agg_errors[j] += ps.op_errors[j].load(Ordering::Relaxed);
            }
        }

        let delta = total_ops.saturating_sub(prev_total);
        let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64().max(0.001);

        let mut buf = String::with_capacity(2048);
        if !first {
            write!(buf, "\x1b[{}A", lines_to_clear).ok();
        }
        first = false;
        // Count lines we emit this iteration.
        let mut emitted_lines: usize = 0;

        let error_suffix = if total_errors > 0 {
            format!(" | ERRORS: {total_errors}")
        } else {
            String::new()
        };

        writeln!(
            buf,
            "\x1b[K[{:02}:{:02}:{:02}] total: {total_ops} (+{delta}) | resets: {resets} (fail: {reset_fails}) | ops/s: {ops_per_sec:.0}{error_suffix}",
            elapsed.as_secs() / 3600,
            (elapsed.as_secs() % 3600) / 60,
            elapsed.as_secs() % 60,
        )
        .ok();
        emitted_lines += 1;

        // Column header.
        write!(buf, "\x1b[K                    ").ok();
        for p in 0..num_procs {
            write!(buf, "{:>8}", format!("P{p}")).ok();
        }
        writeln!(buf, "{:>9}", "Total").ok();
        emitted_lines += 1;

        for (i, label) in LABELS.iter().enumerate() {
            // Skip ops that were never executed.
            if agg_counts[i] == 0 && agg_errors[i] == 0 {
                continue;
            }
            write!(buf, "\x1b[K  {label}").ok();
            for p in 0..num_procs {
                write!(
                    buf,
                    "{:>8}",
                    shmem.procs[p].op_counts[i].load(Ordering::Relaxed)
                )
                .ok();
            }
            let errs = agg_errors[i];
            if errs > 0 {
                writeln!(buf, "{:>9}  !! {errs} fail", agg_counts[i]).ok();
            } else {
                writeln!(buf, "{:>9}", agg_counts[i]).ok();
            }
            emitted_lines += 1;
        }

        eprint!("{buf}");
        lines_to_clear = emitted_lines;
        prev_total = total_ops;

        // Stall detection.
        if total_ops > last_progress_ops {
            last_progress_ops = total_ops;
            last_progress_time = Instant::now();
        } else if !stall_timeout.is_zero() && last_progress_time.elapsed() >= stall_timeout {
            eprintln!();
            eprintln!("=== STALL DETECTED ===");
            eprintln!(
                "No operations completed for {:.0}s — possible deadlock.",
                last_progress_time.elapsed().as_secs_f64()
            );
            eprintln!("Total ops at stall: {total_ops}");
            eprintln!(
                "Resets at stall:    {}",
                shmem.total_resets.load(Ordering::Relaxed)
            );
            eprintln!();
            eprintln!("Check child deadlock logs for thread backtraces:");
            for p in 0..num_procs {
                eprintln!("  resiliency_stress_child_{p}.log");
            }
            shmem.stop.store(true, Ordering::SeqCst);
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Multi-process: child worker process
// ---------------------------------------------------------------------------

#[cfg(not(feature = "mock"))]
#[allow(unsafe_code)]
fn run_as_child(args: Args, child_id: usize) {
    // Register SIGUSR1 handler to dump backtraces on stall detection.
    #[cfg(target_os = "linux")]
    // SAFETY: Shared memory pointer is valid for the lifetime of the process.
    unsafe {
        extern "C" fn sigusr1_handler(_sig: libc::c_int) {
            // SAFETY: eprintln! is not async-signal-safe, but we're about
            // to exit anyway — this is best-effort diagnostics.
            let bt = std::backtrace::Backtrace::force_capture();
            eprintln!("=== SIGUSR1 backtrace (thread interrupted) ===");
            eprintln!("{bt}");
            // Don't exit — let all threads get the signal.
        }
        libc::signal(
            libc::SIGUSR1,
            sigusr1_handler as *const () as libc::sighandler_t,
        );
    }

    // Child's stderr is already redirected to its log file by the parent.
    // Write tracing to stderr so everything goes to one place.
    tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::WARN
        } else {
            tracing::Level::ERROR
        })
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let shmem_path = args
        .shmem_path
        .as_ref()
        .expect("Child process requires --shmem-path");

    let mmap = open_shared_mem(shmem_path);
    // SAFETY: Shared memory pointer is valid for the lifetime of the process.
    let shmem: &SharedMem = unsafe { shmem_ref(&mmap) };
    let proc_stats = &shmem.procs[child_id];

    let ops = parse_ops(&args.ops);

    // Each child opens its own partition + session (no reset — parent handles resets).
    let enable_resiliency = !args.no_resiliency;
    let storage_dir = args.storage_dir.map(PathBuf::from);
    let (part, creds) = open_and_init_partition(enable_resiliency, true, storage_dir);
    let session = open_session(&part, &creds);

    let max_errors = args.max_errors;
    let barrier = Arc::new(Barrier::new(args.workers));

    // Generate the unwrapping key pair once per process (persistent/app-scoped)
    // and share across all workers to avoid concurrent RSA key generation and
    // persistent key slot exhaustion.
    let shared_unwrap_keys = Arc::new(gen_rsa_unwrapping_key_pair(&session));

    // Collect worker pthread IDs so the stall detector can signal each one.
    #[cfg(target_os = "linux")]
    let worker_tids: Arc<parking_lot::Mutex<Vec<libc::pthread_t>>> =
        Arc::new(parking_lot::Mutex::new(Vec::new()));

    let mut worker_handles = Vec::new();
    for i in 0..args.workers {
        let partition = part.clone();
        let session = session.clone();
        let ops = ops.clone();
        let ps_ptr = proc_stats as *const ProcessStats as usize;
        let shmem_ptr = shmem as *const SharedMem as usize;
        let barrier_clone = Arc::clone(&barrier);
        let unwrap_keys = Arc::clone(&shared_unwrap_keys);
        #[cfg(target_os = "linux")]
        let tids_clone = Arc::clone(&worker_tids);
        let handle = thread::spawn(move || {
            // Record this thread's pthread_t so stall detector can signal us.
            #[cfg(target_os = "linux")]
            {
                // SAFETY: Shared memory pointer is valid for the lifetime of the process.
                let tid = unsafe { libc::pthread_self() };
                tids_clone.lock().push(tid);
            }
            // SAFETY: Shared memory pointer is valid for the lifetime of the process.
            let ps = unsafe { &*(ps_ptr as *const ProcessStats) };
            // SAFETY: Shared memory pointer is valid for the lifetime of the process.
            let sm = unsafe { &*(shmem_ptr as *const SharedMem) };
            child_worker_thread(
                i,
                partition,
                session,
                ops,
                ps,
                sm,
                barrier_clone,
                max_errors,
                unwrap_keys,
            )
        });
        worker_handles.push(handle);
    }

    // Spawn deadlock/stall detection thread AFTER workers so it can access
    // their thread IDs for backtrace signaling.
    {
        let shmem_ptr_dd = shmem as *const SharedMem as usize;
        #[cfg(target_os = "linux")]
        let tids_for_dd = Arc::clone(&worker_tids);
        thread::spawn(move || {
            // SAFETY: Shared memory pointer is valid for the lifetime of the process.
            let shmem = unsafe { &*(shmem_ptr_dd as *const SharedMem) };

            loop {
                thread::sleep(Duration::from_secs(5));

                let deadlocks = deadlock::check_deadlock();
                if !deadlocks.is_empty() {
                    tracing::error!("=== DEADLOCK DETECTED ({} cycles) ===", deadlocks.len());
                    for (i, threads) in deadlocks.iter().enumerate() {
                        tracing::error!("--- Cycle {} ({} threads) ---", i + 1, threads.len());
                        for t in threads {
                            tracing::error!("Thread {:?}: {:#?}", t.thread_id(), t.backtrace());
                        }
                    }
                }

                if shmem.stop.load(Ordering::Relaxed) {
                    if !deadlocks.is_empty() {
                        tracing::error!("Stop received with active deadlock(s) — see above.");
                    } else {
                        tracing::error!(
                            "Stop received (possible stall). Signaling worker threads \
                             for backtrace dump."
                        );
                    }

                    #[cfg(target_os = "linux")]
                    {
                        let tids = tids_for_dd.lock();
                        for (i, tid) in tids.iter().enumerate() {
                            eprintln!("--- Backtrace for worker thread {i} ---");
                            // SAFETY: Shared memory pointer is valid for the lifetime of the process.
                            unsafe {
                                libc::pthread_kill(*tid, libc::SIGUSR1);
                            }
                            thread::sleep(Duration::from_millis(500));
                        }
                    }

                    break;
                }
            }
        });
    }

    let mut exit_code = 0;
    for handle in worker_handles {
        if let Ok(true) = handle.join() {
            exit_code = 1;
        }
    }

    std::process::exit(exit_code);
}

/// Worker thread for child processes. Writes stats to shared memory.
/// Returns `true` if the worker triggered a stop due to max errors.
#[allow(unsafe_code)]
fn child_worker_thread(
    thread_id: usize,
    partition: HsmPartition,
    session: HsmSession,
    ops: Vec<OpKind>,
    proc_stats: &ProcessStats,
    shmem: &SharedMem,
    barrier: Arc<Barrier>,
    max_errors: i64,
    shared_unwrap_keys: Arc<(HsmRsaPrivateKey, HsmRsaPublicKey)>,
) -> bool {
    // Pre-create keys (same setup as single-process worker_thread).
    let aes_key = gen_aes_key(&session);
    let (ecc_priv, _ecc_pub) = gen_ecc_key_pair(&session);
    let ecc_hash = {
        let mut h = HsmHashAlgo::Sha256;
        HsmHasher::hash_vec(&session, &mut h, b"stress data for ECC").expect("hash")
    };
    let hmac_key = gen_hmac_key(&session);
    let (ecdh_priv, _) = gen_ecc_derive_key_pair(&session);
    let (_, ecdh_peer_pub) = gen_ecc_derive_key_pair(&session);
    let hkdf_shared_secret = {
        let pub_der = ecdh_peer_pub.pub_key_der_vec().expect("ECDH peer pub DER");
        let mut algo = EcdhAlgo::new(&pub_der);
        let bits = ecdh_priv.ecc_curve().expect("ECC curve").key_size_bits() as u32;
        let secret_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::SharedSecret)
            .bits(bits)
            .can_derive(true)
            .is_session(true)
            .build()
            .expect("secret props");
        HsmKeyManager::derive_key(&session, &mut algo, &ecdh_priv, secret_props)
            .expect("pre-create shared secret")
    };
    // Use the shared (per-process) unwrapping key pair to avoid concurrent
    // RSA key generation and persistent key slot exhaustion.
    let (unwrap_priv, unwrap_pub) = &*shared_unwrap_keys;
    let (rsa_sign_priv, _rsa_sign_pub) = import_rsa_sign_key(&session, unwrap_priv, unwrap_pub);
    let rsa_hash = {
        let mut h = HsmHashAlgo::Sha256;
        HsmHasher::hash_vec(&session, &mut h, b"stress data for RSA sign").expect("RSA hash")
    };
    let (rsa_dec_priv, rsa_enc_pub) = import_rsa_enc_key(&session, unwrap_priv, unwrap_pub);
    let rsa_ciphertext = {
        let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
        HsmEncrypter::encrypt_vec(&mut algo, &rsa_enc_pub, b"stress RSA plaintext")
            .expect("RSA pre-encrypt")
    };
    let aes_wrapped_blob = prepare_wrapped_aes_key(&session, unwrap_priv, unwrap_pub);
    let ecc_wrapped_blob = prepare_wrapped_ecc_key(&session, unwrap_pub);
    let needs_xts = ops.iter().any(|o| {
        matches!(
            o,
            OpKind::AesXtsKeyGen
                | OpKind::XtsUnwrap
                | OpKind::XtsUnmask
                | OpKind::AesXtsKeyGenDelete
        )
    });
    let xts_wrapped_blob = if needs_xts {
        Some(prepare_wrapped_xts_key(&session, unwrap_pub))
    } else {
        None
    };
    let aes_masked = aes_key.masked_key_vec().expect("AES masked key");
    let ecc_masked = ecc_priv.masked_key_vec().expect("ECC masked key");
    let xts_masked = if needs_xts {
        let xts_key = gen_aes_xts_key(&session);
        Some(xts_key.masked_key_vec().expect("XTS masked key"))
    } else {
        None
    };
    // AES-XTS enc+dec setup: pre-create key (mock only).
    #[cfg(feature = "mock")]
    let xts_enc_key = if ops.iter().any(|o| matches!(o, OpKind::AesXtsEncDec)) {
        Some(gen_aes_xts_key(&session))
    } else {
        None
    };
    // AES-GCM enc+dec setup: pre-create key (mock only).
    #[cfg(feature = "mock")]
    let gcm_key = if ops.iter().any(|o| matches!(o, OpKind::AesGcmEncDec)) {
        Some(gen_aes_gcm_key(&session))
    } else {
        None
    };
    let report_data = [0x42u8; 128];

    // All workers in this process wait here until setup is complete.
    // The barrier leader signals the parent that this child is ready
    // for resets (via the shared memory counter).
    let wait_result = barrier.wait();
    if wait_result.is_leader() {
        shmem.children_ready.fetch_add(1, Ordering::Release);
    }

    let mut rng = rand::thread_rng();
    let mut triggered_stop = false;

    while !shmem.stop.load(Ordering::Relaxed) {
        let op = ops[rng.gen_range(0..ops.len())];

        let result = match op {
            OpKind::AesCbcEncDec => exec_aes_cbc_enc_dec(&aes_key),
            OpKind::EccSign => exec_ecc_sign(&ecc_priv, &ecc_hash),
            OpKind::HmacSign => exec_hmac_sign(&hmac_key),
            OpKind::RsaSign => exec_rsa_sign(&rsa_sign_priv, &rsa_hash),
            OpKind::RsaDecrypt => exec_rsa_decrypt(&rsa_dec_priv, &rsa_ciphertext),
            OpKind::EcdhDerive => exec_ecdh_derive(&session, &ecdh_priv, &ecdh_peer_pub),
            OpKind::HkdfDerive => exec_hkdf_derive(&session, &hkdf_shared_secret),
            OpKind::AesKeyGen => exec_aes_keygen(&session),
            OpKind::EccKeyGen => exec_ecc_keygen(&session),
            OpKind::AesXtsKeyGen => exec_aes_xts_keygen(&session),
            OpKind::UnwrappingKeyGen => exec_unwrapping_keygen(&session),
            OpKind::AesUnwrap => exec_aes_unwrap(unwrap_priv, &aes_wrapped_blob),
            OpKind::EccUnwrap => exec_ecc_unwrap(unwrap_priv, &ecc_wrapped_blob),
            OpKind::XtsUnwrap => exec_xts_unwrap(
                unwrap_priv,
                xts_wrapped_blob.as_ref().expect("XTS wrapped blob"),
            ),
            OpKind::AesUnmask => exec_aes_unmask(&session, &aes_masked),
            OpKind::EccUnmask => exec_ecc_unmask(&session, &ecc_masked),
            OpKind::XtsUnmask => {
                exec_xts_unmask(&session, xts_masked.as_ref().expect("XTS masked key"))
            }
            OpKind::EccKeyReport => exec_ecc_key_report(&ecc_priv, &report_data),
            OpKind::RsaKeyReport => exec_rsa_key_report(&rsa_sign_priv, &report_data),
            OpKind::UnwrappingKeyReport => exec_rsa_key_report(unwrap_priv, &report_data),
            OpKind::CertChain => exec_cert_chain(&partition),
            OpKind::AesKeyGenDelete => exec_aes_keygen_delete(&session),
            OpKind::EccKeyGenDelete => exec_ecc_keygen_delete(&session),
            OpKind::AesXtsKeyGenDelete => exec_aes_xts_keygen_delete(&session),
            #[cfg(feature = "mock")]
            OpKind::AesXtsEncDec => {
                exec_aes_xts_enc_dec(xts_enc_key.as_ref().expect("XTS enc key"))
            }
            #[cfg(feature = "mock")]
            OpKind::AesGcmEncDec => exec_aes_gcm_enc_dec(gcm_key.as_ref().expect("GCM key")),
        };

        let op_idx = (op as u8 - 1) as usize;
        match result {
            Ok(()) => {
                proc_stats.increment_op(op_idx);
            }
            Err(err) => {
                proc_stats.increment_error(op_idx);
                eprintln!("  !! t{thread_id}: {op} failed: {err:?}");

                if max_errors == 0
                    || (max_errors > 0
                        && proc_stats.total_errors.load(Ordering::Relaxed) >= max_errors as u64)
                {
                    proc_stats.failed.store(true, Ordering::SeqCst);
                    proc_stats
                        .failed_op
                        .store(op as u8 as u32, Ordering::Relaxed);
                    proc_stats.failed_error.store(err as i32, Ordering::Relaxed);
                    proc_stats
                        .failed_thread
                        .store(thread_id as u32, Ordering::Relaxed);
                    shmem.stop.store(true, Ordering::SeqCst);
                    triggered_stop = true;
                    break;
                }
            }
        }
    }

    triggered_stop
}
