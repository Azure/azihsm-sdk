// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency stress tool for AZIHSM SDK.
//!
//! Continuously runs crypto operations across multiple threads while a
//! dedicated thread triggers device resets at configurable intervals.
//! Stops immediately on any unexpected error, printing the failing
//! scenario and aggregated stats.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicU8;
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
    /// Number of worker threads performing crypto operations.
    #[arg(short = 'w', long, default_value_t = 4)]
    workers: usize,

    /// Reset interval in milliseconds.
    #[arg(short = 'r', long, default_value_t = 200)]
    reset_interval_ms: u64,

    /// Duration to run in seconds (0 = run until Ctrl-C).
    #[arg(short = 'd', long, default_value_t = 60)]
    duration_secs: u64,

    /// Stats reporting interval in seconds.
    #[arg(short = 's', long, default_value_t = 5)]
    stats_interval_secs: u64,

    /// Comma-separated list of operations to include.
    /// Available: aes-cbc,ecc-sign,hmac-sign,rsa-sign,rsa-decrypt,rsa,ecdh,hkdf,
    /// aes-keygen,ecc-keygen,aes-xts-keygen,unwrapping-keygen,aes-unwrap,ecc-unwrap,
    /// xts-unwrap,unwrap,aes-unmask,ecc-unmask,xts-unmask,unmask,
    /// ecc-key-report,rsa-key-report,key-report,cert-chain,
    /// aes-keygen-delete,ecc-keygen-delete,xts-keygen-delete,keygen-delete,all
    #[arg(short = 'o', long, default_value = "all")]
    ops: String,

    /// Stall detection timeout in seconds. If no operations complete
    /// within this duration the tool treats it as a deadlock, dumps
    /// diagnostics, and exits. 0 disables stall detection.
    #[arg(long, default_value_t = 30)]
    stall_timeout_secs: u64,

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
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct SharedStats {
    total_ops: AtomicU64,
    total_resets: AtomicU64,
    reset_failures: AtomicU64,
    stop: AtomicBool,
    // Per-op counters.
    aes_cbc_encrypt: AtomicU64,
    aes_cbc_decrypt: AtomicU64,
    ecc_sign: AtomicU64,
    hmac_sign: AtomicU64,
    rsa_sign: AtomicU64,
    rsa_decrypt: AtomicU64,
    ecdh_derive: AtomicU64,
    hkdf_derive: AtomicU64,
    aes_keygen: AtomicU64,
    ecc_keygen: AtomicU64,
    aes_xts_keygen: AtomicU64,
    unwrapping_keygen: AtomicU64,
    aes_unwrap: AtomicU64,
    ecc_unwrap: AtomicU64,
    xts_unwrap: AtomicU64,
    aes_unmask: AtomicU64,
    ecc_unmask: AtomicU64,
    xts_unmask: AtomicU64,
    ecc_key_report: AtomicU64,
    rsa_key_report: AtomicU64,
    unwrapping_key_report: AtomicU64,
    cert_chain: AtomicU64,
    aes_keygen_delete: AtomicU64,
    ecc_keygen_delete: AtomicU64,
    xts_keygen_delete: AtomicU64,
}

impl SharedStats {
    fn new() -> Self {
        Self {
            total_ops: AtomicU64::new(0),
            total_resets: AtomicU64::new(0),
            reset_failures: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            aes_cbc_encrypt: AtomicU64::new(0),
            aes_cbc_decrypt: AtomicU64::new(0),
            ecc_sign: AtomicU64::new(0),
            hmac_sign: AtomicU64::new(0),
            rsa_sign: AtomicU64::new(0),
            rsa_decrypt: AtomicU64::new(0),
            ecdh_derive: AtomicU64::new(0),
            hkdf_derive: AtomicU64::new(0),
            aes_keygen: AtomicU64::new(0),
            ecc_keygen: AtomicU64::new(0),
            aes_xts_keygen: AtomicU64::new(0),
            unwrapping_keygen: AtomicU64::new(0),
            aes_unwrap: AtomicU64::new(0),
            ecc_unwrap: AtomicU64::new(0),
            xts_unwrap: AtomicU64::new(0),
            aes_unmask: AtomicU64::new(0),
            ecc_unmask: AtomicU64::new(0),
            xts_unmask: AtomicU64::new(0),
            ecc_key_report: AtomicU64::new(0),
            rsa_key_report: AtomicU64::new(0),
            unwrapping_key_report: AtomicU64::new(0),
            cert_chain: AtomicU64::new(0),
            aes_keygen_delete: AtomicU64::new(0),
            ecc_keygen_delete: AtomicU64::new(0),
            xts_keygen_delete: AtomicU64::new(0),
        }
    }

    fn increment_op(&self, op: OpKind) {
        match op {
            OpKind::AesCbcEncrypt => self.aes_cbc_encrypt.fetch_add(1, Ordering::Relaxed),
            OpKind::AesCbcDecrypt => self.aes_cbc_decrypt.fetch_add(1, Ordering::Relaxed),
            OpKind::EccSign => self.ecc_sign.fetch_add(1, Ordering::Relaxed),
            OpKind::HmacSign => self.hmac_sign.fetch_add(1, Ordering::Relaxed),
            OpKind::RsaSign => self.rsa_sign.fetch_add(1, Ordering::Relaxed),
            OpKind::RsaDecrypt => self.rsa_decrypt.fetch_add(1, Ordering::Relaxed),
            OpKind::EcdhDerive => self.ecdh_derive.fetch_add(1, Ordering::Relaxed),
            OpKind::HkdfDerive => self.hkdf_derive.fetch_add(1, Ordering::Relaxed),
            OpKind::AesKeyGen => self.aes_keygen.fetch_add(1, Ordering::Relaxed),
            OpKind::EccKeyGen => self.ecc_keygen.fetch_add(1, Ordering::Relaxed),
            OpKind::AesXtsKeyGen => self.aes_xts_keygen.fetch_add(1, Ordering::Relaxed),
            OpKind::UnwrappingKeyGen => self.unwrapping_keygen.fetch_add(1, Ordering::Relaxed),
            OpKind::AesUnwrap => self.aes_unwrap.fetch_add(1, Ordering::Relaxed),
            OpKind::EccUnwrap => self.ecc_unwrap.fetch_add(1, Ordering::Relaxed),
            OpKind::XtsUnwrap => self.xts_unwrap.fetch_add(1, Ordering::Relaxed),
            OpKind::AesUnmask => self.aes_unmask.fetch_add(1, Ordering::Relaxed),
            OpKind::EccUnmask => self.ecc_unmask.fetch_add(1, Ordering::Relaxed),
            OpKind::XtsUnmask => self.xts_unmask.fetch_add(1, Ordering::Relaxed),
            OpKind::EccKeyReport => self.ecc_key_report.fetch_add(1, Ordering::Relaxed),
            OpKind::RsaKeyReport => self.rsa_key_report.fetch_add(1, Ordering::Relaxed),
            OpKind::UnwrappingKeyReport => {
                self.unwrapping_key_report.fetch_add(1, Ordering::Relaxed)
            }
            OpKind::CertChain => self.cert_chain.fetch_add(1, Ordering::Relaxed),
            OpKind::AesKeyGenDelete => self.aes_keygen_delete.fetch_add(1, Ordering::Relaxed),
            OpKind::EccKeyGenDelete => self.ecc_keygen_delete.fetch_add(1, Ordering::Relaxed),
            OpKind::AesXtsKeyGenDelete => self.xts_keygen_delete.fetch_add(1, Ordering::Relaxed),
        };
        self.total_ops.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy)]
enum OpKind {
    AesCbcEncrypt,
    AesCbcDecrypt,
    EccSign,
    HmacSign,
    RsaSign,
    RsaDecrypt,
    EcdhDerive,
    HkdfDerive,
    AesKeyGen,
    EccKeyGen,
    AesXtsKeyGen,
    UnwrappingKeyGen,
    AesUnwrap,
    EccUnwrap,
    XtsUnwrap,
    AesUnmask,
    EccUnmask,
    XtsUnmask,
    EccKeyReport,
    RsaKeyReport,
    UnwrappingKeyReport,
    CertChain,
    AesKeyGenDelete,
    EccKeyGenDelete,
    AesXtsKeyGenDelete,
}

impl OpKind {
    fn as_u8(self) -> u8 {
        match self {
            Self::AesCbcEncrypt => 1,
            Self::AesCbcDecrypt => 2,
            Self::EccSign => 3,
            Self::HmacSign => 4,
            Self::RsaSign => 5,
            Self::RsaDecrypt => 6,
            Self::EcdhDerive => 7,
            Self::HkdfDerive => 8,
            Self::AesKeyGen => 9,
            Self::EccKeyGen => 10,
            Self::AesXtsKeyGen => 11,
            Self::UnwrappingKeyGen => 12,
            Self::AesUnwrap => 13,
            Self::EccUnwrap => 14,
            Self::XtsUnwrap => 15,
            Self::AesUnmask => 16,
            Self::EccUnmask => 17,
            Self::XtsUnmask => 18,
            Self::EccKeyReport => 19,
            Self::RsaKeyReport => 20,
            Self::UnwrappingKeyReport => 21,
            Self::CertChain => 22,
            Self::AesKeyGenDelete => 23,
            Self::EccKeyGenDelete => 24,
            Self::AesXtsKeyGenDelete => 25,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::AesCbcEncrypt),
            2 => Some(Self::AesCbcDecrypt),
            3 => Some(Self::EccSign),
            4 => Some(Self::HmacSign),
            5 => Some(Self::RsaSign),
            6 => Some(Self::RsaDecrypt),
            7 => Some(Self::EcdhDerive),
            8 => Some(Self::HkdfDerive),
            9 => Some(Self::AesKeyGen),
            10 => Some(Self::EccKeyGen),
            11 => Some(Self::AesXtsKeyGen),
            12 => Some(Self::UnwrappingKeyGen),
            13 => Some(Self::AesUnwrap),
            14 => Some(Self::EccUnwrap),
            15 => Some(Self::XtsUnwrap),
            16 => Some(Self::AesUnmask),
            17 => Some(Self::EccUnmask),
            18 => Some(Self::XtsUnmask),
            19 => Some(Self::EccKeyReport),
            20 => Some(Self::RsaKeyReport),
            21 => Some(Self::UnwrappingKeyReport),
            22 => Some(Self::CertChain),
            23 => Some(Self::AesKeyGenDelete),
            24 => Some(Self::EccKeyGenDelete),
            25 => Some(Self::AesXtsKeyGenDelete),
            _ => None,
        }
    }
}

/// Per-worker state tracking for stall diagnostics.
/// 0 = setup, 255 = idle between ops, 1..=25 = executing OpKind.
struct WorkerStates {
    states: Vec<AtomicU8>,
}

impl WorkerStates {
    fn new(num_workers: usize) -> Self {
        Self {
            states: (0..num_workers).map(|_| AtomicU8::new(0)).collect(),
        }
    }

    fn set(&self, worker_id: usize, op: OpKind) {
        self.states[worker_id].store(op.as_u8(), Ordering::Relaxed);
    }

    fn set_idle(&self, worker_id: usize) {
        self.states[worker_id].store(255, Ordering::Relaxed);
    }

    fn dump(&self) {
        for (i, state) in self.states.iter().enumerate() {
            let v = state.load(Ordering::Relaxed);
            let label = match v {
                0 => "setup/pre-barrier".to_string(),
                255 => "idle (between ops)".to_string(),
                _ => match OpKind::from_u8(v) {
                    Some(op) => format!("executing {op}"),
                    None => format!("unknown ({v})"),
                },
            };
            eprintln!("  Worker {i:>2}: {label}");
        }
    }
}

impl std::fmt::Display for OpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AesCbcEncrypt => write!(f, "AES-CBC encrypt"),
            Self::AesCbcDecrypt => write!(f, "AES-CBC decrypt"),
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
        }
    }
}

// ---------------------------------------------------------------------------
// Partition + session setup
// ---------------------------------------------------------------------------

fn open_and_init_partition(enable_resiliency: bool) -> (HsmPartition, HsmCredentials) {
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
    part.reset().expect("Failed to reset partition");

    let creds = HsmCredentials::new(&[0xAA; 16], &[0xBB; 16]);
    let (sig, pubkey_der) = generate_pota(&part);
    let obk = HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK));
    let pota = HsmPotaEndorsement::new(
        HsmPotaEndorsementSource::Caller,
        Some(HsmPotaEndorsementData::new(&sig, &pubkey_der)),
    );

    // In-memory resiliency storage.
    struct MemStorage(Mutex<HashMap<String, Vec<u8>>>);
    impl ResiliencyStorage for MemStorage {
        fn read(&self, key: &str) -> HsmResult<Vec<u8>> {
            self.0.lock().get(key).cloned().ok_or(HsmError::NotFound)
        }
        fn write(&self, key: &str, data: &[u8]) -> HsmResult<()> {
            self.0.lock().insert(key.to_string(), data.to_vec());
            Ok(())
        }
        fn clear(&self, key: &str) -> HsmResult<()> {
            self.0.lock().remove(key);
            Ok(())
        }
    }

    struct MemLock {
        locked: Mutex<bool>,
    }
    impl MemLock {
        fn new() -> Self {
            Self {
                locked: Mutex::new(false),
            }
        }
    }
    impl ResiliencyLock for MemLock {
        fn lock(&self) -> HsmResult<()> {
            let mut guard = self.locked.lock();
            *guard = true;
            Ok(())
        }
        fn unlock(&self) -> HsmResult<()> {
            let mut guard = self.locked.lock();
            *guard = false;
            Ok(())
        }
    }

    /// POTA re-endorsement callback for resiliency restore.
    /// Uses a **separate** partition handle (its own RwLock) so that
    /// calling `pub_key()` does not re-enter the read lock held by
    /// `restore_partition`.
    struct StressPotaCallback {
        part: HsmPartition,
    }
    impl PotaEndorsementCallback for StressPotaCallback {
        fn endorse(&self, _pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData> {
            let (sig, pubkey_der) = generate_pota(&self.part);
            Ok(HsmPotaEndorsementData::new(&sig, &pubkey_der))
        }
    }

    let resiliency_config = if enable_resiliency {
        // Open a separate partition handle for the POTA callback to avoid
        // re-entering the partition's RwLock during restore.
        let pota_part = HsmPartitionManager::open_partition(&list[0].path)
            .expect("Failed to open POTA callback partition");

        Some(HsmResiliencyConfig {
            storage: Box::new(MemStorage(Mutex::new(HashMap::new()))),
            lock: Arc::new(MemLock::new()),
            pota_callback: Some(Box::new(StressPotaCallback { part: pota_part })),
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

fn import_rsa_sign_key(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let sw_key = azihsm_crypto::RsaPrivateKey::generate(256).expect("SW RSA key gen");
    let der = sw_key.to_vec().expect("RSA DER export");
    let (unwrap_priv, unwrap_pub) = gen_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).expect("RSA key wrap");

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
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .expect("RSA sign key unwrap")
}

fn import_rsa_enc_key(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let sw_key = azihsm_crypto::RsaPrivateKey::generate(256).expect("SW RSA key gen");
    let der = sw_key.to_vec().expect("RSA DER export");
    let (unwrap_priv, unwrap_pub) = gen_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).expect("RSA key wrap");

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
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .expect("RSA enc key unwrap")
}

fn prepare_wrapped_aes_key(session: &HsmSession) -> (HsmRsaPrivateKey, Vec<u8>) {
    let (unwrap_priv, unwrap_pub) = gen_rsa_unwrapping_key_pair(session);
    let aes_key_data = vec![0x42u8; 32];
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &aes_key_data)
        .expect("AES key wrap");
    (unwrap_priv, wrapped)
}

fn prepare_wrapped_ecc_key(session: &HsmSession) -> (HsmRsaPrivateKey, Vec<u8>) {
    let sw_key = azihsm_crypto::EccPrivateKey::from_curve(azihsm_crypto::EccCurve::P256)
        .expect("SW ECC key gen");
    let der = sw_key.to_vec().expect("ECC DER export");
    let (unwrap_priv, unwrap_pub) = gen_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped =
        HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).expect("ECC key wrap");
    (unwrap_priv, wrapped)
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

fn prepare_wrapped_xts_key(session: &HsmSession) -> (HsmRsaPrivateKey, Vec<u8>) {
    let (unwrap_priv, unwrap_pub) = gen_rsa_unwrapping_key_pair(session);
    let key1 = vec![0x11u8; 32];
    let key2 = vec![0x22u8; 32];
    let blob = build_xts_wrapped_blob(&unwrap_pub, HsmHashAlgo::Sha256, &key1, &key2);
    (unwrap_priv, blob)
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

fn exec_aes_cbc_encrypt(key: &HsmAesKey) -> HsmResult<()> {
    let iv = [0u8; 16];
    let data = b"stress test data for encryption!"; // 32 bytes
    let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
    let len = HsmEncrypter::encrypt(&mut algo, key, data, None)?;
    let mut out = vec![0u8; len];
    let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
    HsmEncrypter::encrypt(&mut algo, key, data, Some(&mut out))?;
    Ok(())
}

fn exec_aes_cbc_decrypt(key: &HsmAesKey, ciphertext: &[u8]) -> HsmResult<()> {
    let iv = [0u8; 16];
    let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
    let len = HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?;
    let mut out = vec![0u8; len];
    let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
    HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut out))?;
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

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------

struct WorkerFailure {
    thread_id: usize,
    op: OpKind,
    error: HsmError,
    total_ops: u64,
}

fn worker_thread(
    thread_id: usize,
    partition: HsmPartition,
    session: HsmSession,
    ops: Vec<OpKind>,
    stats: Arc<SharedStats>,
    barrier: Arc<Barrier>,
    worker_states: Arc<WorkerStates>,
) -> Option<WorkerFailure> {
    // Pre-create keys before the barrier so all threads start together.
    let aes_key = gen_aes_key(&session);

    // Pre-encrypt for decrypt ops.
    let iv = [0u8; 16];
    let ciphertext = {
        let data = b"stress test data for encryption!";
        let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
        let len = HsmEncrypter::encrypt(&mut algo, &aes_key, data, None).expect("pre-encrypt len");
        let mut out = vec![0u8; len];
        let mut algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo");
        HsmEncrypter::encrypt(&mut algo, &aes_key, data, Some(&mut out)).expect("pre-encrypt");
        out
    };

    let (ecc_priv, _ecc_pub) = gen_ecc_key_pair(&session);
    let ecc_hash = {
        let mut h = HsmHashAlgo::Sha256;
        HsmHasher::hash_vec(&session, &mut h, b"stress data for ECC").expect("hash")
    };

    let hmac_key = gen_hmac_key(&session);

    // Pre-create ECDH derive key pairs.
    let (ecdh_priv, _) = gen_ecc_derive_key_pair(&session);
    let (_, ecdh_peer_pub) = gen_ecc_derive_key_pair(&session);

    // Pre-create shared secret for HKDF.
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

    // RSA sign key + hash.
    let (rsa_sign_priv, _rsa_sign_pub) = import_rsa_sign_key(&session);
    let rsa_hash = {
        let mut h = HsmHashAlgo::Sha256;
        HsmHasher::hash_vec(&session, &mut h, b"stress data for RSA sign").expect("RSA hash")
    };

    // RSA encrypt/decrypt key + pre-encrypted ciphertext.
    let (rsa_dec_priv, rsa_enc_pub) = import_rsa_enc_key(&session);
    let rsa_ciphertext = {
        let mut algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
        HsmEncrypter::encrypt_vec(&mut algo, &rsa_enc_pub, b"stress RSA plaintext")
            .expect("RSA pre-encrypt")
    };

    // Pre-create wrapped key blobs for unwrap ops.
    let (aes_unwrap_key, aes_wrapped_blob) = prepare_wrapped_aes_key(&session);
    let (ecc_unwrap_key, ecc_wrapped_blob) = prepare_wrapped_ecc_key(&session);
    let (xts_unwrap_key, xts_wrapped_blob) = prepare_wrapped_xts_key(&session);

    // Pre-create masked key blobs for unmask ops.
    let aes_masked = aes_key.masked_key_vec().expect("AES masked key");
    let ecc_masked = ecc_priv.masked_key_vec().expect("ECC masked key");
    let xts_key = gen_aes_xts_key(&session);
    let xts_masked = xts_key.masked_key_vec().expect("XTS masked key");

    // Report data for key report ops.
    let report_data = [0x42u8; 128];

    barrier.wait();

    let mut rng = rand::thread_rng();

    while !stats.stop.load(Ordering::Relaxed) {
        let op = ops[rng.gen_range(0..ops.len())];
        worker_states.set(thread_id, op);

        let result = match op {
            OpKind::AesCbcEncrypt => exec_aes_cbc_encrypt(&aes_key),
            OpKind::AesCbcDecrypt => exec_aes_cbc_decrypt(&aes_key, &ciphertext),
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
            OpKind::AesUnwrap => exec_aes_unwrap(&aes_unwrap_key, &aes_wrapped_blob),
            OpKind::EccUnwrap => exec_ecc_unwrap(&ecc_unwrap_key, &ecc_wrapped_blob),
            OpKind::XtsUnwrap => exec_xts_unwrap(&xts_unwrap_key, &xts_wrapped_blob),
            OpKind::AesUnmask => exec_aes_unmask(&session, &aes_masked),
            OpKind::EccUnmask => exec_ecc_unmask(&session, &ecc_masked),
            OpKind::XtsUnmask => exec_xts_unmask(&session, &xts_masked),
            OpKind::EccKeyReport => exec_ecc_key_report(&ecc_priv, &report_data),
            OpKind::RsaKeyReport => exec_rsa_key_report(&rsa_sign_priv, &report_data),
            OpKind::UnwrappingKeyReport => exec_rsa_key_report(&aes_unwrap_key, &report_data),
            OpKind::CertChain => exec_cert_chain(&partition),
            OpKind::AesKeyGenDelete => exec_aes_keygen_delete(&session),
            OpKind::EccKeyGenDelete => exec_ecc_keygen_delete(&session),
            OpKind::AesXtsKeyGenDelete => exec_aes_xts_keygen_delete(&session),
        };

        match result {
            Ok(()) => {
                worker_states.set_idle(thread_id);
                stats.increment_op(op);
            }
            Err(err) => {
                stats.stop.store(true, Ordering::SeqCst);
                return Some(WorkerFailure {
                    thread_id,
                    op,
                    error: err,
                    total_ops: stats.total_ops.load(Ordering::Relaxed),
                });
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Reset thread
// ---------------------------------------------------------------------------

fn reset_thread(
    path: String,
    interval: Duration,
    stats: Arc<SharedStats>,
    barrier: Arc<Barrier>,
    enabled: bool,
) {
    let partition = HsmPartitionManager::open_partition(&path)
        .expect("Failed to open partition for reset thread");
    barrier.wait();

    if !enabled {
        // No-op: wait until stop is signalled.
        while !stats.stop.load(Ordering::Relaxed) {
            thread::sleep(interval);
        }
        return;
    }

    while !stats.stop.load(Ordering::Relaxed) {
        thread::sleep(interval);
        if stats.stop.load(Ordering::Relaxed) {
            break;
        }
        match partition.reset() {
            Ok(()) => {
                stats.total_resets.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                // Reset failures are expected during stress; count
                // them but don't print to avoid breaking the display.
                stats.reset_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Random fault injection thread (requires res-test feature)
// ---------------------------------------------------------------------------

/// Recovery-path DDI operations — always included in the fault target
/// list because NSSRs can occur during recovery just as they can during
/// primary operations.
#[cfg(feature = "res-test")]
const RECOVERY_DDI_OPS: &[azihsm_res_test_dev::DdiOp] = &[
    azihsm_res_test_dev::DdiOp::InitBk3,
    azihsm_res_test_dev::DdiOp::GetEstablishCredEncryptionKey,
    azihsm_res_test_dev::DdiOp::EstablishCredential,
    azihsm_res_test_dev::DdiOp::GetSessionEncryptionKey,
    azihsm_res_test_dev::DdiOp::OpenSession,
    azihsm_res_test_dev::DdiOp::ReopenSession,
    azihsm_res_test_dev::DdiOp::UnmaskKey,
];

/// Builds the list of DDI ops to target with random fault injection,
/// based on the active worker operations plus recovery-path ops.
#[cfg(feature = "res-test")]
fn build_fault_targets(ops: &[OpKind]) -> Vec<azihsm_res_test_dev::DdiOp> {
    use azihsm_res_test_dev::DdiOp;

    let mut targets: Vec<DdiOp> = Vec::new();

    for op in ops {
        let ddi_op = match op {
            OpKind::AesCbcEncrypt | OpKind::AesCbcDecrypt => DdiOp::AesEncryptDecrypt,
            OpKind::EccSign => DdiOp::EccSign,
            OpKind::HmacSign => DdiOp::Hmac,
            OpKind::RsaSign | OpKind::RsaDecrypt => DdiOp::RsaModExp,
            OpKind::EcdhDerive => DdiOp::EcdhKeyExchange,
            OpKind::HkdfDerive => DdiOp::HkdfDerive,
            OpKind::AesKeyGen | OpKind::AesXtsKeyGen => DdiOp::AesGenerateKey,
            OpKind::EccKeyGen => DdiOp::EccGenerateKeyPair,
            OpKind::UnwrappingKeyGen => DdiOp::GetUnwrappingKey,
            OpKind::AesUnwrap | OpKind::EccUnwrap | OpKind::XtsUnwrap => DdiOp::RsaUnwrap,
            OpKind::AesUnmask | OpKind::EccUnmask | OpKind::XtsUnmask => DdiOp::UnmaskKey,
            OpKind::EccKeyReport | OpKind::RsaKeyReport | OpKind::UnwrappingKeyReport => {
                DdiOp::AttestKey
            }
            OpKind::CertChain => DdiOp::GetCertChainInfo,
            OpKind::AesKeyGenDelete | OpKind::AesXtsKeyGenDelete => DdiOp::AesGenerateKey,
            OpKind::EccKeyGenDelete => DdiOp::EccGenerateKeyPair,
        };
        if !targets.contains(&ddi_op) {
            targets.push(ddi_op);
        }
    }

    // Always include recovery-path ops.
    for &op in RECOVERY_DDI_OPS {
        if !targets.contains(&op) {
            targets.push(op);
        }
    }

    targets
}

/// Continuously injects `reset_on_next` faults on random DDI operations.
///
/// Each iteration picks a random DDI op from the target list and injects
/// a fault rule that triggers an NSSR on the next call to that operation.
/// The target list is built from the active worker operations plus
/// recovery-path ops, so faults only hit DDI calls that are actually
/// being made.
#[cfg(feature = "res-test")]
fn random_fault_thread(
    interval: Duration,
    stats: Arc<SharedStats>,
    barrier: Arc<Barrier>,
    fault_targets: Vec<azihsm_res_test_dev::DdiOp>,
) {
    use azihsm_res_test_dev::*;

    barrier.wait();
    let mut rng = rand::thread_rng();

    while !stats.stop.load(Ordering::Relaxed) {
        thread::sleep(interval);
        if stats.stop.load(Ordering::Relaxed) {
            break;
        }

        // Pick a random DDI op from the target list.
        let op = fault_targets[rng.gen_range(0..fault_targets.len())];
        inject_fault(FaultRule::reset_on_next(op, 1));
        stats.total_resets.fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Stats printer
// ---------------------------------------------------------------------------

fn stats_thread(
    stats: Arc<SharedStats>,
    interval: Duration,
    start: Instant,
    stall_timeout: Duration,
    worker_states: Arc<WorkerStates>,
) -> bool {
    // Use ANSI escape codes to overwrite multiple lines.
    let mut first = true;
    let mut last_progress_ops: u64 = 0;
    let mut last_progress_time = Instant::now();

    // Previous snapshot for computing deltas.
    let mut prev = [0u64; 25];

    while !stats.stop.load(Ordering::Relaxed) {
        thread::sleep(interval);
        let elapsed = start.elapsed();
        let ops = stats.total_ops.load(Ordering::Relaxed);
        let resets = stats.total_resets.load(Ordering::Relaxed);
        let reset_fails = stats.reset_failures.load(Ordering::Relaxed);
        let elapsed_secs = elapsed.as_secs_f64();
        let ops_per_sec = if elapsed_secs > 0.0 {
            ops as f64 / elapsed_secs
        } else {
            0.0
        };

        // Snapshot current per-op counters.
        let cur = [
            stats.aes_cbc_encrypt.load(Ordering::Relaxed),
            stats.aes_cbc_decrypt.load(Ordering::Relaxed),
            stats.ecc_sign.load(Ordering::Relaxed),
            stats.hmac_sign.load(Ordering::Relaxed),
            stats.rsa_sign.load(Ordering::Relaxed),
            stats.rsa_decrypt.load(Ordering::Relaxed),
            stats.ecdh_derive.load(Ordering::Relaxed),
            stats.hkdf_derive.load(Ordering::Relaxed),
            stats.aes_keygen.load(Ordering::Relaxed),
            stats.ecc_keygen.load(Ordering::Relaxed),
            stats.aes_xts_keygen.load(Ordering::Relaxed),
            stats.unwrapping_keygen.load(Ordering::Relaxed),
            stats.aes_unwrap.load(Ordering::Relaxed),
            stats.ecc_unwrap.load(Ordering::Relaxed),
            stats.xts_unwrap.load(Ordering::Relaxed),
            stats.aes_unmask.load(Ordering::Relaxed),
            stats.ecc_unmask.load(Ordering::Relaxed),
            stats.xts_unmask.load(Ordering::Relaxed),
            stats.ecc_key_report.load(Ordering::Relaxed),
            stats.rsa_key_report.load(Ordering::Relaxed),
            stats.unwrapping_key_report.load(Ordering::Relaxed),
            stats.cert_chain.load(Ordering::Relaxed),
            stats.aes_keygen_delete.load(Ordering::Relaxed),
            stats.ecc_keygen_delete.load(Ordering::Relaxed),
            stats.xts_keygen_delete.load(Ordering::Relaxed),
        ];

        // Build the entire stats block into a single string so the
        // terminal output is atomic and cursor-up works reliably.
        use std::fmt::Write as _;
        let mut buf = String::with_capacity(1024);

        let delta_total: u64 = ops.saturating_sub(prev.iter().sum());

        // Move cursor up 21 lines to overwrite (except on first print).
        if !first {
            write!(buf, "\x1b[26A").ok();
        }
        first = false;

        writeln!(
            buf,
            "\x1b[K[{:02}:{:02}:{:02}] total: {} (+{}) | resets: {} (fail: {}) | ops/s: {:.0}",
            elapsed.as_secs() / 3600,
            (elapsed.as_secs() % 3600) / 60,
            elapsed.as_secs() % 60,
            ops,
            delta_total,
            resets,
            reset_fails,
            ops_per_sec,
        )
        .ok();

        // Print per-op breakdown every 12th tick (~1 minute).
        const LABELS: [&str; 25] = [
            "AES-CBC enc:      ",
            "AES-CBC dec:      ",
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
        ];

        for (i, label) in LABELS.iter().enumerate() {
            let delta = cur[i].saturating_sub(prev[i]);
            writeln!(buf, "\x1b[K  {label} {:<8} (+{delta})", cur[i]).ok();
        }

        eprint!("{buf}");

        prev = cur;

        // Stall / deadlock detection.
        if ops > last_progress_ops {
            last_progress_ops = ops;
            last_progress_time = Instant::now();
        } else if !stall_timeout.is_zero() && last_progress_time.elapsed() >= stall_timeout {
            eprintln!();
            eprintln!("=== STALL DETECTED ===");
            eprintln!(
                "No operations completed for {:.0}s — possible deadlock.",
                last_progress_time.elapsed().as_secs_f64()
            );
            eprintln!("Total ops at stall:  {ops}");
            eprintln!("Resets at stall:     {resets}");
            eprintln!(
                "Elapsed:             {:02}:{:02}:{:02}",
                elapsed.as_secs() / 3600,
                (elapsed.as_secs() % 3600) / 60,
                elapsed.as_secs() % 60,
            );
            eprintln!("Per-operation counts at stall:");
            eprintln!(
                "  AES-CBC enc:    {}",
                stats.aes_cbc_encrypt.load(Ordering::Relaxed)
            );
            eprintln!(
                "  AES-CBC dec:    {}",
                stats.aes_cbc_decrypt.load(Ordering::Relaxed)
            );
            eprintln!(
                "  ECC sign:       {}",
                stats.ecc_sign.load(Ordering::Relaxed)
            );
            eprintln!(
                "  HMAC sign:      {}",
                stats.hmac_sign.load(Ordering::Relaxed)
            );
            eprintln!(
                "  RSA sign:       {}",
                stats.rsa_sign.load(Ordering::Relaxed)
            );
            eprintln!(
                "  RSA decrypt:    {}",
                stats.rsa_decrypt.load(Ordering::Relaxed)
            );
            eprintln!(
                "  ECDH derive:    {}",
                stats.ecdh_derive.load(Ordering::Relaxed)
            );
            eprintln!(
                "  HKDF derive:    {}",
                stats.hkdf_derive.load(Ordering::Relaxed)
            );
            eprintln!(
                "  AES key gen:    {}",
                stats.aes_keygen.load(Ordering::Relaxed)
            );
            eprintln!(
                "  ECC key gen:    {}",
                stats.ecc_keygen.load(Ordering::Relaxed)
            );
            eprintln!(
                "  AES-XTS keygen: {}",
                stats.aes_xts_keygen.load(Ordering::Relaxed)
            );
            eprintln!(
                "  Unwrap keygen:  {}",
                stats.unwrapping_keygen.load(Ordering::Relaxed)
            );
            eprintln!(
                "  AES unwrap:     {}",
                stats.aes_unwrap.load(Ordering::Relaxed)
            );
            eprintln!(
                "  ECC unwrap:     {}",
                stats.ecc_unwrap.load(Ordering::Relaxed)
            );
            eprintln!(
                "  XTS unwrap:     {}",
                stats.xts_unwrap.load(Ordering::Relaxed)
            );
            eprintln!(
                "  AES unmask:     {}",
                stats.aes_unmask.load(Ordering::Relaxed)
            );
            eprintln!(
                "  ECC unmask:     {}",
                stats.ecc_unmask.load(Ordering::Relaxed)
            );
            eprintln!(
                "  XTS unmask:     {}",
                stats.xts_unmask.load(Ordering::Relaxed)
            );
            eprintln!(
                "  ECC key report: {}",
                stats.ecc_key_report.load(Ordering::Relaxed)
            );
            eprintln!(
                "  RSA key report: {}",
                stats.rsa_key_report.load(Ordering::Relaxed)
            );
            eprintln!(
                "  Unwrap report:  {}",
                stats.unwrapping_key_report.load(Ordering::Relaxed)
            );
            eprintln!(
                "  Cert chain:     {}",
                stats.cert_chain.load(Ordering::Relaxed)
            );
            eprintln!(
                "  AES keygen+del: {}",
                stats.aes_keygen_delete.load(Ordering::Relaxed)
            );
            eprintln!(
                "  ECC keygen+del: {}",
                stats.ecc_keygen_delete.load(Ordering::Relaxed)
            );
            eprintln!(
                "  XTS keygen+del: {}",
                stats.xts_keygen_delete.load(Ordering::Relaxed)
            );
            eprintln!("Worker states at stall:");
            worker_states.dump();
            stats.stop.store(true, Ordering::SeqCst);
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn parse_ops(ops_str: &str) -> Vec<OpKind> {
    if ops_str == "all" {
        return vec![
            OpKind::AesCbcEncrypt,
            OpKind::AesCbcDecrypt,
            OpKind::EccSign,
            OpKind::HmacSign,
            OpKind::RsaSign,
            OpKind::RsaDecrypt,
            OpKind::EcdhDerive,
            OpKind::HkdfDerive,
            OpKind::AesKeyGen,
            OpKind::EccKeyGen,
            OpKind::AesXtsKeyGen,
            OpKind::UnwrappingKeyGen,
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
        ];
    }
    let mut ops = Vec::new();
    for op in ops_str.split(',') {
        match op.trim() {
            "aes-cbc" => {
                ops.push(OpKind::AesCbcEncrypt);
                ops.push(OpKind::AesCbcDecrypt);
            }
            "aes-cbc-encrypt" => ops.push(OpKind::AesCbcEncrypt),
            "aes-cbc-decrypt" => ops.push(OpKind::AesCbcDecrypt),
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

    tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::WARN
        } else {
            tracing::Level::ERROR
        })
        .init();

    eprintln!("=== Resiliency Stress Tool ===");

    // Validate flag combinations.
    if args.random_fault && args.no_resiliency {
        eprintln!(
            "Error: --random-fault requires resiliency (cannot combine with --no-resiliency)"
        );
        std::process::exit(1);
    }
    if args.random_fault && args.no_reset {
        eprintln!("Error: --random-fault injects resets (cannot combine with --no-reset)");
        std::process::exit(1);
    }

    eprintln!("Workers:        {}", args.workers);
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
        "Stall timeout:  {}",
        if args.stall_timeout_secs == 0 {
            "disabled".to_string()
        } else {
            format!("{}s", args.stall_timeout_secs)
        }
    );
    eprintln!(
        "Mode:           {}",
        if args.no_resiliency {
            "no-resiliency (baseline)"
        } else if args.random_fault {
            "resiliency enabled + random DDI fault injection"
        } else if args.no_reset {
            "resiliency enabled, no resets"
        } else {
            "resiliency enabled + resets"
        }
    );

    let ops = parse_ops(&args.ops);
    eprintln!(
        "Operations:     {}",
        ops.iter()
            .map(|o| format!("{o}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!();

    // Setup partition + session.
    let enable_resiliency = !args.no_resiliency;
    let enable_resets = enable_resiliency && !args.no_reset;
    let (part, creds) = open_and_init_partition(enable_resiliency);
    let path = part.path();

    let stats = Arc::new(SharedStats::new());
    let worker_states = Arc::new(WorkerStates::new(args.workers));
    // +1 for reset thread.
    let barrier = Arc::new(Barrier::new(args.workers + 1));
    let start = Instant::now();

    // Spawn deadlock detection thread.
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        let deadlocks = deadlock::check_deadlock();
        if deadlocks.is_empty() {
            continue;
        }
        eprintln!();
        eprintln!("=== DEADLOCK DETECTED ({} cycles) ===", deadlocks.len());
        for (i, threads) in deadlocks.iter().enumerate() {
            eprintln!("--- Cycle {} ({} threads) ---", i + 1, threads.len());
            for t in threads {
                eprintln!("Thread {:?} ({:?}):", t.thread_id(), t.thread_id());
                eprintln!("{:#?}", t.backtrace());
            }
        }
    });

    // Spawn stats printer.
    let stats_clone = Arc::clone(&stats);
    let stats_interval = Duration::from_secs(args.stats_interval_secs);
    let stall_timeout = Duration::from_secs(args.stall_timeout_secs);
    let ws_clone = Arc::clone(&worker_states);
    let stats_handle = thread::spawn(move || {
        stats_thread(stats_clone, stats_interval, start, stall_timeout, ws_clone)
    });

    // Spawn reset thread (or random fault injection thread).
    let stats_clone = Arc::clone(&stats);
    let barrier_clone = Arc::clone(&barrier);
    let reset_interval = Duration::from_millis(args.reset_interval_ms);
    let use_random_fault = args.random_fault;
    let reset_handle = if use_random_fault {
        #[cfg(feature = "res-test")]
        {
            let fault_targets = build_fault_targets(&ops);
            thread::spawn(move || {
                random_fault_thread(reset_interval, stats_clone, barrier_clone, fault_targets)
            })
        }
        #[cfg(not(feature = "res-test"))]
        {
            eprintln!("Error: --random-fault requires the `res-test` feature.");
            eprintln!("Rebuild with: cargo build --features res-test -p resiliency_stress");
            std::process::exit(1);
        }
    } else {
        thread::spawn(move || {
            reset_thread(
                path,
                reset_interval,
                stats_clone,
                barrier_clone,
                enable_resets,
            )
        })
    };

    // Spawn worker threads — all share a single session.
    let session = open_session(&part, &creds);
    let mut worker_handles = Vec::new();
    for i in 0..args.workers {
        let partition = part.clone();
        let session = session.clone();
        let ops = ops.clone();
        let stats_clone = Arc::clone(&stats);
        let barrier_clone = Arc::clone(&barrier);
        let ws_clone = Arc::clone(&worker_states);
        let handle = thread::spawn(move || {
            worker_thread(
                i,
                partition,
                session,
                ops,
                stats_clone,
                barrier_clone,
                ws_clone,
            )
        });
        worker_handles.push(handle);
    }

    // Duration timer (if not infinite).
    if args.duration_secs > 0 {
        let stats_clone = Arc::clone(&stats);
        let dur = Duration::from_secs(args.duration_secs);
        thread::spawn(move || {
            thread::sleep(dur);
            stats_clone.stop.store(true, Ordering::SeqCst);
        });
    }

    // Wait for workers.
    let mut failure: Option<WorkerFailure> = None;
    for handle in worker_handles {
        if let Ok(Some(f)) = handle.join() {
            if failure.is_none() {
                failure = Some(f);
            }
        }
    }

    // Stop reset and stats threads.
    stats.stop.store(true, Ordering::SeqCst);
    let _ = reset_handle.join();
    let stalled = stats_handle.join().unwrap_or(false);

    let elapsed = start.elapsed();
    let total_ops = stats.total_ops.load(Ordering::Relaxed);
    let total_resets = stats.total_resets.load(Ordering::Relaxed);
    let total_reset_fails = stats.reset_failures.load(Ordering::Relaxed);

    eprintln!("\n");
    eprintln!("=== Final Stats ===");
    eprintln!(
        "Elapsed:        {:02}:{:02}:{:02}",
        elapsed.as_secs() / 3600,
        (elapsed.as_secs() % 3600) / 60,
        elapsed.as_secs() % 60,
    );
    eprintln!("Total ops:      {total_ops}");
    eprintln!("Resets:         {total_resets}");
    eprintln!("Reset failures: {total_reset_fails}");
    eprintln!(
        "Ops/sec:        {:.0}",
        total_ops as f64 / elapsed.as_secs_f64().max(0.001)
    );
    eprintln!();
    eprintln!("Per-operation breakdown:");
    eprintln!(
        "  AES-CBC enc:    {}",
        stats.aes_cbc_encrypt.load(Ordering::Relaxed)
    );
    eprintln!(
        "  AES-CBC dec:    {}",
        stats.aes_cbc_decrypt.load(Ordering::Relaxed)
    );
    eprintln!(
        "  ECC sign:       {}",
        stats.ecc_sign.load(Ordering::Relaxed)
    );
    eprintln!(
        "  HMAC sign:      {}",
        stats.hmac_sign.load(Ordering::Relaxed)
    );
    eprintln!(
        "  RSA sign:       {}",
        stats.rsa_sign.load(Ordering::Relaxed)
    );
    eprintln!(
        "  RSA decrypt:    {}",
        stats.rsa_decrypt.load(Ordering::Relaxed)
    );
    eprintln!(
        "  ECDH derive:    {}",
        stats.ecdh_derive.load(Ordering::Relaxed)
    );
    eprintln!(
        "  HKDF derive:    {}",
        stats.hkdf_derive.load(Ordering::Relaxed)
    );
    eprintln!(
        "  AES key gen:    {}",
        stats.aes_keygen.load(Ordering::Relaxed)
    );
    eprintln!(
        "  ECC key gen:    {}",
        stats.ecc_keygen.load(Ordering::Relaxed)
    );
    eprintln!(
        "  AES-XTS keygen: {}",
        stats.aes_xts_keygen.load(Ordering::Relaxed)
    );
    eprintln!(
        "  Unwrap keygen:  {}",
        stats.unwrapping_keygen.load(Ordering::Relaxed)
    );
    eprintln!(
        "  AES unwrap:     {}",
        stats.aes_unwrap.load(Ordering::Relaxed)
    );
    eprintln!(
        "  ECC unwrap:     {}",
        stats.ecc_unwrap.load(Ordering::Relaxed)
    );
    eprintln!(
        "  XTS unwrap:     {}",
        stats.xts_unwrap.load(Ordering::Relaxed)
    );
    eprintln!(
        "  AES unmask:     {}",
        stats.aes_unmask.load(Ordering::Relaxed)
    );
    eprintln!(
        "  ECC unmask:     {}",
        stats.ecc_unmask.load(Ordering::Relaxed)
    );
    eprintln!(
        "  XTS unmask:     {}",
        stats.xts_unmask.load(Ordering::Relaxed)
    );
    eprintln!(
        "  ECC key report: {}",
        stats.ecc_key_report.load(Ordering::Relaxed)
    );
    eprintln!(
        "  RSA key report: {}",
        stats.rsa_key_report.load(Ordering::Relaxed)
    );
    eprintln!(
        "  Unwrap report:  {}",
        stats.unwrapping_key_report.load(Ordering::Relaxed)
    );
    eprintln!(
        "  Cert chain:     {}",
        stats.cert_chain.load(Ordering::Relaxed)
    );
    eprintln!(
        "  AES keygen+del: {}",
        stats.aes_keygen_delete.load(Ordering::Relaxed)
    );
    eprintln!(
        "  ECC keygen+del: {}",
        stats.ecc_keygen_delete.load(Ordering::Relaxed)
    );
    eprintln!(
        "  XTS keygen+del: {}",
        stats.xts_keygen_delete.load(Ordering::Relaxed)
    );

    if let Some(f) = failure {
        eprintln!();
        eprintln!("=== FAILURE ===");
        eprintln!("Thread:     {}", f.thread_id);
        eprintln!("Operation:  {}", f.op);
        eprintln!("Error:      {:?}", f.error);
        eprintln!("Total ops:  {}", f.total_ops);
        std::process::exit(1);
    } else if stalled {
        eprintln!();
        eprintln!("Exiting due to stall (possible deadlock).");
        std::process::exit(2);
    } else {
        eprintln!();
        eprintln!("All operations completed successfully.");
    }
}
