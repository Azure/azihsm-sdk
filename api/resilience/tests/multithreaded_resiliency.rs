// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crypto::rand;
use mcr_api_resilient::*;
#[cfg(feature = "mock")]
use test_with_tracing::test;

use crate::common::*;

/// Helper function to generate an AES XTS session key
fn generate_session_aes_xts_key(session: &HsmSession, error_context: &str) -> HsmKeyHandle {
    let result = session.aes_generate(AesKeySize::AesXtsBulk256, None, SESSION_KEY_PROPERTIES);

    match result {
        Ok(key_handle) => key_handle,
        Err(e) => panic!("{}: {:?}", error_context, e),
    }
}

/// Helper function to generate a secret key using ECDH key exchange
fn generate_session_secret_key(session: &HsmSession, error_context: &str) -> HsmKeyHandle {
    // Generate two ECC keys for ECDH
    let priv_key_handle1 = session
        .ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        )
        .unwrap_or_else(|e| panic!("{} (ECC key 1 generation): {:?}", error_context, e));

    let priv_key_handle2 = session
        .ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        )
        .unwrap_or_else(|e| panic!("{} (ECC key 2 generation): {:?}", error_context, e));

    // Get DER from second key handle
    let pub_key_der2 = session
        .export_public_key(&priv_key_handle2)
        .unwrap_or_else(|e| panic!("{} (public key export): {:?}", error_context, e));

    // Create secret via ECDH
    let secret_key = session
        .ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        )
        .unwrap_or_else(|e| panic!("{} (ECDH key exchange): {:?}", error_context, e));

    // Clean up the intermediate ECC keys
    session
        .delete_key(&priv_key_handle1)
        .unwrap_or_else(|e| panic!("{} (ECC key 1 cleanup): {:?}", error_context, e));
    session
        .delete_key(&priv_key_handle2)
        .unwrap_or_else(|e| panic!("{} (ECC key 2 cleanup): {:?}", error_context, e));

    secret_key
}

// Test configuration constants
#[cfg(feature = "mock")]
const DEFAULT_THREAD_COUNT: usize = 4;
#[cfg(feature = "mock")]
const DEFAULT_TEST_DURATION_SECS: u64 = 10;
// This is unrealistically low to increase the chance of migration during operations
const MIGRATION_SLEEP_MIN_MS: u32 = 1000;
const MIGRATION_SLEEP_RANGE_MS: u32 = 2000; // Range: 1000-2000ms
const BARRIER_EXTRA_COUNT: usize = 2; // Migration thread + main thread

#[allow(dead_code)]
fn handle_thread_join_result(
    result: Result<(), Box<dyn std::any::Any + Send>>,
    thread_type: &str,
    thread_index: Option<usize>,
) {
    match result {
        Ok(()) => {}
        Err(panic_payload) => {
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic_payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else {
                "Unknown panic payload".to_string()
            };

            match thread_index {
                Some(idx) => panic!("{} thread {} panicked: {}", thread_type, idx, panic_msg),
                None => panic!("{} thread panicked: {}", thread_type, panic_msg),
            }
        }
    }
}

#[allow(dead_code)]
fn migration_thread(device_path: String, barrier: Arc<Barrier>, stop_flag: Arc<AtomicBool>) {
    barrier.wait();
    let mut sleep_buf = [0u8; 4];
    while !stop_flag.load(Ordering::Relaxed) {
        simulate_live_migration_helper(&device_path);

        rand::rand_bytes(&mut sleep_buf)
            .unwrap_or_else(|e| panic!("Failed to generate random sleep: {:?}", e));
        let sleep_ms =
            (u32::from_le_bytes(sleep_buf) % MIGRATION_SLEEP_RANGE_MS) + MIGRATION_SLEEP_MIN_MS;
        thread::sleep(Duration::from_millis(sleep_ms as u64));
    }
}

#[allow(dead_code)]
trait SessionOperation: Send + Clone {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String>;
}

#[allow(dead_code)]
trait DeviceOperation: Send + Clone {
    fn execute(&mut self, device_path: &str, thread_id: usize) -> Result<(), String>;
}

#[allow(dead_code)]
#[derive(Clone)]
enum MixedSessionOperation {
    AesEncryptDecrypt(AesEncryptDecryptOp),
    KeyCreateDelete(KeyCreateDeleteOp),
    AesXts(AesXtsOp),
    HkdfDerive(HkdfDeriveOp),
    UnwrappingKey(UnwrappingKeyOp),
}

#[allow(dead_code)]
impl SessionOperation for MixedSessionOperation {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        match self {
            MixedSessionOperation::AesEncryptDecrypt(op) => op.execute(session, thread_id),
            MixedSessionOperation::KeyCreateDelete(op) => op.execute(session, thread_id),
            MixedSessionOperation::AesXts(op) => op.execute(session, thread_id),
            MixedSessionOperation::HkdfDerive(op) => op.execute(session, thread_id),
            MixedSessionOperation::UnwrappingKey(op) => op.execute(session, thread_id),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct AesEncryptDecryptOp {
    key_handle: Option<HsmKeyHandle>,
    plaintext: Vec<u8>,
    iv: [u8; 16],
}

#[allow(dead_code)]
impl AesEncryptDecryptOp {
    fn new() -> Self {
        let mut plaintext = [0u8; 16];
        rand::rand_bytes(&mut plaintext)
            .unwrap_or_else(|e| panic!("Failed to generate random plaintext: {:?}", e));
        Self {
            key_handle: None,
            plaintext: plaintext.to_vec(),
            iv: [0u8; 16],
        }
    }
}

#[allow(dead_code)]
impl SessionOperation for AesEncryptDecryptOp {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        if self.key_handle.is_none() {
            self.key_handle = Some(generate_session_aes_key(
                session,
                &format!("thread {} aes_generate failed", thread_id),
            ));
        }
        let key_handle = self.key_handle.as_ref().unwrap();

        let enc_result = session.aes_encrypt_decrypt(
            key_handle,
            AesMode::Encrypt,
            self.plaintext.clone(),
            self.iv,
        );
        let ciphertext = enc_result
            .map_err(|e| format!("thread {} encrypt failed: {:?}", thread_id, e))?
            .data;

        let dec_result =
            session.aes_encrypt_decrypt(key_handle, AesMode::Decrypt, ciphertext, self.iv);
        let decrypted = dec_result
            .map_err(|e| format!("thread {} decrypt failed: {:?}", thread_id, e))?
            .data;

        if decrypted != self.plaintext {
            return Err(format!(
                "Thread {}: Decrypted text does not match",
                thread_id
            ));
        }
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct KeyCreateDeleteOp;

#[allow(dead_code)]
impl KeyCreateDeleteOp {
    fn new() -> Self {
        Self
    }
}

#[allow(dead_code)]
impl SessionOperation for KeyCreateDeleteOp {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        let key_handle =
            generate_session_aes_key(session, &format!("thread {} key create failed", thread_id));

        session
            .delete_key(&key_handle)
            .map_err(|e| format!("thread {} key delete failed: {:?}", thread_id, e))?;

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct HkdfDeriveOp;

#[allow(dead_code)]
impl HkdfDeriveOp {
    fn new() -> Self {
        Self
    }
}

#[allow(dead_code)]
impl SessionOperation for HkdfDeriveOp {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        // Always generate a fresh source secret key for each execution
        let source_key = generate_session_secret_key(
            session,
            &format!("thread {} secret key generation failed", thread_id),
        );

        let params = HkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            salt: Some(b"test-salt"),
            info: Some(b"test-info"),
        };

        let derived_key = session
            .hkdf_derive(
                &source_key,
                params,
                None,
                KeyType::HmacSha256,
                KeyProperties {
                    key_usage: KeyUsage::SignVerify,
                    key_availability: KeyAvailability::Session,
                },
            )
            .map_err(|e| format!("thread {} hkdf derive failed: {:?}", thread_id, e))?;

        // Delete the source key
        session
            .delete_key(&source_key)
            .map_err(|e| format!("thread {} source key delete failed: {:?}", thread_id, e))?;

        // Use the derived key for HMAC operations
        let test_data = b"test data for HMAC";
        let hmac_result1 = session
            .hmac(&derived_key, test_data.to_vec())
            .map_err(|e| format!("thread {} hmac operation 1 failed: {:?}", thread_id, e))?;

        // Verify by computing HMAC again with the same data
        let hmac_result2 = session
            .hmac(&derived_key, test_data.to_vec())
            .map_err(|e| format!("thread {} hmac operation 2 failed: {:?}", thread_id, e))?;

        if hmac_result1 != hmac_result2 {
            return Err(format!(
                "thread {} hmac consistency check failed",
                thread_id
            ));
        }

        // Delete the derived key
        session
            .delete_key(&derived_key)
            .map_err(|e| format!("thread {} derived key delete failed: {:?}", thread_id, e))?;

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct AesXtsOp {
    key1: Option<HsmKeyHandle>,
    key2: Option<HsmKeyHandle>,
    plaintext: Vec<u8>,
    tweak: [u8; 16],
}

#[allow(dead_code)]
impl AesXtsOp {
    fn new() -> Self {
        let mut plaintext = vec![0u8; 512];
        rand::rand_bytes(&mut plaintext)
            .unwrap_or_else(|e| panic!("Failed to generate random plaintext: {:?}", e));
        let mut tweak = [0u8; 16];
        rand::rand_bytes(&mut tweak)
            .unwrap_or_else(|e| panic!("Failed to generate random tweak: {:?}", e));
        Self {
            key1: None,
            key2: None,
            plaintext,
            tweak,
        }
    }
}

#[allow(dead_code)]
impl SessionOperation for AesXtsOp {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        if self.key1.is_none() {
            self.key1 = Some(generate_session_aes_xts_key(
                session,
                &format!("thread {} aes xts key1 generate failed", thread_id),
            ));
        }
        if self.key2.is_none() {
            self.key2 = Some(generate_session_aes_xts_key(
                session,
                &format!("thread {} aes xts key2 generate failed", thread_id),
            ));
        }
        let key1 = self.key1.as_ref().unwrap();
        let key2 = self.key2.as_ref().unwrap();

        let enc_result = session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            key1,
            key2,
            self.plaintext.len(),
            self.tweak,
            self.plaintext.clone(),
        );
        let ciphertext = enc_result
            .map_err(|e| format!("thread {} aes xts encrypt failed: {:?}", thread_id, e))?
            .data;

        let dec_result = session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            key1,
            key2,
            ciphertext.len(),
            self.tweak,
            ciphertext,
        );
        let decrypted = dec_result
            .map_err(|e| format!("thread {} aes xts decrypt failed: {:?}", thread_id, e))?
            .data;

        if decrypted != self.plaintext {
            return Err(format!(
                "Thread {}: AES XTS decrypted text does not match",
                thread_id
            ));
        }
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct UnwrappingKeyOp {
    wrapping_key: Option<HsmKeyHandle>,
    wrapped_key_handle: Option<HsmKeyHandle>,
    message: Vec<u8>,
}

#[allow(dead_code)]
impl UnwrappingKeyOp {
    fn new() -> Self {
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
        Self {
            wrapping_key: None,
            wrapped_key_handle: None,
            message,
        }
    }
}

#[allow(dead_code)]
impl SessionOperation for UnwrappingKeyOp {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        // Get unwrapping key (only once per operation instance)
        if self.wrapping_key.is_none() {
            let wrapping_key = session
                .get_unwrapping_key()
                .map_err(|e| format!("thread {} get_unwrapping_key failed: {:?}", thread_id, e))?;
            self.wrapping_key = Some(wrapping_key);
        }
        let wrapping_key = self.wrapping_key.as_ref().unwrap();

        // Attest the unwrapping key
        let report_data = [0x42u8; 128];
        let (attestation_report, _cert) = session
            .attest_key_and_obtain_cert(wrapping_key, &report_data)
            .map_err(|e| format!("thread {} attest_key failed: {:?}", thread_id, e))?;

        if attestation_report.is_empty() {
            return Err(format!(
                "thread {} attestation report should not be empty",
                thread_id
            ));
        }

        // Export public key from unwrapping key
        let public_key_der = session
            .export_public_key(wrapping_key)
            .map_err(|e| format!("thread {} export_public_key failed: {:?}", thread_id, e))?;

        // Generate wrapped data (wrapped private key and its public key)
        let (wrapped_blob, public_key_der_for_target) = generate_wrapped_data(public_key_der);

        // Unwrap the key
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Rsa,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha256,
        };

        let wrapped_key_handle = session
            .rsa_unwrap(
                wrapping_key,
                wrapped_blob,
                wrapped_blob_params,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::Session,
                },
            )
            .map_err(|e| format!("thread {} rsa_unwrap failed: {:?}", thread_id, e))?;

        // Export public key from wrapped key handle and verify it matches
        let wrapped_key_pub = session
            .export_public_key(&wrapped_key_handle)
            .map_err(|e| {
                format!(
                    "thread {} export_public_key (wrapped key) failed: {:?}",
                    thread_id, e
                )
            })?;

        if wrapped_key_pub != public_key_der_for_target {
            return Err(format!(
                "thread {} public key from wrapped handle should match the generated key",
                thread_id
            ));
        }

        // Encrypt with the wrapped key
        let encrypted_data = session
            .rsa_encrypt(
                &wrapped_key_handle,
                self.message.clone(),
                RsaCryptoPadding::Oaep,
                Some(DigestKind::Sha256),
                None,
            )
            .map_err(|e| format!("thread {} rsa_encrypt failed: {:?}", thread_id, e))?;

        // Decrypt with the wrapped key
        let dec_data = session
            .rsa_decrypt(
                &wrapped_key_handle,
                encrypted_data,
                RsaCryptoPadding::Oaep,
                Some(DigestKind::Sha256),
                None,
            )
            .map_err(|e| format!("thread {} rsa_decrypt failed: {:?}", thread_id, e))?;

        if dec_data != self.message {
            return Err(format!(
                "thread {} decrypted message should match original",
                thread_id
            ));
        }

        // Clean up the wrapped key handle
        session.delete_key(&wrapped_key_handle).map_err(|e| {
            format!(
                "thread {} delete_key (wrapped key) failed: {:?}",
                thread_id, e
            )
        })?;

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
enum SharedKeyOperation {
    AesEncryptDecrypt(SharedAesEncryptDecryptOp),
    AesXts(SharedAesXtsOp),
    HkdfDerive(SharedHkdfDeriveOp),
}

#[allow(dead_code)]
impl SessionOperation for SharedKeyOperation {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        match self {
            SharedKeyOperation::AesEncryptDecrypt(op) => op.execute(session, thread_id),
            SharedKeyOperation::AesXts(op) => op.execute(session, thread_id),
            SharedKeyOperation::HkdfDerive(op) => op.execute(session, thread_id),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct SharedAesEncryptDecryptOp {
    key_handle: Option<HsmKeyHandle>,
    plaintext: Vec<u8>,
    iv: [u8; 16],
}

#[allow(dead_code)]
impl SharedAesEncryptDecryptOp {
    fn new_with_shared_key(key_handle: HsmKeyHandle) -> Self {
        let mut plaintext = [0u8; 16];
        rand::rand_bytes(&mut plaintext)
            .unwrap_or_else(|e| panic!("Failed to generate random plaintext: {:?}", e));
        Self {
            key_handle: Some(key_handle),
            plaintext: plaintext.to_vec(),
            iv: [0u8; 16],
        }
    }
}

#[allow(dead_code)]
impl SessionOperation for SharedAesEncryptDecryptOp {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        let key_handle = self
            .key_handle
            .as_ref()
            .expect("Shared AES key should always be provided");

        let enc_result = session.aes_encrypt_decrypt(
            key_handle,
            AesMode::Encrypt,
            self.plaintext.clone(),
            self.iv,
        );
        let ciphertext = enc_result
            .map_err(|e| format!("thread {} encrypt failed: {:?}", thread_id, e))?
            .data;

        let dec_result =
            session.aes_encrypt_decrypt(key_handle, AesMode::Decrypt, ciphertext, self.iv);
        let decrypted = dec_result
            .map_err(|e| format!("thread {} decrypt failed: {:?}", thread_id, e))?
            .data;

        if decrypted != self.plaintext {
            return Err(format!(
                "Thread {}: Shared AES decrypted text does not match",
                thread_id
            ));
        }
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct SharedAesXtsOp {
    key1: Option<HsmKeyHandle>,
    key2: Option<HsmKeyHandle>,
    plaintext: Vec<u8>,
    tweak: [u8; 16],
}

#[allow(dead_code)]
impl SharedAesXtsOp {
    fn new_with_shared_keys(key1: HsmKeyHandle, key2: HsmKeyHandle) -> Self {
        let mut plaintext = vec![0u8; 512];
        rand::rand_bytes(&mut plaintext)
            .unwrap_or_else(|e| panic!("Failed to generate random plaintext: {:?}", e));
        let mut tweak = [0u8; 16];
        rand::rand_bytes(&mut tweak)
            .unwrap_or_else(|e| panic!("Failed to generate random tweak: {:?}", e));
        Self {
            key1: Some(key1),
            key2: Some(key2),
            plaintext,
            tweak,
        }
    }
}

#[allow(dead_code)]
impl SessionOperation for SharedAesXtsOp {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        let key1 = self
            .key1
            .as_ref()
            .expect("Shared AES XTS key1 should always be provided");
        let key2 = self
            .key2
            .as_ref()
            .expect("Shared AES XTS key2 should always be provided");

        let enc_result = session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            key1,
            key2,
            self.plaintext.len(),
            self.tweak,
            self.plaintext.clone(),
        );
        let ciphertext = enc_result
            .map_err(|e| format!("thread {} aes xts encrypt failed: {:?}", thread_id, e))?
            .data;

        let dec_result = session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            key1,
            key2,
            ciphertext.len(),
            self.tweak,
            ciphertext,
        );
        let decrypted = dec_result
            .map_err(|e| format!("thread {} aes xts decrypt failed: {:?}", thread_id, e))?
            .data;

        if decrypted != self.plaintext {
            return Err(format!(
                "Thread {}: Shared AES XTS decrypted text does not match",
                thread_id
            ));
        }
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct SharedHkdfDeriveOp {
    source_key: Option<HsmKeyHandle>,
    plaintext: Vec<u8>,
}

#[allow(dead_code)]
impl SharedHkdfDeriveOp {
    fn new_with_shared_key(source_key: HsmKeyHandle) -> Self {
        SharedHkdfDeriveOp {
            source_key: Some(source_key),
            plaintext: b"test data for HMAC".to_vec(),
        }
    }
}

#[allow(dead_code)]
impl SessionOperation for SharedHkdfDeriveOp {
    fn execute(&mut self, session: &HsmSession, thread_id: usize) -> Result<(), String> {
        let source_key = self
            .source_key
            .as_ref()
            .expect("Shared HKDF source key should always be provided");

        let params = HkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            salt: Some(b"test-salt"),
            info: Some(b"test-info"),
        };

        let derived_key = session
            .hkdf_derive(
                source_key,
                params,
                None,
                KeyType::HmacSha256,
                KeyProperties {
                    key_usage: KeyUsage::SignVerify,
                    key_availability: KeyAvailability::Session,
                },
            )
            .map_err(|e| format!("thread {} hkdf derive failed: {:?}", thread_id, e))?;

        // Use the derived key for HMAC operations
        let hmac_result1 = session
            .hmac(&derived_key, self.plaintext.clone())
            .map_err(|e| format!("thread {} hmac operation 1 failed: {:?}", thread_id, e))?;

        // Verify by computing HMAC again with the same data
        let hmac_result2 = session
            .hmac(&derived_key, self.plaintext.clone())
            .map_err(|e| format!("thread {} hmac operation 2 failed: {:?}", thread_id, e))?;

        if hmac_result1 != hmac_result2 {
            return Err(format!(
                "thread {} hmac consistency check failed",
                thread_id
            ));
        }

        // Delete the derived key (but not the shared source key)
        session
            .delete_key(&derived_key)
            .map_err(|e| format!("thread {} derived key delete failed: {:?}", thread_id, e))?;

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct SessionManagementOp;

#[allow(dead_code)]
impl SessionManagementOp {
    fn new() -> Self {
        Self
    }
}

#[allow(dead_code)]
impl DeviceOperation for SessionManagementOp {
    fn execute(&mut self, device_path: &str, thread_id: usize) -> Result<(), String> {
        let device = HsmDevice::open(device_path)
            .map_err(|e| format!("thread {} failed to open device: {:?}", thread_id, e))?;

        let api_rev = device.get_api_revision_range().max;

        let session = device
            .open_session(api_rev, TEST_CREDENTIALS)
            .map_err(|e| format!("thread {} failed to open session: {:?}", thread_id, e))?;

        let key_handle = session
            .aes_generate(
                AesKeySize::Aes256,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::Session,
                },
            )
            .map_err(|e| format!("thread {} aes key generation failed: {:?}", thread_id, e))?;

        session
            .delete_key(&key_handle)
            .map_err(|e| format!("thread {} key deletion failed: {:?}", thread_id, e))?;

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct DeviceInfoOp;

#[allow(dead_code)]
impl DeviceInfoOp {
    fn new() -> Self {
        Self
    }
}

#[allow(dead_code)]
impl DeviceOperation for DeviceInfoOp {
    fn execute(&mut self, device_path: &str, thread_id: usize) -> Result<(), String> {
        let device = HsmDevice::open(device_path)
            .map_err(|e| format!("thread {} failed to open device: {:?}", thread_id, e))?;

        let _api_rev_range = device.get_api_revision_range();

        let _device_info = device.get_device_info();

        Ok(())
    }
}

#[allow(dead_code)]
fn session_thread<T: SessionOperation + 'static>(
    thread_id: usize,
    device_path: String,
    barrier: Arc<Barrier>,
    stop_flag: Arc<AtomicBool>,
    mut operation: T,
) {
    let device = HsmDevice::open(&device_path)
        .unwrap_or_else(|e| panic!("Thread {} failed to open HSM device: {:?}", thread_id, e));
    let api_rev = device.get_api_revision_range().max;
    let session = device
        .open_session(api_rev, TEST_CREDENTIALS)
        .unwrap_or_else(|e| panic!("Thread {} failed to open session: {:?}", thread_id, e));
    barrier.wait();

    while !stop_flag.load(Ordering::Relaxed) {
        match operation.execute(&session, thread_id) {
            Ok(()) => {}
            Err(e) => panic!("Session thread {} operation failed: {}", thread_id, e),
        }
    }
}

#[allow(dead_code)]
fn shared_session_thread<T: SessionOperation + 'static>(
    thread_id: usize,
    session: Arc<HsmSession>,
    barrier: Arc<Barrier>,
    stop_flag: Arc<AtomicBool>,
    mut operation: T,
) {
    barrier.wait();

    while !stop_flag.load(Ordering::Relaxed) {
        match operation.execute(&session, thread_id) {
            Ok(()) => {}
            Err(e) => panic!(
                "Shared session thread {} operation failed: {}",
                thread_id, e
            ),
        }
    }
}

#[allow(dead_code)]
fn no_session_thread<T: DeviceOperation + 'static>(
    thread_id: usize,
    device_path: String,
    barrier: Arc<Barrier>,
    stop_flag: Arc<AtomicBool>,
    mut operation: T,
) {
    barrier.wait();

    while !stop_flag.load(Ordering::Relaxed) {
        match operation.execute(&device_path, thread_id) {
            Ok(()) => {}
            Err(e) => panic!("Device thread {} operation failed: {}", thread_id, e),
        }
    }
}

#[allow(dead_code)]
struct TestConfig<T> {
    operations: Vec<Box<dyn Fn() -> T + Send + Sync + 'static>>,
    test_duration: Duration,
    barrier_extra_count: usize,
}

#[allow(dead_code)]
impl<T> TestConfig<T> {
    fn new_single(
        operation_factory: impl Fn() -> T + Send + Sync + 'static,
        num_threads: usize,
        test_duration: Duration,
    ) -> Self {
        let mut operation_factories: Vec<Box<dyn Fn() -> T + Send + Sync + 'static>> = Vec::new();
        let factory = Arc::new(operation_factory);
        for _ in 0..num_threads {
            let factory_clone = factory.clone();
            operation_factories.push(Box::new(move || factory_clone()));
        }

        Self {
            operations: operation_factories,
            test_duration,
            barrier_extra_count: BARRIER_EXTRA_COUNT,
        }
    }

    fn new_multiple(
        operation_factories: Vec<Box<dyn Fn() -> T + Send + Sync + 'static>>,
        test_duration: Duration,
    ) -> Self {
        Self {
            operations: operation_factories,
            test_duration,
            barrier_extra_count: BARRIER_EXTRA_COUNT,
        }
    }
}

#[allow(dead_code)]
fn run_separate_session_test<T: SessionOperation + Clone + 'static>(
    config: TestConfig<T>,
    thread_type_name: &str,
) {
    let device_path = get_device_path_helper();
    setup_device(&device_path);

    let num_threads = config.operations.len();

    let barrier = Arc::new(Barrier::new(num_threads + config.barrier_extra_count));
    let stop_flag = Arc::new(AtomicBool::new(false));

    let migration_handle;
    let mut session_handles = vec![];

    {
        let barrier = barrier.clone();
        let stop_flag = stop_flag.clone();
        let device_path = device_path.clone();
        migration_handle = thread::spawn(move || migration_thread(device_path, barrier, stop_flag));
    }

    for (i, operation_factory) in config.operations.iter().enumerate() {
        let barrier = barrier.clone();
        let stop_flag = stop_flag.clone();
        let device_path = device_path.clone();
        let operation = operation_factory();
        session_handles.push(thread::spawn(move || {
            session_thread(i, device_path, barrier, stop_flag, operation)
        }));
    }

    let start = Instant::now();
    barrier.wait();
    while start.elapsed() < config.test_duration {
        thread::sleep(Duration::from_secs(1));
    }
    stop_flag.store(true, Ordering::Relaxed);

    for (i, handle) in session_handles.into_iter().enumerate() {
        handle_thread_join_result(handle.join(), thread_type_name, Some(i));
    }

    handle_thread_join_result(migration_handle.join(), "Migration", None);
}

#[allow(dead_code)]
fn run_shared_session_test<T: SessionOperation + Clone + 'static>(
    config: TestConfig<T>,
    thread_type_name: &str,
) {
    run_shared_session_test_with_setup(config.test_duration, thread_type_name, |_session| {
        // For regular shared session tests, create operations without pre-created keys
        config
            .operations
            .into_iter()
            .map(|factory| factory())
            .collect()
    });
}

#[allow(dead_code)]
fn run_shared_session_test_with_setup<T: SessionOperation + Clone + 'static>(
    test_duration: Duration,
    thread_type_name: &str,
    setup_fn: impl FnOnce(&Arc<HsmSession>) -> Vec<T>,
) {
    let device_path = get_device_path_helper();
    setup_device(&device_path);

    let device = HsmDevice::open(&device_path)
        .unwrap_or_else(|e| panic!("Failed to open HSM device: {:?}", e));
    let api_rev = device.get_api_revision_range().max;
    let session = Arc::new(
        device
            .open_session(api_rev, TEST_CREDENTIALS)
            .unwrap_or_else(|e| panic!("Failed to open session: {:?}", e)),
    );

    // Use the setup function to create operations (with or without pre-created keys)
    let operations = setup_fn(&session);
    let actual_num_threads = operations.len();

    let barrier = Arc::new(Barrier::new(actual_num_threads + BARRIER_EXTRA_COUNT));
    let stop_flag = Arc::new(AtomicBool::new(false));

    let migration_handle;
    let mut session_handles = vec![];

    {
        let barrier = barrier.clone();
        let stop_flag = stop_flag.clone();
        let device_path = device_path.clone();
        migration_handle = thread::spawn(move || migration_thread(device_path, barrier, stop_flag));
    }

    for (i, operation) in operations.into_iter().enumerate() {
        let barrier = barrier.clone();
        let stop_flag = stop_flag.clone();
        let session = session.clone();
        session_handles.push(thread::spawn(move || {
            shared_session_thread(i, session, barrier, stop_flag, operation)
        }));
    }

    let start = Instant::now();
    barrier.wait();
    while start.elapsed() < test_duration {
        thread::sleep(Duration::from_secs(1));
    }
    stop_flag.store(true, Ordering::Relaxed);

    for (i, handle) in session_handles.into_iter().enumerate() {
        handle_thread_join_result(handle.join(), thread_type_name, Some(i));
    }

    handle_thread_join_result(migration_handle.join(), "Migration", None);
}

#[allow(dead_code)]
fn run_no_session_test<T: DeviceOperation + Clone + 'static>(
    config: TestConfig<T>,
    thread_type_name: &str,
) {
    let device_path = get_device_path_helper();
    setup_device(&device_path);

    let num_threads = config.operations.len();

    let barrier = Arc::new(Barrier::new(num_threads + config.barrier_extra_count));
    let stop_flag = Arc::new(AtomicBool::new(false));

    let migration_handle;
    let mut device_handles = vec![];

    {
        let barrier = barrier.clone();
        let stop_flag = stop_flag.clone();
        let device_path = device_path.clone();
        migration_handle = thread::spawn(move || migration_thread(device_path, barrier, stop_flag));
    }

    for (i, operation_factory) in config.operations.iter().enumerate() {
        let barrier = barrier.clone();
        let stop_flag = stop_flag.clone();
        let device_path = device_path.clone();
        let operation = operation_factory();
        device_handles.push(thread::spawn(move || {
            no_session_thread(i, device_path, barrier, stop_flag, operation)
        }));
    }

    let start = Instant::now();
    barrier.wait();
    while start.elapsed() < config.test_duration {
        thread::sleep(Duration::from_secs(1));
    }
    stop_flag.store(true, Ordering::Relaxed);

    for (i, handle) in device_handles.into_iter().enumerate() {
        handle_thread_join_result(handle.join(), thread_type_name, Some(i));
    }

    handle_thread_join_result(migration_handle.join(), "Migration", None);
}

#[cfg(feature = "mock")]
#[test]
#[ignore = "Skip for pipeline due to time constraints"]
fn multithread_resiliency_separate_sessions_aes_encrypt_decrypt() {
    let config = TestConfig::new_single(
        AesEncryptDecryptOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_separate_session_test(config, "AES Session");
}

#[cfg(feature = "mock")]
#[test]
#[ignore = "Skip for pipeline due to time constraints"]
fn multithread_resiliency_separate_sessions_key_create_delete() {
    let config = TestConfig::new_single(
        KeyCreateDeleteOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_separate_session_test(config, "Key Session");
}

#[cfg(feature = "mock")]
#[test]
fn multithread_resiliency_separate_sessions_hkdf_derive() {
    let config = TestConfig::new_single(
        HkdfDeriveOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_separate_session_test(config, "HKDF Session");
}

#[cfg(feature = "mock")]
#[test]
#[ignore = "Skip for pipeline due to time constraints"]
fn multithread_resiliency_separate_sessions_aes_xts() {
    let config = TestConfig::new_single(
        AesXtsOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_separate_session_test(config, "AES XTS Session");
}

#[cfg(feature = "mock")]
#[test]
#[ignore = "Skip for pipeline due to time constraints"]
fn multithread_resiliency_shared_session_aes_encrypt_decrypt() {
    let config = TestConfig::new_single(
        AesEncryptDecryptOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_shared_session_test(config, "Shared AES Session");
}

#[cfg(feature = "mock")]
#[test]
fn multithread_resiliency_shared_session_hkdf_derive() {
    let config = TestConfig::new_single(
        HkdfDeriveOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_shared_session_test(config, "Shared HKDF Session");
}

#[cfg(feature = "mock")]
#[test]
fn multithread_resiliency_shared_session_key_create_delete() {
    let config = TestConfig::new_single(
        KeyCreateDeleteOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_shared_session_test(config, "Shared Key Session");
}

#[cfg(feature = "mock")]
#[test]
#[ignore = "Skip for pipeline due to time constraints"]
fn multithread_resiliency_shared_session_aes_xts() {
    let config = TestConfig::new_single(
        AesXtsOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_shared_session_test(config, "Shared AES XTS Session");
}

#[cfg(feature = "mock")]
#[test]
fn multithread_resiliency_separate_sessions_unwrapping_key() {
    let config = TestConfig::new_single(
        UnwrappingKeyOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_separate_session_test(config, "Unwrapping Key Session");
}

#[cfg(feature = "mock")]
#[test]
fn multithread_resiliency_shared_session_unwrapping_key() {
    let config = TestConfig::new_single(
        UnwrappingKeyOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_shared_session_test(config, "Shared Unwrapping Key Session");
}

#[cfg(feature = "mock")]
#[test]
fn multithread_resiliency_separate_sessions_mixed_operations() {
    let operations = vec![
        Box::new(|| MixedSessionOperation::AesEncryptDecrypt(AesEncryptDecryptOp::new()))
            as Box<dyn Fn() -> MixedSessionOperation + Send + Sync + 'static>,
        Box::new(|| MixedSessionOperation::KeyCreateDelete(KeyCreateDeleteOp::new())),
        Box::new(|| MixedSessionOperation::AesXts(AesXtsOp::new())),
        Box::new(|| MixedSessionOperation::HkdfDerive(HkdfDeriveOp::new())),
        Box::new(|| MixedSessionOperation::UnwrappingKey(UnwrappingKeyOp::new())),
    ];

    let config =
        TestConfig::new_multiple(operations, Duration::from_secs(DEFAULT_TEST_DURATION_SECS));
    run_separate_session_test(config, "Mixed Operations Session");
}

#[cfg(feature = "mock")]
#[test]
fn multithread_resiliency_shared_session_mixed_operations() {
    let operations = vec![
        Box::new(|| MixedSessionOperation::AesEncryptDecrypt(AesEncryptDecryptOp::new()))
            as Box<dyn Fn() -> MixedSessionOperation + Send + Sync + 'static>,
        Box::new(|| MixedSessionOperation::KeyCreateDelete(KeyCreateDeleteOp::new())),
        Box::new(|| MixedSessionOperation::AesXts(AesXtsOp::new())),
        Box::new(|| MixedSessionOperation::HkdfDerive(HkdfDeriveOp::new())),
        Box::new(|| MixedSessionOperation::UnwrappingKey(UnwrappingKeyOp::new())),
    ];

    let config =
        TestConfig::new_multiple(operations, Duration::from_secs(DEFAULT_TEST_DURATION_SECS));
    run_shared_session_test(config, "Mixed Shared Operations Session");
}

#[cfg(feature = "mock")]
#[test]
fn multithread_resiliency_no_session_session_management() {
    let config = TestConfig::new_single(
        SessionManagementOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_no_session_test(config, "Session Management");
}

#[cfg(feature = "mock")]
#[test]
#[ignore = "Skip for pipeline due to time constraints"]
fn multithread_resiliency_no_session_device_info() {
    let config = TestConfig::new_single(
        DeviceInfoOp::new,
        DEFAULT_THREAD_COUNT,
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
    );
    run_no_session_test(config, "Device Info");
}

#[cfg(feature = "mock")]
#[test]
#[ignore = "Skip for pipeline due to time constraints"]
fn multithread_resiliency_shared_key_shared_session_aes_encrypt_decrypt() {
    run_shared_session_test_with_setup(
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
        "Shared Key AES Encrypt/Decrypt",
        |session| {
            // Pre-create the shared key that all threads will use
            let shared_key = generate_session_aes_key(session, "Failed to generate shared AES key");

            // Create operations for all threads using the same key
            (0..DEFAULT_THREAD_COUNT)
                .map(|_| SharedAesEncryptDecryptOp::new_with_shared_key(shared_key.clone()))
                .collect()
        },
    );
}

#[cfg(feature = "mock")]
#[test]
#[ignore = "Skip for pipeline due to time constraints"]
fn multithread_resiliency_shared_key_shared_session_aes_xts() {
    run_shared_session_test_with_setup(
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
        "Shared Key AES XTS",
        |session| {
            // Pre-create the shared keys that all threads will use
            let shared_key1 =
                generate_session_aes_xts_key(session, "Failed to generate shared AES XTS key1");
            let shared_key2 =
                generate_session_aes_xts_key(session, "Failed to generate shared AES XTS key2");

            // Create operations for all threads using the same keys
            (0..DEFAULT_THREAD_COUNT)
                .map(|_| {
                    SharedAesXtsOp::new_with_shared_keys(shared_key1.clone(), shared_key2.clone())
                })
                .collect()
        },
    );
}

#[cfg(feature = "mock")]
#[test]
#[ignore = "Skip for pipeline due to time constraints"]
fn multithread_resiliency_shared_key_shared_session_hkdf_derive() {
    run_shared_session_test_with_setup(
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
        "Shared Key HKDF Derive",
        |session| {
            // Pre-create the shared source key that all threads will use for HKDF
            let shared_source_key =
                generate_session_secret_key(session, "Failed to generate shared source key");

            // Create operations for all threads using the same source key
            (0..DEFAULT_THREAD_COUNT)
                .map(|_| SharedHkdfDeriveOp::new_with_shared_key(shared_source_key.clone()))
                .collect()
        },
    );
}

#[cfg(feature = "mock")]
#[test]
fn multithread_resiliency_shared_key_shared_session_mixed_operations() {
    run_shared_session_test_with_setup(
        Duration::from_secs(DEFAULT_TEST_DURATION_SECS),
        "Shared Key Mixed Operations",
        |session| {
            // Pre-create the shared keys that all threads will use
            let shared_aes_key =
                generate_session_aes_key(session, "Failed to generate shared AES key");
            let shared_aes_xts_key1 =
                generate_session_aes_xts_key(session, "Failed to generate shared AES XTS key1");
            let shared_aes_xts_key2 =
                generate_session_aes_xts_key(session, "Failed to generate shared AES XTS key2");
            let shared_source_key =
                generate_session_secret_key(session, "Failed to generate shared source key");

            // Define the operations that will run in parallel, each using the same keys
            vec![
                SharedKeyOperation::AesEncryptDecrypt(
                    SharedAesEncryptDecryptOp::new_with_shared_key(shared_aes_key.clone()),
                ),
                SharedKeyOperation::AesXts(SharedAesXtsOp::new_with_shared_keys(
                    shared_aes_xts_key1.clone(),
                    shared_aes_xts_key2.clone(),
                )),
                SharedKeyOperation::HkdfDerive(SharedHkdfDeriveOp::new_with_shared_key(
                    shared_source_key.clone(),
                )),
                SharedKeyOperation::AesEncryptDecrypt(
                    SharedAesEncryptDecryptOp::new_with_shared_key(shared_aes_key.clone()),
                ),
            ]
        },
    );
}
