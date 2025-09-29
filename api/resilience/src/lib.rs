// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Manticore Resilient API
//!
//! This crate provides the Manticore API for Rust.
//!
//! Similar to the existing `mcr_api` crate, this crate also
//! offers automatic Migration detection and recovery.
//!

mod memory_manager;
mod resilient_device;

// Redefine mcr_api primitives at this level
pub use mcr_api::AesGcmResult;
pub use mcr_api::AesKeySize;
pub use mcr_api::AesMode;
pub use mcr_api::AesResult;
pub use mcr_api::AesXtsResult;
pub use mcr_api::DeviceKind;
pub use mcr_api::DigestKind;
pub use mcr_api::EccCurve;
pub use mcr_api::HkdfDeriveParameters;
pub use mcr_api::HsmApiRevision;
pub use mcr_api::HsmApiRevisionRange;
pub use mcr_api::HsmAppCredentials;
pub use mcr_api::HsmDevInfo;
pub use mcr_api::HsmDeviceInfo;
pub use mcr_api::HsmError;
pub use mcr_api::HsmResult;
pub use mcr_api::KbkdfDeriveParameters;
pub use mcr_api::KeyAvailability;
pub use mcr_api::KeyClass;
pub use mcr_api::KeyProperties;
pub use mcr_api::KeyType;
pub use mcr_api::KeyUsage;
pub use mcr_api::ManticoreCertificate;
pub use mcr_api::RsaCryptoPadding;
pub use mcr_api::RsaSignaturePadding;
pub use mcr_api::RsaUnwrapParams;
pub use mcr_api::DEFAULT_VAULT_ID;

use crate::resilient_device::*;

/// Size of the report data.
const REPORT_DATA_SIZE: usize = 128;

// Implement HsmDevice using ResilientDevice
/// HSM Device
#[derive(Debug)]
pub struct HsmDevice {
    inner: ResilientDevice,
}

impl HsmDevice {
    /// Returns the HSM device list
    ///
    /// # Returns
    /// * `Vec<HsmDevInfo>` - HSM device list
    pub fn get_devices() -> Vec<HsmDevInfo> {
        mcr_api::HsmDevice::get_devices()
    }

    /// Open HSM device
    ///
    /// # Arguments
    /// * `path` - Device path
    ///
    /// # Returns
    /// * `HsmResult<Self>` - HSM Device Instance
    ///
    /// # Errors
    /// * DDI errors if device cannot be opened
    pub fn open(path: &str) -> HsmResult<Self> {
        let resilient_device = ResilientDevice::open_device(path)?;
        Ok(HsmDevice {
            inner: resilient_device,
        })
    }

    /// Get HSM API Revision Range from cache
    ///
    /// # Returns
    /// * `HsmApiRevisionRange` - HSM API Revision Range from cache
    pub fn get_api_revision_range(&self) -> HsmApiRevisionRange {
        self.inner.get_api_revision_range()
    }

    /// Get DDI device info from cache
    ///
    /// # Returns
    /// * `HsmDeviceInfo` - HSM API device info from cache
    pub fn get_device_info(&self) -> HsmDeviceInfo {
        self.inner.get_device_info()
    }

    /// Establish Credentials
    ///
    /// # Arguments
    /// * `api_rev` - API Revision for the session
    /// * `credentials` - Application Credentials
    ///
    /// # Returns
    /// * `HsmResult<()>` - Success or DDI error
    ///
    /// # Errors
    /// * DDI errors if credential establishment fails
    pub fn establish_credential(
        &self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
    ) -> HsmResult<()> {
        self.inner.establish_credential(api_rev, credentials)
    }

    /// Open Session
    ///
    /// # Arguments
    /// * `api_rev` - API Revision for the session
    /// * `credentials` - Application Credentials
    ///
    /// # Returns
    /// * `HsmResult<HsmSession>` - Application Session
    ///
    /// # Errors
    /// * DDI errors if session cannot be opened
    pub fn open_session(
        &self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
    ) -> HsmResult<HsmSession> {
        let resilient_session = self.inner.open_session(api_rev, credentials)?;
        Ok(HsmSession {
            inner: resilient_session,
        })
    }
}

// Implement HsmSession using ResilientSession
/// HSM Session Structure
#[derive(Debug)]
pub struct HsmSession {
    inner: ResilientSession,
}

/// HSM Key Handle Structure
#[derive(Debug, Clone)]
pub struct HsmKeyHandle {
    inner: ResilientKey,
}

impl HsmKeyHandle {
    /// Get Key Type
    ///
    /// # Returns
    /// * `KeyType` - The type of the key
    pub fn kind(&self) -> KeyType {
        let fn_get_kind = |key: &mcr_api::HsmKeyHandle| key.kind();
        self.inner.get_key_property(&fn_get_kind)
    }
}

// Macro for operations that take a session and return a result
macro_rules! session_op {
    ($(#[$meta:meta])* $fn_name:ident, $ret_ty:ty, $($arg_name:ident: $arg_ty:ty),*) => {
        $(#[$meta])*
        pub fn $fn_name(&self, $($arg_name: $arg_ty),*) -> HsmResult<$ret_ty> {
            let fn_op = |session: &mcr_api::HsmSession| session.$fn_name($($arg_name),*);
            self.inner.session_op(&fn_op)
        }
    };
}

// Macro for operations that take a session and key, return a result
macro_rules! key_op {
    ($(#[$meta:meta])* $fn_name:ident, $ret_ty:ty, $($arg_name:ident: $arg_ty:ty),*) => {
        $(#[$meta])*
        pub fn $fn_name(&self, key: &HsmKeyHandle, $($arg_name: $arg_ty),*) -> HsmResult<$ret_ty> {
            let fn_op = |session: &mcr_api::HsmSession, key: &mcr_api::HsmKeyHandle| {
                session.$fn_name(key, $($arg_name),*)
            };
            self.inner.key_op(&key.inner, &fn_op)
        }
    };
}

// Macro for key operations with arguments that need cloning to capture (such as Vec<u8>)
// Arguments need to be captured and used multiple times, as API may need to be retried multiple times
macro_rules! key_op_clone {
    ($(#[$meta:meta])* $fn_name:ident, $ret_ty:ty, $($arg_name:ident: $arg_ty:ty),*) => {
        $(#[$meta])*
        pub fn $fn_name(&self, key: &HsmKeyHandle, $($arg_name: $arg_ty),*) -> HsmResult<$ret_ty> {
            let fn_op = |session: &mcr_api::HsmSession, key: &mcr_api::HsmKeyHandle| {
                session.$fn_name(key, $($arg_name.clone()),*)
            };
            self.inner.key_op(&key.inner, &fn_op)
        }
    };
}

// Macro for operations that create a new key
macro_rules! create_key_op {
    ($(#[$meta:meta])* $fn_name:ident, $($arg_name:ident: $arg_ty:ty),*) => {
        $(#[$meta])*
        pub fn $fn_name(&self, $($arg_name: $arg_ty),*) -> HsmResult<HsmKeyHandle> {
            let fn_op = |session: &mcr_api::HsmSession| session.$fn_name($($arg_name),*);
            let key_id = self.inner.create_key_op(&fn_op)?;
            Ok(HsmKeyHandle { inner: key_id })
        }
    };
}

// Macro for operations that create a new key and need cloning to capture (such as Vec<u8>)
#[cfg(feature = "testhooks")]
macro_rules! create_key_op_clone {
    ($(#[$meta:meta])* $fn_name:ident, $($arg_name:ident: $arg_ty:ty),*) => {
        $(#[$meta])*
        pub fn $fn_name(&self, $($arg_name: $arg_ty),*) -> HsmResult<HsmKeyHandle> {
            let fn_op = |session: &mcr_api::HsmSession| session.$fn_name($($arg_name.clone()),*);
            let key_id = self.inner.create_key_op(&fn_op)?;
            Ok(HsmKeyHandle { inner: key_id })
        }
    };
}

// Macro for operations that create a new key using an existing key
macro_rules! create_key_key_op {
    ($(#[$meta:meta])* $fn_name:ident, $($arg_name:ident: $arg_ty:ty),*) => {
        $(#[$meta])*
        pub fn $fn_name(&self, key: &HsmKeyHandle, $($arg_name: $arg_ty),*) -> HsmResult<HsmKeyHandle> {
            let fn_op = |session: &mcr_api::HsmSession, key: &mcr_api::HsmKeyHandle| {
                session.$fn_name(key, $($arg_name.clone()),*)
            };
            let key_id = self.inner.create_key_key_op(&key.inner, &fn_op)?;
            Ok(HsmKeyHandle { inner: key_id })
        }
    };
}

impl HsmSession {
    /// Close Session
    ///
    /// # Returns
    /// * `HsmResult<()>` - Success or error
    ///
    /// # Errors
    /// * `HsmError::SessionClosed` - Session is closed
    /// * DDI errors
    pub fn close_session(&mut self) -> HsmResult<()> {
        self.inner.close_session()
    }

    //
    // Session operations
    //

    // TODO: resilient_mcr_api does not support operations that can impact experiences in other sessions.
    // change_pin (when other processes will not be aware pin changing and won't be able to restore session) should be removed.
    // TASK 34413237
    // We will leave for now, for better mcr_api test compatibility.
    session_op!(
        /// Change User PIN
        ///
        /// # Arguments
        /// * `new_pin` - New User PIN
        ///
        /// # Returns
        /// * `HsmResult<()>` - Success or error
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * DDI errors
        change_pin, (), new_pin: [u8; 16]
    );

    session_op!(
        /// Get Manticore certificate from the HSM device
        ///
        /// # Returns
        /// * `ManticoreCertificate` - Device certificate information
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * DDI errors
        get_certificate, ManticoreCertificate,
    );

    //
    // Create key operations
    //

    // TODO: resilient_mcr_api does not support operations that can impact keys in other sessions.
    // open_key (which exposes named key functionality) should be removed. TASK 34413237
    // We will leave for now, for better mcr_api test compatibility.
    create_key_op!(
        /// Open Key by Name
        /// Only app  keys are allowed to be opened by name.
        /// The name must be 2 bytes in length and cannot be 0.
        /// It must also be unique for the partition.
        ///
        /// # Arguments
        /// * `key_name` - Key Name
        ///
        /// # Returns
        /// * `HsmKeyHandle` - Key Handle
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * DDI errors
        open_key, key_name: u16
    );

    create_key_op!(
        /// Generate a new ECC key pair
        ///
        /// # Arguments
        /// * `curve` - The elliptic curve to use for key generation
        /// * `key_name` - Optional name to assign to the key
        /// * `key_properties` - Properties and usage permissions for the key
        ///
        /// # Returns
        /// * `HsmKeyHandle` - Handle to the newly generated key
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * DDI errors
        ecc_generate, curve: EccCurve, key_name: Option<u16>, key_properties: KeyProperties
    );

    create_key_op!(
        /// Get Unwrapping Key
        ///
        /// # Returns
        /// * `HsmKeyHandle` - Handle to the unwrapping key
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * DDI errors
        get_unwrapping_key,
    );

    create_key_op!(
        /// Generate an AES Key
        ///
        /// # Arguments
        /// * `key_size` - Key size
        /// * `key_name` - Optional name to assign to the key
        /// * `key_properties` - Properties and usage permissions for the key
        ///
        /// # Returns
        /// * `HsmKeyHandle` - Handle to the newly generated key
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * DDI errors
        aes_generate, key_size: AesKeySize, key_name: Option<u16>, key_properties: KeyProperties
    );

    //
    // Create key operations with Vec<u8> parameters (cloning needed)
    //

    #[cfg(feature = "testhooks")]
    create_key_op_clone!(
        /// Import Key
        ///
        /// # Arguments
        /// * `der` - Key in DER format
        /// * `key_class` - Key type
        /// * `key_name` - Optional name to assign to the key
        /// * `key_properties` - Properties and usage permissions for the key
        ///
        /// # Returns
        /// * `HsmKeyHandle` - Handle to the imported key
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * DDI errors
        import_key, der: Vec<u8>, key_class: KeyClass, key_name: Option<u16>, key_properties: KeyProperties
    );

    //
    // Simple key operations
    //

    key_op!(
        /// Export Public Key
        ///
        /// # Arguments
        /// * `key` - Key Handle
        ///
        /// # Returns
        /// * `Vec<u8>` - Public Key in DER format
        export_public_key, Vec<u8>,
    );

    key_op!(
        /// Attest Key
        ///
        /// # Arguments
        /// * `key` - Key Handle to attest
        /// * `report_data` - 128-byte report data to include in the attestation
        ///
        /// # Returns
        /// * `Vec<u8>` - The attestation report
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * DDI errors
        attest_key, Vec<u8>, report_data: &[u8; REPORT_DATA_SIZE]
    );

    //
    // Key operations with Vec<u8> parameters (cloning needed)
    //

    key_op_clone!(
        /// ECC Sign using Private Key
        ///
        /// # Arguments
        /// * `key` - ECC private key handle for signing
        /// * `digest` - The message digest to sign
        ///
        /// # Returns
        /// * `Vec<u8>` - The digital signature
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for signing
        /// * DDI errors
        ecc_sign, Vec<u8>, digest: Vec<u8>
    );

    key_op_clone!(
        /// Hash-based Message Authentication Code
        ///
        /// # Arguments
        /// * `key` - Own key, must have KeyType `HmacSha`
        /// * `msg` - input data
        ///
        /// # Returns
        /// * `Vec<u8>` - HMAC result
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for HMAC
        /// * DDI errors
        hmac, Vec<u8>, msg: Vec<u8>
    );

    key_op_clone!(
        /// ECC Verify using Public Key
        ///
        /// # Arguments
        /// * `key` - Private Key Handle, it must include a valid public key
        /// * `digest` - The digest used to generate the signature
        /// * `signature` - The signature (in raw format) to be verified
        ///
        /// # Returns
        /// * `()` - If verification succeeds.
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - If the current App Session is closed.
        /// * `HsmError::InvalidParameter` - If the handle does not contain a valid public key, or parameters are invalid.
        /// * `HsmError::InvalidKeyType` - If the Key type is not ECC public.
        /// * `HsmError::EccFromDerError` - If fail to convert key handle to ECC Key.
        /// * `HsmError::DerAndKeyTypeMismatch` - If the handle's key and type mismatch.
        /// * `HsmError::EccVerifyFailed` - If the verification fails.
        ecc_verify, (), digest: Vec<u8>, signature: Vec<u8>
    );

    key_op_clone!(
        /// RSA Encrypt using Public Key
        ///
        /// # Arguments
        /// * `key` - Private Key Handle, it must include a valid public key
        /// * `data` - Data to encrypt
        /// * `padding` - Padding type
        /// * `hash_algorithm` - Hash algorithm
        /// * `label` - Optional label for padding
        ///
        /// # Returns
        /// * `Vec<u8>` - Encrypted data
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - If the current App Session is closed.
        /// * `HsmError::InvalidParameter` - If the handle does not contain a valid public key, or data length exceeds limit.
        /// * `HsmError::InvalidKeyType` - If the Key type is not RSA public.
        /// * `HsmError::RsaFromDerError` - If fail to convert key handle to RSA Key.
        /// * `HsmError::DerAndKeyTypeMismatch` - If the handle's key and type mismatch.
        /// * `HsmError::RsaEncryptFailed` - If the encryption fails.
        rsa_encrypt, Vec<u8>, data: Vec<u8>, padding: RsaCryptoPadding, hash_algorithm: Option<DigestKind>, label: Option<&[u8]>
    );

    key_op_clone!(
        /// RSA Decrypt using Private Key
        ///
        /// # Arguments
        /// * `key` - Private Key Handle
        /// * `data` - Data to decrypt
        /// * `padding` - Padding type
        /// * `hash_algorithm` - Hash algorithm
        /// * `label` - Optional label for padding
        ///
        /// # Returns
        /// * `Vec<u8>` - Decrypted data
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for decryption
        /// * DDI errors
        rsa_decrypt, Vec<u8>, data: Vec<u8>, padding: RsaCryptoPadding, hash_algorithm: Option<DigestKind>, label: Option<&[u8]>
    );

    key_op_clone!(
        /// RSA Sign using Private Key
        ///
        /// # Arguments
        /// * `key` - Private Key Handle
        /// * `digest` - Digest to sign
        /// * `padding` - Padding type
        /// * `hash_algorithm` - Hash algorithm
        /// * `salt_len` - Salt length
        ///
        /// # Returns
        /// * `Vec<u8>` - Signature
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for signing
        /// * DDI errors
        rsa_sign, Vec<u8>, digest: Vec<u8>, padding: RsaSignaturePadding, hash_algorithm: Option<DigestKind>, salt_len: Option<u16>
    );

    key_op_clone!(
        /// RSA Verify using Public Key
        ///
        /// # Arguments
        /// * `key` - Private Key Handle, it must include a valid public key
        /// * `digest` - The digest used to generate the signature
        /// * `signature` - Signature to be verified
        /// * `padding` - Rsa Signature Padding
        /// * `hash_algorithm` - Hash Algorithm
        /// * `salt_len` - Optional Salt Length
        ///
        /// # Returns
        /// * `()` - If signature is valid
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - If the current App Session is closed.
        /// * `HsmError::InvalidParameter` - If the handle does not contain a valid public key, or parameters are invalid.
        /// * `HsmError::InvalidKeyType` - If the Key type is not RSA public.
        /// * `HsmError::RsaFromDerError` - If fail to convert key handle to RSA Key.
        /// * `HsmError::DerAndKeyTypeMismatch` - If the handle's key and type mismatch.
        /// * `HsmError::RsaVerifyFailed` - If the verification fails.
        rsa_verify, (), digest: Vec<u8>, signature: Vec<u8>, padding: RsaSignaturePadding, hash_algorithm: Option<DigestKind>, salt_len: Option<u16>
    );

    key_op_clone!(
        /// AES Encrypt/Decrypt
        ///
        /// # Arguments
        /// * `key` - AES key handle
        /// * `mode` - Encrypt or decrypt mode
        /// * `data` - Data to be processed
        /// * `iv` - Initialization vector
        ///
        /// # Returns
        /// * `AesResult` - Result containing processed data
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for AES operations
        /// * DDI errors
        aes_encrypt_decrypt, AesResult, mode: AesMode, data: Vec<u8>, iv: [u8; 16usize]
    );

    key_op_clone!(
        /// AES GCM Encrypt/Decrypt
        ///
        /// # Arguments
        /// * `key` - AES key handle
        /// * `mode` - Encrypt or decrypt mode
        /// * `data` - Data to be encrypted (cleartext) or decrypted
        /// * `iv` - Initialization vector
        /// * `aad` - Optional additional authentication data
        /// * `tag` - Optional for encryption, required for decryption
        ///
        /// # Returns
        /// * `AesGcmResult` - Result containing processed data and authentication tag
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for AES GCM operations
        /// * DDI errors
        aes_gcm_encrypt_decrypt, AesGcmResult, mode: AesMode, data: Vec<u8>, iv: [u8; 12usize], aad: Option<Vec<u8>>, tag: Option<[u8; 16usize]>
    );

    // Create key operations that use an existing key

    create_key_key_op!(
        /// ECDH Key Exchange
        ///
        /// # Arguments
        /// * `key` - Own private key, must be Ecc Private type, must have KeyUsage `Derive`
        /// * `peer_pub_key` - Other party's public key, must be Ecc Public type and same curve name as private key
        /// * `target_key_name` - Target key name
        /// * `target_key_type` - Target key type, must be `Secret` type with matching bit size
        /// * `target_key_properties` - Target key properties, must be `Derive` usage
        ///
        /// # Returns
        /// * `HsmKeyHandle` - New key handle with KeyType `Secret` and KeyUsage `Derive`
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for ECDH
        /// * DDI errors
        ecdh_key_exchange, peer_pub_key: &[u8], target_key_name: Option<u16>, target_key_type: KeyType, target_key_properties: KeyProperties
    );

    create_key_key_op!(
        /// HMAC Key Derivation Function
        ///
        /// # Arguments
        /// * `key` - Own key, must be Secret type, must have KeyUsage `Derive`
        /// * `params` - Parameters for HKDF, including `hash_algorithm`, `salt`, `info` values
        /// * `target_key_name` - Target key name
        /// * `target_key_type` - Target key type, must be Secret or Aes
        /// * `target_key_properties` - Target key properties
        ///
        /// # Returns
        /// * `HsmKeyHandle` - New derived key handle
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for derivation
        /// * DDI errors
        hkdf_derive, params: HkdfDeriveParameters<'_>, target_key_name: Option<u16>, target_key_type: KeyType, target_key_properties: KeyProperties
    );

    create_key_key_op!(
        /// Key-Based Key Derivation Function (Counter-mode, HMAC)
        ///
        /// # Arguments
        /// * `key` - Own key, must have KeyUsage `Derive`
        /// * `params` - Parameters for KBKDF, including `hash_algorithm`, `salt`, `info` values
        /// * `target_key_name` - Target key name
        /// * `target_key_type` - Target key type, must be Secret or Aes
        /// * `target_key_properties` - Target key properties
        ///
        /// # Returns
        /// * `HsmKeyHandle` - New derived key handle
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for derivation
        /// * DDI errors
        kbkdf_counter_hmac_derive, params: KbkdfDeriveParameters<'_>, target_key_name: Option<u16>, target_key_type: KeyType, target_key_properties: KeyProperties
    );

    create_key_key_op!(
        /// Perform RSA Unwrap on the wrapped blob using the import key
        ///
        /// # Arguments
        /// * `key` - Import Key Handle
        /// * `wrapped_blob` - Wrapped Blob
        /// * `wrapped_blob_params` - Wrapped blob parameters including key type, padding, and hash algorithm
        /// * `target_key_name` - Target Key Name
        /// * `target_key_properties` - Target key properties
        ///
        /// # Returns
        /// * `HsmKeyHandle` - Unwrapped Key Handle
        ///
        /// # Errors
        /// * `HsmError::SessionClosed` - Session is closed
        /// * `HsmError::InvalidKey` - Key is not suitable for unwrapping
        /// * DDI errors
        rsa_unwrap, wrapped_blob: Vec<u8>, wrapped_blob_params: RsaUnwrapParams, target_key_name: Option<u16>, target_key_properties: KeyProperties
    );

    // TODO: resilient_mcr_api does not support operations that can impact keys in
    // other sessions. clear_device should be removed. TASK 34413237
    // We will leave for now, for better mcr_api test compatibility.

    /// Clear Device
    ///
    /// # Returns
    /// * `HsmResult<()>` - Success or error
    ///
    /// # Errors
    /// * `HsmError::SessionClosed` - Session is closed
    /// * DDI errors
    pub fn clear_device(&mut self) -> HsmResult<()> {
        self.inner.clear_device()
    }

    /// Delete Key
    ///
    /// # Arguments
    /// * `key` - Key handle to delete
    ///
    /// # Returns
    /// * `HsmResult<()>` - Success or error
    ///
    /// # Errors
    /// * `HsmError::SessionClosed` - Session is closed
    /// * DDI errors
    pub fn delete_key(&self, key: &HsmKeyHandle) -> HsmResult<()> {
        self.inner.delete_key_op(&key.inner)
    }

    /// AES XTS Encrypt/Decrypt
    ///
    /// # Arguments
    /// * `mode` - Encrypt or decrypt mode
    /// * `key_1` - First AES key handle
    /// * `key_2` - Second AES key handle
    /// * `dul` - Data unit length
    /// * `tweak` - 16-byte tweak value
    /// * `data` - Data to be processed
    ///
    /// # Returns
    /// * `HsmResult<AesXtsResult>` - Result containing processed data
    ///
    /// # Errors
    /// * `HsmError::SessionClosed` - Session is closed
    /// * `HsmError::InvalidKey` - Key(s) are not suitable for AES XTS operations
    /// * DDI errors
    pub fn aes_xts_encrypt_decrypt(
        &self,
        mode: AesMode,
        key_1: &HsmKeyHandle,
        key_2: &HsmKeyHandle,
        dul: usize,
        tweak: [u8; 16usize],
        data: Vec<u8>,
    ) -> HsmResult<AesXtsResult> {
        let fn_aes_xts_encrypt_decrypt =
            |session: &mcr_api::HsmSession,
             key_1: &mcr_api::HsmKeyHandle,
             key_2: &mcr_api::HsmKeyHandle| {
                session.aes_xts_encrypt_decrypt(mode, key_1, key_2, dul, tweak, data.clone())
            };
        self.inner
            .two_key_op(&key_1.inner, &key_2.inner, &fn_aes_xts_encrypt_decrypt)
    }
}
