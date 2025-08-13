// Copyright (C) Microsoft Corporation. All rights reserved.

/// This file implements several fuzzing input objects, or "payloads". The
/// NCrypt API that's used to invoke the AZIHSM KSP has many functions that
/// share the same input parameters. The objects defined in this file serve as a
/// way to standardize the fuzzing of these NCrypt API input parameters.
///
/// Each of these objects are implemented with the `Arbitrary` trait derived.
/// This allows LibFuzzer to easily convert a string of bytes into individual
/// struct fields.

// Windows imports.
//
// See the Rust docs for the Windows Cryptography API here:
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Cryptography/
#[cfg(target_os = "windows")]
use windows::{
    core::*,
    Win32::Security::Cryptography::{
        CERT_KEY_SPEC, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_PKCS1_PADDING_INFO,
        BCRYPT_PSS_PADDING_INFO,
    },
    Win32::Security::OBJECT_SECURITY_INFORMATION,
};

// Imports
use arbitrary::Arbitrary;
use rand::RngCore;
use std::hash::{DefaultHasher, Hash, Hasher};
use widestring::U16CString;

// Local imports
use crate::common::{
    azihsmksp_close_key, azihsmksp_create_key, azihsmksp_delete_key, azihsmksp_finalize_key,
    azihsmksp_open_key, rand_get, AZIHSMKSP_BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
    /* TODO - Debug ASAN failure that occurs when using unwrap key
    AZIHSMKSP_BUILTIN_UNWRAP_KEY_NAME,
    */
    AZIHSMKSP_DEVICE_CERT_CHAIN_PROPERTY,
    AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED,
};

// ============================ Payload Objects ============================= //
/// A struct to be used when fuzzing NCrypt API functions that accept a 32-bit
/// bit-flag integer.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptFlags {
    pub raw: u32,
}

#[allow(dead_code)]
impl NCryptFlags {
    /// Converts the object into a Windows API `NCRYPT_FLAGS`.
    pub fn as_ncrypt_flags(&self) -> NCRYPT_FLAGS {
        NCRYPT_FLAGS(self.raw)
    }

    /// Converts the object into a Windows API `OBJECT_SECURITY_INFORMATION`.
    pub fn as_object_security_info(&self) -> OBJECT_SECURITY_INFORMATION {
        OBJECT_SECURITY_INFORMATION(self.raw)
    }
}

impl From<u32> for NCryptFlags {
    fn from(num: u32) -> Self {
        NCryptFlags { raw: num }
    }
}

/// A struct to be used when fuzzing NCrypt API functions that accept a cert key
/// specification.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptCertKeySpec {
    pub raw: u32,
}

#[allow(dead_code)]
impl NCryptCertKeySpec {
    /// Converts the object into a Windows API `CERT_KEY_SPEC`.
    pub fn as_cert_key_spec(&self) -> CERT_KEY_SPEC {
        CERT_KEY_SPEC(self.raw)
    }
}

#[allow(dead_code)]
impl From<u32> for NCryptCertKeySpec {
    fn from(num: u32) -> Self {
        NCryptCertKeySpec { raw: num }
    }
}

/// A struct used when fuzzing NCrypt API functions that accept a Windows string
/// (`PCWSTR`, `PCSTR`, `PWSTR`, `PSTR`).
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct WindowsString {
    pub string: String,
}

#[allow(dead_code)]
impl WindowsString {
    /// Converts the object into a Windows API `HSTRING`, which is an immutable
    /// UTF-16 null-terminated string.
    pub fn as_hstring(&self) -> HSTRING {
        HSTRING::from(&self.string)
    }
    
    /// Converts the string to a UTF-16 encoded vector.
    pub fn to_utf16(&self) -> Vec<u16> {
        // encode as UTF-16, and append a string terminator
        let mut utf16 = self.string.encode_utf16().collect::<Vec<u16>>();
        utf16.push(0);
        utf16
    }

    /// Creates and returns a U16 widestring copy of the inner Rust string.
    pub fn to_widestring(&self) -> std::result::Result<U16CString, String> {
        U16CString::from_vec(self.to_utf16()).map_err(|_|
            String::from("Failed to convert bytes to widestring")
        )
    }
    
    /// Returns a reference to the internal string object.
    pub fn as_str(&self) -> &str {
        &self.string
    }

    pub fn hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.string.hash(&mut hasher);
        hasher.finish()
    }
}

/// Allows `WindowsString` objects to be created from a `&str` slice.
#[allow(dead_code)]
impl From<&str> for WindowsString {
    fn from(text: &str) -> Self {
        WindowsString {
            string: String::from(text),
        }
    }
}

/// A struct used to create randomized buffers with inputs provided by the
/// fuzzer (via this `Arbitrary` struct).
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct BufferPayload {
    /// This value is used to determine the number of bytes present in the
    /// buffer. Because it can be *any* integer value, the chosen value will
    /// likely be very large, and should be trimmed down using a modulus or
    /// similar operation.
    pub buffer_len: usize,

    /// This is a seed value used to fill the buffer with random values.
    pub buffer_seed: u64,
}

#[allow(dead_code)]
impl BufferPayload {
    /// Creates and returns a vector that does not exceed the given capacity.
    pub fn create(&self, capacity: usize) -> Vec<u8> {
        // compute the length of the buffer, based on the randomly-generated
        // `buffer_len` field. Cap it off at the max length
        let buffer_len = self.buffer_len % capacity;

        // use the length to allocate a buffer
        let mut buffer: Vec<u8> = Vec::with_capacity(buffer_len);

        // lastly, create a seeded RNG and use it to fill up the vector
        let mut rng = rand_get(self.buffer_seed);
        rng.fill_bytes(buffer.as_mut_slice());
        buffer
    }
}

// =================== Payload Objects for KSP Operations =================== //
// These structs use the above payload objects as "building blocks" to construct
// complex fuzzing input structs for specific operations with NCrypt API (such
// as opening a key, or opening a provider).

// ---------------------------------- Keys ---------------------------------- //
const NCRYPT_KEY_ALGORITHMS_LEN: usize = 36;

/// A vector of all accepted NCrypt key algorithms. See here for more info:
///
/// https://learn.microsoft.com/en-us/windows/win32/SecCNG/cng-algorithm-identifiers
const NCRYPT_KEY_ALGORITHMS: [&str; NCRYPT_KEY_ALGORITHMS_LEN] = [
    "3DES",
    "3DES_112",
    "AES",
    "AES-CMAC",
    "AES-GMAC",
    "CAPI_KDF",
    "DES",
    "DESX",
    "DH",
    "DSA",
    "ECDH_P256",
    "ECDH_P384",
    "ECDH_P521",
    "ECDSA_P256",
    "ECDSA_P384",
    "ECDSA_P521",
    "MD2",
    "MD4",
    "MD5",
    "RC2",
    "RC4",
    "RNG",
    "DUALECRNG",
    "FIPS186DSARNG",
    "RSA",
    "RSA_SIGN",
    "SHA1",
    "SHA256",
    "SHA384",
    "SHA512",
    "SP800_108_CTR_HMAC",
    "SP800_56A_CONCAT",
    "PBKDF2",
    "ECDSA",
    "ECDH",
    "XTS-AES",
];

/// A struct used when fuzzing the `NCryptOpenKey()` function.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptOpenKeyPayload {
    /// The name of the key to open.
    pub key_name: WindowsString,

    /// The key specification.
    pub key_spec: NCryptCertKeySpec,

    /// The bitflags to pass into `NCryptOpenKey()`.
    pub flags: NCryptFlags,

    /* TODO - Debug ASAN failure that occurs when using unwrap key
    /// A flag that controls whether or not the built-in unwrapping key is used
    /// instead of the randomly-generated key name.
    pub use_builtin_unwrap_key: bool,
    */
}

#[allow(dead_code)]
impl NCryptOpenKeyPayload {
    /// Returns one of the following:
    ///
    /// 1. A `WindowsString` containing the bytes in `self.key_name` (which are,
    ///    most likely, random bytes).
    /// 2. A `WindowsString` containing the AZIHSM KSP built-in unwrap key.
    ///
    /// Which of the two is returned is decided by
    /// `self.use_builtin_unwrap_key`. If the field is true, #2 will be
    /// returned. If it's false, #1 will be returned.
    ///
    /// This approach lets us fuzz `NCryptOpenKey()` with both random key names
    /// and the built-in unwrapping key.
    pub fn get_name(&self) -> WindowsString {
        /* TODO - Debug ASAN failure that occurs when using unwrap key
        if self.use_builtin_unwrap_key
        { return WindowsString::from(AZIHSMKSP_BUILTIN_UNWRAP_KEY_NAME); }
        */
        WindowsString::from(self.key_name.as_str())
    }
}

/// A struct used when fuzzing the `NCryptCreatePersistedKey()` function.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptCreatePersistedKeyPayload {
    /// The name of the alogorithm the key will use.
    pub algorithm: WindowsString,

    /// A flag that decides whether or not a valid algorithm name is used. If
    /// true, an algorithm name supported by Windows CNG is used when creating
    /// the key. If false, whatever random bytes are assigned to the `algorithm`
    /// field in this struct are used instead.
    pub use_valid_algorithm: bool,

    /// The name of the key to open.
    pub key_name: WindowsString,

    /// A flag that decides whether or not a null string should be passed into
    /// `NCryptCreatePersistedKey()`, for the key name string.
    pub use_null_key_name: bool,
    
    /// A flag that decides whether or not a null string should be passed into
    /// `NCryptCreatePersistedKey()`, for the algorithm ID string.
    pub use_null_algorithm_name: bool,

    /// The key specification.
    pub key_spec: NCryptCertKeySpec,

    /// The bitflags to pass into `NCryptOpenKey()`.
    pub flags: NCryptFlags,
}

#[allow(dead_code)]
impl NCryptCreatePersistedKeyPayload {
    /// Generates and returns a WindowsString with a valid (i.e. not random
    /// bytes) key algorithm from the Windows CNG list of valid algorithms.
    ///
    /// https://learn.microsoft.com/en-us/windows/win32/SecCNG/cng-algorithm-identifiers
    ///
    /// Fields within the struct are used to deterministically select one of the
    /// valid algorithm names.
    pub fn get_valid_algorithm(&self) -> WindowsString {
        // hash the current algorithm string (which likely contains a bunch of
        // junk) and use it to select an index into our list of valid algorithms
        let hash = self.algorithm.hash();
        let index = (hash as usize) % NCRYPT_KEY_ALGORITHMS_LEN;
        WindowsString::from(NCRYPT_KEY_ALGORITHMS[index])
    }

    /// Returns one of the following:
    ///
    /// 1. A `WindowsString` containing the bytes in `self.algorithm` (which
    ///    are, most likely, random bytes).
    /// 2. A `WindowsString` containing one of the valid algorithm names as
    ///    defined in `NCRYPT_KEY_ALGORITHMS`.
    ///
    /// Which of the two is returned is decided by `self.use_valid_algorithm`.
    /// If the field is true, #2 will be returned. If it's false, #1 will be
    /// returned.
    ///
    /// This approach lets us fuzz `NCryptCreatePersistedKey()` with both valid
    /// and invalid algorithm names.
    pub fn get_algorithm(&self) -> WindowsString {
        if self.use_valid_algorithm {
            return self.get_valid_algorithm();
        }
        WindowsString::from(self.algorithm.as_str())
    }
}

/// A struct used when fuzzing the `NCryptDeleteKey()` function.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptDeleteKeyPayload {
    /// The bitflags to pass into `NCryptDeleteKey()`.
    pub flags: NCryptFlags,
}

/// A struct used when fuzzing the `NCryptFinalizeKey()` function.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptFinalizeKeyPayload {
    /// The bitflags to pass into `NCryptFinalizeKey()`.
    pub flags: NCryptFlags,
}

const NCRYPT_KEY_BLOB_TYPES_LEN: usize = 23;

/// A vector containing all valid NCrypt Blob Type names. See here for the full
/// list:
///
/// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptexportkey
const NCRYPT_KEY_BLOB_TYPES: [&str; NCRYPT_KEY_BLOB_TYPES_LEN] = [
    "BCRYPT_DH_PRIVATE_BLOB",
    "BCRYPT_DH_PUBLIC_BLOB",
    "BCRYPT_DSA_PRIVATE_BLOB",
    "BCRYPT_DSA_PUBLIC_BLOB",
    "BCRYPT_ECCPRIVATE_BLOB",
    "BCRYPT_ECCPUBLIC_BLOB",
    "BCRYPT_PUBLIC_KEY_BLOB",
    "BCRYPT_PRIVATE_KEY_BLOB",
    "BCRYPT_RSAFULLPRIVATE_BLOB",
    "BCRYPT_RSAPRIVATE_BLOB",
    "BCRYPT_RSAPUBLIC_BLOB",
    "LEGACY_DH_PRIVATE_BLOB",
    "LEGACY_DH_PUBLIC_BLOB",
    "LEGACY_DSA_PRIVATE_BLOB",
    "LEGACY_DSA_PUBLIC_BLOB",
    "LEGACY_RSAPRIVATE_BLOB",
    "LEGACY_RSAPUBLIC_BLOB",
    "NCRYPT_CIPHER_KEY_BLOB",
    "NCRYPT_OPAQUETRANSPORT_BLOB",
    "NCRYPT_PKCS7_ENVELOPE_BLOB",
    "NCRYPT_PKCS8_PRIVATE_KEY_BLOB",
    "NCRYPT_PROTECTED_KEY_BLOB",
    // ------------ AZIHSM KSP Blob Types ------------ //
    AZIHSMKSP_BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
];

/// A struct the fuzzer can use to randomize the blob type string used in calls
/// to `NCryptImportKey()` and `NCryptExportKey()`.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptBlobTypePayload {
    /// The blob type string.
    pub name: WindowsString,

    /// A flag that decides whether or not a valid property name is used with
    /// this struct.  If true, one of the valid property names (as defined in
    /// `NCRYPT_KEY_BLOB_TYPES`) are deterministically selected.  Otherwise,
    /// whatever random bytes are present in this struct's `name` field is
    /// used instead.
    pub use_valid_name: bool,
}

#[allow(dead_code)]
impl NCryptBlobTypePayload {
    /// Generates and returns a WindowsString with a valid (i.e. not random
    /// bytes) blob type string from the Windows CNG list of valid blob types
    /// identifiers.
    ///
    /// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptexportkey
    ///
    /// Fields within the struct are used to deterministically select one of the
    /// valid blob types.
    pub fn get_valid_name(&self) -> WindowsString {
        // hash the current algorithm string (which likely contains a bunch of
        // junk) and use it to select an index into our list of valid properties
        let hash = self.name.hash();
        let index = (hash as usize) % NCRYPT_KEY_BLOB_TYPES_LEN;
        WindowsString::from(NCRYPT_KEY_BLOB_TYPES[index])
    }

    /// Returns one of the following:
    ///
    /// 1. A `WindowsString` containing the bytes in `self.name` (which are,
    ///    most likely, random bytes).
    /// 2. A `WindowsString` containing one of the valid property
    ///    identifiers/names, as defined in `NCRYPT_KEY_BLOB_TYPES`.
    ///
    /// Which of the two is returned is decided by `self.use_valid_name`. If
    /// the field is true, #2 will be returned. If it's false, #1 will be
    /// returned.
    ///
    /// This approach lets us fuzz `NCryptGetProperty()` with both valid and
    /// invalid property names.
    pub fn get_name(&self) -> WindowsString {
        if self.use_valid_name {
            return self.get_valid_name();
        }
        WindowsString::from(self.name.as_str())
    }
}

/// A struct used when fuzzing the `NCryptImportKey()` function.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptImportKeyPayload {
    /// A flag that decides whether or not a handle to a separate cryptographic
    /// key is passed into `NCryptImportKey`. This key, if provided as a
    /// parameter, is assumed to be the key that was used to encrypt the key
    /// BLOB when it was previously exported.
    pub use_decryption_key: bool,

    /// Parameters used to create and interact with the decryption key used
    /// during import.
    pub decryption_key: NCryptKeyPayload,

    /// An object used to generate a blob type string.
    pub blob_type: NCryptBlobTypePayload,

    /// An object used to define a buffer, which contains the key BLOB to be
    /// imported.
    pub blob_data: BufferPayload,

    /// The bitflags to pass into `NCryptImportKey()`.
    pub flags: NCryptFlags,
}

/// A struct used when fuzzing the `NCryptExportKey()` function.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptExportKeyPayload {
    /// A flag that decides whether or not a handle to a separate cryptographic
    /// key is passed into `NCryptExportKey`. This key, if provided as a
    /// parameter, is used to encrypt the key BLOB as it is exported.
    pub use_encryption_key: bool,

    /// Parameters used to create and interact with the encryption key used
    /// during export.
    pub encryption_key: NCryptKeyPayload,

    /// An object used to generate a blob type string.
    pub blob_type: NCryptBlobTypePayload,

    /// An object used to define a buffer, which is passed into
    /// `NCryptExportKey()` to store the resulting storage data.
    pub blob_data: BufferPayload,

    /// A flag that controls whether or not a buffer is passed into
    /// `NCryptExportKey()`. (It is an optional function parameter; passing a
    /// buffer in, versus *not* passing a buffer in, should get us to trigger
    /// different behavior in the KSP.)
    pub blob_data_is_enabled: bool,

    /// The bitflags to pass into `NCryptImportKey()`.
    pub flags: NCryptFlags,
}

/// A struct that combines several of the above key-related payloads into one.
/// Useful for tests that must create keys in order to test other parts of the
/// KSP functionality, but still want those key interactions to be fuzzed with
/// random inputs.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptKeyPayload {
    /// Parameters to use when creating the key.
    pub create: NCryptCreatePersistedKeyPayload,

    /// Parameters to use when deleting the key.
    pub delete: NCryptDeleteKeyPayload,

    /// Parameters to use when finalizing the key.
    pub finalize: NCryptFinalizeKeyPayload,

    /// Parameters to use when opening a handle to the key.
    pub open: NCryptOpenKeyPayload,
}

#[allow(dead_code)]
impl NCryptKeyPayload {
    pub fn create(&self, azihsmksp: NCRYPT_PROV_HANDLE) -> (Result<()>, NCRYPT_KEY_HANDLE) {
        let mut key = NCRYPT_KEY_HANDLE(0);
        let result = azihsmksp_create_key(azihsmksp, &mut key, &self.create);
        (result, key)
    }

    pub fn delete(
        &self,
        #[cfg(feature = "direct-invoke-dll")] provider: NCRYPT_PROV_HANDLE,
        key: NCRYPT_KEY_HANDLE
    ) -> Result<()> {
        azihsmksp_delete_key(
            #[cfg(feature = "direct-invoke-dll")] provider,
            key,
            &self.delete
        )
    }

    pub fn finalize(
        &self,
        #[cfg(feature = "direct-invoke-dll")] provider: NCRYPT_PROV_HANDLE,
        key: NCRYPT_KEY_HANDLE
    ) -> Result<()> {
        azihsmksp_finalize_key(
            #[cfg(feature = "direct-invoke-dll")] provider,
            key,
            &self.finalize
        )
    }

    pub fn open(&self, azihsmksp: NCRYPT_PROV_HANDLE) -> (Result<()>, NCRYPT_KEY_HANDLE) {
        let mut key = NCRYPT_KEY_HANDLE(0);
        let result = azihsmksp_open_key(azihsmksp, &mut key, &self.open);
        (result, key)
    }

    pub fn close(
        &self,
        #[cfg(feature = "direct-invoke-dll")] provider: NCRYPT_PROV_HANDLE,
        key: NCRYPT_KEY_HANDLE,
    ) -> Result<()> {
        azihsmksp_close_key(
            #[cfg(feature = "direct-invoke-dll")] provider,
            key,
        )
    }
}

// ------------------------------- Properties ------------------------------- //
const NCRYPT_PROPERTY_NAMES_LEN: usize = 36;

/// A vector containing all valid NCrypt Property Identifiers (names). See here
/// for the full list:
///
/// https://learn.microsoft.com/en-us/windows/win32/SecCNG/key-storage-property-identifiers
const NCRYPT_PROPERTY_NAMES: [&str; NCRYPT_PROPERTY_NAMES_LEN] = [
    "Algorithm Group",
    "Algorithm Name",
    "SmartCardAssociatedECDHKey",
    "Block Length",
    "SmartCardKeyCertificate",
    "DHParameters",
    "Export Policy",
    "Impl Type",
    "Key Type",
    "Key Usage",
    "Modified",
    "Length",
    "Lengths",
    "Max Name Length",
    "Name",
    "SmartCardPinPrompt",
    "SmartCardPin",
    "Provider Handle",
    "SmartCardReader",
    "SmartCardRootCertStore",
    "SmartCardPinId",
    "SmartCardPinInfo",
    "SmartCardSecurePin",
    "SecurityDescr",
    "SecurityDescrSupport",
    "SmartCardGuid",
    "UI Policy",
    "Unique Name",
    "Use Context",
    "Enabled Use Count",
    "Use Count",
    "SmartCardUserCertStore",
    "Version",
    "HWND Handle",
    // ------------ AZIHSM KSP Properties ------------ //
    AZIHSMKSP_DEVICE_CERT_CHAIN_PROPERTY,
    AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED,
];

/// A struct the fuzzer can use to randomize the name of a property when calling
/// `NCryptGetProperty()` and `NCryptSetProperty()`.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptPropertyNamePayload {
    /// The name of the property to retrieve.
    pub name: WindowsString,

    /// A flag that decides whether or not a valid property name is used with
    /// this struct.  If true, one of the valid property names (as defined in
    /// `NCRYPT_PROPERTY_NAMES`) are deterministically selected.  Otherwise,
    /// whatever random bytes are present in this struct's `name` field is
    /// used instead.
    pub use_valid_name: bool,
}

#[allow(dead_code)]
impl NCryptPropertyNamePayload {
    /// Generates and returns a WindowsString with a valid (i.e. not random
    /// bytes) property name from the Windows CNG list of valid property
    /// identifiers.
    ///
    /// https://learn.microsoft.com/en-us/windows/win32/SecCNG/key-storage-property-identifiers
    ///
    /// Fields within the struct are used to deterministically select one of the
    /// valid propety names.
    pub fn get_valid_name(&self) -> WindowsString {
        // hash the current algorithm string (which likely contains a bunch of
        // junk) and use it to select an index into our list of valid properties
        let hash = self.name.hash();
        let index = (hash as usize) % NCRYPT_PROPERTY_NAMES_LEN;
        WindowsString::from(NCRYPT_PROPERTY_NAMES[index])
    }

    /// Returns one of the following:
    ///
    /// 1. A `WindowsString` containing the bytes in `self.name` (which are,
    ///    most likely, random bytes).
    /// 2. A `WindowsString` containing one of the valid property
    ///    identifiers/names, as defined in `NCRYPT_PROPERTY_NAMES`.
    ///
    /// Which of the two is returned is decided by `self.use_valid_name`. If
    /// the field is true, #2 will be returned. If it's false, #1 will be
    /// returned.
    ///
    /// This approach lets us fuzz `NCryptGetProperty()` with both valid and
    /// invalid property names.
    pub fn get_name(&self) -> WindowsString {
        if self.use_valid_name {
            return self.get_valid_name();
        }
        WindowsString::from(self.name.as_str())
    }
}

/// A struct the fuzzer can use to randomize the inputs passed to
/// `NCryptGetProperty()`.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptGetPropertyPayload {
    /// The object used to determine the name of the property to retrieve.
    pub property: NCryptPropertyNamePayload,

    /// The bitflags to pass into `NCryptGetProperty()`.
    pub flags: NCryptFlags,

    /// Whether or not to pass a valid buffer of bytes into
    /// `NCryptGetProperty()`.
    pub buffer_is_enabled: bool,

    /// An object used to generate a random buffer to pass into
    /// `NCryptGetProperty()`.
    pub buffer: BufferPayload,
}

/// A struct the fuzzer can use to randomize the inputs passed to
/// `NCryptSetProperty()`.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptSetPropertyPayload {
    /// The object used to determine the name of the property to update.
    pub property: NCryptPropertyNamePayload,

    /// The bitflags to pass into `NCryptSetProperty()`.
    pub flags: NCryptFlags,

    /// An object used to generate a random buffer to pass into
    /// `NCryptSetProperty()`.
    pub buffer: BufferPayload,
}

// ---------------------- Padding Info Struct Payloads ---------------------- //
/// An enum used in tandem with `NCryptPaddingInfoPayload` to randomly choose
/// between the available padding info types.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub enum NCryptPaddingInfoType {
    OAEP,
    PKCS1,
    PSS,
}

/// A struct that the fuzzer can use to randomly select one of the three padding
/// types and randomize its fields.
///
/// * `BCRYPT_OAEP_PADDING_INFO`
/// * `BCRYPT_PKCS1_PADDING_INFO`
/// * `BCRYPT_PSS_PADDING_INFO`
///
/// This can be used for encryption, decryption, and any other NCrypt operation
/// that accepts a `pPaddingInfo` parameter. For example:
///
/// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptencrypt
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptPaddingInfoPayload {
    /// The type of padding info struct.
    pub ptype: NCryptPaddingInfoType,
    
    /// The algorithm ID string.
    pub algo: WindowsString,
    
    /// A switch that controls whether or not a valid algorithm string is used,
    /// or if random bytes are used.
    pub use_valid_algo_name: bool,
    
    /// The optional label used with `BCRYPT_OAEP_PADDING_INFO`.
    pub oaep_label: Option<Vec<u8>>,
    
    /// The salt value used with `BCRYPT_PSS_PADDING_INFO`.
    pub pss_salt: u32,
}

#[allow(dead_code)]
impl NCryptPaddingInfoPayload {
    /// Generates and returns a WindowsString with a valid (i.e. not random
    /// bytes) algorithm ID string.
    ///
    /// Fields within the struct are used to deterministically select one of the
    /// valid blob types.
    pub fn get_valid_name(&self) -> WindowsString {
        // hash the current algorithm string (which likely contains a bunch of
        // junk) and use it to select an index into our list of valid properties
        let hash = self.algo.hash();
        let index = (hash as usize) % NCRYPT_KEY_ALGORITHMS_LEN;
        WindowsString::from(NCRYPT_KEY_ALGORITHMS[index])
    }

    /// Returns one of the following:
    ///
    /// 1. A `WindowsString` containing the bytes in `self.name` (which are,
    ///    most likely, random bytes).
    /// 2. A `WindowsString` containing one of the valid property
    ///    identifiers/names, as defined in `NCRYPT_KEY_ALGORITHMS`.
    ///
    /// Which of the two is returned is decided by `self.use_valid_algo_name`.
    /// If the field is true, #2 will be returned. If it's false, #1 will be
    /// returned.
    ///
    /// This approach lets us fuzz using padding info structs containing both
    /// valid and invalid algorithm ID names.
    pub fn get_name(&self) -> WindowsString {
        if self.use_valid_algo_name {
            return self.get_valid_name();
        }
        WindowsString::from(self.algo.as_str())
    }
    
    /// Helper function that attempts to convert the object's internal
    /// `WindowsString` name for the algorithm ID into a widestring.
    pub fn get_name_widestring(&self) -> std::result::Result<U16CString, String> {
        let widename = self.get_name().to_widestring()?;
        Ok(widename)
    }

    ///
    /// Requires that the caller use `WindowsString::to_widestring()` to first
    /// convert the algorithm name into a `U16CString` wide string, then pass a
    /// reference into this function. This is done to ensure the string outlives
    /// this function call and that the `PCWSTR` stored in the resulting padding
    /// info struct is valid.
    pub fn to_oaep(&mut self, algo_id: &U16CString) -> BCRYPT_OAEP_PADDING_INFO {
        let (label_ptr, label_len) = match &mut self.oaep_label {
            None => (std::ptr::null_mut(), 0),
            Some(label_vec) => (label_vec.as_mut_ptr(), label_vec.len() as u32),
        };
        
        BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: PCWSTR::from_raw(algo_id.as_ptr()),
            pbLabel: label_ptr,
            cbLabel: label_len,
        }
    }
    
    /// Creates and returns a `BCRYPT_PKCS1_PADDING_INFO` struct.
    pub fn to_pkcs1(&mut self, algo_id: &U16CString) -> BCRYPT_PKCS1_PADDING_INFO {
        BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: PCWSTR::from_raw(algo_id.as_ptr()),
        }
    }
    
    /// Creates and returns a `BCRYPT_PSS_PADDING_INFO` struct.
    pub fn to_pss(&mut self, algo_id: &U16CString) -> BCRYPT_PSS_PADDING_INFO {
        BCRYPT_PSS_PADDING_INFO {
            pszAlgId: PCWSTR::from_raw(algo_id.as_ptr()),
            cbSalt: self.pss_salt,
        }
    }
    
    /// Returns one of the three possible NCrypt padding info struct in a `Box`.
    pub fn get_struct(&mut self, algo_id: &U16CString) -> Box<dyn std::any::Any> {
        match self.ptype {
            NCryptPaddingInfoType::OAEP => Box::new(self.to_oaep(algo_id)),
            NCryptPaddingInfoType::PKCS1 => Box::new(self.to_pkcs1(algo_id)),
            NCryptPaddingInfoType::PSS => Box::new(self.to_pss(algo_id)),
        }
    }
    
    /// Returns a void C pointer used to point to the provided object (which
    /// should be the same thing that was returned from `get_struct()`).
    pub fn get_struct_ptr(&self, obj: &Box<dyn std::any::Any>) -> *const std::ffi::c_void {
        match self.ptype {
            NCryptPaddingInfoType::OAEP => {
                obj.downcast_ref::<BCRYPT_OAEP_PADDING_INFO>().expect(
                    "Failed to downcast from `Any` back to `BCRYPT_OAEP_PADDING_INFO`"
                ) as *const BCRYPT_OAEP_PADDING_INFO as *const std::ffi::c_void
            },
            NCryptPaddingInfoType::PKCS1 => {
                obj.downcast_ref::<BCRYPT_PKCS1_PADDING_INFO>().expect(
                    "Failed to downcast from `Any` back to `BCRYPT_PKCS1_PADDING_INFO`"
                ) as *const BCRYPT_PKCS1_PADDING_INFO as *const std::ffi::c_void
            },
            NCryptPaddingInfoType::PSS => {
                obj.downcast_ref::<BCRYPT_PSS_PADDING_INFO>().expect(
                    "Failed to downcast from `Any` back to `BCRYPT_PSS_PADDING_INFO`"
                ) as *const BCRYPT_PSS_PADDING_INFO as *const std::ffi::c_void
            },
        }
    }
}

// ----------------------- Encryption and Decryption ------------------------ //
/// A struct the fuzzer can use to randomize the inputs passed to
/// `NCryptEncrypt()` and `NCryptDecrypt()`.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptEncryptDecryptPayload {
    /// The bitflags to pass into `NCryptSetProperty()`.
    pub flags: NCryptFlags,

    /// Information to pass to key-related functions for creating and using a
    /// key for encrypting/decrypting.
    pub key: NCryptKeyPayload,
    
    /// An optional padding info struct, used to fuzz with padding info.
    pub padding_info: Option<NCryptPaddingInfoPayload>,

    /// An object used to generate a random buffer to pass into
    /// `NCryptSetProperty()`.
    pub input_buffer: BufferPayload,

    /// A flag that controls whether or not a valid input buffer is passed into
    /// `NCryptEncrypt()`.
    pub input_buffer_is_enabled: bool,

    /// An object used to generate a random buffer to pass into
    /// `NCryptSetProperty()`.
    pub output_buffer: BufferPayload,

    /// A flag that controls whether or not a valid output buffer is passed into
    /// `NCryptEncrypt()`.
    pub output_buffer_is_enabled: bool,
}

// ------------------------- Signing and Verifying -------------------------- //
/// A struct the fuzzer can use to randomize the inputs passed to
/// `NCryptSignHash()`.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptSignHashPayload {
    /// The bitflags to pass into `NCryptSignHash()`.
    pub flags: NCryptFlags,

    /// An optional padding info struct, used to fuzz with padding info.
    pub padding_info: Option<NCryptPaddingInfoPayload>,

    /// An object used to generate a random buffer to pass into
    /// `NCryptSignHash()`, which represents the hash to the be signed.
    pub hash_buffer: BufferPayload,

    /// An object used to generate a random buffer to pass into
    /// `NCryptSignHash()`, which will be used to store the resulting signature.
    pub sign_buffer: BufferPayload,

    /// A flag that controls whether or not a valid signature buffer is passed
    /// into `NCryptSignHash()`. (The parameter is optional, so this lets us
    /// test both scenarios.)
    pub sign_buffer_is_enabled: bool,
}

/// A struct the fuzzer can use to randomize the inputs passed to
/// `NCryptVerifySignature()`.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptVerifySignaturePayload {
    /// The bitflags to pass into `NCryptVerifySignature()`.
    pub flags: NCryptFlags,

    /// An optional padding info struct, used to fuzz with padding info.
    pub padding_info: Option<NCryptPaddingInfoPayload>,

    /// An object used to generate a random buffer to pass into
    /// `NCryptVerifySignature()`, which represents the hash that was signed.
    pub hash_buffer: BufferPayload,

    /// An object used to generate a random buffer to pass into
    /// `NCryptSignHash()`, which represents the signature that was previously
    /// generated for the hash.
    pub sign_buffer: BufferPayload,
}

// -------------------------------- Secrets --------------------------------- //
/// A struct the fuzzer can use to randmomize the inputs passed to
/// `NCryptSecretAgreement()`.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptSecretAgreementPayload {
    /// The bitflags to pass into `NCryptSecretAgreement()`.
    pub flags: NCryptFlags,

    /// Information to pass to key-related functions for creating and using a
    /// private key for generating secrets.
    pub private_key: NCryptKeyPayload,

    /// Information to pass to key-related functions for creating and using a
    /// public key for generating secrets.
    pub public_key: NCryptKeyPayload,
}

// --------------------------- Attestation/Claims --------------------------- //
/// A struct the fuzzer can use to randmomize the inputs passed to
/// `NCryptCreateClaim()`.
#[derive(Debug, Arbitrary, Clone)]
#[allow(dead_code)]
pub struct NCryptCreateClaimPayload {
    /// The bitflags to pass into `NCryptSecretAgreement()`.
    pub flags: NCryptFlags,

    /// Information to pass to key-related function in order to create and use a
    /// key that represents the subject key in claim creation.
    pub subject_key: NCryptKeyPayload,

    /// Information to pass to key-related function in order to create and use a
    /// key that represents the authority key in claim creation.
    pub authority_key: NCryptKeyPayload,

    /// A 32-bit value that represents the claim type.
    pub claim_type: u32,

    /// An object used to generate a random buffer to pass into
    /// `NCryptCreateClaim()`, which will be used to store the resulting claim
    /// blob.
    pub blob_buffer: BufferPayload,

    /// A flag that controls whether or not a valid buffer is passed into
    /// `NCryptCreateClaim()`. (The parameter is optional, so this lets us test
    /// both scenarios.)
    pub blob_buffer_is_enabled: bool,
}
