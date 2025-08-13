// Copyright (C) Microsoft Corporation. All rights reserved.

use std::mem::size_of;
use std::ptr;
use std::slice;

use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use windows::core::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

#[allow(dead_code)]
pub(crate) const AES_GCM_AAD_SIZE: usize = 32;

#[allow(dead_code)]
pub(crate) const AES_GCM_IV_SIZE: usize = 12;

// #[cfg(test)]
pub(crate) const AZIHSM_KSP_NAME: PCWSTR =
    w!("Microsoft Azure Integrated HSM Key Storage Provider");

#[allow(dead_code)]
pub(crate) const AZIHSM_DEVICE_CERT_CHAIN_PROPERTY: PCWSTR =
    w!("AZIHSM_DEVICE_CERT_CHAIN_PROPERTY");

/// The property names for AZIHSM device Resource capacity.
/// 4 bytes, holds the little-endian representation of Max number of keys this device can hold
#[allow(dead_code)]
pub(crate) const AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY: PCWSTR =
    w!("AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY");

/// 4 bytes, holds the little-endian representation of Max total size of keys this device can hold, in Kilo Bytes
#[allow(dead_code)]
pub(crate) const AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY: PCWSTR =
    w!("AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY");

#[allow(dead_code)]
pub(crate) const AZIHSM_BUILTIN_UNWRAP_KEY: PCWSTR = w!("AZIHSM_BUILTIN_UNWRAP_KEY");

#[allow(dead_code)]
pub(crate) const BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB: PCWSTR = w!("PKCS11RsaAesWrapBlob");

// Redefinition of custom RSA key property for enabling CRT when importing RSA
// keys. See the original definition in `plugins/ksp/src/key/base_key.rs`.
#[allow(dead_code)]
pub(crate) const AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED: PCWSTR = w!("RsaCrtEnabled");

#[allow(dead_code)]
pub(crate) const BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC: u32 = 0x57504152;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub(crate) struct BCRYPT_PKCS11_RSA_AES_WRAP_BLOB {
    pub dw_magic: u32,          // BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC
    pub cb_key: u32,            // Number of bytes in the binary PKCS#11 wrapped key blob
    pub cb_padding_alg_id: u32, // Number of bytes in OAEP Padding algorithm per OAEPParams in PKCS#11 specification
    pub cb_padding_label: u32, // Number of bytes in OAEP Padding label per OAEPParams in PKCS#11 specification
}

#[allow(dead_code)]
pub(crate) const REPORT_DATA_SIZE: u32 = 128;

#[allow(dead_code)]
pub(crate) const AZIHSM_DERIVED_KEY_IMPORT_BLOB: PCWSTR = w!("AzIHsmDerivedKeyImportBlob");

#[allow(dead_code)]
pub(crate) const AES_KEY_BIT_LENGTH_128: usize = 128;

#[allow(dead_code)]
pub(crate) const AES_KEY_BIT_LENGTH_192: usize = 192;

#[allow(dead_code)]
pub(crate) const AES_KEY_BIT_LENGTH_256: usize = 256;

#[allow(dead_code)]
pub(crate) const RSA_2K_DATA_SIZE_LIMIT: usize = 256;
#[allow(dead_code)]
pub(crate) const RSA_3K_DATA_SIZE_LIMIT: usize = 384;
#[allow(dead_code)]
pub(crate) const RSA_4K_DATA_SIZE_LIMIT: usize = 512;

#[allow(dead_code)]
pub(crate) fn copy_pcwstr_to_slice(pcwstr: PCWSTR, slice: &mut [u8], out_size: &mut u32) {
    let output = pcwstr.as_ptr().cast::<u8>();
    let output_size =
        unsafe { ((pcwstr.to_string().unwrap().len() + 1) * size_of::<u16>()) as u32 };
    if slice.is_empty() {
        *out_size = output_size;
        return;
    }

    slice[..output_size as usize]
        .copy_from_slice(unsafe { std::slice::from_raw_parts(output, output_size as usize) });
    *out_size = output_size;
}

#[allow(dead_code)]
pub(crate) fn byte_slice_to_pcwstr(byte_slice: &[u8]) -> Option<PCWSTR> {
    if byte_slice.len() % 2 != 0 {
        return None; // The byte slice length must be even
    }

    let wide_slice: &[u16] =
        unsafe { slice::from_raw_parts(byte_slice.as_ptr() as *const u16, byte_slice.len() / 2) };

    Some(PCWSTR(wide_slice.as_ptr() as *mut u16))
}

/// Represents the type of key to be generated.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub(crate) enum KeyType {
    /// 2048-bit RSA key
    Rsa2k,
    /// 3072-bit RSA key
    Rsa3k,
    /// 4096-bit RSA key
    Rsa4k,
    /// 256-bit ECC key
    Ecc256,
    /// 384-bit ECC key
    Ecc384,
    /// 521-bit ECC key
    Ecc521,
    /// 128-bit AES key
    Aes128,
    /// 192-bit AES key
    Aes192,
    /// 256-bit AES key
    Aes256,
}

/// The encryption algorithm to use to protect the key material.
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub(crate) enum KeyEncryptionAlgorithm {
    /// Uses SHA1 for OAEP padding
    CKM_RSA_AES_KEY_WRAP,
    /// Uses SHA256 for OAEP padding
    RSA_AES_KEY_WRAP_256,
    /// Uses SHA384 for OAEP padding
    RSA_AES_KEY_WRAP_384,
}

#[allow(dead_code)]
pub(crate) static KEY_ENC_ALOG: [KeyEncryptionAlgorithm; 3] = [
    KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
    KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
    KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
];

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub(crate) enum NCryptShaAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha1,
}

impl From<NCryptShaAlgorithm> for PCWSTR {
    fn from(alg: NCryptShaAlgorithm) -> Self {
        match alg {
            NCryptShaAlgorithm::Sha256 => NCRYPT_SHA256_ALGORITHM,
            NCryptShaAlgorithm::Sha384 => NCRYPT_SHA384_ALGORITHM,
            NCryptShaAlgorithm::Sha512 => NCRYPT_SHA512_ALGORITHM,
            NCryptShaAlgorithm::Sha1 => NCRYPT_SHA1_ALGORITHM,
        }
    }
}

#[allow(dead_code)]
pub(crate) static NCRYPT_SHA_ALGORITHMS: [NCryptShaAlgorithm; 3] = [
    NCryptShaAlgorithm::Sha256,
    NCryptShaAlgorithm::Sha384,
    NCryptShaAlgorithm::Sha512,
];

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub(crate) enum NCryptPaddingType {
    Pkcs1,
    Pss,
}

#[allow(dead_code)]
pub(crate) static NCRYPT_PADDING_TYPES: [NCryptPaddingType; 2] =
    [NCryptPaddingType::Pkcs1, NCryptPaddingType::Pss];

/// Generates an RSA key pair using OpenSSL.
///
/// # Arguments
///
/// * `key_type` - The type of RSA key to generate.
///
/// # Returns
///
/// A tuple containing the private key and public key in DER format.
#[allow(dead_code)]
pub(crate) fn generate_rsa_der(key_type: KeyType) -> (Vec<u8>, Vec<u8>) {
    let size = match key_type {
        KeyType::Rsa2k => 2048,
        KeyType::Rsa3k => 3072,
        KeyType::Rsa4k => 4096,
        _ => panic!("Invalid key type"),
    };

    let result = openssl::rsa::Rsa::generate(size);
    assert!(result.is_ok());
    let rsa_private_key = result.unwrap();

    let result = openssl::pkey::PKey::from_rsa(rsa_private_key);
    assert!(result.is_ok());
    let pkey = result.unwrap();

    let result = pkey.private_key_to_pkcs8();
    assert!(result.is_ok());
    let private_key_der = result.unwrap();

    let result = pkey.public_key_to_der();
    assert!(result.is_ok());
    let public_key_der = result.unwrap();

    (private_key_der, public_key_der)
}

/// Generates an AES key.
///
/// # Arguments
///
/// * `key_type` - The type of AES key to generate.
///
/// # Returns
///
/// A vector containing the AES key.
#[allow(dead_code)]
pub(crate) fn generate_aes(key_type: KeyType) -> Vec<u8> {
    let buf_len = match key_type {
        KeyType::Aes128 => 16,
        KeyType::Aes192 => 24,
        KeyType::Aes256 => 32,
        _ => panic!("Invalid key type"),
    };

    let mut buf = [0u8; 32];
    let buf_slice = &mut buf[..buf_len as usize];
    let _ = rand_bytes(buf_slice);
    buf_slice.to_vec()
}

/// Generates an ECC key pair using OpenSSL.
///
/// # Arguments
///
/// * `key_type` - The type of ECC key to generate.
///
/// # Returns
///
/// A tuple containing the private key and public key in DER format.
#[allow(dead_code)]
pub(crate) fn generate_ecc_der(key_type: KeyType) -> (Vec<u8>, Vec<u8>) {
    let curve_name = match key_type {
        KeyType::Ecc256 => Nid::X9_62_PRIME256V1,
        KeyType::Ecc384 => Nid::SECP384R1,
        KeyType::Ecc521 => Nid::SECP521R1,
        _ => panic!("Invalid key type"),
    };

    let result = openssl::ec::EcGroup::from_curve_name(curve_name);
    assert!(result.is_ok());
    let group = result.unwrap();

    let result = openssl::ec::EcKey::generate(&group);
    assert!(result.is_ok());
    let ecc_private_key = result.clone().unwrap();

    let result = openssl::pkey::PKey::from_ec_key(ecc_private_key);
    assert!(result.is_ok());
    let pkey = result.unwrap();

    let result = pkey.private_key_to_pkcs8();
    assert!(result.is_ok());
    let private_key_der = result.unwrap();

    let result = pkey.public_key_to_der();
    assert!(result.is_ok());
    let public_key_der = result.unwrap();

    (private_key_der, public_key_der)
}

/// Wraps data using a specified key encryption algorithm.
///
/// # Arguments
///
/// * `wrapping_pub_key_der` - The DER-encoded RSA public key used for wrapping.
/// * `data` - The data to be wrapped.
/// * `enc` - The key encryption algorithm to use.
///
/// # Returns
///
/// A vector containing the wrapped data.
#[allow(dead_code)]
pub(crate) fn wrap_data(
    wrapping_pub_key_der: Vec<u8>,
    data: &[u8],
    enc: KeyEncryptionAlgorithm,
) -> Vec<u8> {
    let aes_key = generate_aes(KeyType::Aes256);
    let aes_key_slice = aes_key.as_slice();

    let rsa_public_key = openssl::rsa::Rsa::public_key_from_der(&wrapping_pub_key_der)
        .expect("Failed to load RSA public key from DER");

    let pkey = openssl::pkey::PKey::from_rsa(rsa_public_key)
        .expect("Failed to convert RSA public key to PKey");

    let mut pkey_ctx = openssl::pkey_ctx::PkeyCtx::new(&pkey).expect("Failed to create PkeyCtx");
    pkey_ctx
        .encrypt_init()
        .expect("Failed to initialize encryption");
    pkey_ctx
        .set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
        .expect("Failed to set RSA padding");

    let md = match enc {
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP => openssl::md::Md::sha1(),
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256 => openssl::md::Md::sha256(),
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384 => openssl::md::Md::sha384(),
    };

    pkey_ctx
        .set_rsa_oaep_md(md)
        .expect("Failed to set RSA OAEP message digest");

    // Encrypt AES key with RSA public key
    let encrypted_aes_key_len = pkey_ctx
        .encrypt(aes_key_slice, None)
        .expect("Failed to determine buffer length for encrypted AES key");
    let mut encrypted_aes_key = vec![0u8; encrypted_aes_key_len];
    let encrypted_len = pkey_ctx
        .encrypt(aes_key_slice, Some(&mut encrypted_aes_key))
        .expect("Failed to encrypt AES key");
    encrypted_aes_key.truncate(encrypted_len);

    let aes_cipher = openssl::cipher::Cipher::aes_256_wrap_pad();
    let mut cipher_ctx = openssl::cipher_ctx::CipherCtx::new().expect("Failed to create CipherCtx");
    cipher_ctx.set_flags(openssl::cipher_ctx::CipherCtxFlags::FLAG_WRAP_ALLOW);
    cipher_ctx
        .encrypt_init(Some(aes_cipher), Some(aes_key_slice), None)
        .expect("Failed to initialize AES encryption");

    // Encrypt data with AES key
    let padding = 8 - data.len() % 8;
    let mut encrypted_data = vec![0; data.len() + padding + aes_cipher.block_size() * 2];
    let count = cipher_ctx
        .cipher_update(data, Some(&mut encrypted_data))
        .expect("Failed to update AES encryption");
    let rest = cipher_ctx
        .cipher_final(&mut encrypted_data[count..])
        .expect("Failed to finalize AES encryption");
    encrypted_data.truncate(count + rest);

    // Concatenate encrypted AES key and encrypted data
    let mut wrapped_data = Vec::with_capacity(encrypted_aes_key.len() + encrypted_data.len());
    wrapped_data.extend_from_slice(&encrypted_aes_key);
    wrapped_data.extend_from_slice(&encrypted_data);

    wrapped_data
}

/// Creates a PKCS#11 RSA-AES wrap blob in a format that can be imported by CNG.
///
/// # Arguments
///
/// * `private_key` - The wrapped key blob.
/// * `enc` - The key encryption algorithm to use.
///
/// # Returns
///
/// A vector containing the PKCS#11 RSA-AES wrap blob.
#[allow(dead_code)]
pub(crate) fn create_pkcs11_rsa_aes_wrap_blob(
    private_key: &[u8],
    enc: KeyEncryptionAlgorithm,
) -> Vec<u8> {
    let hash_alg = match enc {
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP => NCRYPT_SHA1_ALGORITHM,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256 => NCRYPT_SHA256_ALGORITHM,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384 => NCRYPT_SHA384_ALGORITHM,
    };

    let mut hash_alg_size =
        unsafe { ((hash_alg.to_string().unwrap().len() + 1) * size_of::<u16>()) as u32 };

    let blob = BCRYPT_PKCS11_RSA_AES_WRAP_BLOB {
        dw_magic: BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC,
        cb_key: private_key.len() as u32,
        cb_padding_alg_id: hash_alg_size,
        cb_padding_label: 0,
    };

    let blob_bytes = unsafe {
        std::slice::from_raw_parts(
            &blob as *const BCRYPT_PKCS11_RSA_AES_WRAP_BLOB as *const u8,
            std::mem::size_of::<BCRYPT_PKCS11_RSA_AES_WRAP_BLOB>(),
        )
    };

    let mut hash_alg_bytes = vec![0; hash_alg_size as usize];
    copy_pcwstr_to_slice(hash_alg, &mut hash_alg_bytes, &mut hash_alg_size);

    let mut wrapped_blob = Vec::new();
    wrapped_blob.extend_from_slice(blob_bytes);
    wrapped_blob.extend_from_slice(private_key);
    wrapped_blob.extend_from_slice(&hash_alg_bytes);

    wrapped_blob
}

// Helper function for RSA tests that uses the AZIHSM built-in unwrapping key
// to wrap an RSA private key and import it into AZIHSM via the KSP.
//
// This function does not finalize the key, nor does it set any key properties.
// See `import_wrapped_key` for the full process.
#[allow(dead_code)]
pub(crate) fn import_wrapped_key_not_finalized(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
) -> (KeyHandle, KeyHandle) {
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

    unsafe {
        // Open handle to the built-in import key
        let result = NCryptOpenKey(
            prov_handle,
            import_key.as_mut(),
            AZIHSM_BUILTIN_UNWRAP_KEY,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Export public key from the import key
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a 'key_type' RSA private key
        // Wrap it with the import public key using 'key_enc_algo' key encryption algorithm
        let private_key = generate_rsa_der(key_type).0;
        let encrypted_blob = wrap_data(pub_key, &private_key, key_enc_algo);
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(&encrypted_blob, key_enc_algo);

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_RSA_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_RSA_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            prov_handle,
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());
    }

    (import_key, target_key)
}

// Helper function for RSA tests that uses the AZIHSM built-in unwrapping key
// to wrap an RSA private key and import it into AZIHSM via the KSP.
#[allow(dead_code)]
pub(crate) fn import_wrapped_key(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    key_usage: u32,
    key_enable_crt: Option<bool>,
) -> (KeyHandle, KeyHandle) {
    // Use the non-finalized helper function to do the heavy lifting for
    // generating and importing the RSA private key.
    let (import_key, target_key) =
        import_wrapped_key_not_finalized(prov_handle, key_type, key_enc_algo);

    unsafe {
        // Set the key's usage property to the provided value.
        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &key_usage.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set the `RsaCrtEnabled` property to enable or disable CRT for this
        // key, before we finalize it, if a value was provided.
        if let Some(enable_crt) = key_enable_crt {
            // We pass in `1` for the expected initial value, because RSA keys
            // are, by default, imported with CRT enabled. This means the
            // `RsaCrtEnabled` property should return `1`.
            set_key_rsa_crt_enabled_property_withcheck(&target_key, enable_crt as u32, 1);
        }

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());
    }

    (import_key, target_key)
}

pub(crate) trait CleanupTrait {
    fn cleanup(&self);
}

impl CleanupTrait for NCRYPT_PROV_HANDLE {
    fn cleanup(&self) {
        unsafe {
            if *self != NCRYPT_PROV_HANDLE(0) {
                let _ = NCryptFreeObject(*self);
            }
        }
    }
}

impl CleanupTrait for NCRYPT_KEY_HANDLE {
    fn cleanup(&self) {
        unsafe {
            if *self != NCRYPT_KEY_HANDLE(0) {
                let _ = NCryptDeleteKey(*self, NCRYPT_SILENT_FLAG.0);
            }
        }
    }
}

impl CleanupTrait for NCRYPT_SECRET_HANDLE {
    fn cleanup(&self) {
        unsafe {
            if *self != NCRYPT_SECRET_HANDLE(0) {
                let secret: NCRYPT_HANDLE = NCRYPT_HANDLE(self.0);
                let _ = NCryptFreeObject(secret);
            }
        }
    }
}

pub(crate) struct Handle<T: CleanupTrait> {
    handle: T,
}

impl<T: CleanupTrait + Clone> Handle<T> {
    pub fn new() -> Self {
        Self {
            handle: unsafe { std::mem::zeroed() },
        }
    }

    pub fn as_mut(&mut self) -> &mut T {
        &mut self.handle
    }

    #[allow(dead_code)]
    pub fn handle(&self) -> T {
        self.handle.clone()
    }

    #[allow(dead_code)]
    pub fn release(&mut self) -> T {
        let handle = self.handle.clone();
        self.handle = unsafe { std::mem::zeroed() };
        handle
    }
}

impl<T: CleanupTrait> Drop for Handle<T> {
    fn drop(&mut self) {
        self.handle.cleanup();
    }
}

#[allow(dead_code)]
pub(crate) type ProviderHandle = Handle<NCRYPT_PROV_HANDLE>;

#[allow(dead_code)]
pub(crate) type KeyHandle = Handle<NCRYPT_KEY_HANDLE>;

#[allow(dead_code)]
pub(crate) type SecretHandle = Handle<NCRYPT_SECRET_HANDLE>;

// Create and return a tuple of (IV, AAD, Tag)
#[allow(dead_code)]
pub(crate) fn test_helper_create_iv_aad_tag(
    azihsm_key: NCRYPT_KEY_HANDLE,
) -> ([u8; AES_GCM_IV_SIZE], [u8; AES_GCM_AAD_SIZE], Vec<u8>) {
    // Generate IV
    let mut iv = [0u8; AES_GCM_IV_SIZE];
    rand_bytes(&mut iv).unwrap();

    // Generate AAD
    let mut aad = [0u8; AES_GCM_AAD_SIZE];
    rand_bytes(&mut aad).unwrap();

    unsafe {
        // Get the tag length property size
        let mut tag_length_property_size = 0u32;
        let result = NCryptGetProperty(
            azihsm_key,
            BCRYPT_AUTH_TAG_LENGTH,
            None,
            ptr::addr_of_mut!(tag_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());
        assert_eq!(tag_length_property_size, size_of::<u32>() as u32);

        // Get the tag length property value
        let mut tag_length_bytes = vec![0u8; tag_length_property_size as usize];
        let result = NCryptGetProperty(
            azihsm_key,
            BCRYPT_AUTH_TAG_LENGTH,
            Some(&mut tag_length_bytes),
            ptr::addr_of_mut!(tag_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());

        let tag_length = u32::from_le_bytes(tag_length_bytes.try_into().unwrap());
        assert_eq!(tag_length, 16);

        // Create the tag buffer
        let tag = vec![0u8; tag_length as usize];

        (iv, aad, tag)
    }
}

// Helper function that retrieves the current value of an RSA key's
// `RsaCrtEnabled` property.
//
// This should only be called on key handles pointing to an RSA key.
#[allow(dead_code)]
pub(crate) fn get_key_rsa_crt_enabled_property(key: &KeyHandle) -> u32 {
    unsafe {
        // We have to call `NCryptGetProperty` twice; once to get the number of
        // bytes required to store the value, and another time to retrieve the
        // value itself.
        let mut key_crt_enabled_size = 0u32;
        let result = NCryptGetProperty(
            key.handle(),
            AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED,
            None,
            ptr::addr_of_mut!(key_crt_enabled_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());
        assert_eq!(key_crt_enabled_size, size_of::<u32>() as u32);

        // Allocate a buffer to contain the property's bytes, then call
        // `NCryptGetProperty` a second time.
        let mut key_crt_enabled_bytes = vec![0u8; key_crt_enabled_size as usize];
        let result = NCryptGetProperty(
            key.handle(),
            AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED,
            Some(&mut key_crt_enabled_bytes),
            ptr::addr_of_mut!(key_crt_enabled_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());

        // Finally, convert the bytes into a u32, and return it
        u32::from_le_bytes(key_crt_enabled_bytes.try_into().unwrap())
    }
}

// Helper function that examines and sets the given key's `RsaCrtEnabled`
// property to the provided u32.
//
// This should only be called on key handles pointing to an RSA key.
#[allow(dead_code)]
pub(crate) fn set_key_rsa_crt_enabled_property(key: &KeyHandle, value: u32) {
    unsafe {
        // Set the property via `NCryptSetProperty`.
        let result = NCryptSetProperty(
            key.handle(),
            AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED,
            &value.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Read the property back and ensure the value we just set above was
        // committed.
        let key_crt_enabled: u32 = get_key_rsa_crt_enabled_property(key);
        assert_eq!(key_crt_enabled, value);
    }
}

// Helper function that wraps around `set_key_rsa_crt_enabled_property`, but
// additionally checks the *current* value of the RSA CRT key property and
// compares it with the given `expected_initial_value`.
//
// This should only be called on key handles pointing to an RSA key.
#[allow(dead_code)]
pub(crate) fn set_key_rsa_crt_enabled_property_withcheck(
    key: &KeyHandle,
    new_value: u32,
    expected_initial_value: u32,
) {
    // Retrieve the current value of the key's `RsaCrtEnabled` property, and
    // compare it with the expected initial value
    let key_crt_enabled: u32 = get_key_rsa_crt_enabled_property(key);
    assert_eq!(key_crt_enabled, expected_initial_value);

    // Use the common helper function to set the key property.
    set_key_rsa_crt_enabled_property(key, new_value);
}

// Helper function that wraps around `import_wrapped_key()` to import an RSA
// private key. Takes in the following parameters:
//
// * `key_type` - Specifies the type of RSA key (2k, 3k, 4k) to import. The
//   value passed in *must* be an RSA key type; any other type will cause an
//   assertion error.
// * `key_encryption_type` - Specifies the digest type to use when creating the
//   wrapped blob of data that is to be passed into `NCryptImportKey()`.
// * `enable_crt` - Controls whether or not the `RsaCrtEnabled` key property is
//   set before finalizing the RSA key, and the value it is set to.
//		* If `Some(true)`, then `NCryptSetProperty()` will be invoked to set
//		  the value to a non-zero integer, thus enabling CRT for the imported
//		  RSA key.
//		* If `Some(false)`, then `NCryptSetProperty()` will be invoked to set
//		  the value to zero, thus disabling CRT for the imported RSA key.
//      * If `None`, then `NCryptSetProperty()` will *not* be called, and the
// 		  `RsaCrtProperty` will be left to its default value.
// * `key_usage` - The 32-bit unsigned integer that's passed into
//   `NCryptSetProperty()` when setting the key usage property.
//
// These parameters allow the below #[test] functions to exercise several
// difference scenarios when importing an RSA key.
//
// This function returns a `KeyHandle` object, which references the
// newly-imported key.
#[allow(dead_code)]
pub(crate) fn test_helper_rsa_key_unwrap(
    key_type: &KeyType,
    key_encryption_type: KeyEncryptionAlgorithm,
    key_enable_crt: Option<bool>,
    key_usage: u32,
) -> KeyHandle {
    let mut azihsm_provider = ProviderHandle::new();

    // Make sure the provided key type is one of the RSA key types; anything
    // else is not supported by this test
    let _ = match key_type {
        KeyType::Rsa2k | KeyType::Rsa3k | KeyType::Rsa4k => 0,
        _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
    };

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            *key_type,
            key_encryption_type,
            key_usage,
            key_enable_crt,
        );

        target_key
    }
}

// Helper function that uses the provided key handle to encrypt with RSA.
// Accepts the following parameters:
//
// * `target_key` - A handle to an imported RSA private key.
// * `key_type` - The type of RSA key that `target_key` points to. Must be one
//   of the RSA key types.
// * `padding_alg` - The algorithm ID that should be used for the
//   `BCRYPT_OAEP_PADDING_INFO` struct used during encryption/decryption.
// * `padding_label` - An optional slice of bytes that is used as the label for
//   the OAEP padding struct created and used for encrypt/decrypt.
// * `plaintext` - The buffer containing the plaintext to encrypt.
// * `should_fail` - If set to true, this function will assert that
//   `NCryptEncrypt()` returns an error, and the function will return early.
//
// On success, the encrypted ciphertext is returned in a vector.
#[allow(dead_code)]
pub(crate) fn test_helper_rsa_encrypt(
    target_key: &KeyHandle,
    key_type: &KeyType,
    padding_alg: NCryptShaAlgorithm,
    mut label: Option<&mut [u8]>,
    plaintext: &[u8],
    should_fail: bool,
) -> std::result::Result<Vec<u8>, String> {
    unsafe {
        // We will encrypt and decrypt with the imported key. Start by setting
        // up a padding info struct.
        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: match label {
                None => ptr::null_mut(),
                Some(ref mut label_slice) => label_slice.as_mut_ptr(),
            },
            cbLabel: match label {
                None => 0,
                Some(ref label_slice) => label_slice.len() as u32,
            },
        };

        // Based on the provided key type, choose an appropriate maximum size
        // for the ciphertext and plaintext.
        let data_len_max: usize = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        // Create a buffer to store the ciphertext
        let mut ciphertext: Vec<u8> = vec![0u8; data_len_max];
        let mut ciphertext_len = 0u32;

        // Call `NCryptEncrypt()` to encrypt the plaintext. The resulting
        // ciphertext should have a length equivalent to the value that gets
        // stored in `ciphertext_len`. It should also not exceed
        // `data_len_max`.
        let result = NCryptEncrypt(
            target_key.handle(),
            Some(plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        if should_fail {
            assert!(result.is_err(), "result {:?}", result);
            return Err(format!("Encryption failed as expected: {:?}", result));
        }

        assert!(result.is_ok(), "Encryption failed: {:?}", result);
        assert_eq!(ciphertext.len(), ciphertext_len as usize);
        assert!(ciphertext_len <= data_len_max as u32);

        // truncate the ciphertext buffer to the length that was returned, and
        // return it
        ciphertext.truncate(ciphertext_len as usize);
        Ok(ciphertext)
    }
}

// Helper function that uses the provided key handle to decrypt with RSA.
// Accepts the following parameters:
//
// * `target_key` - A handle to an imported RSA private key.
// * `key_type` - The type of RSA key that `target_key` points to. Must be one
//   of the RSA key types.
// * `padding_alg` - The algorithm ID that should be used for the
//   `BCRYPT_OAEP_PADDING_INFO` struct used during encryption/decryption.
// * `padding_label` - An optional slice of bytes that is used as the label for
//   the OAEP padding struct created and used for encrypt/decrypt.
//  * `ciphertext` - The ciphertext buffer to decrypt.
// * `should_fail` - If set to true, this function will assert that
//   `NCryptDecrypt()` returns an error, and the function will return early.
//
// On success, a vector containing the decrypted bytes is returned.
#[allow(dead_code)]
pub(crate) fn test_helper_rsa_decrypt(
    target_key: &KeyHandle,
    key_type: &KeyType,
    padding_alg: NCryptShaAlgorithm,
    mut label: Option<&mut [u8]>,
    ciphertext: &[u8],
    should_fail: bool,
) -> std::result::Result<Vec<u8>, String> {
    unsafe {
        // We will encrypt and decrypt with the imported key. Start by setting
        // up a padding info struct.
        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: match label {
                None => ptr::null_mut(),
                Some(ref mut label_slice) => label_slice.as_mut_ptr(),
            },
            cbLabel: match label {
                None => 0,
                Some(ref label_slice) => label_slice.len() as u32,
            },
        };

        // Based on the provided key type, choose an appropriate maximum size
        // for the ciphertext and plaintext.
        let data_len_max: usize = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        // Create a buffer to store the decrypted ciphertext.
        let mut decrypted: Vec<u8> = vec![0u8; data_len_max];
        let mut decrypted_len = 0u32;

        // Call `NCryptDecrypt()` to decrypt the ciphertext back into the
        // plaintext
        let result = NCryptDecrypt(
            target_key.handle(),
            Some(ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(decrypted.as_mut_slice()),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        if should_fail {
            assert!(result.is_err(), "result {:?}", result);
            return Err(format!("Decryption failed as expected: {:?}", result));
        }

        assert!(result.is_ok(), "Decryption failed: {:?}", result);
        assert!(decrypted_len <= data_len_max as u32);

        // truncate the vector down to the correct size, and return
        decrypted.truncate(decrypted_len as usize);
        Ok(decrypted)
    }
}

// Helper function for the below tests that uses the provided key handle to
// encrypt and decrypt. Accepts the following parameters.
//
// * `target_key` - A handle to an imported RSA private key.
// * `key_type` - The type of RSA key that `target_key` points to. Must be one
//   of the RSA key types.
// * `padding_alg` - The algorithm ID that should be used for the
//   `BCRYPT_OAEP_PADDING_INFO` struct used during encryption/decryption.
// * `padding_label` - An optional slice of bytes that is used as the label for
//   the OAEP padding struct created and used for encrypt/decrypt.
// * `encrypt_should_fail` - If set to true, this function will assert that
//   `NCryptEncrypt()` returns an error, and the function will return early.
// * `decrypt_should_fail` - If set to true, this function will assert that
//   `NCryptDecrypt()` returns an error.
#[allow(dead_code)]
pub(crate) fn test_helper_rsa_encrypt_decrypt(
    target_key: &KeyHandle,
    key_type: &KeyType,
    padding_alg: NCryptShaAlgorithm,
    label: Option<&mut [u8]>,
    encrypt_should_fail: bool,
    decrypt_should_fail: bool,
) {
    // generate a random plaintext buffer
    let mut plaintext: Vec<u8> = vec![0u8; 100];
    rand_bytes(plaintext.as_mut_slice()).unwrap();

    // make two copies of the label `Option` to avoid ownership issues when
    // invoking the encrypt and decrypt helper functions below
    let (mut enc_label, mut dec_label) = label
        .map(|slice| {
            let v1 = slice.to_vec();
            let v2 = slice.to_vec();
            (Some(v1), Some(v2))
        })
        .unwrap_or((None, None));

    // call the encryption helper function to encrypt the plaintext
    let enc_result = test_helper_rsa_encrypt(
        target_key,
        key_type,
        padding_alg,
        enc_label.as_deref_mut(),
        plaintext.as_slice(),
        encrypt_should_fail,
    );

    // make sure we didn't have any unexpected behavior, and unpack the
    // ciphertext
    if encrypt_should_fail {
        if enc_result.is_err() {
            // encryption failed as expect - return early
            return;
        }
        panic!("RSA encryption succeeded when it should have failed");
    }
    if enc_result.is_err() {
        panic!("RSA encryption failed when it was not expected to fail");
    }
    let ciphertext = enc_result.unwrap();

    // call the decryption helper function to decrypt the ciphertext
    let dec_result = test_helper_rsa_decrypt(
        target_key,
        key_type,
        padding_alg,
        dec_label.as_deref_mut(),
        ciphertext.as_slice(),
        decrypt_should_fail,
    );

    // make sure we didn't have any unexpected behavior, and unpack the
    // decrypted plaintext
    if decrypt_should_fail {
        if dec_result.is_err() {
            // decryption failed as expect - return early
            return;
        }
        panic!("RSA decryption succeeded when it should have failed");
    }
    if dec_result.is_err() {
        panic!("RSA decryption failed when it was not expected to fail");
    }
    let decrypted = dec_result.unwrap();

    // if we expected decryption to succeed, make sure the plaintext matches
    // the ciphertext
    assert_eq!(plaintext.len(), decrypted.len());
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

// Helper function that tests signing hashes and verifying signatures with the
// provided key handle. Takes in the following parameters:
//
// * `target_key` - A handle to an imported RSA private key.
// * `key_type` - The type of RSA key that `target_key` points to. Must be one
//   of the RSA key types.
// * `padding_type` - The type of padding that should be used when signing and
//   verifying. This controls the type of padding info struct/object created and
//   passed into the NCrypt API. If left as `None`, *no* padding will be used
//   during signing and verifying. (No padding info object will be created.)
// * `padding_flag_type` - This controls the NCrypt flag used when invoking the
//   NCrypt API (i.e. `NCRYPT_PAD_PKCS1_FLAG` and `NCRYPT_PAD_PSS_FLAG`). In
//   some cases, this can be specified even when no padding info struct is
//   passed in (when `padding_type` is `None`).
// * `padding_alg` - The type of padding algorithm to use when padding. This
//   also controls the size of the digest used when padding. If `padding_type`
//   is set to `None`, this will still be used to determine the digest size.
// * `enable_crt` - An option that, if specified, will set the `RsaCrtEnabled`
//   property for the imported RSA key.
// * `sign_should_fail` - If set to true, this function will assert that
//   `NCryptSignHash()` returns an error, and the function will return early.
// * `verify_should_fail` - If set to true, this function will assert that
//   `NCryptVerifySignature()` returns an error.
#[allow(dead_code)]
pub(crate) fn test_helper_rsa_sign_verify(
    target_key: &KeyHandle,
    key_type: &KeyType,
    padding_type: Option<NCryptPaddingType>,
    padding_flag_type: Option<NCryptPaddingType>,
    padding_alg: NCryptShaAlgorithm,
    sign_should_fail: bool,
    verify_should_fail: bool,
) {
    unsafe {
        // Based on the provided key type, choose an appropriate maximum size
        // for the ciphertext and plaintext.
        let data_len_max: usize = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        // Choose a digest size appropriate to the specified padding algorithm
        let digest_size: usize = match padding_alg {
            NCryptShaAlgorithm::Sha256 => 32,
            NCryptShaAlgorithm::Sha384 => 48,
            NCryptShaAlgorithm::Sha512 => 64,
            NCryptShaAlgorithm::Sha1 => 20,
        };

        // Set the padding flag based on the provided parameter.
        let mut padding_flag = NCRYPT_FLAGS(0);
        if let Some(pftype) = padding_flag_type {
            padding_flag = match pftype {
                NCryptPaddingType::Pkcs1 => NCRYPT_PAD_PKCS1_FLAG,
                NCryptPaddingType::Pss => NCRYPT_PAD_PSS_FLAG,
            };
        }

        // Similarly, set up the padding info structs, if the provided
        // `padding_type` parameter was specified.
        let padding_info_pkcs1;
        let padding_info_pss;
        let mut padding_info_param: Option<*const std::ffi::c_void> = None;
        if let Some(ptype) = padding_type {
            // set up the padding info structs, if necessary
            match ptype {
                NCryptPaddingType::Pkcs1 => {
                    padding_info_pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pkcs1) as *const std::ffi::c_void);
                }
                NCryptPaddingType::Pss => {
                    padding_info_pss = BCRYPT_PSS_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                        cbSalt: rand::random::<u32>() % digest_size as u32,
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pss) as *const std::ffi::c_void);
                }
            };
        }

        // Create a randomized hash digest.
        let mut digest = vec![1u8; digest_size];
        rand_bytes(&mut digest).unwrap();

        // Call `NCryptSignHash()` once, to determine the number of bytes
        // required to hold the resulting signature.
        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            target_key.handle(),
            padding_info_param,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            padding_flag,
        );
        if sign_should_fail {
            assert!(result.is_err(), "result {:?}", result);
            return;
        } else {
            assert!(result.is_ok());
            assert_eq!(signature_size, data_len_max as u32);
        }
        // Allocate a buffer of the appropriate size, then call
        // `NCryptSignHash()` a second time, to retrieve the signature bytes.
        let mut signature = vec![0u8; signature_size as usize];
        let result = NCryptSignHash(
            target_key.handle(),
            padding_info_param,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            padding_flag,
        );
        assert!(result.is_ok());
        assert_eq!(signature_size, data_len_max as u32);

        // Call `NCryptVerifySignature` with the signature we generated earlier,
        // and the original hash digest.
        let result = NCryptVerifySignature(
            target_key.handle(),
            padding_info_param,
            &digest,
            &signature,
            padding_flag,
        );
        if verify_should_fail {
            assert!(result.is_err(), "result {:?}", result);
        } else {
            assert!(result.is_ok());
        }
    }
}

// Helper function that checks the provided key's key length property against
// expected values. Takes in the following parameters:
//
// * `target_key` - The key handle to check.
// * `key_type` - The type of key that `target_key` is referencing.
#[allow(dead_code)]
pub(crate) fn test_helper_check_key_length(target_key: &KeyHandle, key_type: &KeyType) {
    unsafe {
        // Call `NCryptGetProperty()` once, to retrieve the number of bytes
        // needed to store the key size property's data.
        //
        // We should only need the number of bytes equivalent to a `u32`.
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            target_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            None,
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());
        assert_eq!(key_length_property_size, size_of::<u32>() as u32);

        // Allocate a buffer to store the result, and call `NCryptGetProperty()`
        // a second time, to retrieve the property's bytes.
        let mut key_length_bytes = vec![0u8; key_length_property_size as usize];
        let result = NCryptGetProperty(
            target_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            Some(&mut key_length_bytes),
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        // Convert the bytes to a `u32` and compare it with the expected value,
        // based on the provided `KeyType`.
        assert!(result.is_ok());
        let key_length = u32::from_le_bytes(key_length_bytes.try_into().unwrap());
        let expected_key_length: u32 = match key_type {
            KeyType::Rsa2k => 2048,
            KeyType::Rsa3k => 3072,
            KeyType::Rsa4k => 4096,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };
        assert_eq!(key_length, expected_key_length);
    }
}

// Helper function that checks the provided key's key usage property against
// expected values. Takes in the following parameters:
//
// * `target_key` - The key handle to check.
// * `key_usage` - The 32-bit value that is expected to be returned when
//   retrieving the key usage property.
#[allow(dead_code)]
pub(crate) fn test_helper_check_key_usage(target_key: &KeyHandle, key_usage: u32) {
    unsafe {
        // Call `NCryptGetProperty()` once, to retrieve the number of bytes
        // needed to store the key usage property's data.
        //
        // We should only need the number of bytes equivalent to a `u32`.
        let mut key_usage_property_size = 0u32;
        let result = NCryptGetProperty(
            target_key.handle(),
            NCRYPT_KEY_USAGE_PROPERTY,
            None,
            ptr::addr_of_mut!(key_usage_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());
        assert_eq!(key_usage_property_size, size_of::<u32>() as u32);

        // Allocate a buffer to store the result, and call `NCryptGetProperty()`
        // a second time, to retrieve the property's bytes.
        let mut key_usage_bytes = vec![0u8; key_usage_property_size as usize];
        let result = NCryptGetProperty(
            target_key.handle(),
            NCRYPT_KEY_USAGE_PROPERTY,
            Some(&mut key_usage_bytes),
            ptr::addr_of_mut!(key_usage_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let key_usage_val = u32::from_le_bytes(key_usage_bytes.try_into().unwrap());
        assert_eq!(key_usage_val, key_usage);
    }
}
