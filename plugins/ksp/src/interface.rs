// Copyright (C) Microsoft Corporation. All rights reserved.

use lazy_static::*;
use mcr_api::EccCurve;
use winapi::ctypes::c_void;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Cryptography::*;

use super::AZIHSM_BUILTIN_UNWRAP_KEY;
use super::AZIHSM_DERIVED_KEY_IMPORT_BLOB;
use super::AZIHSM_KSP_NAME;
use super::BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB;
use super::REPORT_DATA_SIZE;
use crate::algorithms::allocate;
use crate::algorithms::enum_algorithms;
use crate::algorithms::free;
use crate::algorithms::is_alg_supported;
use crate::handle_table::*;
use crate::key::base_key::*;
use crate::ncrypt_types::*;
use crate::provider::*;
use crate::utils::*;

macro_rules! validate_handle {
    ($handle:expr) => {
        if $handle.is_invalid() {
            tracing::error!("Invalid handle: [{}]", stringify!($handle));
            return NTE_INVALID_HANDLE;
        }
    };
    ($handle:expr, $prov:expr) => {
        if $handle.is_invalid() {
            tracing::error!(
                "Provider [{}]: Invalid handle: [{}]",
                $prov.handle(),
                stringify!($handle),
            );
            return NTE_INVALID_HANDLE;
        }
    };
}

macro_rules! validate_arg {
    ($arg:expr) => {
        if !$arg {
            tracing::error!("Condition not met: [{}]", stringify!($arg));
            return NTE_INVALID_PARAMETER;
        }
    };
    ($arg:expr, $prov:expr) => {
        if !$arg {
            tracing::error!(
                "Provider [{}]: Condition not met: [{}]",
                $prov.handle(),
                stringify!($arg)
            );
            return NTE_INVALID_PARAMETER;
        }
    };
}

macro_rules! provider {
    ($handle:expr) => {{
        validate_handle!($handle);
        match PROVIDERS.get($handle.0) {
            Some(provider) => provider,
            None => {
                tracing::error!("Provider handle not found: [{}]", $handle.0);
                return NTE_INVALID_PARAMETER;
            }
        }
    }};
}

macro_rules! string {
    ($pcwstr:expr, $prov:expr) => {{
        validate_arg!(!$pcwstr.is_null(), $prov);
        match unsafe { $pcwstr.to_string() } {
            Ok(string) => string,
            Err(_) => {
                tracing::error!(
                    "Provider [{}]: Failed to convert wide string to string: [{}]",
                    $prov.handle(),
                    stringify!($pcwstr)
                );
                return NTE_INVALID_PARAMETER;
            }
        }
    }};
    ($pcwstr:expr) => {{
        validate_arg!(!$pcwstr.is_null());
        match unsafe { $pcwstr.to_string() } {
            Ok(string) => string,
            Err(_) => {
                tracing::error!(
                    "Failed to convert wide string to string: [{}]",
                    stringify!($pcwstr)
                );
                return NTE_INVALID_PARAMETER;
            }
        }
    }};
}

macro_rules! key_kind {
    ($algo:expr, $prov:expr) => {{
        validate_arg!(!$algo.is_null(), $prov);
        if pcwstr::equals($algo, BCRYPT_RSA_ALGORITHM) {
            KeyKind::Rsa { key_length: 0 }
        } else if pcwstr::equals($algo, BCRYPT_AES_ALGORITHM) {
            KeyKind::Aes {
                key_length: None,
                encryption_mode: None,
            }
        } else if pcwstr::equals($algo, BCRYPT_ECDSA_P256_ALGORITHM) {
            KeyKind::Ecdsa {
                curve_type: Some(EccCurve::P256),
            }
        } else if pcwstr::equals($algo, BCRYPT_ECDSA_P384_ALGORITHM) {
            KeyKind::Ecdsa {
                curve_type: Some(EccCurve::P384),
            }
        } else if pcwstr::equals($algo, BCRYPT_ECDSA_P521_ALGORITHM) {
            KeyKind::Ecdsa {
                curve_type: Some(EccCurve::P521),
            }
        } else if pcwstr::equals($algo, BCRYPT_ECDSA_ALGORITHM) {
            KeyKind::Ecdsa { curve_type: None }
        } else if pcwstr::equals($algo, BCRYPT_ECDH_P256_ALGORITHM) {
            KeyKind::Ecdh {
                curve_type: Some(EccCurve::P256),
            }
        } else if pcwstr::equals($algo, BCRYPT_ECDH_P384_ALGORITHM) {
            KeyKind::Ecdh {
                curve_type: Some(EccCurve::P384),
            }
        } else if pcwstr::equals($algo, BCRYPT_ECDH_P521_ALGORITHM) {
            KeyKind::Ecdh {
                curve_type: Some(EccCurve::P521),
            }
        } else if pcwstr::equals($algo, BCRYPT_ECDH_ALGORITHM) {
            KeyKind::Ecdh { curve_type: None }
        } else {
            #[cfg(not(feature = "disable-fp"))]
            {
                use crate::key::aes_key::AesEncryptionMode;
                if pcwstr::equals($algo, BCRYPT_XTS_AES_ALGORITHM) {
                    KeyKind::Aes {
                        key_length: None,
                        encryption_mode: Some(AesEncryptionMode::XTS),
                    }
                } else {
                    tracing::error!(
                        "Provider [{}]: Unsupported algorithm: [{:?}]",
                        $prov.handle(),
                        string!($algo, $prov)
                    );
                    return NTE_NOT_SUPPORTED;
                }
            }
            #[cfg(feature = "disable-fp")]
            {
                tracing::error!(
                    "Provider [{}]: Unsupported algorithm: [{:?}]",
                    $prov.handle(),
                    string!($algo, $prov)
                );
                return NTE_NOT_SUPPORTED;
            }
        }
    }};
}

macro_rules! validate_allowed_flags {
    ($flags:expr, $allowed_flags:expr, $prov:expr) => {{
        if $flags & !($allowed_flags) != NCRYPT_FLAGS(0) {
            tracing::error!(
                "Provider [{}]: Invalid flags: {:#010X}",
                $prov.handle(),
                $flags.0
            );
            return NTE_BAD_FLAGS;
        }
    }};
}

/// The version of the interface supported by KSP
const AZIHSM_INTERFACE_VERSION: NCryptInterfaceVersion = NCryptInterfaceVersion {
    MajorVersion: 3, // Key attestation is supported version (3, 0) onwards
    MinorVersion: 0,
};

/// KSP function table
const INTERFACE: NCryptKeyStorageFuncTable = NCryptKeyStorageFuncTable {
    version: AZIHSM_INTERFACE_VERSION,
    open_provider: azihsm_open_provider,
    open_key: azihsm_open_key,
    create_persisted_key: azihsm_create_persisted_key,
    get_provider_property: azihsm_get_provider_property,
    get_key_property: azihsm_get_key_property,
    set_provider_property: azihsm_set_provider_property,
    set_key_property: azihsm_set_key_property,
    finalize_key: azihsm_finalize_key,
    delete_key: azihsm_delete_key,
    free_provider: azihsm_close_provider,
    free_key: azihsm_free_key,
    free_buffer: azihsm_free_buffer,
    encrypt: azihsm_encrypt,
    decrypt: azihsm_decrypt,
    is_alg_supported: azihsm_is_alg_supported,
    enum_algorithms: azihsm_enum_algorithms,
    enum_keys: azihsm_enum_keys,
    import_key: azihsm_import_key,
    export_key: azihsm_export_key,
    sign_hash: azihsm_sign,
    verify_signature: azihsm_verify,
    prompt_user: azihsm_prompt_user,
    notify_change_key: azihsm_notify_change_key,
    secret_agreement: azihsm_generate_secret,
    derive_key: azihsm_derive_key,
    free_secret: azihsm_delete_secret,
    key_derivation: azihsm_key_derivation,
    create_claim: azihsm_create_claim,
    verify_claim: azihsm_verify_claim,
};

lazy_static! {
    static ref PROVIDERS: HandleTable<Provider> = HandleTable::default();
}

/// Retrieves the key storage interface.
///
/// # Arguments
/// * `prov_name` - The name of the provider.
/// * `interface` - A pointer to the key storage interface.
/// * `flags`     - Flags that modify the behavior of the function No flags are defined for this function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[export_name = "GetKeyStorageInterface"]
extern "system" fn azihsm_get_key_storage_interface(
    prov_name: PCWSTR,
    interface: *mut *const NCryptKeyStorageFuncTable,
    _flags: u32,
) -> HRESULT {
    dll::boundary(|| {
        validate_arg!(!prov_name.is_null());
        validate_arg!(!interface.is_null());
        validate_arg!(pcwstr::equals(prov_name, AZIHSM_KSP_NAME));

        unsafe {
            *interface = &INTERFACE;
        }

        tracing::debug!("Storage interface queried");
        S_OK
    })
}

/// Opens the key storage provider.
///
/// # Arguments
/// * `prov_handle` - A pointer to the provider handle.
/// * `prov_name`   - The name of the provider.
/// * `flags`  - Flags that modify the behavior of the function No flags are defined for this function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_open_provider")]
extern "system" fn azihsm_open_provider(
    prov_handle: *mut NCRYPT_PROV_HANDLE,
    prov_name: PCWSTR,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_open_provider");
        let _enter = span.enter();

        validate_arg!(!prov_handle.is_null());

        // Make sure the provider name is not null, and that it matches the
        // expected AZIHSM KSP name
        validate_arg!(!prov_name.is_null());
        validate_arg!(pcwstr::equals(prov_name, AZIHSM_KSP_NAME));

        let mut provider = Provider::default();
        if let Err(err) = provider.open_app_session() {
            tracing::error!(%err, "Failed to open an HSM app session");
            return err;
        }
        validate_allowed_flags!(flags, NCRYPT_FLAGS(0), provider);

        let handle = PROVIDERS.insert(provider.clone());
        provider.set_handle(handle);

        unsafe {
            *prov_handle = NCRYPT_PROV_HANDLE(handle);
        }

        tracing::debug!(prov_handle = handle, "Provider opened.");
        S_OK
    })
}

/// Closes the key storage provider.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_close_provider")]
extern "system" fn azihsm_close_provider(prov_handle: NCRYPT_PROV_HANDLE) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_close_provider", ?prov_handle);
        let _enter = span.enter();

        validate_handle!(prov_handle);

        let mut provider = match PROVIDERS.remove(prov_handle.0) {
            Some(provider) => provider,
            None => {
                tracing::error!(?prov_handle, "Provider not found.");
                return NTE_INVALID_HANDLE;
            }
        };

        if let Err(err) = provider.close_app_session() {
            tracing::error!(%err, "Failed to close the HSM app session.");
            return err;
        }

        tracing::debug!("Provider closed.");
        S_OK
    })
}

/// Creates a new persisted key.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - A pointer to the key handle.
/// * `algo`        - The algorithm to use.
/// * `key_name`    - The name of the key.
/// * `key_spec`    - The key specification.
/// * `flags`       - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(
    feature = "expose-symbols",
    export_name = "azihsm_create_persisted_key"
)]
extern "system" fn azihsm_create_persisted_key(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: *mut NCRYPT_KEY_HANDLE,
    algo: PCWSTR,
    key_name: PCWSTR,
    _key_spec: CERT_KEY_SPEC,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_create_persisted_key", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);

        // We will use the `key_handle` pointer provided by the caller to store
        // the resulting key handle in. So, it must not be null
        validate_arg!(!key_handle.is_null(), prov);

        // Make sure the algorithm ID string is not null, then use it to
        // interpret the type of key the caller wants
        validate_arg!(!algo.is_null(), prov);
        let key_kind = key_kind!(algo, prov);

        // Make sure only allowed flags were specified by the caller
        validate_allowed_flags!(
            flags,
            NCRYPT_SILENT_FLAG | NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG,
            prov
        );

        // We don't support persistent keys.
        if !key_name.is_null() {
            tracing::error!("This provider doesn't support Persistent keys.");
            return NTE_NOT_SUPPORTED;
        }

        let handle = prov.create_and_add_key(key_kind);
        unsafe {
            *key_handle = NCRYPT_KEY_HANDLE(handle);
        }

        tracing::debug!(handle, "Key created.");
        S_OK
    })
}

/// Finalizes a key.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - A pointer to the key handle.
/// * `algo`        - The algorithm to use.
/// * `key_name`    - The name of the key.
/// * `key_spec`    - The key specification.
/// * `flags`       - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_finalize_key")]
extern "system" fn azihsm_finalize_key(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_finalize_key", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);
        validate_allowed_flags!(flags, NCRYPT_SILENT_FLAG, prov);

        match prov.finalize_key(key_handle.0) {
            Ok(_) => {
                tracing::debug!(?key_handle, "Key finalized.");
                S_OK
            }
            Err(err) => {
                tracing::error!(?key_handle, %err, "Failed to finalize key.");
                err
            }
        }
    })
}

/// Deletes a key with optional flags.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
/// * `flags`       - Optional flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
fn delete_key_internal(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    flags: Option<NCRYPT_FLAGS>,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("delete_key_internal", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);

        if let Some(flags) = flags {
            validate_allowed_flags!(flags, NCRYPT_SILENT_FLAG, prov);
        }

        match prov.delete_key(key_handle.0) {
            Ok(_) => {
                tracing::debug!(?key_handle, "Key deleted.");
                S_OK
            }
            Err(err) => {
                tracing::error!(?key_handle, %err, "Failed to delete the key");
                err
            }
        }
    })
}

/// Deletes a key.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
/// * `flags`       - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_delete_key")]
extern "system" fn azihsm_delete_key(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    tracing::debug!("azihsm_delete_key called");
    delete_key_internal(prov_handle, key_handle, Some(flags))
}

/// Frees up a key handle.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_free_key")]
extern "system" fn azihsm_free_key(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
) -> HRESULT {
    tracing::debug!("azihsm_free_key called");
    delete_key_internal(prov_handle, key_handle, None)
}

/// Sets a property on a key.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
/// * `flags`       - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_set_key_property")]
extern "system" fn azihsm_set_key_property(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    property: PCWSTR,
    pbinput: *mut u8,
    cbinput: u32,
    _flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_set_key_property", ?prov_handle);
        let _enter = span.enter();
        tracing::debug!(?key_handle, "Setting key property");

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);
        validate_arg!(!property.is_null(), prov);
        validate_arg!(!pbinput.is_null(), prov);
        validate_arg!(cbinput > 0, prov);

        let input = unsafe { std::slice::from_raw_parts(pbinput, cbinput as usize) };
        let property = KeyPropertyIdentifier::from(property);

        match prov.set_key_property(key_handle.0, &property, input) {
            Ok(_) => {
                tracing::debug!(?key_handle, "Key property set");
                S_OK
            }
            Err(err) => {
                tracing::error!(
                    ?key_handle,
                    %err,
                    "Failed to set key property [{:?}].",
                    property,
                );
                err
            }
        }
    })
}

/// Encrypt a buffer with the specified key.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
/// * `pbinput`     - The input buffer to encrypt.
/// * `cbinput`     - The size, in bytes, of the input buffer.
/// * `ppaddinginfo` - A pointer to a `NCRYPT_CIPHER_PADDING_INFO` structure that contains padding information.
/// * `pboutput`    - The output buffer that receives the encrypted data.
/// * `cboutput`    - The size, in bytes, of the output buffer.
/// * `pcbresult`   - A pointer to a `u32` that receives the number of bytes of encrypted data written to the output buffer.
/// * `flags`       - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_encrypt")]
extern "system" fn azihsm_encrypt(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    pbinput: *const u8,
    cbinput: u32,
    ppaddinginfo: *const c_void,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_encrypt", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);
        validate_arg!(!pbinput.is_null());
        validate_arg!(cbinput > 0);
        validate_arg!(!pcbresult.is_null());
        validate_allowed_flags!(
            flags,
            NCRYPT_SILENT_FLAG
                | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG)
                | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG)
                | NCRYPT_PAD_OAEP_FLAG
                | NCRYPT_FLAGS(NCRYPT_PCP_STORAGE_KEY), // Flag for .NET API for RSA key
            prov
        );

        let input = unsafe { std::slice::from_raw_parts(pbinput, cbinput as usize) };

        let output = match pboutput.is_null() {
            true => &mut [],
            false => {
                validate_arg!(cboutput > 0);
                unsafe { std::slice::from_raw_parts_mut(pboutput, cboutput as usize) }
            }
        };

        // Get the pcbresult ref.
        let result = unsafe { &mut *(pcbresult.cast::<u32>()) };

        let params = EncDecParams {
            is_encrypt: true,
            key_handle: key_handle.0,
            input,
            ppaddinginfo,
            output,
            result,
            flags,
        };

        match prov.encrypt_decrypt(params) {
            Ok(_) => {
                tracing::debug!(?key_handle, "Data encrypted successfully.");
                S_OK
            }
            Err(err) => {
                tracing::error!(?key_handle, %err, "Failed to encrypt data");
                err
            }
        }
    })
}

/// Decrypt a buffer with the specified key.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
/// * `pbinput`     - The input buffer to decrypt.
/// * `cbinput`     - The size, in bytes, of the input buffer.
/// * `ppaddinginfo` - A pointer to a `NCRYPT_CIPHER_PADDING_INFO` structure that contains padding information.
/// * `pboutput`    - The output buffer that receives the decrypted data.
/// * `cboutput`    - The size, in bytes, of the output buffer.
/// * `pcbresult`   - A pointer to a `u32` that receives the number of bytes of decrypted data written to the output buffer.
/// * `flags`       - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_decrypt")]
extern "system" fn azihsm_decrypt(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    pbinput: *const u8,
    cbinput: u32,
    ppaddinginfo: *const c_void,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_decrypt", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);
        validate_arg!(!pbinput.is_null());
        validate_arg!(!pcbresult.is_null());
        validate_allowed_flags!(
            flags,
            NCRYPT_SILENT_FLAG
                | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG)
                | NCRYPT_PAD_OAEP_FLAG
                | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG),
            prov
        );

        let input = unsafe { std::slice::from_raw_parts(pbinput, cbinput as usize) };

        let output = match pboutput.is_null() {
            true => &mut [],
            false => {
                validate_arg!(cboutput > 0);
                unsafe { std::slice::from_raw_parts_mut(pboutput, cboutput as usize) }
            }
        };

        // Get the pcbresult ref.
        let result = unsafe { &mut *(pcbresult.cast::<u32>()) };

        let params = EncDecParams {
            is_encrypt: false,
            key_handle: key_handle.0,
            input,
            ppaddinginfo,
            output,
            result,
            flags,
        };

        match prov.encrypt_decrypt(params) {
            Ok(_) => {
                tracing::debug!(?key_handle, "Data decrypted successfully.");
                S_OK
            }
            Err(err) => {
                tracing::error!(?key_handle, %err, "Failed to decrypt data.");
                err
            }
        }
    })
}

/// Signs a hash value.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
/// * `ppaddinginfo` - A pointer to a padding info structure that contains padding information.
/// * `pbhashvalue` - The hash value to sign.
/// * `cbhashvalue` - The size, in bytes, of the hash value.
/// * `pbsignature` - The buffer that receives the signature.
/// * `cbsignature` - The size, in bytes, of the signature buffer.
/// * `pcbresult`   - A pointer to a `u32` that receives the number of bytes of the signature written to the output buffer.
/// * `flags`       - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_sign")]
extern "system" fn azihsm_sign(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    ppaddinginfo: *const c_void,
    pbhashvalue: *const u8,
    cbhashvalue: u32,
    pbsignature: *mut u8,
    cbsignature: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_sign", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);
        validate_arg!(!pbhashvalue.is_null());
        validate_arg!(cbhashvalue > 0);
        validate_arg!(!pcbresult.is_null());
        validate_allowed_flags!(
            flags,
            NCRYPT_SILENT_FLAG | NCRYPT_FLAGS(BCRYPT_PAD_PKCS1.0) | NCRYPT_FLAGS(BCRYPT_PAD_PSS.0),
            prov
        );

        let input = unsafe { std::slice::from_raw_parts(pbhashvalue, cbhashvalue as usize) };
        let output = match pbsignature.is_null() {
            true => &mut [],
            false => {
                validate_arg!(cbsignature > 0);
                unsafe { std::slice::from_raw_parts_mut(pbsignature, cbsignature as usize) }
            }
        };

        let ptr = pcbresult.cast::<u32>();
        let result = unsafe { &mut *ptr };

        match prov.sign(key_handle.0, input, ppaddinginfo, output, result, flags) {
            Ok(_) => {
                tracing::debug!(?key_handle, "Data signed successfully.");
                S_OK
            }
            Err(err) => {
                tracing::error!(?key_handle, %err, "Failed to sign data.");
                err
            }
        }
    })
}

/// Verifies a signature.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
/// * `ppaddinginfo` - A pointer to a padding info structure that contains padding information.
/// * `pbhashvalue` - The hash value to verify.
/// * `cbhashvalue` - The size, in bytes, of the hash value.
/// * `pbsignature` - The signature to verify.
/// * `cbsignature` - The size, in bytes, of the signature.
/// * `dwflags`     - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_verify")]
extern "system" fn azihsm_verify(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    ppaddinginfo: *const c_void,
    pbhashvalue: *const u8,
    cbhashvalue: u32,
    pbsignature: *const u8,
    cbsignature: u32,
    dwflags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_verify", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);
        validate_arg!(!pbhashvalue.is_null());
        validate_arg!(cbhashvalue > 0);
        validate_arg!(!pbsignature.is_null());
        validate_arg!(cbsignature > 0);
        validate_allowed_flags!(
            dwflags,
            NCRYPT_SILENT_FLAG | NCRYPT_FLAGS(BCRYPT_PAD_PKCS1.0) | NCRYPT_FLAGS(BCRYPT_PAD_PSS.0),
            prov
        );

        let hash_value = unsafe { std::slice::from_raw_parts(pbhashvalue, cbhashvalue as usize) };
        let signature = unsafe { std::slice::from_raw_parts(pbsignature, cbsignature as usize) };

        match prov.verify(key_handle.0, hash_value, ppaddinginfo, signature, dwflags) {
            Ok(_) => {
                tracing::debug!(?key_handle, "Data verified sucessfully.");
                S_OK
            }
            Err(err) => {
                tracing::error!(?key_handle, %err, "Failed to verify data.");
                err
            }
        }
    })
}

/// Retrieves a key property.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
/// * `property`    - The name of the property to retrieve.
/// * `pboutput`    - The output buffer that receives the property value.
/// * `cboutput`    - The size, in bytes, of the output buffer.
/// * `pcbresult`   - A pointer to a `u32` that receives the number of bytes of the property value written to the output buffer.
/// * `flags`       - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_get_key_property")]
extern "system" fn azihsm_get_key_property(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    property: PCWSTR,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_get_key_property", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);
        validate_arg!(!property.is_null(), prov);
        validate_arg!(!pcbresult.is_null(), prov);
        validate_allowed_flags!(flags, NCRYPT_SILENT_FLAG, prov);

        let property = KeyPropertyIdentifier::from(property);
        let output = match pboutput.is_null() {
            true => &mut [],
            false => {
                validate_arg!(cboutput > 0, prov);
                unsafe { std::slice::from_raw_parts_mut(pboutput, cboutput as usize) }
            }
        };

        // Get the pcbresult ref.
        let result = unsafe { &mut *(pcbresult.cast::<u32>()) };
        match prov.get_key_property(key_handle.0, &property, output, result) {
            Ok(_) => {
                tracing::debug!(?key_handle, "Key property [{:?}] retrieved", property);
                S_OK
            }
            Err(err) => {
                tracing::error!(
                    ?key_handle,
                    %err,
                    "Failed to retrieve key property [{:?}].",
                    property,
                );
                err
            }
        }
    })
}

/// Imports a key.
///
/// # Arguments
/// * `prov_handle`         - The provider handle.
/// * `import_key_handle`   - The optional key handle with which the imported key is encrypted.
/// * `pszblobtype`         - A pointer to a null-terminated Unicode string that contains the type of key blob being imported.
/// * `pparameterlist`      - A pointer to a `BCryptBufferDesc` structure that contains the key import parameters.
/// * `imported_key_handle` - A pointer to the key handle of the imported key.
/// * `pbdata`              - A pointer to a buffer that contains the key BLOB to import.
/// * `cbdata`              - The size, in bytes, of the key BLOB.
/// * `flags`               - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_import_key")]
extern "system" fn azihsm_import_key(
    prov_handle: NCRYPT_PROV_HANDLE,
    import_key_handle: NCRYPT_KEY_HANDLE,
    pszblobtype: PCWSTR,
    pparameterlist: *const BCryptBufferDesc,
    imported_key_handle: *mut NCRYPT_KEY_HANDLE,
    pbdata: *const u8,
    cbdata: u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!(
            "azihsm_import_key",
            ?prov_handle,
            blobtype = string!(pszblobtype)
        );
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_arg!(!pszblobtype.is_null());
        validate_arg!(!pbdata.is_null());
        validate_arg!(cbdata > 0);
        validate_arg!(!imported_key_handle.is_null());
        validate_allowed_flags!(
            flags,
            NCRYPT_SILENT_FLAG | NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
            prov
        );

        let key_blob = unsafe { std::slice::from_raw_parts(pbdata, cbdata as usize) };
        tracing::debug!(
            prov_handle = prov.handle(),
            "Importing key. Key Type: [{}]",
            string!(pszblobtype)
        );

        // PKCS#11 RSA AES wrap key import
        if pcwstr::equals(pszblobtype, BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB) {
            tracing::debug!("Import BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB");
            validate_handle!(import_key_handle, prov);
            validate_arg!(!pparameterlist.is_null());

            let algorithm_id = match rsa_unwrap::extract_algorithm_id(pparameterlist) {
                Some(algo_id) => algo_id,
                None => {
                    tracing::error!("Failed to extract algorithm ID");
                    return NTE_INVALID_PARAMETER;
                }
            };

            // Importing of AES-XTS keys is not currently supported.
            //
            // AES-XTS keys are made up of *two* separate AES keys. For example:
            // AES-XTS-512 (the XTS key size supported by AzIHSM) uses two
            // individual AES-256 keys.
            //
            // If secure import for AES-XTS is implemented in the future, the
            // AzIHSM KSP would need to be able to extract two separate AES keys
            // from within the same key blob, and the user would need to to
            // generate two AES keys and pack them together into the same key
            // blob before passing it to the AzIHSM via `NCryptImportKey()`.
            if pcwstr::equals(algorithm_id, BCRYPT_XTS_AES_ALGORITHM) {
                tracing::error!("Secure import not supported for XTS AES keys");
                return NTE_NOT_SUPPORTED;
            }

            // Interpret the algorithm ID string and match it to one of the
            // `KeyKind` enum values.
            let key_kind = key_kind!(algorithm_id, prov);

            // Pass the key type, unwrapping key handle, and blob data, into the
            // provider's RSA unwrapping function to import the key
            let handle = match prov.rsa_unwrap(key_kind, import_key_handle.0, key_blob) {
                Ok(handle) => handle,
                Err(err) => {
                    tracing::error!(%err, "Failed PKCS#11 RSA AES wrap key import.");
                    return err;
                }
            };

            unsafe {
                *imported_key_handle = NCRYPT_KEY_HANDLE(handle);
            }
        }
        //
        // ECDH Derived key import
        // The `AZIHSM_DERIVED_KEY_IMPORT_BLOB` type is used to import a derived key after
        // a Key Derivation Function (KDF) operation. In this context, the `key_blob` represents
        // an internal key handle that was created during the key derivation process.
        //
        else if pcwstr::equals(pszblobtype, AZIHSM_DERIVED_KEY_IMPORT_BLOB) {
            tracing::debug!("Import AZIHSM_DERIVED_KEY_IMPORT_BLOB");

            if key_blob.len() != std::mem::size_of::<usize>() {
                tracing::error!(
                    "Invalid key_blob length: expected {}, got {}",
                    std::mem::size_of::<usize>(),
                    key_blob.len()
                );
                return NTE_INVALID_PARAMETER;
            }

            let handle = match key_blob.try_into() {
                Ok(bytes) => usize::from_be_bytes(bytes),
                Err(_) => {
                    tracing::error!("Failed to convert key_blob to usize");
                    return NTE_INVALID_PARAMETER;
                }
            };

            match prov.get_key(handle) {
                Some(_) => unsafe {
                    *imported_key_handle = NCRYPT_KEY_HANDLE(handle);
                },
                None => {
                    tracing::error!(?handle, "Derived key not found for handle");
                    return NTE_NOT_FOUND;
                }
            }
        }
        // ECDH Public key import
        else if pcwstr::equals(pszblobtype, BCRYPT_ECCPUBLIC_BLOB)
            | pcwstr::equals(pszblobtype, BCRYPT_PUBLIC_KEY_BLOB)
        {
            tracing::debug!("Import public key blob");

            let handle = match prov.import_bcrypt_blob(key_blob) {
                Ok(handle) => handle,
                Err(err) => {
                    tracing::error!(%err, "Failed to import key.");
                    return err;
                }
            };

            unsafe {
                *imported_key_handle = NCRYPT_KEY_HANDLE(handle);
            }
        }
        // Plain-text key import
        else if pcwstr::equals(pszblobtype, NCRYPT_OPAQUETRANSPORT_BLOB) {
            tracing::debug!("Import Plain-text key");

            let handle = match prov.import_key(pszblobtype, key_blob) {
                Ok(handle) => handle,
                Err(err) => {
                    tracing::error!(%err, "Failed to import plain-text key.");
                    return err;
                }
            };

            unsafe {
                *imported_key_handle = NCRYPT_KEY_HANDLE(handle);
            }
        } else {
            tracing::error!(
                "Unsupported Blob type. Expecting BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB, AZIHSM_DERIVED_KEY_IMPORT_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_PUBLIC_KEY_BLOB or NCRYPT_OPAQUETRANSPORT_BLOB"
            );
            return NTE_INVALID_PARAMETER;
        }

        if !flags.contains(NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG)) {
            tracing::debug!("Finalize key during import_key");

            let handle = unsafe { *imported_key_handle };
            let result = prov.assign_default(handle.0);
            if let Err(err) = result {
                tracing::error!(?prov_handle, ?imported_key_handle, %err, "Failed to assign default key.");
                return err;
            }

            let result = prov.finalize_key(handle.0);
            match result {
                Ok(()) => {
                    tracing::debug!(
                        ?imported_key_handle,
                        "Key imported and finalized successfully."
                    );
                    S_OK
                }
                Err(err) => {
                    tracing::error!(?prov_handle, ?imported_key_handle, %err, "Failed to finalize key after import.");
                    err
                }
            }
        } else {
            tracing::debug!("Done importing key without finalizing it.");
            S_OK
        }
    })
}

/// Exports a key to memory Blob.
///
/// # Arguments
/// * `prov_handle`         - A handle of the key storage provider.
/// * `key_handle`          - A handle of the key to export
/// * `export_key_handle`   - An optional handle to a cryptographic key of the destination user. The key data within
/// *                         the exported key BLOB is encrypted using this key. This ensures that only
/// *                         the destination user is able to make use of the key BLOB
/// * `pszblobtype`         - A pointer to a null-terminated Unicode string that contains the type of key blob being exported.
/// * `pparameterlist`      - A pointer to a `BCryptBufferDesc` structure that contains the key export parameters.
/// * `pboutput`            - The address of a buffer that receives the exported key BLOB.
/// * `pcbresult`           - A pointer to a `u32` that receives the number of bytes copied to the pbOutput buffer.
/// *                         If the pbOutput parameter is NULL, this parameter will receive the buffer size of output in bytes
/// * `flags`               - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_export_key")]
extern "system" fn azihsm_export_key(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    _export_key_handle: NCRYPT_KEY_HANDLE,
    pszblobtype: PCWSTR,
    _pparameterlist: *const BCryptBufferDesc,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_export_key", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);
        validate_arg!(!pszblobtype.is_null());
        validate_arg!(!pcbresult.is_null());
        validate_allowed_flags!(flags, NCRYPT_SILENT_FLAG, prov);

        let output = match pboutput.is_null() {
            true => &mut [],
            false => {
                validate_arg!(cboutput > 0);
                unsafe { std::slice::from_raw_parts_mut(pboutput, cboutput as usize) }
            }
        };
        let result = unsafe { &mut *(pcbresult.cast::<u32>()) };

        let blob_type: KeyBlobType = pszblobtype.into();
        match blob_type {
            KeyBlobType::OpaqueTransport => match prov.export_key(key_handle.0, output, result) {
                Ok(_) => {
                    tracing::debug!("Public key export successful");
                    S_OK
                }
                Err(err) => {
                    tracing::error!(%err, "Failed to export public key");
                    err
                }
            },
            KeyBlobType::EccPublicBlob | KeyBlobType::RsaPublicBlob | KeyBlobType::PublicBlob => {
                match prov.export_bcrypt_blob(key_handle.0, blob_type, output, result) {
                    Ok(_) => {
                        tracing::debug!("Public key export successful");
                        S_OK
                    }
                    Err(err) => {
                        tracing::error!(%err, "Failed to export public key.");
                        err
                    }
                }
            }
            KeyBlobType::Unknown => {
                tracing::error!(
                    "Unsupported Blob type. Expecting NCRYPT_OPAQUETRANSPORT_BLOB or BCRYPT_PUBLIC_KEY_BLOB"
                );
                NTE_BAD_TYPE
            }
        }
    })
}

/// Opens the built-in unwrapping key.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `key_handle`  - The key handle.
/// * `key_name`    - The name of the key.
/// * `key_spec`    - The key specification (unused).
/// * `flags`       - Flags that modify the behavior of the function (unused).
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_open_key")]
extern "system" fn azihsm_open_key(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: *mut NCRYPT_KEY_HANDLE,
    key_name: PCWSTR,
    _key_spec: CERT_KEY_SPEC,
    _flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_open_key", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_arg!(!key_handle.is_null(), prov);
        validate_arg!(!key_name.is_null(), prov);
        tracing::debug!("[{}] Opening key [{}]", prov.handle(), string!(key_name));
        if !pcwstr::equals(key_name, AZIHSM_BUILTIN_UNWRAP_KEY) {
            tracing::error!("AZIHSMKSP currently does not support named keys");
            return NTE_NOT_FOUND;
        }

        let handle = match prov.open_key() {
            Ok(handle) => handle,
            Err(err) => {
                tracing::error!(%err, "Failed to open key.");
                return err;
            }
        };

        unsafe {
            *key_handle = NCRYPT_KEY_HANDLE(handle);
        }

        tracing::debug!("AZIHSM_BUILTIN_UNWRAP_KEY opened successfully",);
        S_OK
    })
}

/// Generates a secret agreement value from a private and a peer public key
///
/// # Arguments
/// * `prov_handle`         - A handle of the key storage provider.
/// * `priv_key`            - The handle of the private key to use to create the secret agreement value
/// * `pub_key`             - The imported handle of the peer's public key to use to create the secret agreement value
/// * `secret_agreement`    - A pointer to an NCRYPT_SECRET_HANDLE variable that receives a handle that represents the secret agreement value.
/// * `flags`               - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_generate_secret")]
extern "system" fn azihsm_generate_secret(
    prov_handle: NCRYPT_PROV_HANDLE,
    priv_key: NCRYPT_KEY_HANDLE,
    pub_key: NCRYPT_KEY_HANDLE,
    secret_agreement: *mut NCRYPT_SECRET_HANDLE,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_generate_secret", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(priv_key, prov);
        validate_handle!(pub_key, prov);
        validate_arg!(!secret_agreement.is_null(), prov);
        validate_allowed_flags!(flags, NCRYPT_SILENT_FLAG, prov);

        let secret_handle = match prov.generate_secret(priv_key.0, pub_key.0) {
            Ok(secret_handle) => secret_handle,
            Err(err) => {
                tracing::error!(%err, "Failed to generate the secret.");
                return err;
            }
        };

        unsafe {
            *secret_agreement = NCRYPT_SECRET_HANDLE(secret_handle);
        }

        tracing::debug!(?secret_agreement, "Secret generated successfully!");
        S_OK
    })
}

/// Deletes a secret.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `secret_handle`  - The secret handle.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_delete_secret")]
extern "system" fn azihsm_delete_secret(
    prov_handle: NCRYPT_PROV_HANDLE,
    secret_handle: NCRYPT_SECRET_HANDLE,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_delete_secret", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(secret_handle, prov);

        match prov.delete_secret(secret_handle.0) {
            Ok(_) => {
                tracing::debug!(?secret_handle, "Secret deleted.");
                S_OK
            }
            Err(err) => {
                tracing::error!(%err, "Failed to delete the secret.");
                err
            }
        }
    })
}

/// Retrieves a provider property.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `property`    - The name of the property to retrieve.
/// * `pboutput`    - The output buffer that receives the property value.
/// * `cboutput`    - The size, in bytes, of the output buffer.
/// * `pcbresult`   - A pointer to a `u32` that receives the number of bytes of the property value written to the output buffer.
/// * `flags`       - Flags that modify the behavior of the function.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(
    feature = "expose-symbols",
    export_name = "azihsm_get_provider_property"
)]
extern "system" fn azihsm_get_provider_property(
    prov_handle: NCRYPT_PROV_HANDLE,
    property: PCWSTR,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_get_provider_property", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_arg!(!property.is_null(), prov);
        validate_arg!(!pcbresult.is_null(), prov);
        validate_allowed_flags!(flags, NCRYPT_SILENT_FLAG, prov);

        let property = ProviderPropertyIdentifier::from(property);
        let output = match pboutput.is_null() {
            true => &mut [],
            false => {
                validate_arg!(cboutput > 0, prov);
                unsafe { std::slice::from_raw_parts_mut(pboutput, cboutput as usize) }
            }
        };
        let result = unsafe { &mut *(pcbresult.cast::<u32>()) };
        match prov.get_provider_property(&property, output, result) {
            Ok(_) => {
                tracing::debug!(
                    ?property,
                    prov_handle = prov.handle(),
                    "Provider property retrieved"
                );
                S_OK
            }
            Err(err) => {
                tracing::error!(
                    ?property,
                    %err,
                    "Failed to retrieve provider property.",
                );
                err
            }
        }
    })
}

/// Creates an attestation claim for the key.
///
/// # Arguments
/// * `prov_handle`           - The provider handle.
/// * `key_handle`            - The key handle.
/// * `_authority_key_handle` - The key handle of the authority key (unused).
/// * `_claim_type`           - The type of the claim (unused).
/// * `pparameterlist`        - A pointer to a `BCryptBufferDesc` structure that contains the claim parameters.
/// * `pbclaimblob`           - The address of a buffer that receives the claim blob.
/// * `cbclaimblob`           - The size, in bytes, of the claim blob.
/// * `pcbresult`             - A pointer to a `u32` that receives the number of bytes copied to the `pbclaimblob` buffer.
/// * `dwflags`               - Flags that modify the behavior of the function. Must be set to 0.
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_create_claim")]
extern "system" fn azihsm_create_claim(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    authority_key_handle: NCRYPT_KEY_HANDLE,
    _claim_type: u32, // [TODO] check if a new claim type should be defined for AZIHSM
    pparameterlist: *const BCryptBufferDesc,
    pbclaimblob: *mut u8,
    cbclaimblob: u32,
    pcbresult: *mut u32,
    dwflags: u32,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_create_claim", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(key_handle, prov);
        validate_arg!(!pcbresult.is_null(), prov);
        validate_arg!(!pparameterlist.is_null(), prov);
        validate_arg!(authority_key_handle.is_invalid(), prov); // Authority key is not supported; make sure it is NULL.
        validate_arg!(dwflags == 0, prov); // dwFlags must be set to 0.

        let buffer_desc: &BCryptBufferDesc = unsafe { &*(pparameterlist as *const _) };
        if buffer_desc.ulVersion != BCRYPTBUFFER_VERSION {
            tracing::error!(
                "Invalid BCryptBufferDesc version {}. Expecting BCRYPTBUFFER_VERSION",
                buffer_desc.ulVersion
            );
            return NTE_INVALID_PARAMETER;
        }

        let mut report_data: Option<&[u8; REPORT_DATA_SIZE as usize]> = None;
        for buffer_index in 0..buffer_desc.cBuffers {
            let buffer = unsafe { &*buffer_desc.pBuffers.add(buffer_index as usize) };
            let buffer_type = buffer.BufferType;
            let buffer_size = buffer.cbBuffer;
            let buffer_data = unsafe {
                std::slice::from_raw_parts(buffer.pvBuffer as *const u8, buffer_size as usize)
            };

            tracing::debug!(
                "BCryptBufferDesc buffer[{}]: type: {}, size: {}",
                buffer_index,
                buffer_type,
                buffer_size
            );

            if buffer_type == NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE {
                if buffer_size != REPORT_DATA_SIZE {
                    tracing::error!(
                        "Invalid report data size {}, expecting {}",
                        buffer_size,
                        REPORT_DATA_SIZE
                    );
                    return NTE_INVALID_PARAMETER;
                }
                report_data = Some(match buffer_data.try_into() {
                    Ok(data) => data,
                    Err(_) => {
                        tracing::error!("Failed to convert buffer_data to &[u8; 128]");
                        return NTE_INVALID_PARAMETER;
                    }
                });
                break;
            }
        }

        let report_data = match report_data {
            Some(data) => data,
            None => {
                tracing::error!("Missing report data in BCryptBufferDesc");
                return NTE_INVALID_PARAMETER;
            }
        };

        let output = match pbclaimblob.is_null() {
            true => &mut [],
            false => {
                validate_arg!(cbclaimblob > 0, prov);
                unsafe { std::slice::from_raw_parts_mut(pbclaimblob, cbclaimblob as usize) }
            }
        };
        let result = unsafe { &mut *(pcbresult.cast::<u32>()) };
        match prov.create_claim(key_handle.0, report_data, output, result) {
            Ok(_) => {
                tracing::debug!(?key_handle, "Claim created successfully.");
                S_OK
            }
            Err(err) => {
                tracing::error!(%err, "Failed to create claim.");
                err
            }
        }
    })
}

/// Derives a key from a shared secret.
///
/// # Arguments
/// * `prov_handle`         - The provider handle.
/// * `secret_key_handle`   - The shared secret key handle.
/// * `pwszkdf`             - A pointer to a null-terminated Unicode string that identifies the key derivation function (KDF).
/// * `pparameterlist`      - A pointer to a `BCryptBufferDesc` structure that contains the KDF parameters.
/// * `pbderivedkey`        - A pointer to the user buffer. This will contain the key handle of the derived key.
/// * `cbderivedkey`        - The size, in bytes, of the user buffer.
/// * `pcbresult`           - A pointer to a `u32` that receives the size of the derived key handle. If pbderivedkey is NULL, this receives the size of the key handle.
/// * `flags`               - Flags that modify the behavior of the function. (unused)
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_derive_key")]
extern "system" fn azihsm_derive_key(
    prov_handle: NCRYPT_PROV_HANDLE,
    secret_key_handle: NCRYPT_SECRET_HANDLE,
    pwszkdf: PCWSTR,
    pparameterlist: *const BCryptBufferDesc,
    pbderivedkey: *mut u8,
    cbderivedkey: u32,
    pcbresult: *mut u32,
    _flags: u32,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_derive_key", ?prov_handle);
        tracing::debug!("Deriving key with function {:?}", pwszkdf);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_handle!(secret_key_handle, prov);
        validate_arg!(!pwszkdf.is_null());
        validate_arg!(!pparameterlist.is_null());
        validate_arg!(!pcbresult.is_null());

        // Get the pcbresult ref.
        let result = unsafe { &mut *(pcbresult.cast::<u32>()) };
        let parameter_list = unsafe { &*pparameterlist };
        if parameter_list.cBuffers == 0 || parameter_list.pBuffers.is_null() {
            tracing::error!("Empty parameter list.");
            return NTE_INVALID_PARAMETER;
        }
        if parameter_list.ulVersion != BCRYPTBUFFER_VERSION {
            tracing::error!(
                "Unsupported/Invalid BCryptBufferDesc version {}. Expecting {}",
                parameter_list.ulVersion,
                BCRYPTBUFFER_VERSION
            );
            return NTE_INVALID_PARAMETER;
        }

        if pbderivedkey.is_null() {
            *result = std::mem::size_of::<Handle>() as u32;
            return S_OK;
        } else {
            validate_arg!(cbderivedkey > 0);
        }

        let key_handle = match prov.derive_key(secret_key_handle.0, pwszkdf, parameter_list) {
            Ok(key_handle) => {
                tracing::debug!(?secret_key_handle, "Key derived successfully.");
                key_handle
            }
            Err(err) => {
                tracing::error!(%err, "Failed to derive key.");
                return err;
            }
        };
        // Send the key handle back to the caller.
        let derived_key =
            unsafe { std::slice::from_raw_parts_mut(pbderivedkey, cbderivedkey as usize) };
        if cbderivedkey as usize >= std::mem::size_of::<Handle>() {
            derived_key[..std::mem::size_of::<Handle>()].copy_from_slice(&key_handle.to_be_bytes());
            *result = std::mem::size_of::<Handle>() as u32;
        } else {
            tracing::error!(
                "cbderivedkey [{:?}] is too small for the copy operation. Expected at least [{:?}].",
                cbderivedkey,
                std::mem::size_of::<Handle>()
            );
            return NTE_BUFFER_TOO_SMALL;
        }
        S_OK
    })
}

extern "system" fn azihsm_set_provider_property(
    _hprovider: NCRYPT_PROV_HANDLE,
    _pszproperty: PCWSTR,
    _pbinput: *const u8,
    _cbinput: u32,
    _dwflags: u32,
) -> HRESULT {
    dll::boundary(|| NTE_NOT_SUPPORTED)
}

#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_free_buffer")]
extern "system" fn azihsm_free_buffer(pvinput: *mut c_void) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_free_buffer");
        let _enter = span.enter();

        if pvinput.is_null() {
            return S_OK;
        }

        let result = unsafe { free(pvinput as *mut std::ffi::c_void) };

        match result {
            Ok(_) => {
                tracing::debug!("Finished azihsm_free_buffer");
                S_OK
            }
            Err(err) => {
                tracing::error!(%err, "Failed to free buffer");
                err
            }
        }
    })
}

/// Check if given algorithm is supported by the provider.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `algorithm`   - The algorithm to check.
/// * `flags`       - Flags that modify the behavior of the function. Can be 0 or NCRYPT_SILENT_FLAG
///
/// # Returns
/// `S_OK` if the algorithm is supported, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_is_alg_supported")]
extern "system" fn azihsm_is_alg_supported(
    prov_handle: NCRYPT_PROV_HANDLE,
    algorithm: PCWSTR,
    flags: u32,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_is_alg_supported", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_arg!(!algorithm.is_null());

        // We don't use the flag, still check for valid value
        let flags = NCRYPT_FLAGS(flags);
        validate_allowed_flags!(flags, NCRYPT_SILENT_FLAG, prov);

        let supported = is_alg_supported(algorithm);

        tracing::debug!(?supported, "Finished azihsm_is_alg_supported");
        if supported {
            S_OK
        } else {
            NTE_NOT_SUPPORTED
        }
    })
}

/// List algorithms supported by the provider.
///
/// # Arguments
/// * `prov_handle` - The provider handle.
/// * `algoclass`   - The algorithm class to enumerate.
/// * `count`       - A pointer to a `u32` that receives the length of algolist.
/// * `algolist`    - A pointer to a list of NCryptAlgorithmName.
/// * `flags`       - Flags that modify the behavior of the function. Can be 0 or NCRYPT_SILENT_FLAG
///
/// # Returns
/// `S_OK` if the function succeeds, otherwise an error code.
///
#[cfg_attr(feature = "expose-symbols", export_name = "azihsm_enum_algorithms")]
extern "system" fn azihsm_enum_algorithms(
    prov_handle: NCRYPT_PROV_HANDLE,
    algclass: u32,
    count: *mut u32,
    alglist: *mut *mut NCryptAlgorithmName,
    flags: u32,
) -> HRESULT {
    dll::boundary(|| {
        let span = tracing::debug_span!("azihsm_enum_algorithms", ?prov_handle);
        let _enter = span.enter();

        let prov = provider!(prov_handle);
        validate_arg!(!count.is_null());
        validate_arg!(!alglist.is_null());

        // Dereference pointers
        let count = unsafe { &mut *count };
        let algolist = unsafe { &mut *alglist };

        // We don't use the flag, still check for valid value
        let flags = NCRYPT_FLAGS(flags);
        validate_allowed_flags!(flags, NCRYPT_SILENT_FLAG, prov);

        // validate algoclass
        let algclass = NCRYPT_OPERATION(algclass);
        if algclass
            & !(NCRYPT_CIPHER_OPERATION
                | NCRYPT_HASH_OPERATION
                | NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION
                | NCRYPT_SECRET_AGREEMENT_OPERATION
                | NCRYPT_SIGNATURE_OPERATION)
            != NCRYPT_OPERATION(0)
        {
            tracing::error!(?prov_handle, ?algclass, "Invalid algorithm class");
            return NTE_INVALID_PARAMETER;
        }

        let algorithms = enum_algorithms(algclass);
        let algorithms_count = algorithms.len();

        // User should free it later with NCryptFreeBuffer
        let result = unsafe { allocate(algorithms) };
        if result.is_err() {
            tracing::error!("Failed to allocate memory for algorithm list");
            return result.unwrap_err();
        }
        let ptr = result.unwrap();

        *count = algorithms_count as u32;
        *algolist = ptr;

        tracing::debug!(size = *count, "Finished azihsm_enum_algorithms");
        S_OK
    })
}

extern "system" fn azihsm_enum_keys(
    _hprovider: NCRYPT_PROV_HANDLE,
    _pszscope: PCWSTR,
    _ppkeyname: *mut *mut NCryptKeyName,
    _ppenumstate: *mut *mut c_void,
    _dwflags: u32,
) -> HRESULT {
    dll::boundary(|| NTE_NOT_SUPPORTED)
}

extern "system" fn azihsm_prompt_user(
    _hprovider: NCRYPT_PROV_HANDLE,
    _hkey: NCRYPT_KEY_HANDLE,
    _pszoperation: PCWSTR,
    _dwflags: u32,
) -> HRESULT {
    dll::boundary(|| NTE_NOT_SUPPORTED)
}

extern "system" fn azihsm_notify_change_key(
    _hprovider: NCRYPT_PROV_HANDLE,
    _phevent: *mut *mut c_void,
    _dwflags: u32,
) -> HRESULT {
    dll::boundary(|| NTE_NOT_SUPPORTED)
}

extern "system" fn azihsm_key_derivation(
    _hprovider: NCRYPT_PROV_HANDLE,
    _hkey: NCRYPT_KEY_HANDLE,
    _pparameterlist: *const BCryptBufferDesc,
    _pbderivedkey: *mut u8,
    _cbderivedkey: u32,
    _pcbresult: *mut u32,
    _dwflags: u32,
) -> HRESULT {
    dll::boundary(|| NTE_NOT_SUPPORTED)
}

extern "system" fn azihsm_verify_claim(
    _hprov: NCRYPT_PROV_HANDLE,
    _hsubjectkey: NCRYPT_KEY_HANDLE,
    _hauthoritykey: NCRYPT_KEY_HANDLE,
    _dwclaimtype: u32,
    _pparameterlist: *const BCryptBufferDesc,
    _pbclaimblob: *const u8,
    _cbclaimblob: u32,
    _poutput: *mut BCryptBufferDesc,
    _dwflags: u32,
) -> HRESULT {
    dll::boundary(|| NTE_NOT_SUPPORTED)
}
