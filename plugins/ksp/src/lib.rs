// Copyright (C) Microsoft Corporation. All rights reserved.

mod algorithms;
mod config;
mod errors;
mod etw_tracing;
mod handle_table;
mod interface;
mod key;
mod ncrypt_types;
mod provider;
mod utils;

use etw_tracing::register_tracing_subscriber;
use utils::*;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::SystemServices::*;

pub(crate) type AzIHsmHresult<T> = core::result::Result<T, HRESULT>;

/// The name of the key storage provider.
pub(crate) const AZIHSM_KSP_NAME: PCWSTR =
    w!("Microsoft Azure Integrated HSM Key Storage Provider");

/// The property name for AZIHSM device cert chain.
pub(crate) const AZIHSM_DEVICE_CERT_CHAIN_PROPERTY: PCWSTR =
    w!("AZIHSM_DEVICE_CERT_CHAIN_PROPERTY");

/// The property names for AZIHSM device Resource capacity.
/// 4 bytes, holds the little-endian representation of Max number of keys this device can hold
pub(crate) const AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY: PCWSTR =
    w!("AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY");

/// 4 bytes, holds the little-endian representation of Max total size of keys this device can hold, in Kilo Bytes
pub(crate) const AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY: PCWSTR =
    w!("AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY");

/// The name of the built-in unwrap key.
pub(crate) const AZIHSM_BUILTIN_UNWRAP_KEY: PCWSTR = w!("AZIHSM_BUILTIN_UNWRAP_KEY");

/// Data structures and constants for PKCS#11 RSA AES wrap key blob
pub(crate) const BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB: PCWSTR = w!("PKCS11RsaAesWrapBlob");
pub(crate) const BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC: u32 = 0x57504152;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub(crate) struct BCRYPT_PKCS11_RSA_AES_WRAP_BLOB {
    pub dw_magic: u32,          // BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC
    pub cb_key: u32,            // Number of bytes in the binary PKCS#11 wrapped key blob
    pub cb_padding_alg_id: u32, // Number of bytes in OAEP Padding algorithm per OAEPParams in PKCS#11 specification
    pub cb_padding_label: u32, // Number of bytes in OAEP Padding label per OAEPParams in PKCS#11 specification
}

/// The size of the report data used in azihsm_create_claim API.
pub(crate) const REPORT_DATA_SIZE: u32 = 128;

/// The `AZIHSM_DERIVED_KEY_IMPORT_BLOB` type is used to import a derived key after
/// a Key Derivation Function (KDF) operation.
pub(crate) const AZIHSM_DERIVED_KEY_IMPORT_BLOB: PCWSTR = w!("AzIHsmDerivedKeyImportBlob");

/// Windows dynamic-link library entry point.
#[export_name = "DllMain"]
extern "system" fn dll_main(_: HINSTANCE, reason: u32, _: *mut ()) -> bool {
    std::panic::catch_unwind(|| {
        match reason {
            DLL_PROCESS_ATTACH => {
                // Setup ETW tracing
                let ret = register_tracing_subscriber();
                tracing::info!(
                    "DLL_PROCESS_ATTACH with ret {}. CARGO_PKG_VERSION={}",
                    ret,
                    env!("CARGO_PKG_VERSION")
                );
            }
            DLL_PROCESS_DETACH => {}
            _ => {}
        }
        true
    })
    .is_ok()
}

/// Registers the cryptographic service provider.
#[export_name = "DllRegisterServer"]
extern "system" fn dll_register_server() -> HRESULT {
    dll::boundary(|| match config::register_ksp() {
        Ok(_) => S_OK,
        Err(hr) => hr,
    })
}

/// Unregisters the cryptographic service provider.
#[export_name = "DllUnregisterServer"]
extern "system" fn dll_unregister_server() -> HRESULT {
    dll::boundary(|| match config::unregister_ksp() {
        Ok(_) => S_OK,
        Err(hr) => hr,
    })
}
