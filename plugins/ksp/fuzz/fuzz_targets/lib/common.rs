// Copyright (C) Microsoft Corporation. All rights reserved.

/// This file implements common functions used across several (or all) KSP
/// fuzzing harnesses.

// Imports
use std::ptr;
use rand::{rngs::StdRng, SeedableRng};
use widestring::U16CString;

// Windows imports.
//
// See the Rust docs for the Windows Cryptography API here:
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Cryptography/
#[cfg(target_os = "windows")]
use windows::{
    Win32::Security::Cryptography::{
        NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_SECRET_HANDLE,
    },
    core::PCWSTR,
};

// Only import the NCrypt API functions if we're not using the
// `direct-invoke-dll` feature.
#[cfg(not(feature = "direct-invoke-dll"))]
use windows::Win32::Security::Cryptography::{
    NCryptCreateClaim, NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey,
    NCryptEncrypt, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject,
    NCryptGetProperty, NCryptImportKey, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSecretAgreement, NCryptSetProperty,
    NCryptSignHash, NCryptVerifySignature,
};

#[cfg(feature = "direct-invoke-dll")]
use windows::Win32::Security::Cryptography::{
    NCRYPT_FLAGS, CERT_KEY_SPEC, BCryptBufferDesc,
};
#[cfg(feature = "direct-invoke-dll")]
use winapi::ctypes::c_void;

// Imports for the `direct-invoke-dll` feature.
#[cfg(feature = "direct-invoke-dll")]
use std::path::PathBuf;
#[cfg(feature = "direct-invoke-dll")]
use walkdir::WalkDir;
#[cfg(feature = "direct-invoke-dll")]
use libloading::{Library, Symbol};
#[cfg(feature = "direct-invoke-dll")]
use std::env;
#[cfg(feature = "direct-invoke-dll")]
use std::sync::OnceLock;
#[cfg(feature = "direct-invoke-dll")]
use windows::core::HRESULT;

// Local imports
use crate::payloads;

// ================================ Globals ================================= //
/// Redefinition of the KSP name string for AZIHSM. (The one defined in
/// `plugins/ksp/lib.rs` is only visible at the crate level.)
pub const AZIHSMKSP_NAME: &str = "Microsoft Azure Integrated HSM Key Storage Provider";

/// Redefinition of the KSP built-in unwrapping key for AZIHSM.
#[allow(dead_code)]
pub const AZIHSMKSP_BUILTIN_UNWRAP_KEY_NAME: &str = "AZIHSM_BUILTIN_UNWRAP_KEY";

/// Redefinition of the AZIHSM KSP device cert chain property name.
#[allow(dead_code)]
pub const AZIHSMKSP_DEVICE_CERT_CHAIN_PROPERTY: &str = "AZIHSM_DEVICE_CERT_CHAIN_PROPERTY";

/// Redefinition of the AZIHSM KSP RSA key property that's used to
/// enable/disable CRT when importing an RSA key.
pub const AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED: &str = "RsaCrtEnabled";

/// Redefinition of the AZIHSM KSP PKCS11 RSA/AES Wrap Key Blob string.
#[allow(dead_code)]
pub const AZIHSMKSP_BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB: &str = "PKCS11RsaAesWrapBlob";

/// The maximum size of the buffer passed into `NCryptGetProperty()`.
#[allow(dead_code)]
pub const PROPERTY_BUFFER_MAXLEN: usize = 2048;

/// The maximum size of the input buffer passed into `NCryptEncrypt()`.
#[allow(dead_code)]
pub const ENCRYPT_PLAINTEXT_BUFFER_MAXLEN: usize = 2048;

/// The maximum size of the output buffer passed into `NCryptEncrypt()`.
#[allow(dead_code)]
pub const ENCRYPT_CIPHERTEXT_BUFFER_MAXLEN: usize = 2048;

/// The maximum size of the input buffer passed into `NCryptDecrypt()`.
#[allow(dead_code)]
pub const DECRYPT_PLAINTEXT_BUFFER_MAXLEN: usize = ENCRYPT_PLAINTEXT_BUFFER_MAXLEN;

/// The maximum size of the output buffer passed into `NCryptDecrypt()`.
#[allow(dead_code)]
pub const DECRYPT_CIPHERTEXT_BUFFER_MAXLEN: usize = ENCRYPT_CIPHERTEXT_BUFFER_MAXLEN;

/// The maximum size of the buffer passed into `NCryptImportKey()`.
#[allow(dead_code)]
pub const IMPORT_KEY_BUFFER_MAXLEN: usize = 2048;

/// The maximum size of the buffer passed into `NCryptExportKey()`.
#[allow(dead_code)]
pub const EXPORT_KEY_BUFFER_MAXLEN: usize = IMPORT_KEY_BUFFER_MAXLEN;

/// The maximum size of the buffer passed into `NCryptSignHash()`.
#[allow(dead_code)]
pub const HASH_BUFFER_MAXLEN: usize = 2048;

/// The maximum size of the buffer passed into `NCryptVerifySignature()`.
#[allow(dead_code)]
pub const SIGNATURE_BUFFER_MAXLEN: usize = HASH_BUFFER_MAXLEN;

/// The maximum size of the buffer passed into `NCryptCreateClaim()`.
#[allow(dead_code)]
pub const CLAIM_BUFFER_MAXLEN: usize = 2048;


// ========================= Direct DLL Invocation ========================== //
/// The name of the environment variable that will be checked for the presence
/// of a path to the KSP DLL.
#[cfg(feature = "direct-invoke-dll")]
pub const DLL_PATH_ENV_NAME: &str = "AZIHSMKSP_DLL_PATH";

/// The name of the DLL file to load.
#[cfg(feature = "direct-invoke-dll")]
pub const DLL_NAME: &str = "azihsmksp.dll";

/// Type definition for `azihsm_open_provider`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeOpenProvider = extern "system" fn(
    prov_handle: *mut NCRYPT_PROV_HANDLE,
    prov_name: PCWSTR,
    _flags: u32,
) -> HRESULT;

/// Type definition for `azihsm_close_provider`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeCloseProvider = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
) -> HRESULT;

/// Type definition for `azihsm_open_key`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeOpenKey = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: *mut NCRYPT_KEY_HANDLE,
    key_name: PCWSTR,
    _key_spec: CERT_KEY_SPEC,
    _flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_free_key`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeFreeKey = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
) -> HRESULT;

/// Type definition for `azihsm_create_persisted_key`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeCreateKey = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: *mut NCRYPT_KEY_HANDLE,
    algo: PCWSTR,
    key_name: PCWSTR,
    _key_spec: CERT_KEY_SPEC,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_delete_key`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeDeleteKey = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_finalize_key`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeFinalizeKey = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_get_provider_property`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeGetProviderProperty = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    property: PCWSTR,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_get_key_property`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeGetKeyProperty = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    property: PCWSTR,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_set_key_property`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeSetKeyProperty = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    property: PCWSTR,
    pbinput: *mut u8,
    cbinput: u32,
    _flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_encrypt`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeEncrypt = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    pbinput: *const u8,
    cbinput: u32,
    ppaddinginfo: *const c_void,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_decrypt`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeDecrypt = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    pbinput: *const u8,
    cbinput: u32,
    ppaddinginfo: *const c_void,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_import_key`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeImportKey = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    import_key_handle: NCRYPT_KEY_HANDLE,
    pszblobtype: PCWSTR,
    pparameterlist: *const BCryptBufferDesc,
    imported_key_handle: *mut NCRYPT_KEY_HANDLE,
    pbdata: *const u8,
    cbdata: u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_export_key`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeExportKey = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    _export_key_handle: NCRYPT_KEY_HANDLE,
    pszblobtype: PCWSTR,
    _pparameterlist: *const BCryptBufferDesc,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_sign`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeSign = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    ppaddinginfo: *const c_void,
    pbhashvalue: *const u8,
    cbhashvalue: u32,
    pbsignature: *mut u8,
    cbsignature: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_verify`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeVerify = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    ppaddinginfo: *const c_void,
    pbhashvalue: *const u8,
    cbhashvalue: u32,
    pbsignature: *const u8,
    cbsignature: u32,
    dwflags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_generate_secret`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeGenerateSecret = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    priv_key: NCRYPT_KEY_HANDLE,
    pub_key: NCRYPT_KEY_HANDLE,
    secret_agreement: *mut NCRYPT_SECRET_HANDLE,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

/// Type definition for `azihsm_create_claim`.
#[cfg(feature = "direct-invoke-dll")]
pub type DllFuncTypeCreateClaim = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    authority_key_handle: NCRYPT_KEY_HANDLE,
    _claim_type: u32,
    pparameterlist: *const BCryptBufferDesc,
    pbclaimblob: *mut u8,
    cbclaimblob: u32,
    pcbresult: *mut u32,
    dwflags: u32,
) -> HRESULT;

/// A struct containing one field per function type used by the fuzzing tests,
/// when compiling with the `direct-invoke-dll` feature.
#[cfg(feature = "direct-invoke-dll")]
#[derive(Debug)]
pub struct DllFuncTable {
    open_provider: Symbol<'static, DllFuncTypeOpenProvider>,
    close_provider: Symbol<'static, DllFuncTypeCloseProvider>,
    open_key: Symbol<'static, DllFuncTypeOpenKey>,
    free_key: Symbol<'static, DllFuncTypeFreeKey>,
    create_key: Symbol<'static, DllFuncTypeCreateKey>,
    delete_key: Symbol<'static, DllFuncTypeDeleteKey>,
    finalize_key: Symbol<'static, DllFuncTypeFinalizeKey>,
    get_provider_property: Symbol<'static, DllFuncTypeGetProviderProperty>,
    get_key_property: Symbol<'static, DllFuncTypeGetKeyProperty>,
    set_key_property: Symbol<'static, DllFuncTypeSetKeyProperty>,
    encrypt: Symbol<'static, DllFuncTypeEncrypt>,
    decrypt: Symbol<'static, DllFuncTypeDecrypt>,
    import_key: Symbol<'static, DllFuncTypeImportKey>,
    export_key: Symbol<'static, DllFuncTypeExportKey>,
    sign: Symbol<'static, DllFuncTypeSign>,
    verify: Symbol<'static, DllFuncTypeVerify>,
    generate_secret: Symbol<'static, DllFuncTypeGenerateSecret>,
    create_claim: Symbol<'static, DllFuncTypeCreateClaim>,
}

#[cfg(feature = "direct-invoke-dll")]
static DLL: OnceLock<Option<Library>> = OnceLock::new();
#[cfg(feature = "direct-invoke-dll")]
static DLL_FUNC_TABLE: OnceLock<Option<DllFuncTable>> = OnceLock::new();

/// Searches for the KSP DLL within the given directory.
#[cfg(feature = "direct-invoke-dll")]
fn dll_find(target_dir: &PathBuf) -> Result<PathBuf, String> {
    for result in WalkDir::new(target_dir.to_str().unwrap()) {
        if let Err(err) = result {
            return Err(String::from(format!(
                "failed to retrieve directory entry: {:?}",
                err
            )));
        }
        let entry = result.unwrap();

        // skip any entries that aren't files
        if !entry.file_type().is_file() {
            continue;
        }

        // does the file name match the expected DLL name?
        if entry.file_name().eq(DLL_NAME) {
            return Ok(PathBuf::from(entry.path()));
        }
    }

    Err(String::from(format!(
        "failed to find DLL within `{}`",
        target_dir.to_str().unwrap()
    )))
}

/// Loads the DLL from the provided file path.
#[cfg(feature = "direct-invoke-dll")]
pub fn dll_load(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // load the library
    let lib = unsafe { Library::new(path.as_path())? };
    DLL.set(Some(lib)).expect(
        "Failed to set global KSP DLL object"
    );

    Ok(())
}

/// Loads functions from the DLL, which was previously loaded within
/// `dll_load()`.
#[cfg(feature = "direct-invoke-dll")]
pub fn dll_load_functions() -> Result<(), Box<dyn std::error::Error>> {
    // get a reference to the library
    let lib = dll_get_lib();

    // using the library, load several other functions that are needed by
    // the below `azihsmksp_*()` functions
    let func_open_provider: Symbol<DllFuncTypeOpenProvider> = unsafe { lib.get(b"azihsm_open_provider")? };
    let func_close_provider: Symbol<DllFuncTypeCloseProvider> = unsafe { lib.get(b"azihsm_close_provider")? };
    let func_open_key: Symbol<DllFuncTypeOpenKey> = unsafe { lib.get(b"azihsm_open_key")? };
    let func_free_key: Symbol<DllFuncTypeFreeKey> = unsafe { lib.get(b"azihsm_free_key")? };
    let func_create_persisted_key: Symbol<DllFuncTypeCreateKey> = unsafe { lib.get(b"azihsm_create_persisted_key")? };
    let func_delete_key: Symbol<DllFuncTypeDeleteKey> = unsafe { lib.get(b"azihsm_delete_key")? };
    let func_finalize_key: Symbol<DllFuncTypeFinalizeKey> = unsafe { lib.get(b"azihsm_finalize_key")? };
    let func_get_provider_property: Symbol<DllFuncTypeGetProviderProperty> = unsafe { lib.get(b"azihsm_get_provider_property")? };
    let func_get_key_property: Symbol<DllFuncTypeGetKeyProperty> = unsafe { lib.get(b"azihsm_get_key_property")? };
    let func_set_key_property: Symbol<DllFuncTypeSetKeyProperty> = unsafe { lib.get(b"azihsm_set_key_property")? };
    let func_encrypt: Symbol<DllFuncTypeEncrypt> = unsafe { lib.get(b"azihsm_encrypt")? };
    let func_decrypt: Symbol<DllFuncTypeDecrypt> = unsafe { lib.get(b"azihsm_decrypt")? };
    let func_import_key: Symbol<DllFuncTypeImportKey> = unsafe { lib.get(b"azihsm_import_key")? };
    let func_export_key: Symbol<DllFuncTypeExportKey> = unsafe { lib.get(b"azihsm_export_key")? };
    let func_sign: Symbol<DllFuncTypeSign> = unsafe { lib.get(b"azihsm_sign")? };
    let func_verify: Symbol<DllFuncTypeVerify> = unsafe { lib.get(b"azihsm_verify")? };
    let func_generate_secret: Symbol<DllFuncTypeGenerateSecret> = unsafe { lib.get(b"azihsm_generate_secret")? };
    let func_create_claim: Symbol<DllFuncTypeCreateClaim> = unsafe { lib.get(b"azihsm_create_claim")? };

    // construct the function table and return
    let table = DllFuncTable {
        open_provider: func_open_provider,
        close_provider: func_close_provider,
        open_key: func_open_key,
        free_key: func_free_key,
        create_key: func_create_persisted_key,
        delete_key: func_delete_key,
        finalize_key: func_finalize_key,
        get_provider_property: func_get_provider_property,
        get_key_property: func_get_key_property,
        set_key_property: func_set_key_property,
        encrypt: func_encrypt,
        decrypt: func_decrypt,
        import_key: func_import_key,
        export_key: func_export_key,
        sign: func_sign,
        verify: func_verify,
        generate_secret: func_generate_secret,
        create_claim: func_create_claim,
    };

    // save fields from this function to the `OnceLock` globals
    DLL_FUNC_TABLE.set(Some(table)).expect(
        "Failed to set global KSP DLL function table"
    );

    Ok(())
}

/// Initialization function that should be called by any of the below
/// `azihsmksp_*()` functions prior to attempting to retrieve any function
/// handles from the loaded DLL.
#[cfg(feature = "direct-invoke-dll")]
pub fn dll_init() -> Result<(), String> {
    // is the DLL function table already initialized? If so, we can return early
    if DLL_FUNC_TABLE.get().is_some() {
        return Ok(());
    }

    let mut dll_pathbuf: Option<PathBuf> = None;

    // was a path to the DLL specified via an environment variable?
    if let Ok(dll_path) = env::var(DLL_PATH_ENV_NAME) {
        let pathbuf = PathBuf::from(dll_path);
        eprintln!(
            "Retrieved DLL path from environment variable: {}",
            pathbuf.to_str().expect("Failed to convert PathBuf to string")
        );

        // make sure the string we got from the environment variable actually
        // points to a file that exists
        if !pathbuf.is_file() {
            return Err(format!(
                "The file path provided via the {} environment variable does not point to a valid file. \
                 Please specify the full, real path to the KSP DLL.",
                DLL_PATH_ENV_NAME
            ));
        }
        dll_pathbuf = Some(pathbuf);
    }

    // if not, search the cargo target directory, if applicable
    if dll_pathbuf.is_none() {
        if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
            let target_dir_pathbuf = PathBuf::from(target_dir);
            let target_dir_result = dll_find(&target_dir_pathbuf);
            if target_dir_result.is_ok() {
                let pathbuf = target_dir_result.unwrap();
                eprintln!(
                    "Found DLL path within CARGO_TARGET_DIR ({}): {}",
                    target_dir_pathbuf.to_str().expect("Failed to convert PathBuf to string"),
                    pathbuf.to_str().expect("Failed to convert PathBuf to string")
                );
                dll_pathbuf = Some(pathbuf);
            } else {
                eprintln!(
                    "Could not find DLL within CARGO_TARGET_DIR ({}).",
                    target_dir_pathbuf.to_str().expect("Failed to convert PathBuf to string"),
                );
            }
        }
    }

    // if not, search the current directory for the DLL
    if dll_pathbuf.is_none() {
        let current_dir = PathBuf::from(env::current_dir().expect(
            "Failed to retrieve the current working directory"
        ));
        let current_dir_pathbuf = dll_find(&current_dir);
        if current_dir_pathbuf.is_ok() {
            let pathbuf = current_dir_pathbuf.unwrap();
            eprintln!(
                "Found DLL path within current directory ({}): {}",
                current_dir.to_str().expect("Failed to convert PathBuf to string"),
                pathbuf.to_str().expect("Failed to convert PathBuf to string"),
            );
            dll_pathbuf = Some(pathbuf);
        } else {
            eprintln!(
                "Could not find DLL within current directory ({}).",
                current_dir.to_str().expect("Failed to convert PathBuf to string"),
            );
        }
    }

    // if all else fails, look for the DLL in System32
    if dll_pathbuf.is_none() {
        let system_dir = PathBuf::from("C:\\Windows\\System32");
        let system_dir_pathbuf = dll_find(&system_dir);
        if system_dir_pathbuf.is_ok() {
            let pathbuf = system_dir_pathbuf.unwrap();
            eprintln!(
                "Found DLL path within system32 directory ({}): {}",
                system_dir.to_str().expect("Failed to convert PathBuf to string"),
                pathbuf.to_str().expect("Failed to convert PathBuf to string"),
            );
            dll_pathbuf = Some(pathbuf);
        } else {
            eprintln!(
                "Could not find DLL within system32 directory ({}).",
                system_dir.to_str().expect("Failed to convert PathBuf to string"),
            );
        }
    }

    // if, at this point, we still haven't found a path to a DLL, error out
    if dll_pathbuf.is_none() {
        return Err(format!(
            "Could not locate the KSP DLL. \
             Please specify the path to the DLL by setting the {} environment variable.",
            DLL_PATH_ENV_NAME
        ));
    }

    // attempt to load the DLL, then load the function table
    dll_load(dll_pathbuf.as_ref().unwrap()).expect(
        "Failed to load the KSP DLL"
    );
    dll_load_functions().expect(
        "Failed to load the KSP DLL function table"
    );
    eprintln!("Loaded DLL function table successfully.");
    return Ok(());

}

/// Returns a static reference to the DLL library object.
#[cfg(feature = "direct-invoke-dll")]
pub fn dll_get_lib() -> &'static Library {
    &DLL.get().expect(
        "DLL not loaded"
    ).as_ref().unwrap()
}

/// Returns a static reference to the DLL function table.
#[cfg(feature = "direct-invoke-dll")]
pub fn dll_get_func_table() -> &'static DllFuncTable {
    &DLL_FUNC_TABLE.get().expect(
        "DLL function table not initialized"
    ).as_ref().unwrap()
}


// ========================= Miscellaneous Helpers ========================== //
/// Creates and returns a seeded random number generator.
#[allow(dead_code)]
pub fn rand_get(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Helper macro used by the below helper functions to create a widestring
/// representing the algorithm ID used by padding info structsc.
macro_rules! setup_padding_info_algid {
    ($input:expr) => {
        // if padding info was provided in the input struct, first attempt to
        // convert the algorithm ID string into a widestring. Depending on whether
        // or not this succeeds, we will create a struct to pass into NCrypt
        match $input {
            None => None,
            Some(pinfo) => pinfo.get_name_widestring().ok(),
        }
    }
}

/// Helper macro used by the below helper functions to create a padding info
/// struct, using the provided algorithm ID widestring that was previously
/// created using `setup_padding_info_algid!()`.
macro_rules! setup_padding_info_obj {
    ($input:expr, $padding_info_algo:expr) => {{
        // if converting the algorithm ID string to a widestring was successful, we
        // can proceed with creating a padding info object
        let mut padding_info: Option<Box<dyn std::any::Any>> = None;
        if $padding_info_algo.is_some() {
            let algo_str: &U16CString = $padding_info_algo.as_ref().unwrap();

            // generate the appropriate padding info struct (wrapped in a box)
            // and get a pointer to it
            let pinfo = $input.as_mut().unwrap();
            padding_info = Some(pinfo.get_struct(algo_str));
        }
        padding_info
    }}
}

/// Helper macro used by the below helper functions to create a pointer to the
/// padding info struct that was previously created using
/// `setup_padding_info_obj!()`.
macro_rules! setup_padding_info_ptr {
    ($input:expr, $padding_info:expr) => {{
        // if the provided padding info object is None, we'll use a null
        // pointer. Otherwise, create a `*const c_void` pointer that is
        // compatible with the NCrypt API
        match $padding_info {
            None => std::ptr::null(),
            Some(boxed_obj) => {
                let pinfo = $input.as_ref().unwrap();
                pinfo.get_struct_ptr(boxed_obj)
            }
        }
    }}
}


// ========================= AZIHSM KSP Helpers ========================== //
/// Attempts to open a AZIHSM KSP handle.
/// If expect_success is true, panics on failure. A panic here
/// suggests that the `azihsmksp.dll` DLL may not be installed correctly and/or may
/// not be able to be loaded by Windows.
/// If expect_success is false, this method will not panic on failure,
/// and will return the error.
pub fn azihsmksp_open(flags: &payloads::NCryptFlags, handle: &mut NCRYPT_PROV_HANDLE) -> windows::core::Result<()> {
    let expect_success = flags.raw == 0;
    let err_msg = format!(
        "! ======= NCryptOpenStorageProvider Failure ======= !\n\
         Failed to open a AZIHSM KSP handle.\n\
         \n\
         Please ensure the DLL is installed at \
         \"C:\\Windows\\System32\\azihsmksp.dll\".\n\
         Please ensure the DLL is registered by running:\
         \"regsvr32 C:\\Windows\\System32\\azihsmksp.dll\".\n\
         \n\
         It's possible the azihsmksp DLL failed to load. \
         Please use the Windows Debugger to investigate.\n\
         \n\
         1. Run `gflags /i path\\to\\your\\fuzzing_target.exe +sls` \
            to enable loader snapshots in the Windows Debugger.\n\
         2. Run `windbg path\\to\\your\\fuzzing_target.exe [fuzzing_target_args]` \
            to launch the debugger.\n\
         3. In the debugger, run `sxe ld azihsmksp.dll` \
            to set a breakpoint when the DLL is loaded.\n\
         \n\
         It's also possible you forgot to call `azihsmksp_close()` before your \
         fuzzing target exited. If that's the case, you may see this error \
         appear after a few executions of the fuzzer.\n\
         If your fuzzing target is calling `azihsmksp_open()`, make sure every \
         return-point calls `azihsmksp_close()`.\n\
         ! ================================================= !\n\
         "
    );

    let ksp_name = payloads::WindowsString::from(AZIHSMKSP_NAME);
    let ksp_name_utf16 = ksp_name.to_utf16();

    #[cfg(feature = "direct-invoke-dll")] {
        let dll = dll_get_func_table();
        let result: HRESULT = (dll.open_provider)(
            handle,
            PCWSTR::from_raw(ksp_name_utf16.as_ptr()),
            flags.raw,
        );

        if expect_success && result.is_err() {
            panic!("{}", err_msg);
        };

        result.ok()
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptOpenStorageProvider(
                handle,
                PCWSTR::from_raw(ksp_name_utf16.as_ptr()),
                flags.raw,
            )
        };

        if expect_success && result.is_err() {
            panic!("{}", err_msg);
        };

        result
    }
}

/// Closes the given AZIHSM KSP handle.
#[allow(dead_code)]
pub fn azihsmksp_close(handle: NCRYPT_PROV_HANDLE) {
    #[cfg(feature = "direct-invoke-dll")] {
        let dll = dll_get_func_table();
        let result = (dll.close_provider)(handle);
        if result.is_err() {
            panic!("Failed to free provider handle: {}", result.message());
        }
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        unsafe { NCryptFreeObject(handle) }.expect("Failed to free azihsmksp handle");
    }
}

/// Opens a key with the provided input payload. On success, `key` is updated to
/// store the key's handle.
#[allow(dead_code)]
pub fn azihsmksp_open_key(
    handle: NCRYPT_PROV_HANDLE,
    key: &mut NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptOpenKeyPayload,
) -> windows::core::Result<()> {
    let name = input.get_name();
    let name_utf16 = name.to_utf16();

    #[cfg(feature = "direct-invoke-dll")] {
        let dll = dll_get_func_table();
        (dll.open_key)(
            handle,
            key,
            PCWSTR::from_raw(name_utf16.as_ptr()),
            input.key_spec.as_cert_key_spec(),
            input.flags.as_ncrypt_flags(),
        ).ok()
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        unsafe {
            NCryptOpenKey(
                handle,
                key,
                PCWSTR::from_raw(name_utf16.as_ptr()),
                input.key_spec.as_cert_key_spec(),
                input.flags.as_ncrypt_flags(),
            )
        }
    }
}

/// Closes the given key handle.
#[allow(dead_code)]
pub fn azihsmksp_close_key(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE
) -> windows::core::Result<()> {
    #[cfg(feature = "direct-invoke-dll")] {
        let dll = dll_get_func_table();
        (dll.free_key)(
            handle,
            key
        ).ok()
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        unsafe { NCryptFreeObject(key) }
    }
}

/// Creates a new key with the KSP.
#[allow(dead_code)]
pub fn azihsmksp_create_key(
    handle: NCRYPT_PROV_HANDLE,
    key: &mut NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptCreatePersistedKeyPayload,
) -> windows::core::Result<()> {
    // decide what pointer to pass for the key name (a valid string *or* a
    // null string), based on `use_null_key_name`)
    let name_utf16 = input.key_name.to_utf16();
    let name: PCWSTR = if input.use_null_key_name {
        PCWSTR::null()
    } else {
        PCWSTR::from_raw(name_utf16.as_ptr())
    };

    // decide what pointer to pass for the algorithm name (a valid string
    // *or* a null string), based on `use_null_algorithm_name`)
    let alg_utf16 = input.algorithm.to_utf16();
    let alg: PCWSTR = if input.use_null_algorithm_name {
        PCWSTR::null()
    } else {
        PCWSTR::from_raw(alg_utf16.as_ptr())
    };

    #[cfg(feature = "direct-invoke-dll")] {
        let dll = dll_get_func_table();
        (dll.create_key)(
            handle,
            key,
            alg,
            name,
            input.key_spec.as_cert_key_spec(),
            input.flags.as_ncrypt_flags(),
        ).ok()
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        unsafe {
            NCryptCreatePersistedKey(
                handle,
                key,
                alg,
                name,
                input.key_spec.as_cert_key_spec(),
                input.flags.as_ncrypt_flags(),
            )
        }
    }
}

/// Deletes the given key from the KSP.
#[allow(dead_code)]
pub fn azihsmksp_delete_key(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptDeleteKeyPayload,
) -> windows::core::Result<()> {
    #[cfg(feature = "direct-invoke-dll")] {
        let dll = dll_get_func_table();
        (dll.delete_key)(
            handle,
            key,
            input.flags.as_ncrypt_flags(),
        ).ok()
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        unsafe { NCryptDeleteKey(key, input.flags.raw) }
    }
}

/// Finalizes the given key within the KSP.
#[allow(dead_code)]
pub fn azihsmksp_finalize_key(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptFinalizeKeyPayload,
) -> windows::core::Result<()> {
    #[cfg(feature = "direct-invoke-dll")] {
        let dll = dll_get_func_table();
        (dll.finalize_key)(
            handle,
            key,
            input.flags.as_ncrypt_flags(),
        ).ok()
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        unsafe { NCryptFinalizeKey(key, input.flags.as_ncrypt_flags()) }
    }
}

/// Retrieves a provider property from the KSP.
#[allow(dead_code)]
pub fn azihsmksp_get_provider_property(
    handle: NCRYPT_PROV_HANDLE,
    input: &payloads::NCryptGetPropertyPayload,
    buffer: Option<&mut [u8]>,
) -> (windows::core::Result<()>, u32) {
    let mut value: u32 = 0;
    let property_name = input.property.get_name();
    let property_name_utf16 = property_name.to_utf16();

    #[cfg(feature = "direct-invoke-dll")] {
        // compute the buffer pointer and length values depending on whether or
        // not a buffer was provided
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut buf_len: u32 = 0;
        if let Some(given_buffer) = buffer {
            buf = given_buffer.as_mut_ptr();
            buf_len = given_buffer.len() as u32;
        }

        let dll = dll_get_func_table();
        let result: HRESULT = (dll.get_provider_property)(
            handle,
            PCWSTR::from_raw(property_name_utf16.as_ptr()),
            buf,
            buf_len,
            ptr::addr_of_mut!(value),
            input.flags.as_ncrypt_flags(),
        );
        (result.ok(), value)
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptGetProperty(
                handle,
                PCWSTR::from_raw(property_name_utf16.as_ptr()),
                buffer,
                ptr::addr_of_mut!(value),
                input.flags.as_object_security_info(),
            )
        };
        (result, value)
    }
}

/// Retrieves a key property from the KSP.
#[allow(dead_code)]
pub fn azihsmksp_get_key_property(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptGetPropertyPayload,
    buffer: Option<&mut [u8]>,
) -> (windows::core::Result<()>, u32) {
    let mut value: u32 = 0;
    let property_name = input.property.get_name();
    let property_name_utf16 = property_name.to_utf16();

    #[cfg(feature = "direct-invoke-dll")] {
        // compute the buffer pointer and length values depending on whether or
        // not a buffer was provided
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut buf_len: u32 = 0;
        if let Some(given_buffer) = buffer {
            buf = given_buffer.as_mut_ptr();
            buf_len = given_buffer.len() as u32;
        }

        let dll = dll_get_func_table();
        let result: HRESULT = (dll.get_key_property)(
            handle,
            key,
            PCWSTR::from_raw(property_name_utf16.as_ptr()),
            buf,
            buf_len,
            ptr::addr_of_mut!(value),
            input.flags.as_ncrypt_flags(),
        );
        (result.ok(), value)
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptGetProperty(
                key,
                PCWSTR::from_raw(property_name_utf16.as_ptr()),
                buffer,
                ptr::addr_of_mut!(value),
                input.flags.as_object_security_info(),
            )
        };
        (result, value)
    }

    // return the result, *and* the retrieved property value
}

/// Retrieves a key property from the KSP.
#[allow(dead_code)]
pub fn azihsmksp_set_key_property(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptSetPropertyPayload,
    buffer: &mut [u8],
) -> windows::core::Result<()> {
    let property_name = input.property.get_name();
    let property_name_utf16 = property_name.to_utf16();

    #[cfg(feature = "direct-invoke-dll")] {
        let buf: *mut u8 = buffer.as_mut_ptr();
        let buf_len: u32 = buffer.len() as u32;

        let dll = dll_get_func_table();
        (dll.set_key_property)(
            handle,
            key,
            PCWSTR::from_raw(property_name_utf16.as_ptr()),
            buf,
            buf_len,
            input.flags.as_ncrypt_flags(),
        ).ok()
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        unsafe {
            NCryptSetProperty(
                key,
                PCWSTR::from_raw(property_name_utf16.as_ptr()),
                buffer,
                input.flags.as_ncrypt_flags(),
            )
        }
    }
}

/// Calls `NCryptEncrypt()`.
#[allow(dead_code)]
pub fn azihsmksp_encrypt(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptEncryptDecryptPayload,
    input_buffer: Option<&[u8]>,
    output_buffer: Option<&mut [u8]>,
) -> (windows::core::Result<()>, u32) {
    let mut input = input.clone();
    let mut value: u32 = 0;

    let padding_info_algo = setup_padding_info_algid!(&input.padding_info);
    let padding_info = setup_padding_info_obj!(input.padding_info, padding_info_algo);
    let padding_info_ptr = setup_padding_info_ptr!(input.padding_info, &padding_info);

    #[cfg(feature = "direct-invoke-dll")] {
        // compute the input buffer pointer and length values depending on
        // whether or not a buffer was provided
        let mut inbuf: *const u8 = std::ptr::null();
        let mut inbuf_len: u32 = 0;
        if let Some(given_buffer) = input_buffer {
            inbuf = given_buffer.as_ptr();
            inbuf_len = given_buffer.len() as u32;
        }

        // do the same for the output buffer
        let mut outbuf: *mut u8 = std::ptr::null_mut();
        let mut outbuf_len: u32 = 0;
        if let Some(given_buffer) = output_buffer {
            outbuf = given_buffer.as_mut_ptr();
            outbuf_len = given_buffer.len() as u32;
        }

        let dll = dll_get_func_table();
        let result: HRESULT = (dll.encrypt)(
            handle,
            key,
            inbuf,
            inbuf_len,
            padding_info_ptr as *const c_void,
            outbuf,
            outbuf_len,
            ptr::addr_of_mut!(value),
            input.flags.as_ncrypt_flags(),
        );
        (result.ok(), value)
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptEncrypt(
                key,
                input_buffer,
                if padding_info.is_some() { Some(padding_info_ptr) } else { None },
                output_buffer,
                ptr::addr_of_mut!(value),
                input.flags.as_ncrypt_flags(),
            )
        };
        (result, value)
    }
}

/// Calls `NCryptDecrypt()`.
#[allow(dead_code)]
pub fn azihsmksp_decrypt(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptEncryptDecryptPayload,
    input_buffer: Option<&[u8]>,
    output_buffer: Option<&mut [u8]>,
) -> (windows::core::Result<()>, u32) {
    let mut input = input.clone();
    let mut value: u32 = 0;

    let padding_info_algo = setup_padding_info_algid!(&input.padding_info);
    let padding_info = setup_padding_info_obj!(input.padding_info, padding_info_algo);
    let padding_info_ptr = setup_padding_info_ptr!(input.padding_info, &padding_info);

    #[cfg(feature = "direct-invoke-dll")] {
        // compute the input buffer pointer and length values depending on
        // whether or not a buffer was provided
        let mut inbuf: *const u8 = std::ptr::null();
        let mut inbuf_len: u32 = 0;
        if let Some(given_buffer) = input_buffer {
            inbuf = given_buffer.as_ptr();
            inbuf_len = given_buffer.len() as u32;
        }

        // do the same for the output buffer
        let mut outbuf: *mut u8 = std::ptr::null_mut();
        let mut outbuf_len: u32 = 0;
        if let Some(given_buffer) = output_buffer {
            outbuf = given_buffer.as_mut_ptr();
            outbuf_len = given_buffer.len() as u32;
        }

        let dll = dll_get_func_table();
        let result: HRESULT = (dll.decrypt)(
            handle,
            key,
            inbuf,
            inbuf_len,
            padding_info_ptr as *const c_void,
            outbuf,
            outbuf_len,
            ptr::addr_of_mut!(value),
            input.flags.as_ncrypt_flags(),
        );
        (result.ok(), value)
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptDecrypt(
                key,
                input_buffer,
                if padding_info.is_some() { Some(padding_info_ptr) } else { None },
                output_buffer,
                ptr::addr_of_mut!(value),
                input.flags.as_ncrypt_flags(),
            )
        };
        (result, value)
    }
}

/// Calls `NCryptImportKey()`.
#[allow(dead_code)]
pub fn azihsmksp_import_key(
    handle: NCRYPT_PROV_HANDLE,
    encrypt_key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptImportKeyPayload,
    blob_data_buffer: &[u8],
) -> (windows::core::Result<()>, NCRYPT_KEY_HANDLE) {
    let mut output_key = NCRYPT_KEY_HANDLE(0);
    let blob_type_str = input.blob_type.get_name();
    let blob_type_str_utf16 = blob_type_str.to_utf16();

    #[cfg(feature = "direct-invoke-dll")] {
        let buf: *const u8 = blob_data_buffer.as_ptr();
        let buf_len: u32 = blob_data_buffer.len() as u32;

        let dll = dll_get_func_table();
        let result: HRESULT = (dll.import_key)(
            handle,
            encrypt_key,
            PCWSTR::from_raw(blob_type_str_utf16.as_ptr()),
            std::ptr::null(), // TODO - add ability to fuzz with `BCryptBufferDesc` info
            ptr::addr_of_mut!(output_key),
            buf,
            buf_len,
            input.flags.as_ncrypt_flags(),
        );
        (result.ok(), output_key)
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptImportKey(
                handle,
                encrypt_key,
                PCWSTR::from_raw(blob_type_str_utf16.as_ptr()),
                None, // TODO - add ability to fuzz with `BCryptBufferDesc` info
                ptr::addr_of_mut!(output_key),
                blob_data_buffer,
                input.flags.as_ncrypt_flags(),
            )
        };
        (result, output_key)
    }
}

/// Calls `NCryptExportKey()`.
#[allow(dead_code)]
pub fn azihsmksp_export_key(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    encrypt_key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptExportKeyPayload,
    blob_data_buffer: Option<&mut [u8]>,
) -> (windows::core::Result<()>, u32) {
    let mut value: u32 = 0;
    let blob_type_str = input.blob_type.get_name();
    let blob_type_str_utf16 = blob_type_str.to_utf16();

    #[cfg(feature = "direct-invoke-dll")] {
        // compute the buffer pointer and length values depending on whether or
        // not a buffer was provided
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut buf_len: u32 = 0;
        if let Some(given_buffer) = blob_data_buffer {
            buf = given_buffer.as_mut_ptr();
            buf_len = given_buffer.len() as u32;
        }

        let dll = dll_get_func_table();
        let result: HRESULT = (dll.export_key)(
            handle,
            key,
            encrypt_key,
            PCWSTR::from_raw(blob_type_str_utf16.as_ptr()),
            std::ptr::null(), // TODO - add ability to fuzz with `BCryptBufferDesc` info
            buf,
            buf_len,
            ptr::addr_of_mut!(value),
            input.flags.as_ncrypt_flags(),
        );
        (result.ok(), value)
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptExportKey(
                key,
                encrypt_key,
                PCWSTR::from_raw(blob_type_str_utf16.as_ptr()),
                None, // TODO - add ability to fuzz with `BCryptBufferDesc` info
                blob_data_buffer,
                ptr::addr_of_mut!(value),
                input.flags.as_ncrypt_flags(),
            )
        };
        (result, value)
    }
}

/// Calls `NCryptSignHash()`.
#[allow(dead_code)]
pub fn azihsmksp_sign_hash(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptSignHashPayload,
    hash_buffer: &[u8],
    sign_buffer: Option<&mut [u8]>,
) -> (windows::core::Result<()>, u32) {
    let mut input = input.clone();
    let mut value: u32 = 0;

    let padding_info_algo = setup_padding_info_algid!(&input.padding_info);
    let padding_info = setup_padding_info_obj!(input.padding_info, padding_info_algo);
    let padding_info_ptr = setup_padding_info_ptr!(input.padding_info, &padding_info);

    #[cfg(feature = "direct-invoke-dll")] {
        let inbuf: *const u8 = hash_buffer.as_ptr();
        let inbuf_len: u32 = hash_buffer.len() as u32;

        // compute the output buffer pointer and length values depending on
        // whether or not a buffer was provided
        let mut outbuf: *mut u8 = std::ptr::null_mut();
        let mut outbuf_len: u32 = 0;
        if let Some(given_buffer) = sign_buffer {
            outbuf = given_buffer.as_mut_ptr();
            outbuf_len = given_buffer.len() as u32;
        }

        let dll = dll_get_func_table();
        let result: HRESULT = (dll.sign)(
            handle,
            key,
            padding_info_ptr as *const c_void,
            inbuf,
            inbuf_len,
            outbuf,
            outbuf_len,
            ptr::addr_of_mut!(value),
            input.flags.as_ncrypt_flags(),
        );
        (result.ok(), value)
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptSignHash(
                key,
                if padding_info.is_some() { Some(padding_info_ptr) } else { None },
                hash_buffer,
                sign_buffer,
                ptr::addr_of_mut!(value),
                input.flags.as_ncrypt_flags(),
            )
        };
        (result, value)
    }
}

/// Calls `NCryptVerifySignature()`.
#[allow(dead_code)]
pub fn azihsmksp_verify_signature(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptVerifySignaturePayload,
    hash_buffer: &[u8],
    sign_buffer: &[u8],
) -> windows::core::Result<()> {
    let mut input = input.clone();

    let padding_info_algo = setup_padding_info_algid!(&input.padding_info);
    let padding_info = setup_padding_info_obj!(input.padding_info, padding_info_algo);
    let padding_info_ptr = setup_padding_info_ptr!(input.padding_info, &padding_info);

    #[cfg(feature = "direct-invoke-dll")] {
        let hbuf: *const u8 = hash_buffer.as_ptr();
        let hbuf_len: u32 = hash_buffer.len() as u32;
        let sbuf: *const u8 = sign_buffer.as_ptr();
        let sbuf_len: u32 = sign_buffer.len() as u32;

        let dll = dll_get_func_table();
        (dll.verify)(
            handle,
            key,
            padding_info_ptr as *const c_void,
            hbuf,
            hbuf_len,
            sbuf,
            sbuf_len,
            input.flags.as_ncrypt_flags(),
        ).ok()
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        unsafe {
            NCryptVerifySignature(
                key,
                if padding_info.is_some() { Some(padding_info_ptr) } else { None },
                hash_buffer,
                sign_buffer,
                input.flags.as_ncrypt_flags(),
            )
        }
    }
}

/// Calls `NCryptSecretAgreement()`.
#[allow(dead_code)]
pub fn azihsmksp_secret_agreement(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    private_key: NCRYPT_KEY_HANDLE,
    public_key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptSecretAgreementPayload,
) -> (windows::core::Result<()>, NCRYPT_SECRET_HANDLE) {
    let mut secret = NCRYPT_SECRET_HANDLE(0);

    #[cfg(feature = "direct-invoke-dll")] {
        let dll = dll_get_func_table();
        let result: HRESULT = (dll.generate_secret)(
            handle,
            private_key,
            public_key,
            ptr::addr_of_mut!(secret),
            input.flags.as_ncrypt_flags(),
        );
        (result.ok(), secret)
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptSecretAgreement(
                private_key,
                public_key,
                ptr::addr_of_mut!(secret),
                input.flags.as_ncrypt_flags(),
            )
        };
        (result, secret)
    }
}

/// Calls `NCryptCreateclaim()`.
#[allow(dead_code)]
pub fn azihsmksp_create_claim(
    #[cfg(feature = "direct-invoke-dll")] handle: NCRYPT_PROV_HANDLE,
    subject_key: NCRYPT_KEY_HANDLE,
    authority_key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptCreateClaimPayload,
    blob_buffer: Option<&mut [u8]>,
) -> (windows::core::Result<()>, u32) {
    let mut value: u32 = 0;

    #[cfg(feature = "direct-invoke-dll")] {
        // compute the buffer pointer and length values depending on whether or
        // not a buffer was provided
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut buf_len: u32 = 0;
        if let Some(given_buffer) = blob_buffer {
            buf = given_buffer.as_mut_ptr();
            buf_len = given_buffer.len() as u32;
        }

        let dll = dll_get_func_table();
        let result: HRESULT = (dll.create_claim)(
            handle,
            subject_key,
            authority_key,
            input.claim_type,
            std::ptr::null(), // TODO - add ability to fuzz with `BCryptBufferDesc`
            buf,
            buf_len,
            ptr::addr_of_mut!(value),
            input.flags.raw,
        );
        (result.ok(), value)
    }

    #[cfg(not(feature = "direct-invoke-dll"))] {
        let result = unsafe {
            NCryptCreateClaim(
                subject_key,
                authority_key,
                input.claim_type,
                None, // TODO - add ability to fuzz with `BCryptBufferDesc`
                blob_buffer,
                ptr::addr_of_mut!(value),
                input.flags.raw,
            )
        };
        (result, value)
    }

}
