// Copyright (C) Microsoft Corporation. All rights reserved.

use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;
use windows::core::*;
use windows::Win32::Security::Cryptography::*;

pub(crate) type NCryptInterfaceVersion = BCRYPT_INTERFACE_VERSION;

pub(crate) type NCryptOpenStorageProviderFn = extern "system" fn(
    ph_provider: *mut NCRYPT_PROV_HANDLE,
    psz_provider_name: PCWSTR,
    dw_flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptFreeProviderFn = extern "system" fn(hprovider: NCRYPT_PROV_HANDLE) -> HRESULT;

pub(crate) type NCryptFreeKeyFn =
    extern "system" fn(prov_handle: NCRYPT_PROV_HANDLE, key_handle: NCRYPT_KEY_HANDLE) -> HRESULT;

pub(crate) type NCryptCreatePersistedKeyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: *mut NCRYPT_KEY_HANDLE,
    algo: PCWSTR,
    key_name: PCWSTR,
    key_spec: CERT_KEY_SPEC,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptSetKeyPropertyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    property: PCWSTR,
    input: *mut u8,
    cb_input: u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptFinalizeKeyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    hkey: NCRYPT_KEY_HANDLE,
    dw_flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptDeleteKeyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptEncryptFn = extern "system" fn(
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

pub(crate) type NCryptDecryptFn = extern "system" fn(
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

pub(crate) type NcryptSignHashFn = extern "system" fn(
    hprov: NCRYPT_PROV_HANDLE,
    hkey: NCRYPT_KEY_HANDLE,
    ppaddinginfo: *const c_void,
    pbhashvalue: *const u8,
    cbhashvalue: u32,
    pbsignature: *mut u8,
    cbsignature: u32,
    pcbresult: *mut u32,
    dw_flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NcryptVerifySignatureFn = extern "system" fn(
    hprov: NCRYPT_PROV_HANDLE,
    hkey: NCRYPT_KEY_HANDLE,
    ppaddinginfo: *const c_void,
    pbhashvalue: *const u8,
    cbhashvalue: u32,
    pbsignature: *const u8,
    cbsignature: u32,
    dw_flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptGetKeyPropertyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    property: PCWSTR,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptImportKeyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    himportkey: NCRYPT_KEY_HANDLE,
    pszblobtype: PCWSTR,
    pparameters: *const BCryptBufferDesc,
    phkey: *mut NCRYPT_KEY_HANDLE,
    pbdata: *const u8,
    cbdata: u32,
    dw_flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptExportKeyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    export_key_handle: NCRYPT_KEY_HANDLE,
    pszblobtype: PCWSTR,
    pparameterlist: *const BCryptBufferDesc,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptOpenKeyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    key_handle: *mut NCRYPT_KEY_HANDLE,
    key_name: PCWSTR,
    key_spec: CERT_KEY_SPEC,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptSecretAgreementFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    priv_key: NCRYPT_KEY_HANDLE,
    pub_key: NCRYPT_KEY_HANDLE,
    secret_agreement: *mut NCRYPT_SECRET_HANDLE,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptFreeSecretFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    secret_handle: NCRYPT_SECRET_HANDLE,
) -> HRESULT;

pub(crate) type NCryptGetProviderPropertyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    property: PCWSTR,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    flags: NCRYPT_FLAGS,
) -> HRESULT;

pub(crate) type NCryptCreateClaimFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    subject_key_handle: NCRYPT_KEY_HANDLE,
    authority_key_handle: NCRYPT_KEY_HANDLE,
    claim_type: u32,
    pparameterlist: *const BCryptBufferDesc,
    pbclaimblob: *mut u8,
    cbclaimblob: u32,
    pcbresult: *mut u32,
    dw_flags: u32,
) -> HRESULT;

pub(crate) type NCryptDeriveKeyFn = extern "system" fn(
    prov_handle: NCRYPT_PROV_HANDLE,
    hsharedsecret: NCRYPT_SECRET_HANDLE,
    pwszkdf: PCWSTR,
    pparameterlist: *const BCryptBufferDesc,
    pbderivedkey: *mut u8,
    cbderivedkey: u32,
    pcbresult: *mut u32,
    dw_flags: u32,
) -> HRESULT;

pub(crate) type NCryptSetProviderPropertyFn = extern "system" fn(
    hprovider: NCRYPT_PROV_HANDLE,
    pszproperty: PCWSTR,
    pbinput: *const u8,
    cbinput: u32,
    dw_flags: u32,
) -> HRESULT;

pub(crate) type NCryptFreeBufferFn = extern "system" fn(pvinput: *mut c_void) -> HRESULT;

pub(crate) type NCryptIsAlgSupportedFn =
    extern "system" fn(hprovider: NCRYPT_PROV_HANDLE, pszalgid: PCWSTR, dw_flags: u32) -> HRESULT;

pub(crate) type NCryptEnumAlgorithmsFn = extern "system" fn(
    hprovider: NCRYPT_PROV_HANDLE,
    dwalgclass: u32,
    pdwalgcount: *mut u32,
    ppalglist: *mut *mut NCryptAlgorithmName,
    dw_flags: u32,
) -> HRESULT;

pub(crate) type NCryptEnumKeysFn = extern "system" fn(
    hprovider: NCRYPT_PROV_HANDLE,
    pszscope: PCWSTR,
    ppkeyname: *mut *mut NCryptKeyName,
    ppenumstate: *mut *mut c_void,
    dw_flags: u32,
) -> HRESULT;

pub(crate) type NCryptPromptUserFn = extern "system" fn(
    hprovider: NCRYPT_PROV_HANDLE,
    hkey: NCRYPT_KEY_HANDLE,
    pszoperation: PCWSTR,
    dw_flags: u32,
) -> HRESULT;

pub(crate) type NCryptNotifyChangeKeyFn = extern "system" fn(
    hprovider: NCRYPT_PROV_HANDLE,
    phevent: *mut HANDLE,
    dw_flags: u32,
) -> HRESULT;

pub(crate) type NCryptKeyDerivationFn = extern "system" fn(
    hprovider: NCRYPT_PROV_HANDLE,
    hkey: NCRYPT_KEY_HANDLE,
    pparameterlist: *const BCryptBufferDesc,
    pbderivedkey: *mut u8,
    cbderivedkey: u32,
    pcbresult: *mut u32,
    dw_flags: u32,
) -> HRESULT;

pub(crate) type NCryptVerifyClaimFn = extern "system" fn(
    hprov: NCRYPT_PROV_HANDLE,
    hsubjectkey: NCRYPT_KEY_HANDLE,
    hauthoritykey: NCRYPT_KEY_HANDLE,
    dwclaimtype: u32,
    pparameterlist: *const BCryptBufferDesc,
    pbclaimblob: *const u8,
    cbclaimblob: u32,
    poutput: *mut BCryptBufferDesc,
    dw_flags: u32,
) -> HRESULT;

#[repr(C)]
pub(crate) struct NCryptKeyStorageFuncTable {
    pub version: NCryptInterfaceVersion,
    pub open_provider: NCryptOpenStorageProviderFn,
    pub open_key: NCryptOpenKeyFn,
    pub create_persisted_key: NCryptCreatePersistedKeyFn,
    pub get_provider_property: NCryptGetProviderPropertyFn,
    pub get_key_property: NCryptGetKeyPropertyFn,
    pub set_provider_property: NCryptSetProviderPropertyFn,
    pub set_key_property: NCryptSetKeyPropertyFn,
    pub finalize_key: NCryptFinalizeKeyFn,
    pub delete_key: NCryptDeleteKeyFn,
    pub free_provider: NCryptFreeProviderFn,
    pub free_key: NCryptFreeKeyFn,
    pub free_buffer: NCryptFreeBufferFn,
    pub encrypt: NCryptEncryptFn,
    pub decrypt: NCryptDecryptFn,
    pub is_alg_supported: NCryptIsAlgSupportedFn,
    pub enum_algorithms: NCryptEnumAlgorithmsFn,
    pub enum_keys: NCryptEnumKeysFn,
    pub import_key: NCryptImportKeyFn,
    pub export_key: NCryptExportKeyFn,
    pub sign_hash: NcryptSignHashFn,
    pub verify_signature: NcryptVerifySignatureFn,
    pub prompt_user: NCryptPromptUserFn,
    pub notify_change_key: NCryptNotifyChangeKeyFn,
    pub secret_agreement: NCryptSecretAgreementFn,
    pub derive_key: NCryptDeriveKeyFn,
    pub free_secret: NCryptFreeSecretFn,
    pub key_derivation: NCryptKeyDerivationFn,
    pub create_claim: NCryptCreateClaimFn,
    pub verify_claim: NCryptVerifyClaimFn,
}
