// Copyright (C) Microsoft Corporation. All rights reserved.

use std::path::PathBuf;

use scopeguard::*;
use widestring::*;
use winapi::um::winnt::SECURITY_DESCRIPTOR_MIN_LENGTH;
use winapi::um::winnt::SECURITY_DESCRIPTOR_REVISION;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;

use super::AZIHSM_KSP_NAME;
use crate::AzIHsmHresult;

/// The name of the DLL that contains the key storage provider.
const KSP_DLL_NAME: &str = "azihsmksp.dll";

/// Creates the cache file with appropriate ACLs for all users.
///
/// Creates `%ALLUSERSPROFILE%\Microsoft\azihsmguest\partition_cache` as a file with modify
/// permissions for the Built-in Users group.
///
/// # Returns
/// - `Ok(())` if the cache file was successfully created.
/// - `Err(HRESULT)` if an error occurred.
fn create_cache_file() -> AzIHsmHresult<()> {
    // Get %ALLUSERSPROFILE% environment variable
    let all_users_profile = std::env::var("ALLUSERSPROFILE")
        .or_else(|_| std::env::var("ProgramData"))
        .map_err(|e| {
            tracing::error!(
                "Failed to get ALLUSERSPROFILE or ProgramData environment variable: {}",
                e
            );
            E_FAIL
        })?;

    let cache_dir = PathBuf::from(all_users_profile)
        .join("Microsoft")
        .join("azihsmguest");

    let cache_file_path = cache_dir.join("partition_cache");

    tracing::debug!("Creating cache file: {:?}", cache_file_path);

    // Create parent directory if it doesn't exist
    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        tracing::error!(
            "Failed to create parent directory at {:?}: {}",
            cache_dir,
            e
        );
        return Err(E_FAIL);
    }

    // Create the cache file if it doesn't exist
    if !cache_file_path.exists() {
        match std::fs::File::create(&cache_file_path) {
            Ok(_file) => {
                // File handle will be dropped here, closing the file
                tracing::debug!("Cache file created successfully at {:?}", cache_file_path);
            }
            Err(e) => {
                tracing::error!(
                    "Failed to create cache file at {:?}: {}",
                    cache_file_path,
                    e
                );
                return Err(E_FAIL);
            }
        }
    } else {
        tracing::debug!("Cache file already exists at {:?}", cache_file_path);
    }

    // Convert path to wide string for Windows API
    let path_wide = match U16CString::from_os_str(&cache_file_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to convert path to wide string: {}, rolling back", e);
            // Rollback: delete the file we just created
            let _ = std::fs::remove_file(&cache_file_path);
            return Err(E_FAIL);
        }
    };

    // Set up ACLs - if this fails, rollback and return error
    // Create security descriptor for "Users" group with modify access
    unsafe {
        // Get SID for the Built-in Users group
        let mut sid_size = SECURITY_MAX_SID_SIZE;
        let well_known_sid = WinBuiltinUsersSid;

        let mut sid_buffer = vec![0u8; sid_size as usize];
        let users_sid = PSID(sid_buffer.as_mut_ptr() as *mut _);

        if CreateWellKnownSid(well_known_sid, PSID::default(), users_sid, &mut sid_size).is_err() {
            let err = HRESULT::from_win32(GetLastError().0);
            tracing::error!(%err, "CreateWellKnownSid failed, rolling back");
            // Rollback: delete the file
            let _ = std::fs::remove_file(&cache_file_path);
            return Err(err);
        }

        // Create explicit access for Users group with MODIFY rights
        // MODIFY = READ + WRITE + EXECUTE + DELETE
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_GENERIC_READ.0
                | FILE_GENERIC_WRITE.0
                | FILE_DELETE_CHILD.0
                | DELETE.0,
            grfAccessMode: SET_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(users_sid.0 as *mut u16),
            },
        };

        // Create new ACL
        let mut acl: *mut ACL = std::ptr::null_mut();
        let status = SetEntriesInAclW(Some(&[ea]), None, &mut acl as *mut _);
        if status != WIN32_ERROR(0) {
            let err = HRESULT::from_win32(status.0);
            tracing::error!(%err, "SetEntriesInAclW failed, rolling back");
            // Rollback: delete the file
            let _ = std::fs::remove_file(&cache_file_path);
            return Err(err);
        }

        let acl_guard = guard(acl, |acl| {
            if !acl.is_null() {
                let _ = winapi::um::winbase::LocalFree(acl as *mut _);
            }
        });

        // Create and initialize security descriptor
        let mut sd_buffer = vec![0u8; SECURITY_DESCRIPTOR_MIN_LENGTH];
        let sd = PSECURITY_DESCRIPTOR(sd_buffer.as_mut_ptr() as *mut _);

        if InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION).is_err() {
            let err = HRESULT::from_win32(GetLastError().0);
            tracing::error!(%err, "InitializeSecurityDescriptor failed, rolling back");
            // Rollback: delete the file
            let _ = std::fs::remove_file(&cache_file_path);
            return Err(err);
        }

        // Set the DACL
        if SetSecurityDescriptorDacl(sd, true, Some(acl), false).is_err() {
            let err = HRESULT::from_win32(GetLastError().0);
            tracing::error!(%err, "SetSecurityDescriptorDacl failed, rolling back");
            // Rollback: delete the file
            let _ = std::fs::remove_file(&cache_file_path);
            return Err(err);
        }

        // Apply security descriptor to the file
        let status = SetNamedSecurityInfoW(
            PWSTR(path_wide.as_ptr() as *mut u16),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(acl),
            None,
        );

        if status != WIN32_ERROR(0) {
            let err = HRESULT::from_win32(status.0);
            tracing::error!(%err, "SetNamedSecurityInfoW failed, rolling back");
            // Rollback: delete the file
            let _ = std::fs::remove_file(&cache_file_path);
            return Err(err);
        }

        ScopeGuard::into_inner(acl_guard);
    }

    tracing::debug!(
        "Cache file created with appropriate ACLs: {:?}",
        cache_file_path
    );
    Ok(())
}

/// Register the key storage provider.
///
/// # Returns
/// - `Ok(())` if the key storage provider was successfully registered.
/// - `Err(HRESULT)` if an error occurred.
pub(crate) fn register_ksp() -> AzIHsmHresult<()> {
    // Create cache file with proper ACLs first
    create_cache_file()?;

    let mut algo_names = [NCRYPT_KEY_STORAGE_ALGORITHM];

    let mut algo_class = CRYPT_INTERFACE_REG {
        dwInterface: NCRYPT_KEY_STORAGE_INTERFACE,
        dwFlags: CRYPT_LOCAL,
        cFunctions: algo_names.len() as u32,
        rgpszFunctions: &mut algo_names as *mut _ as *mut _,
    };

    let mut algo_classes = [&mut algo_class];

    let mut image = CRYPT_IMAGE_REG {
        pszImage: {
            let s = U16CString::from(u16cstr!(KSP_DLL_NAME));
            PWSTR::from_raw(s.into_raw())
        },
        cInterfaces: algo_classes.len() as u32,
        rgpInterfaces: &mut algo_classes as *mut _ as *mut _,
    };

    let provider: CRYPT_PROVIDER_REG = CRYPT_PROVIDER_REG {
        cAliases: 0,
        rgpszAliases: std::ptr::null_mut(),
        pUM: &mut image,
        pKM: std::ptr::null_mut(),
    };

    bcrypt_register_provider(provider)?;
    let provider_registration_guard = guard((), |_| {
        let _ = bcrypt_unregister_provider();
    });

    bcrypt_add_context_function()?;
    let context_function_guard = guard((), |_| {
        let _ = bcrypt_remove_context_function();
    });

    bcrypt_add_context_function_provider()?;

    ScopeGuard::into_inner(context_function_guard);
    ScopeGuard::into_inner(provider_registration_guard);

    tracing::debug!("KSP successfully registered.");

    Ok(())
}

/// Unregister the key storage provider.
///
/// # Returns
/// - `Ok(())` if the key storage provider was successfully unregistered.
/// - `Err(HRESULT)` if an error occurred.
pub(crate) fn unregister_ksp() -> AzIHsmHresult<()> {
    let mut result = Ok(());

    let tmp_result = bcrypt_remove_context_function_provider();
    if tmp_result.is_err() {
        result = tmp_result;
    }

    let tmp_result = bcrypt_remove_context_function();
    if result.is_ok() && tmp_result.is_err() {
        result = tmp_result;
    }

    let tmp_result = bcrypt_unregister_provider();
    if result.is_ok() && tmp_result.is_err() {
        result = tmp_result;
    }

    match result {
        Ok(()) => tracing::debug!("KSP successfully unregistered."),
        Err(err) => tracing::error!(%err, "Failed to unregister KSP."),
    }

    result
}

fn bcrypt_register_provider(mut provider: CRYPT_PROVIDER_REG) -> AzIHsmHresult<()> {
    windows_targets::link!(
        "bcrypt.dll"
        "system"
        fn BCryptRegisterProvider(
            name: PCWSTR,
            flags:u32,
            reg: *mut CRYPT_PROVIDER_REG
        ) -> NTSTATUS
    );

    let status = unsafe { BCryptRegisterProvider(AZIHSM_KSP_NAME, 0, &mut provider as *mut _) };
    if status.is_err() {
        let err = status.to_hresult();
        tracing::error!(
            %err,
            "BCryptRegisterProvider failed"
        );
        Err(err)?;
    }

    Ok(())
}

fn bcrypt_unregister_provider() -> AzIHsmHresult<()> {
    windows_targets::link!(
        "bcrypt.dll"
        "system"
        fn BCryptUnregisterProvider(
            name: PCWSTR,
        ) -> NTSTATUS
    );

    let status = unsafe { BCryptUnregisterProvider(AZIHSM_KSP_NAME) };
    if status.is_err() {
        let err = status.to_hresult();
        tracing::error!(
            %err,
            "BCryptUnregisterProvider failed"
        );
        Err(err)?;
    }

    Ok(())
}

fn bcrypt_add_context_function() -> AzIHsmHresult<()> {
    let status = unsafe {
        BCryptAddContextFunction(
            CRYPT_LOCAL,
            PCWSTR::null(),
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM,
            CRYPT_PRIORITY_BOTTOM,
        )
    };

    if status.is_err() {
        let err = status.to_hresult();
        tracing::error!(
            %err,
            "BCryptAddContextFunction failed"
        );
        Err(err)?;
    }

    Ok(())
}

fn bcrypt_remove_context_function() -> AzIHsmHresult<()> {
    let status = unsafe {
        BCryptRemoveContextFunction(
            CRYPT_LOCAL,
            PCWSTR::null(),
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM,
        )
    };

    if status.is_err() {
        let err = status.to_hresult();
        tracing::error!(
            %err,
            "BCryptRemoveContextFunction failed"
        );
        Err(err)?;
    }

    Ok(())
}

fn bcrypt_add_context_function_provider() -> AzIHsmHresult<()> {
    windows_targets::link!(
        "bcrypt.dll"
        "system"
        fn BCryptAddContextFunctionProvider(
            table : BCRYPT_TABLE,
            context : PCWSTR,
            interface : BCRYPT_INTERFACE,
            function : PCWSTR,
            provider: PCWSTR,
            position : u32
        ) -> NTSTATUS
    );

    let status = unsafe {
        BCryptAddContextFunctionProvider(
            CRYPT_LOCAL,
            PCWSTR::null(),
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM,
            AZIHSM_KSP_NAME,
            CRYPT_PRIORITY_BOTTOM,
        )
    };
    if status.is_err() {
        let err = status.to_hresult();
        tracing::error!(
            %err,
            "BCryptAddContextFunctionProvider failed"
        );
        Err(err)?;
    }

    Ok(())
}

fn bcrypt_remove_context_function_provider() -> AzIHsmHresult<()> {
    windows_targets::link!(
        "bcrypt.dll"
        "system"
        fn BCryptRemoveContextFunctionProvider(
            table : BCRYPT_TABLE,
            context : PCWSTR,
            interface : BCRYPT_INTERFACE,
            function : PCWSTR,
            provider: PCWSTR,
        ) -> NTSTATUS
    );

    let status = unsafe {
        BCryptRemoveContextFunctionProvider(
            CRYPT_LOCAL,
            PCWSTR::null(),
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM,
            AZIHSM_KSP_NAME,
        )
    };
    if status.is_err() {
        let err = status.to_hresult();
        tracing::error!(
            %err,
            "BCryptRemoveContextFunctionProvider failed"
        );
        Err(err)?;
    }

    Ok(())
}
