// Copyright (C) Microsoft Corporation. All rights reserved.

use scopeguard::*;
use widestring::*;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Cryptography::*;

use super::AZIHSM_KSP_NAME;
use crate::AzIHsmHresult;

/// The name of the DLL that contains the key storage provider.
const KSP_DLL_NAME: &str = "azihsmksp.dll";

/// Register the key storage provider.
///
/// # Returns
/// - `Ok(())` if the key storage provider was successfully registered.
/// - `Err(HRESULT)` if an error occurred.
pub(crate) fn register_ksp() -> AzIHsmHresult<()> {
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
