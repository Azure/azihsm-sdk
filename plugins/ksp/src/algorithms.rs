use std::alloc::Layout;

// Copyright (C) Microsoft Corporation. All rights reserved.
use windows::core::*;
use windows::Win32::Foundation::NTE_INTERNAL_ERROR;
use windows::Win32::Foundation::NTE_NO_MEMORY;
use windows::Win32::Security::Cryptography::*;

use crate::AzIHsmHresult;

#[cfg(not(feature = "disable-fp"))]
const SUPPORTED_ALGORITHMS: &[PCWSTR] = &[
    BCRYPT_AES_ALGORITHM,
    BCRYPT_XTS_AES_ALGORITHM,
    BCRYPT_RSA_ALGORITHM,
    BCRYPT_ECDH_ALGORITHM,
    BCRYPT_ECDH_P256_ALGORITHM,
    BCRYPT_ECDH_P384_ALGORITHM,
    BCRYPT_ECDH_P521_ALGORITHM,
    BCRYPT_ECDSA_ALGORITHM,
    BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECDSA_P384_ALGORITHM,
    BCRYPT_ECDSA_P521_ALGORITHM,
    BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
    BCRYPT_HKDF_ALGORITHM,
];

#[cfg(feature = "disable-fp")]
const SUPPORTED_ALGORITHMS: &[PCWSTR] = &[
    BCRYPT_AES_ALGORITHM,
    BCRYPT_RSA_ALGORITHM,
    BCRYPT_ECDH_ALGORITHM,
    BCRYPT_ECDH_P256_ALGORITHM,
    BCRYPT_ECDH_P384_ALGORITHM,
    BCRYPT_ECDH_P521_ALGORITHM,
    BCRYPT_ECDSA_ALGORITHM,
    BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECDSA_P384_ALGORITHM,
    BCRYPT_ECDSA_P521_ALGORITHM,
    BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
    BCRYPT_HKDF_ALGORITHM,
];

// Keep track of content type and content-specific data
// So we could free pointer accordingly
// This will be represented as a C Union
// https://doc.rust-lang.org/reference/type-layout.html#r-layout.repr.primitive.adt
#[derive(Debug)]
#[repr(C)]
pub(crate) enum Header {
    Algorithms(u32),
}

impl Header {
    pub(crate) fn create_layout(&self) -> AzIHsmHresult<Layout> {
        match self {
            Header::Algorithms(count) => {
                let layout_header = Layout::new::<Header>();
                let layout_algo =
                    Layout::array::<NCryptAlgorithmName>(*count as usize).map_err(|err| {
                        tracing::error!(?err, "Failed to create layout for NCryptAlgorithmName");
                        NTE_INTERNAL_ERROR
                    })?;

                let (layout_combined, _) = layout_header.extend(layout_algo).map_err(|err| {
                    tracing::error!(?err, "Failed to extend layout for NCryptAlgorithmName");
                    NTE_INTERNAL_ERROR
                })?;

                Ok(layout_combined)
            }
        }
    }
}

// Allocate a buffer, then filled with a copy of algorithms
// The buffer comes with a header at the beginning
// Returned pointer SKIPS the header and points to the first NCryptAlgorithmName
pub(crate) unsafe fn allocate(
    algorithms: Vec<NCryptAlgorithmName>,
) -> AzIHsmHresult<*mut NCryptAlgorithmName> {
    let count = algorithms.len();

    let header = Header::Algorithms(count as u32);
    let layout = header.create_layout()?;
    let buffer = std::alloc::alloc(layout);
    tracing::debug!(?layout, "Buffer allocated successfully");
    if buffer.is_null() {
        tracing::error!(size = layout.size(), "Failed to allocate memory");
        return Err(NTE_NO_MEMORY);
    }

    // Copy header into buffer
    let ptr = buffer;
    let header_ptr = &header;
    std::ptr::copy_nonoverlapping(header_ptr, ptr as *mut Header, 1);

    // Copy the algorithms into the buffer
    let ptr = ptr.byte_add(std::mem::size_of::<Header>()) as *mut NCryptAlgorithmName;
    std::ptr::copy_nonoverlapping(algorithms.as_ptr(), ptr, count);

    // Return the pointer to the first NCryptAlgorithmName
    Ok(ptr)
}

pub(crate) unsafe fn free(ptr: *mut std::ffi::c_void) -> AzIHsmHresult<()> {
    if ptr.is_null() {
        return Ok(());
    }

    // Get the pointer to the start of original buffer
    let buffer = ptr.byte_sub(std::mem::size_of::<Header>());

    // Try to create header
    let ptr_header = buffer as *mut Header;
    let header = &*ptr_header;
    tracing::debug!(?header, "Freeing buffer");

    // Free the content accordingly
    match &header {
        Header::Algorithms(count) => {
            let header = Header::Algorithms(*count);
            let count = *count as usize;

            // We need to free each NCryptAlgorithmName's pszName
            // Make a copy of pointer
            // If we box it instead of making a copy, the buffer is going to be freed when the Box is dropped
            // We don't want that but we want to free the buffer later as a whole
            let mut algorithms = Vec::with_capacity(count);
            std::ptr::copy_nonoverlapping(
                ptr as *mut NCryptAlgorithmName,
                algorithms.as_mut_ptr(),
                count,
            );
            algorithms.set_len(count);

            for each in algorithms {
                if !each.pszName.is_null() {
                    // Box the pointer so its freed correctly
                    let _ = Box::from_raw(each.pszName.as_ptr());
                }
            }

            let layout = header.create_layout()?;
            std::alloc::dealloc(buffer as *mut u8, layout);
            tracing::debug!(?layout, "Buffer deallocated successfully");
        }
    };

    Ok(())
}

// Convert Constant Wide String to Wide String by copy and create new
unsafe fn pcwstr_to_pwstr(p: PCWSTR) -> PWSTR {
    // as_wide() returns String data without the trailing 0
    let mut buffer = p.as_wide().to_vec();
    // add the trailing 0
    buffer.push(0);

    // Leak the ownership of the buffer so that it is not freed by Rust
    // User should free the buffer with a later call to `azihsm_free_buffer`
    let b = Box::into_raw(buffer.into_boxed_slice());

    PWSTR::from_raw(b as *mut u16)
}

unsafe fn compare(a: PCWSTR, b: PCWSTR) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }

    let a = a.as_wide();
    let b = b.as_wide();
    if a.len() != b.len() {
        return false;
    }

    a == b
}

pub(crate) fn is_alg_supported(algorithm: PCWSTR) -> bool {
    if algorithm.is_null() {
        return false;
    }

    for each in SUPPORTED_ALGORITHMS {
        if unsafe { compare(*each, algorithm) } {
            return true;
        }
    }

    false
}

pub(crate) fn enum_algorithms(algclass: NCRYPT_OPERATION) -> Vec<NCryptAlgorithmName> {
    tracing::debug!(?algclass, "Enumerating algorithms");

    // If 0, enum all algorithms
    let algclass = if algclass == NCRYPT_OPERATION(0) {
        NCRYPT_CIPHER_OPERATION
            | NCRYPT_HASH_OPERATION
            | NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION
            | NCRYPT_SECRET_AGREEMENT_OPERATION
            | NCRYPT_SIGNATURE_OPERATION
    } else {
        algclass
    };

    let mut algos = vec![];
    // symmetric encryption algorithms
    if algclass.contains(NCRYPT_CIPHER_OPERATION) {
        algos.push((
            BCRYPT_AES_ALGORITHM,
            // This is not documented on NCryptAlgorithmName page
            // But it is returned by Microsoft Software Key Storage Provider
            // So we return 1 here to match the behavior
            NCRYPT_ALGORITHM_NAME_CLASS(1),
            NCRYPT_CIPHER_OPERATION,
        ));
        #[cfg(not(feature = "disable-fp"))]
        {
            algos.push((
                BCRYPT_XTS_AES_ALGORITHM,
                NCRYPT_ALGORITHM_NAME_CLASS(1),
                NCRYPT_CIPHER_OPERATION,
            ))
        }
    }
    // No Hash supported, so no check for NCRYPT_HASH_OPERATION

    // Add RSA for either asymmetric encryption or signature
    if algclass.contains(NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION)
        || algclass.contains(NCRYPT_SIGNATURE_OPERATION)
    {
        algos.push((
            BCRYPT_RSA_ALGORITHM,
            NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE,
            NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SIGNATURE_OPERATION,
        ));
    }
    // Add Secret agreement algorithms
    if algclass.contains(NCRYPT_SECRET_AGREEMENT_OPERATION) {
        algos.extend(vec![
            (
                BCRYPT_ECDH_ALGORITHM,
                NCRYPT_SECRET_AGREEMENT_INTERFACE,
                NCRYPT_SECRET_AGREEMENT_OPERATION,
            ),
            (
                BCRYPT_ECDH_P256_ALGORITHM,
                NCRYPT_SECRET_AGREEMENT_INTERFACE,
                NCRYPT_SECRET_AGREEMENT_OPERATION,
            ),
            (
                BCRYPT_ECDH_P384_ALGORITHM,
                NCRYPT_SECRET_AGREEMENT_INTERFACE,
                NCRYPT_SECRET_AGREEMENT_OPERATION,
            ),
            (
                BCRYPT_ECDH_P521_ALGORITHM,
                NCRYPT_SECRET_AGREEMENT_INTERFACE,
                NCRYPT_SECRET_AGREEMENT_OPERATION,
            ),
        ]);
    }
    // Add Digital signature algorithms
    if algclass.contains(NCRYPT_SIGNATURE_OPERATION) {
        algos.extend(vec![
            (
                BCRYPT_ECDSA_ALGORITHM,
                NCRYPT_SIGNATURE_INTERFACE,
                NCRYPT_SIGNATURE_OPERATION,
            ),
            (
                BCRYPT_ECDSA_P256_ALGORITHM,
                NCRYPT_SIGNATURE_INTERFACE,
                NCRYPT_SIGNATURE_OPERATION,
            ),
            (
                BCRYPT_ECDSA_P384_ALGORITHM,
                NCRYPT_SIGNATURE_INTERFACE,
                NCRYPT_SIGNATURE_OPERATION,
            ),
            (
                BCRYPT_ECDSA_P521_ALGORITHM,
                NCRYPT_SIGNATURE_INTERFACE,
                NCRYPT_SIGNATURE_OPERATION,
            ),
        ]);
    }

    algos
        .into_iter()
        .map(|(algo, class, operation)| NCryptAlgorithmName {
            pszName: unsafe { pcwstr_to_pwstr(algo) },
            dwClass: class,
            dwAlgOperations: operation,
            dwFlags: 0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_null_ptr() {
        // Freeing a null pointer should not panic
        unsafe {
            assert!(free(std::ptr::null_mut()).is_ok());
        }
    }

    #[test]
    fn test_is_alg_supported() {
        assert!(is_alg_supported(BCRYPT_AES_ALGORITHM));
        #[cfg(not(feature = "disable-fp"))]
        {
            assert!(is_alg_supported(BCRYPT_XTS_AES_ALGORITHM));
        }
        assert!(is_alg_supported(BCRYPT_RSA_ALGORITHM));
        assert!(is_alg_supported(BCRYPT_ECDH_ALGORITHM));
        assert!(is_alg_supported(BCRYPT_ECDSA_ALGORITHM));

        // Negative cases
        assert!(!is_alg_supported(PCWSTR::null()));
        assert!(!is_alg_supported(BCRYPT_AES_CMAC_ALGORITHM));
    }

    #[test]
    fn test_compare_enum_all_algorithms() {
        let algos = enum_algorithms(NCRYPT_OPERATION(0));
        assert!(!algos.is_empty());

        let expected = [
            (
                BCRYPT_AES_ALGORITHM,
                // This is not documented on NCryptAlgorithmName page
                // But it is returned by Microsoft Software Key Storage Provider
                // So we return 1 here to match the behavior
                NCRYPT_ALGORITHM_NAME_CLASS(1),
                NCRYPT_CIPHER_OPERATION,
            ),
            #[cfg(not(feature = "disable-fp"))]
            (
                BCRYPT_XTS_AES_ALGORITHM,
                NCRYPT_ALGORITHM_NAME_CLASS(1),
                NCRYPT_CIPHER_OPERATION,
            ),
            (
                BCRYPT_RSA_ALGORITHM,
                NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE,
                NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SIGNATURE_OPERATION,
            ),
            (
                BCRYPT_ECDH_ALGORITHM,
                NCRYPT_SECRET_AGREEMENT_INTERFACE,
                NCRYPT_SECRET_AGREEMENT_OPERATION,
            ),
            (
                BCRYPT_ECDH_P256_ALGORITHM,
                NCRYPT_SECRET_AGREEMENT_INTERFACE,
                NCRYPT_SECRET_AGREEMENT_OPERATION,
            ),
            (
                BCRYPT_ECDH_P384_ALGORITHM,
                NCRYPT_SECRET_AGREEMENT_INTERFACE,
                NCRYPT_SECRET_AGREEMENT_OPERATION,
            ),
            (
                BCRYPT_ECDH_P521_ALGORITHM,
                NCRYPT_SECRET_AGREEMENT_INTERFACE,
                NCRYPT_SECRET_AGREEMENT_OPERATION,
            ),
            (
                BCRYPT_ECDSA_ALGORITHM,
                NCRYPT_SIGNATURE_INTERFACE,
                NCRYPT_SIGNATURE_OPERATION,
            ),
            (
                BCRYPT_ECDSA_P256_ALGORITHM,
                NCRYPT_SIGNATURE_INTERFACE,
                NCRYPT_SIGNATURE_OPERATION,
            ),
            (
                BCRYPT_ECDSA_P384_ALGORITHM,
                NCRYPT_SIGNATURE_INTERFACE,
                NCRYPT_SIGNATURE_OPERATION,
            ),
            (
                BCRYPT_ECDSA_P521_ALGORITHM,
                NCRYPT_SIGNATURE_INTERFACE,
                NCRYPT_SIGNATURE_OPERATION,
            ),
        ];

        for i in 0..algos.len() {
            let a = unsafe { algos[i].pszName.as_wide() };
            let b = unsafe { expected[i].0.as_wide() };
            assert_eq!(a, b);

            assert_eq!(algos[i].dwClass, expected[i].1);
            assert_eq!(algos[i].dwAlgOperations, expected[i].2);
        }
    }
}
