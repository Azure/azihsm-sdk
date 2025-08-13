// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::ptr;

use openssl::x509::X509;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

use crate::common::*;

#[test]
fn test_get_collateral() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut collateral_size = 0u32;

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptGetProperty(
            azihsm_provider.handle(),
            AZIHSM_DEVICE_CERT_CHAIN_PROPERTY,
            None,
            ptr::addr_of_mut!(collateral_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        assert!(collateral_size > 0);

        let mut collateral = vec![0u8; collateral_size as usize];
        let result = NCryptGetProperty(
            azihsm_provider.handle(),
            AZIHSM_DEVICE_CERT_CHAIN_PROPERTY,
            Some(&mut collateral),
            ptr::addr_of_mut!(collateral_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        collateral.truncate(collateral_size as usize);

        let x509_cert = X509::from_pem(&collateral);
        assert!(x509_cert.is_ok());

        let public_key = x509_cert.unwrap().public_key();
        assert!(public_key.is_ok());
    }
}
