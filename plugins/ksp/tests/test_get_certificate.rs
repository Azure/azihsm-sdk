// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::ptr;

use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

use x509::X509Certificate;
use x509::X509CertificateOp;

use crate::common::*;

#[test]
fn test_get_certificate() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut certificate_size = 0u32;

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptGetProperty(
            azihsm_provider.handle(),
            AZIHSM_DEVICE_CERT_CHAIN_PROPERTY,
            None,
            ptr::addr_of_mut!(certificate_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        assert!(certificate_size > 0);

        let mut certificate = vec![0u8; certificate_size as usize];
        let result = NCryptGetProperty(
            azihsm_provider.handle(),
            AZIHSM_DEVICE_CERT_CHAIN_PROPERTY,
            Some(&mut certificate),
            ptr::addr_of_mut!(certificate_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        certificate.truncate(certificate_size as usize);

        // --------------------- Parse X509 Certificate --------------------- //
        // Parse the certificate's PEM bytes and create an `X509Certificate`
        // object
        let cert = X509Certificate::from_pem(&certificate).expect("Failed to parse certificate");

        // Extract the public key DER blob from the certificate
        let _public_key_blob = cert
            .get_public_key_der()
            .expect("Failed to get public key blob");
    }
}
