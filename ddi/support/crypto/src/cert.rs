// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for certificate.

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and SymCrypt cannot be enabled at the same time.");

#[cfg(feature = "use-openssl")]
use openssl::x509::X509;
#[cfg(feature = "use-symcrypt")]
use pem_rfc7468::LineEnding;

use crate::CryptoError;

/// Convert DER to PEM
#[cfg(feature = "use-openssl")]
pub fn der_to_pem(der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cert = X509::from_der(der).map_err(|err| {
        tracing::error!(?err, "Failed to convert DER to PEM");
        CryptoError::InvalidCertificate
    })?;

    cert.to_pem().map_err(|err| {
        tracing::error!(?err, "Failed to export PEM from cert");
        CryptoError::InvalidCertificate
    })
}

#[cfg(feature = "use-symcrypt")]
pub fn der_to_pem(der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pem_string =
        pem_rfc7468::encode_string("CERTIFICATE", LineEnding::LF, der).map_err(|err| {
            tracing::error!(?err, "Failed to export PEM from cert");
            CryptoError::InvalidCertificate
        })?;
    Ok(pem_string.as_bytes().to_vec())
}
