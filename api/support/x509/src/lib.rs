// Copyright (C) Microsoft Corporation. All rights reserved.

//! This module implements utilities for parsing and interacting with X509
//! certificates.

#[cfg(target_os = "linux")]
use openssl::pkey::PKey;
#[cfg(target_os = "linux")]
use openssl::pkey::Public;
#[cfg(target_os = "linux")]
use openssl::x509::X509;
use thiserror::Error;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::GetLastError;
#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::*;

/// Enum to represent errors that can occur when working with X509 certificates.
#[derive(Error, Debug, PartialEq, Eq, Clone, Copy)]
pub enum X509CertificateError {
    #[error("Failed to parse PEM-encoded certificate")]
    PemParseError,

    #[error("Failed to parse DER-encoded certificate")]
    DerParseError,

    #[cfg(target_os = "windows")]
    #[error("Failed to create CNG `CERT_CONTEXT` object")]
    WinCertContextError,

    #[cfg(target_os = "linux")]
    #[error("Failed to create OpenSSL `PKey<Public>` object")]
    OSSLGetPublicKeyError,

    #[error("Failed to extract public key blob from certificate")]
    PublicKeyToDerError,
}

/// A trait defining common functions for `X509Certificate` objects that are
/// implemented for both Windows and Linux.
pub trait X509CertificateOp {
    fn from_pem(pem_bytes: &[u8]) -> Result<X509Certificate, X509CertificateError>;
    fn from_der(der_bytes: &[u8]) -> Result<X509Certificate, X509CertificateError>;
    fn get_public_key_der(&self) -> Result<Vec<u8>, X509CertificateError>;
}

/// A struct representing an X509 certificate.
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// The DER-encoded bytes representing the X509 certificate.
    der: Vec<u8>,

    /// The OpenSSL X509 object representing the certificate.
    #[cfg(target_os = "linux")]
    cert: X509,
}

/// A wreapper for a `*mut CERT_CONTEXT` pointer, which is used by the Windows
/// implementation in this crate.
#[cfg(target_os = "windows")]
struct CertContext {
    pub ptr: *mut CERT_CONTEXT,
}

#[cfg(target_os = "windows")]
/// Drop implementation for `CertContext`, which allows allocated `*mut
/// CERT_CONTEXT` objects to be auto-freed when a Rust function returns.
impl Drop for CertContext {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let _free_result = unsafe { CertFreeCertificateContext(Some(self.ptr)) };
        }
    }
}

/// OS-specific functions and OS-agnostic implementations for the
/// `X509Certificate` object.
impl X509Certificate {
    /// Return the DER-encoded certificate as a byte slice.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Private helper function for Windows that allocates and returns a pointer
    /// to a CNG `CERT_CONTEXT` object representing the certificate.
    #[cfg(target_os = "windows")]
    fn create_cert_context(&self) -> Result<CertContext, X509CertificateError> {
        // Retrieve the object's DER encodngina and pass it into
        // `CertCreateCertificateContext` to create a new `CERT_CONTEXT`.
        let der: &[u8] = self.as_der();
        let cert_ctx: *mut CERT_CONTEXT =
            unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der) };
        if cert_ctx.is_null() {
            let err = unsafe { GetLastError() };
            tracing::error!("CertCreateCertificateContext failed: {:?}", err);
            return Err(X509CertificateError::WinCertContextError);
        }

        Ok(CertContext { ptr: cert_ctx })
    }

    /// Helper function for Linux that returns an OpenSSL `PKey<Public>` object.
    #[cfg(target_os = "linux")]
    fn get_public_key(&self) -> Result<PKey<Public>, X509CertificateError> {
        let public_key = self.cert.public_key().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            X509CertificateError::OSSLGetPublicKeyError
        })?;
        Ok(public_key)
    }
}

/// Windows implementation of X509 operations.
#[cfg(target_os = "windows")]
impl X509CertificateOp for X509Certificate {
    /// Create a new `X509Certificate` from a PEM encoding.
    fn from_pem(pem_bytes: &[u8]) -> Result<Self, X509CertificateError> {
        // Call `CryptStringToBinaryA` once to determine how many bytes we need
        // to store the binary data.
        let mut der_len: u32 = 0;
        let result = unsafe {
            CryptStringToBinaryA(
                pem_bytes,
                CRYPT_STRING_BASE64HEADER,
                None,
                std::ptr::addr_of_mut!(der_len),
                None,
                None,
            )
        };
        if result.is_err() {
            let err = unsafe { GetLastError() };
            tracing::error!("CryptStringToBinaryA (call #1) failed: {:?}", err);
            return Err(X509CertificateError::PemParseError);
        }

        // Allocate a buffer of the required size and call
        // `CryptStringToBinaryA` again to retrieve the binary data.
        let mut der = vec![0u8; der_len as usize];
        let result = unsafe {
            CryptStringToBinaryA(
                pem_bytes,
                CRYPT_STRING_BASE64HEADER,
                Some(der.as_mut_ptr()),
                std::ptr::addr_of_mut!(der_len),
                None,
                None,
            )
        };
        if result.is_err() {
            let err = unsafe { GetLastError() };
            tracing::error!("CryptStringToBinaryA (call #2) failed: {:?}", err);
            return Err(X509CertificateError::PemParseError);
        }

        // Pass the DER encoded bytes into the `from_der` function to finish the
        // initialization.
        Self::from_der(&der)
    }

    /// Create a new `X509Certificate` from a DER encoding.
    fn from_der(der_bytes: &[u8]) -> Result<Self, X509CertificateError> {
        let der = Vec::from(der_bytes);
        let cert = Self { der };

        // To verify the validity of the DER bytes, we'll attempt to create a
        // CNG `CERT_CONTEXT` object from it. If it fails, we know something is
        // wrong with the provided DER bytes.
        let _cert_ctx = cert.create_cert_context()?;

        Ok(cert)
    }

    /// Parses the public key DER blob from the certificates and returns it in a
    /// vector.
    fn get_public_key_der(&self) -> Result<Vec<u8>, X509CertificateError> {
        // In order to get the public key blob, we need to create a CNG
        // certificate context from the DER-encoded certificate.
        let cert_ctx: CertContext = self.create_cert_context()?;

        // Within the `CERT_CONTEXT` object, look for the
        // `CERT_PUBLIC_KEY_INFO`. This contains information on the public key.
        let spki: CERT_PUBLIC_KEY_INFO =
            unsafe { (*(*cert_ctx.ptr).pCertInfo).SubjectPublicKeyInfo };

        // Invoke `CryptEncodeObjectEx` once to determine how many bytes we need
        // to store the DER encoding of the public key.
        let mut der_len: u32 = 0;
        let encode_result = unsafe {
            CryptEncodeObjectEx(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                std::ptr::addr_of!(spki) as *const std::ffi::c_void,
                CRYPT_ENCODE_OBJECT_FLAGS(0),
                None,
                None,
                std::ptr::addr_of_mut!(der_len),
            )
        };
        if encode_result.is_err() {
            tracing::error!("CryptEncodeObjectEx failed: {:?}", encode_result);
            return Err(X509CertificateError::PublicKeyToDerError);
        }

        // Allocate a buffer and call `CryptEncodeObjectEx` again to retrieve
        // the DER encoding of the public key.
        let mut public_key_blob_data: Vec<u8> = vec![0u8; der_len as usize];
        let encode_result = unsafe {
            CryptEncodeObjectEx(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                std::ptr::addr_of!(spki) as *const std::ffi::c_void,
                CRYPT_ENCODE_OBJECT_FLAGS(0),
                None,
                Some(public_key_blob_data.as_mut_ptr() as *mut std::ffi::c_void),
                std::ptr::addr_of_mut!(der_len),
            )
        };
        if encode_result.is_err() {
            tracing::error!("CryptEncodeObjectEx failed: {:?}", encode_result);
            return Err(X509CertificateError::PublicKeyToDerError);
        }

        Ok(public_key_blob_data)
    }
}

/// Linux implementation of X509 operations.
#[cfg(target_os = "linux")]
impl X509CertificateOp for X509Certificate {
    /// Create a new `X509Certificate` from a PEM encoding.
    fn from_pem(pem_bytes: &[u8]) -> Result<Self, X509CertificateError> {
        // Attempt to parse the PEM encoding with OpenSSL; dump the error stack
        // and return the appropriate error code on failure.
        let cert = X509::from_pem(pem_bytes).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            X509CertificateError::PemParseError
        })?;

        // Get a DER encoding of the certificate and store it in the resulting
        // `X509Certificate` object.
        let der = cert.to_der().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            X509CertificateError::PemParseError
        })?;
        Ok(Self { der, cert })
    }

    /// Create a new `X509Certificate` from a DER encoding.
    fn from_der(der_bytes: &[u8]) -> Result<Self, X509CertificateError> {
        // Parse the DER encoding with OpenSSL; dump the error stack and return
        // the appropriate error code on failure.
        let cert = X509::from_der(der_bytes).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            X509CertificateError::DerParseError
        })?;

        let der = Vec::from(der_bytes);
        Ok(Self { der, cert })
    }

    /// Parses the public key DER blob from the certificates and returns it in a
    /// vector.
    fn get_public_key_der(&self) -> Result<Vec<u8>, X509CertificateError> {
        let public_key = self.get_public_key()?;

        // Export the public key in DER format
        let public_key_der = public_key
            .public_key_to_der()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                X509CertificateError::PublicKeyToDerError
            })?;
        Ok(public_key_der)
    }
}

// ================================= Tests ================================== //
/// Tests to exercise the x509 certificate functionality implemented above.
#[cfg(test)]
pub mod tests {
    use super::*;

    /// Returns a valid PEM-encoded certificate, containing an RSA public key,
    /// for test usage.
    fn get_rsa_pem_valid() -> &'static str {
        "-----BEGIN CERTIFICATE-----\n\
        MIIDazCCAlOgAwIBAgIUM0mXvaKXU/FeGvPJMK7Bz8cr16swDQYJKoZIhvcNAQEL\n\
        BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\n\
        GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNTEwMDgxNTMxMDdaFw0yNjEw\n\
        MDgxNTMxMDdaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\n\
        HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\n\
        AQUAA4IBDwAwggEKAoIBAQDOaRpBHrZDaq4ZsjiwKJi31c4bKPOxYxe+ICk6sLXo\n\
        eGukMFBQ9rB5wh88SyML7S2CYO5LkR/vbEi+XRN5F230QX5cr6FJHzE/Lw9LpASN\n\
        0sBkMnq2aEBgWPblwAFjPjH8OEimGYLQKD6SflJSlqR1WtIs/Rj0y1RjGs2Af19d\n\
        jbdQh/+IbY2x7Y1opgMEL+SySjXbGOJ0aa637lVQmpHU0o50Nhi+JS4RMaHRrAgU\n\
        5kemPgUrLq5X9/wNOfCHqvLOJ4wNyU3MqTphJP0/paEpyv5jC6m7lF9+fDogSA03\n\
        CQKrqx5Sx1lohfvs+rPfuVxmt42uHqC0unWkSDFwoKgBAgMBAAGjUzBRMB0GA1Ud\n\
        DgQWBBQUVqkx5Awz2sX+PfLf9dXGON/nmzAfBgNVHSMEGDAWgBQUVqkx5Awz2sX+\n\
        PfLf9dXGON/nmzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCQ\n\
        WA9iUJaySXUhse5n6YDn1Jovk3dZCtPOulxmF4/F2g3lnJGdEMG24lXRTU9X4vBm\n\
        xTKKPOQIIszgd9GQAIYVclZnUZl8AZgq+lpVZbC32OD5oPAok+YDGcal868SQnfq\n\
        cYfvAAg6XRkdFYI7FOH0HKv3Lb2Kxw/oPvdJARzRl9Cb5N89gAj7qNN7w39A41YZ\n\
        CqTNkpG5WPamsFUS0bt7UUtQiLkNEAHnId52COzQfsCqvh20wYLUXfrFNRW7sxou\n\
        ZkW1giCpfNZX9LjceXkcLw/xblKaayCeQk9g/mDOcHImQ27DatJe8/wUeEwyYotM\n\
        k0QXvFmRKy4aOC74koM/\n\
        -----END CERTIFICATE-----\n"
    }

    /// Returns a valid PEM-encoded certificate, containing an ECC public key,
    /// for test usage.
    fn get_ecc_pem_valid() -> &'static str {
        "-----BEGIN CERTIFICATE-----\n\
        MIIBmzCCASCgAwIBAgIBATAKBggqhkjOPQQDAzAWMRQwEgYDVQQDDAtleGFtcGxl\n\
        LmNvbTAeFw0yNTEwMDYxNjA2NDBaFw0yNjEwMDYxNjA2NDBaMBYxFDASBgNVBAMM\n\
        C2V4YW1wbGUuY29tMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEm6Fac52u6LBjjZ3F\n\
        W7W4M/Ntx37nrKbycI2cjhEMRGtZPtQhpPKf/HZtKUANmbK+Rx68Z3gCEq7r55oC\n\
        2yux3SyWpJ5mAKqMpOmYzPPOnDGejq59XULEseNoNBdHqqsdo0IwQDAdBgNVHQ4E\n\
        FgQUvXd6Gugsiea6oYL597d3YdRBBYowDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n\
        Af8EBAMCAQYwCgYIKoZIzj0EAwMDaQAwZgIxAKGxVVEDfIA5khZP2CTrPGnkylZP\n\
        m5loQ4etSdAnBoYvTAh7+pggESE5sEW82Y3qGgIxAIXugVl1oaCYfgzMuPoZcIqV\n\
        q9CStUMn61DtbXbK/d4V/jfKQlLHi+zZfPjWC7kPxQ==\n\
        -----END CERTIFICATE-----\n"
    }

    /// Returns a malformed/invalid PEM-encoded certificate, for test usage.
    fn get_pem_invalid() -> &'static str {
        "-----THIS WILL NOT PARSE-----\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        -----END CERTIFICATE-----\n"
    }

    /// Returns a valid DER-encoded certificate, containing an RSA public key,
    /// for test usage.
    fn get_rsa_der_valid() -> &'static [u8] {
        let der: &[u8] = &[
            0x30, 0x82, 0x03, 0x6b, 0x30, 0x82, 0x02, 0x53, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
            0x14, 0x33, 0x49, 0x97, 0xbd, 0xa2, 0x97, 0x53, 0xf1, 0x5e, 0x1a, 0xf3, 0xc9, 0x30,
            0xae, 0xc1, 0xcf, 0xc7, 0x2b, 0xd7, 0xab, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
            0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09,
            0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06,
            0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61,
            0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
            0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74,
            0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x1e, 0x17, 0x0d, 0x32,
            0x35, 0x31, 0x30, 0x30, 0x38, 0x31, 0x35, 0x33, 0x31, 0x30, 0x37, 0x5a, 0x17, 0x0d,
            0x32, 0x36, 0x31, 0x30, 0x30, 0x38, 0x31, 0x35, 0x33, 0x31, 0x30, 0x37, 0x5a, 0x30,
            0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55,
            0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d,
            0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55,
            0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57,
            0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64,
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a,
            0x02, 0x82, 0x01, 0x01, 0x00, 0xce, 0x69, 0x1a, 0x41, 0x1e, 0xb6, 0x43, 0x6a, 0xae,
            0x19, 0xb2, 0x38, 0xb0, 0x28, 0x98, 0xb7, 0xd5, 0xce, 0x1b, 0x28, 0xf3, 0xb1, 0x63,
            0x17, 0xbe, 0x20, 0x29, 0x3a, 0xb0, 0xb5, 0xe8, 0x78, 0x6b, 0xa4, 0x30, 0x50, 0x50,
            0xf6, 0xb0, 0x79, 0xc2, 0x1f, 0x3c, 0x4b, 0x23, 0x0b, 0xed, 0x2d, 0x82, 0x60, 0xee,
            0x4b, 0x91, 0x1f, 0xef, 0x6c, 0x48, 0xbe, 0x5d, 0x13, 0x79, 0x17, 0x6d, 0xf4, 0x41,
            0x7e, 0x5c, 0xaf, 0xa1, 0x49, 0x1f, 0x31, 0x3f, 0x2f, 0x0f, 0x4b, 0xa4, 0x04, 0x8d,
            0xd2, 0xc0, 0x64, 0x32, 0x7a, 0xb6, 0x68, 0x40, 0x60, 0x58, 0xf6, 0xe5, 0xc0, 0x01,
            0x63, 0x3e, 0x31, 0xfc, 0x38, 0x48, 0xa6, 0x19, 0x82, 0xd0, 0x28, 0x3e, 0x92, 0x7e,
            0x52, 0x52, 0x96, 0xa4, 0x75, 0x5a, 0xd2, 0x2c, 0xfd, 0x18, 0xf4, 0xcb, 0x54, 0x63,
            0x1a, 0xcd, 0x80, 0x7f, 0x5f, 0x5d, 0x8d, 0xb7, 0x50, 0x87, 0xff, 0x88, 0x6d, 0x8d,
            0xb1, 0xed, 0x8d, 0x68, 0xa6, 0x03, 0x04, 0x2f, 0xe4, 0xb2, 0x4a, 0x35, 0xdb, 0x18,
            0xe2, 0x74, 0x69, 0xae, 0xb7, 0xee, 0x55, 0x50, 0x9a, 0x91, 0xd4, 0xd2, 0x8e, 0x74,
            0x36, 0x18, 0xbe, 0x25, 0x2e, 0x11, 0x31, 0xa1, 0xd1, 0xac, 0x08, 0x14, 0xe6, 0x47,
            0xa6, 0x3e, 0x05, 0x2b, 0x2e, 0xae, 0x57, 0xf7, 0xfc, 0x0d, 0x39, 0xf0, 0x87, 0xaa,
            0xf2, 0xce, 0x27, 0x8c, 0x0d, 0xc9, 0x4d, 0xcc, 0xa9, 0x3a, 0x61, 0x24, 0xfd, 0x3f,
            0xa5, 0xa1, 0x29, 0xca, 0xfe, 0x63, 0x0b, 0xa9, 0xbb, 0x94, 0x5f, 0x7e, 0x7c, 0x3a,
            0x20, 0x48, 0x0d, 0x37, 0x09, 0x02, 0xab, 0xab, 0x1e, 0x52, 0xc7, 0x59, 0x68, 0x85,
            0xfb, 0xec, 0xfa, 0xb3, 0xdf, 0xb9, 0x5c, 0x66, 0xb7, 0x8d, 0xae, 0x1e, 0xa0, 0xb4,
            0xba, 0x75, 0xa4, 0x48, 0x31, 0x70, 0xa0, 0xa8, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01,
            0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
            0x14, 0x14, 0x56, 0xa9, 0x31, 0xe4, 0x0c, 0x33, 0xda, 0xc5, 0xfe, 0x3d, 0xf2, 0xdf,
            0xf5, 0xd5, 0xc6, 0x38, 0xdf, 0xe7, 0x9b, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
            0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x14, 0x56, 0xa9, 0x31, 0xe4, 0x0c, 0x33, 0xda,
            0xc5, 0xfe, 0x3d, 0xf2, 0xdf, 0xf5, 0xd5, 0xc6, 0x38, 0xdf, 0xe7, 0x9b, 0x30, 0x0f,
            0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
            0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
            0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x90, 0x58, 0x0f, 0x62, 0x50, 0x96, 0xb2,
            0x49, 0x75, 0x21, 0xb1, 0xee, 0x67, 0xe9, 0x80, 0xe7, 0xd4, 0x9a, 0x2f, 0x93, 0x77,
            0x59, 0x0a, 0xd3, 0xce, 0xba, 0x5c, 0x66, 0x17, 0x8f, 0xc5, 0xda, 0x0d, 0xe5, 0x9c,
            0x91, 0x9d, 0x10, 0xc1, 0xb6, 0xe2, 0x55, 0xd1, 0x4d, 0x4f, 0x57, 0xe2, 0xf0, 0x66,
            0xc5, 0x32, 0x8a, 0x3c, 0xe4, 0x08, 0x22, 0xcc, 0xe0, 0x77, 0xd1, 0x90, 0x00, 0x86,
            0x15, 0x72, 0x56, 0x67, 0x51, 0x99, 0x7c, 0x01, 0x98, 0x2a, 0xfa, 0x5a, 0x55, 0x65,
            0xb0, 0xb7, 0xd8, 0xe0, 0xf9, 0xa0, 0xf0, 0x28, 0x93, 0xe6, 0x03, 0x19, 0xc6, 0xa5,
            0xf3, 0xaf, 0x12, 0x42, 0x77, 0xea, 0x71, 0x87, 0xef, 0x00, 0x08, 0x3a, 0x5d, 0x19,
            0x1d, 0x15, 0x82, 0x3b, 0x14, 0xe1, 0xf4, 0x1c, 0xab, 0xf7, 0x2d, 0xbd, 0x8a, 0xc7,
            0x0f, 0xe8, 0x3e, 0xf7, 0x49, 0x01, 0x1c, 0xd1, 0x97, 0xd0, 0x9b, 0xe4, 0xdf, 0x3d,
            0x80, 0x08, 0xfb, 0xa8, 0xd3, 0x7b, 0xc3, 0x7f, 0x40, 0xe3, 0x56, 0x19, 0x0a, 0xa4,
            0xcd, 0x92, 0x91, 0xb9, 0x58, 0xf6, 0xa6, 0xb0, 0x55, 0x12, 0xd1, 0xbb, 0x7b, 0x51,
            0x4b, 0x50, 0x88, 0xb9, 0x0d, 0x10, 0x01, 0xe7, 0x21, 0xde, 0x76, 0x08, 0xec, 0xd0,
            0x7e, 0xc0, 0xaa, 0xbe, 0x1d, 0xb4, 0xc1, 0x82, 0xd4, 0x5d, 0xfa, 0xc5, 0x35, 0x15,
            0xbb, 0xb3, 0x1a, 0x2e, 0x66, 0x45, 0xb5, 0x82, 0x20, 0xa9, 0x7c, 0xd6, 0x57, 0xf4,
            0xb8, 0xdc, 0x79, 0x79, 0x1c, 0x2f, 0x0f, 0xf1, 0x6e, 0x52, 0x9a, 0x6b, 0x20, 0x9e,
            0x42, 0x4f, 0x60, 0xfe, 0x60, 0xce, 0x70, 0x72, 0x26, 0x43, 0x6e, 0xc3, 0x6a, 0xd2,
            0x5e, 0xf3, 0xfc, 0x14, 0x78, 0x4c, 0x32, 0x62, 0x8b, 0x4c, 0x93, 0x44, 0x17, 0xbc,
            0x59, 0x91, 0x2b, 0x2e, 0x1a, 0x38, 0x2e, 0xf8, 0x92, 0x83, 0x3f,
        ];
        der
    }

    /// Returns a valid DER-encoded certificate, containing an ECC public key,
    /// for test usage.
    fn get_ecc_der_valid() -> &'static [u8] {
        let der: &[u8] = &[
            0x30, 0x82, 0x01, 0x9b, 0x30, 0x82, 0x01, 0x20, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
            0x01, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
            0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d,
            0x32, 0x35, 0x31, 0x30, 0x30, 0x36, 0x31, 0x36, 0x30, 0x36, 0x34, 0x30, 0x5a, 0x17,
            0x0d, 0x32, 0x36, 0x31, 0x30, 0x30, 0x36, 0x31, 0x36, 0x30, 0x36, 0x34, 0x30, 0x5a,
            0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x76, 0x30, 0x10,
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
            0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x9b, 0xa1, 0x5a, 0x73, 0x9d, 0xae, 0xe8, 0xb0,
            0x63, 0x8d, 0x9d, 0xc5, 0x5b, 0xb5, 0xb8, 0x33, 0xf3, 0x6d, 0xc7, 0x7e, 0xe7, 0xac,
            0xa6, 0xf2, 0x70, 0x8d, 0x9c, 0x8e, 0x11, 0x0c, 0x44, 0x6b, 0x59, 0x3e, 0xd4, 0x21,
            0xa4, 0xf2, 0x9f, 0xfc, 0x76, 0x6d, 0x29, 0x40, 0x0d, 0x99, 0xb2, 0xbe, 0x47, 0x1e,
            0xbc, 0x67, 0x78, 0x02, 0x12, 0xae, 0xeb, 0xe7, 0x9a, 0x02, 0xdb, 0x2b, 0xb1, 0xdd,
            0x2c, 0x96, 0xa4, 0x9e, 0x66, 0x00, 0xaa, 0x8c, 0xa4, 0xe9, 0x98, 0xcc, 0xf3, 0xce,
            0x9c, 0x31, 0x9e, 0x8e, 0xae, 0x7d, 0x5d, 0x42, 0xc4, 0xb1, 0xe3, 0x68, 0x34, 0x17,
            0x47, 0xaa, 0xab, 0x1d, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
            0x0e, 0x04, 0x16, 0x04, 0x14, 0xbd, 0x77, 0x7a, 0x1a, 0xe8, 0x2c, 0x89, 0xe6, 0xba,
            0xa1, 0x82, 0xf9, 0xf7, 0xb7, 0x77, 0x61, 0xd4, 0x41, 0x05, 0x8a, 0x30, 0x0f, 0x06,
            0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
            0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
            0x01, 0x06, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
            0x03, 0x69, 0x00, 0x30, 0x66, 0x02, 0x31, 0x00, 0xa1, 0xb1, 0x55, 0x51, 0x03, 0x7c,
            0x80, 0x39, 0x92, 0x16, 0x4f, 0xd8, 0x24, 0xeb, 0x3c, 0x69, 0xe4, 0xca, 0x56, 0x4f,
            0x9b, 0x99, 0x68, 0x43, 0x87, 0xad, 0x49, 0xd0, 0x27, 0x06, 0x86, 0x2f, 0x4c, 0x08,
            0x7b, 0xfa, 0x98, 0x20, 0x11, 0x21, 0x39, 0xb0, 0x45, 0xbc, 0xd9, 0x8d, 0xea, 0x1a,
            0x02, 0x31, 0x00, 0x85, 0xee, 0x81, 0x59, 0x75, 0xa1, 0xa0, 0x98, 0x7e, 0x0c, 0xcc,
            0xb8, 0xfa, 0x19, 0x70, 0x8a, 0x95, 0xab, 0xd0, 0x92, 0xb5, 0x43, 0x27, 0xeb, 0x50,
            0xed, 0x6d, 0x76, 0xca, 0xfd, 0xde, 0x15, 0xfe, 0x37, 0xca, 0x42, 0x52, 0xc7, 0x8b,
            0xec, 0xd9, 0x7c, 0xf8, 0xd6, 0x0b, 0xb9, 0x0f, 0xc5,
        ];
        der
    }

    /// Returns a malformed/invalid DER-encoded certificate, for test usage.
    fn get_der_invalid() -> &'static [u8] {
        let der: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        der
    }

    /// Tests a successful case of parsing a DER-encoded certificate.
    #[test]
    fn test_from_der_success() {
        let test_inputs = vec![get_rsa_der_valid(), get_ecc_der_valid()];

        for der_bytes in test_inputs {
            let _cert =
                X509Certificate::from_der(der_bytes).expect("Failed to parse certificate DER");
        }
    }

    /// Tests a failing case of parsing a DER-encoded certificate.
    #[test]
    fn test_from_der_failure() {
        let der_bytes = get_der_invalid();
        let _cert = X509Certificate::from_der(der_bytes)
            .expect_err("DER parsing succeeded when it was expected to fail");
    }

    /// Tests a successful case of parsing a PEM-encoded certificate.
    #[test]
    fn test_from_pem_success() {
        let test_inputs = vec![
            get_rsa_pem_valid().as_bytes(),
            get_ecc_pem_valid().as_bytes(),
        ];

        for pem_bytes in test_inputs {
            let _cert =
                X509Certificate::from_pem(pem_bytes).expect("Failed to parse certificate PEM");
        }
    }

    /// Tests a failing case of parsing a PEM-encoded certificate.
    #[test]
    fn test_from_pem_failure() {
        let pem_bytes = get_pem_invalid().as_bytes();
        let _cert = X509Certificate::from_pem(pem_bytes)
            .expect_err("PEM parsing succeeded when it was expected to fail");
    }

    /// Tests getting a public key DER blob from a valid certificate.
    #[test]
    fn test_get_public_key_der() {
        let test_inputs = vec![
            get_rsa_pem_valid().as_bytes(),
            get_ecc_pem_valid().as_bytes(),
        ];

        for pem_bytes in test_inputs {
            let cert =
                X509Certificate::from_pem(pem_bytes).expect("Failed to parse certificate PEM");
            let _public_key_blob = cert
                .get_public_key_der()
                .expect("Failed to get public key DER blob");
        }
    }

    /// Tests deriving a public key from a certificate and turning it into a
    /// usable RSA public key.
    #[test]
    fn test_rsa_public_key_from_cert() {
        use crypto::CryptoRsaCryptoPadding;
        use crypto::rsa::RsaOp;
        use crypto::rsa::RsaPublicKey;
        use crypto::rsa::RsaPublicOp;

        let der_bytes = get_rsa_der_valid();

        let cert = X509Certificate::from_der(der_bytes).expect("Failed to parse certificate DER");

        // Extract the public key DER encoding and pass it into an RSA
        // public key object.
        let public_key_der = cert
            .get_public_key_der()
            .expect("Failed to get public key DER blob");
        let public_key = RsaPublicKey::from_der(public_key_der.as_slice(), None).expect(
            "Failed to parse public key DER blob while attempting to create RSA public key",
        );

        // Test the RSA public key we just parsed by using it to encrypt data.
        let _ciphertext = public_key
            .encrypt(b"TEST_PLAINTEXT", CryptoRsaCryptoPadding::Oaep, None, None)
            .expect("Failed to encrypt data with RSA public key");
    }

    /// Tests deriving a public key from a certificate and turning it into a
    /// usable ECC public key.
    #[test]
    fn test_ecc_public_key_from_cert() {
        use crypto::ecc::EccOp;
        use crypto::ecc::EccPublicKey;

        let der_bytes = get_ecc_der_valid();

        let cert = X509Certificate::from_der(der_bytes).expect("Failed to parse certificate DER");

        // Extract the public key DER encoding and pass it into an ECC
        // public key object.
        let public_key_der = cert
            .get_public_key_der()
            .expect("Failed to get public key DER blob");
        let _public_key = EccPublicKey::from_der(public_key_der.as_slice(), None).expect(
            "Failed to parse public key DER blob while attempting to create ECC public key",
        );

        // Because this test derives an ECC public key from an X509 certificate,
        // and because we do not have the corresponding private key (nor any
        // signature produced by it), we can't test the key's functionality.
        // (ECC public keys can only verify signatures).
        //
        // However, the above code is proof enough that the public key can be
        // parsed from its DER format into a usable key. The
        // `EccPublicKey::from_der` function would have thrown an error if
        // parsing failed.
    }
}
