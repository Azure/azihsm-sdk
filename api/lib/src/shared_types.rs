// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common types used across the HSM library.
//!
//! This module provides core type definitions including key classes, key kinds,
//! and elliptic curve identifiers that are shared between the library and native layers.

use open_enum::open_enum;
use zerocopy::*;

/// A single DER-encoded certificate in a certificate chain.
///
/// Borrowed view over one certificate's DER bytes, used by the
/// partition-provisioning API (e.g. [`HsmSession::part_final`]) to accept
/// a PTA certificate chain as `&[HsmCertDescriptor]`.
///
/// This is a Rust borrowed view, **not** a `#[repr(C)]` / ABI-stable
/// type: it cannot be shared across the FFI boundary directly. The
/// native FFI layer instead converts a C array of `{ data, len }`
/// certificate buffers into a `&[HsmCertDescriptor]`, wrapping each
/// buffer's bytes (the DER is borrowed, not copied). The wire-level
/// side-band `(offset, length)` descriptors stay an internal detail the
/// SDK derives on the caller's behalf.
///
/// [`HsmSession::part_final`]: crate::HsmSession::part_final
#[derive(Debug, Clone, Copy)]
pub struct HsmCertDescriptor<'a> {
    /// DER-encoded bytes of the certificate.
    pub cert: &'a [u8],
}

/// Cryptographic key class.
///
/// Defines the fundamental category of a cryptographic key.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmKeyClass {
    /// Symmetric secret key (e.g., AES, HMAC).
    Secret = 1,

    /// Public key from an asymmetric key pair.
    Public = 2,

    /// Private key from an asymmetric key pair.
    Private = 3,
}

/// Cryptographic key algorithm type.
///
/// Specifies the algorithm family for a cryptographic key.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmKeyKind {
    /// RSA asymmetric key kind.
    Rsa = 1,

    /// Elliptic Curve (EC) asymmetric key kind.
    Ecc = 2,

    /// Advanced Encryption Standard (AES) symmetric key kind.
    Aes = 3,

    /// AES XTS symmetric key kind.
    AesXts = 4,

    /// Shared secret key kind.
    SharedSecret = 5,

    /// HMAC SHA 1 is not supported.
    // HmacSha1 = 6,

    /// HMAC SHA 256
    HmacSha256 = 7,

    /// HMAC SHA 384
    HmacSha384 = 8,

    /// HMAC SHA 512
    HmacSha512 = 9,

    /// AES GCM symmetric key kind.
    AesGcm = 10,
}

/// Elliptic Curve Cryptography (ECC) curve identifier.
///
/// Specifies the elliptic curve used for ECC keys, as defined by NIST.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmEccCurve {
    /// NIST P-256 curve (secp256r1), 256-bit security.
    P256 = 1,
    /// NIST P-384 curve (secp384r1), 384-bit security.
    P384 = 2,
    /// NIST P-521 curve (secp521r1), 521-bit security.
    P521 = 3,
}

impl HsmEccCurve {
    /// Returns the key size in bits for the ECC curve.
    pub fn key_size_bits(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 256,
            HsmEccCurve::P384 => 384,
            HsmEccCurve::P521 => 521,
        }
    }

    /// Returns the signature size in bytes for the ECC curve.
    pub fn signature_size(&self) -> usize {
        self.component_size() * 2
    }

    /// Returns the component size in bytes for the ECC curve.
    pub fn component_size(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 32,
            HsmEccCurve::P384 => 48,
            HsmEccCurve::P521 => 66,
        }
    }
}

/// HSM partition type.
///
/// Indicates whether the partition is a virtual (simulated) or physical (hardware) device.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmPartType {
    /// Virtual/simulated partition.
    Virtual = 1,

    /// Physical hardware partition.
    Physical = 2,
}

/// Owner backup key source.
///
/// Specifies the source of the owner backup key (OBK) during partition initialization.
#[repr(u32)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmOwnerBackupKeySource {
    /// Caller provided backup key.
    Caller = 1,

    /// TPM-sealed backup key (retrieved from device and unsealed).
    Tpm = 2,
}

/// HSM partition owner trust anchor (aka POTA) endorsement source.
#[repr(u32)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmPotaEndorsementSource {
    /// Caller provided endorsement.
    Caller = 1,

    /// TPM-generated endorsement.
    Tpm = 2,
}
