// Copyright (C) Microsoft Corporation. All rights reserved.

//! DER (Distinguished Encoding Rules) encoding and decoding utilities.
//!
//! This module provides functionality for encoding and decoding cryptographic keys
//! in DER format, which is a binary encoding of ASN.1 data structures. DER is widely
//! used for key exchange, storage, and interoperability with external systems.
//!
//! # Supported Key Types
//!
//! - **ECC Keys**: Elliptic curve private and public keys per RFC 5915 and SEC1
//! - **RSA Keys**: RSA private and public keys per PKCS#1 and X.509
//!
//! # Standards Support
//!
//! The module implements encoding and decoding according to:
//! - **RFC 5915**: Elliptic Curve Private Key Structure
//! - **RFC 5480**: Elliptic Curve Cryptography Subject Public Key Information
//! - **PKCS#1**: RSA Cryptography Standard
//! - **X.509**: Public Key Infrastructure standard for certificates
//! - **SEC1**: Elliptic Curve Cryptography standard
//!
//! # Architecture
//!
//! - [`ecc`]: ECC-specific DER encoding/decoding utilities
//! - [`rsa`]: RSA-specific DER encoding/decoding utilities
//!
//! Each submodule provides structures and conversion functions for their
//! respective key types, handling the complexities of ASN.1 encoding.
//!
//! # Format Details
//!
//! DER encoding provides:
//! - Deterministic binary representation
//! - Compact format compared to text-based encodings
//! - Wide interoperability with cryptographic libraries
//! - Hierarchical structure via ASN.1 tagging
//!
//! # Security Considerations
//!
//! - Validate all imported keys before use
//! - Check key parameters against algorithm requirements
//! - Be aware of malformed DER data that could cause parser issues
//! - Private keys in DER format must be encrypted before storage or transmission
//! - Use appropriate Object Identifiers (OIDs) for curve and algorithm identification
mod digest;
mod ecc;
mod rsa;

pub use digest::*;
pub use ecc::*;
pub use rsa::*;

use super::*;
pub use crate::ecc::EccCurve;

#[cfg(test)]
mod tests;
