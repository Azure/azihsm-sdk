// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DER encoding and decoding for DigestInfo structures.
//!
//! This module provides functionality to encode and decode DigestInfo structures
//! as specified in RFC 8017 and PKCS#1. DigestInfo is used in RSA signatures to
//! encapsulate a message digest along with its algorithm identifier.
//!
//! # DigestInfo Structure
//!
//! The DigestInfo structure is defined as:
//! ```text
//! DigestInfo ::= SEQUENCE {
//!     digestAlgorithm AlgorithmIdentifier,
//!     digest OCTET STRING
//! }
//! ```
//!
//! # Supported Hash Algorithms
//!
//! - **SHA-1**: Legacy hash function (OID 1.3.14.3.2.26)
//! - **SHA-256**: Secure hash from SHA-2 family (OID 2.16.840.1.101.3.4.2.1)
//! - **SHA-384**: Secure hash from SHA-2 family (OID 2.16.840.1.101.3.4.2.2)
//! - **SHA-512**: Secure hash from SHA-2 family (OID 2.16.840.1.101.3.4.2.3)
//!
//! # Usage
//!
//! This module is primarily used for RSA PKCS#1 v1.5 signature operations where
//! the DigestInfo structure must be DER-encoded before padding and signing.

use super::*;

/// ASN.1 Object Identifier for SHA-1 hash algorithm.
///
/// OID: 1.3.14.3.2.26
///
/// # Security Warning
///
/// SHA-1 is cryptographically broken and should not be used for new applications.
pub const OID_SHA1: asn1::ObjectIdentifier = asn1::oid!(1, 3, 14, 3, 2, 26);

/// ASN.1 Object Identifier for SHA-256 hash algorithm.
///
/// OID: 2.16.840.1.101.3.4.2.1
///
/// SHA-256 is part of the SHA-2 family and is recommended for most applications.
pub const OID_SHA256: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);

/// ASN.1 Object Identifier for SHA-384 hash algorithm.
///
/// OID: 2.16.840.1.101.3.4.2.2
///
/// SHA-384 is part of the SHA-2 family and provides enhanced security.
pub const OID_SHA384: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2);

/// ASN.1 Object Identifier for SHA-512 hash algorithm.
///
/// OID: 2.16.840.1.101.3.4.2.3
///
/// SHA-512 is part of the SHA-2 family and provides the highest security level.
pub const OID_SHA512: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 3);

/// ASN.1 AlgorithmIdentifier for RSA keys.
///
/// This is the standard X.509 `AlgorithmIdentifier` shape used in SPKI / PKCS#8-like wrappers.
///
/// Notes:
/// - RFC 3279 commonly uses a DER NULL for `parameters`, but some encodings omit it.
///   We model this as `Option<Null>` and accept both forms during decoding.
/// - During encoding we emit `parameters = NULL` for deterministic output and to match
///   common SPKI/PKCS#8 encodings (and our legacy DER vectors).
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct AlgorithmIdentifier {
    algorithm: asn1::ObjectIdentifier,
    parameters: Option<asn1::Null>,
}

/// Internal ASN.1 representation of DigestInfo structure.
///
/// This structure is used for ASN.1 serialization and deserialization.
/// It represents the DigestInfo SEQUENCE containing the algorithm OID
/// and the digest value.
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct DigestInfo<'a> {
    /// The hash algorithm OID
    algorithm: AlgorithmIdentifier,
    /// The message digest bytes
    digest: &'a [u8],
}

/// Hash algorithm enumeration for DigestInfo encoding.
///
/// This enum represents the supported hash algorithms that can be
/// encoded in a DigestInfo structure. Each variant corresponds to
/// a specific ASN.1 Object Identifier.
///
/// # Security Considerations
///
/// - **Sha1**: Cryptographically broken, use only for compatibility
/// - **Sha256**: Recommended for most applications
/// - **Sha384**: High security applications
/// - **Sha512**: Maximum security applications
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DerDigestAlgo {
    /// SHA-1 hash algorithm (20 bytes output)
    Sha1,
    /// SHA-256 hash algorithm (32 bytes output)
    Sha256,
    /// SHA-384 hash algorithm (48 bytes output)
    Sha384,
    /// SHA-512 hash algorithm (64 bytes output)
    Sha512,
}

impl DerDigestAlgo {
    /// Returns the output size of the hash algorithm in bytes.
    ///
    /// # Returns
    ///
    /// The size of the hash output in bytes.
    pub fn digest_size(&self) -> usize {
        match self {
            DerDigestAlgo::Sha1 => 20,
            DerDigestAlgo::Sha256 => 32,
            DerDigestAlgo::Sha384 => 48,
            DerDigestAlgo::Sha512 => 64,
        }
    }
}

/// DigestInfo structure for DER encoding/decoding.
///
/// This structure represents a DigestInfo as defined in RFC 8017,
/// which encapsulates a message digest along with its hash algorithm
/// identifier. It is primarily used in RSA PKCS#1 v1.5 signatures.
///
/// # Structure
///
/// The DigestInfo contains:
/// - A hash algorithm identifier (mapped to ASN.1 OID)
/// - The message digest bytes
pub struct DerDigestInfo {
    /// The hash algorithm used to produce the digest
    algo: DerDigestAlgo,
    /// The message digest bytes
    pub digest: Vec<u8>,
}

impl DerDigestInfo {
    /// Creates a new DigestInfo instance.
    ///
    /// # Arguments
    ///
    /// * `algo` - The hash algorithm used to produce the digest
    /// * `digest` - The message digest bytes
    ///
    /// # Returns
    ///
    /// A new `DerDigestInfo` instance containing the algorithm and digest.
    pub fn new(algo: DerDigestAlgo, digest: &[u8]) -> Result<Self, CryptoError> {
        if algo.digest_size() != digest.len() {
            return Err(CryptoError::DerInvalidDigestSize);
        }

        Ok(Self {
            algo,
            digest: digest.to_vec(),
        })
    }

    /// Returns the hash algorithm used for this DigestInfo.
    ///
    /// # Returns
    ///
    /// The `DerDigestAlgo` enum variant representing the hash algorithm.
    pub fn algo(&self) -> DerDigestAlgo {
        self.algo
    }

    /// Returns the message digest bytes.
    ///
    /// # Returns
    ///
    /// A slice containing the digest bytes.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Decodes a DigestInfo from DER format.
    ///
    /// This method deserializes a DER-encoded DigestInfo structure and
    /// validates that the hash algorithm OID is recognized.
    ///
    /// # Arguments
    ///
    /// * `input` - The DER-encoded DigestInfo bytes
    ///
    /// # Returns
    ///
    /// * `Ok(DerDigestInfo)` - The decoded DigestInfo structure
    /// * `Err(CryptoError::DerAsn1DecodeError)` - If ASN.1 decoding fails
    /// * `Err(CryptoError::DerInvalidOid)` - If the hash algorithm OID is not recognized
    pub fn from_der<'a>(input: &'a [u8]) -> Result<Self, CryptoError> {
        let digest_info: DigestInfo<'a> =
            asn1::parse_single(input).map_err(|_| CryptoError::DerAsn1DecodeError)?;
        let algo = DerDigestAlgo::try_from(digest_info.algorithm.algorithm)?;
        // confirm the digest size matches the algorithm
        if algo.digest_size() != digest_info.digest.len() {
            return Err(CryptoError::DerInvalidDigestSize);
        }
        Ok(DerDigestInfo {
            algo,
            digest: digest_info.digest.to_vec(),
        })
    }

    /// Encodes the DigestInfo to DER format.
    ///
    /// This method serializes the DigestInfo structure into Distinguished
    /// Encoding Rules (DER) format as specified in X.690 and used in PKCS#1.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, only calculates the required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes written or required
    /// * `Err(CryptoError::DerAsn1EncodeError)` - If ASN.1 encoding fails
    /// * `Err(CryptoError::DerBufferTooSmall)` - If the output buffer is too small
    pub fn to_der(&self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let digest_info = DigestInfo {
            algorithm: self.algo.into(),
            digest: &self.digest,
        };
        let der = asn1::write_single(&digest_info).map_err(|_| CryptoError::DerAsn1EncodeError)?;

        if let Some(output_buf) = output {
            if output_buf.len() < der.len() {
                return Err(CryptoError::DerBufferTooSmall);
            }
            output_buf[..der.len()].copy_from_slice(&der);
        }
        Ok(der.len())
    }

    /// Encodes the DigestInfo to a new vector in DER format.
    ///
    /// This is a convenience method that allocates a buffer of the required
    /// size and performs the DER encoding. It uses `to_der()` internally.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A vector containing the DER-encoded bytes
    /// * `Err(CryptoError::DerAsn1EncodeError)` - If ASN.1 encoding fails
    ///
    /// # Performance
    ///
    /// This method performs two calls to `to_der()`:
    /// 1. Query the required size
    /// 2. Perform the actual encoding
    ///
    /// For performance-critical code where the buffer size is known,
    /// consider calling `to_der()` directly with a pre-allocated buffer.
    pub fn to_der_vec(&self) -> Result<Vec<u8>, CryptoError> {
        let size = self.to_der(None)?;
        let mut buffer = vec![0u8; size];
        self.to_der(Some(&mut buffer))?;
        Ok(buffer)
    }
}

impl From<DerDigestAlgo> for asn1::ObjectIdentifier {
    /// Converts a hash algorithm enum to its corresponding ASN.1 Object Identifier.
    ///
    /// This conversion maps each supported hash algorithm to its standard OID
    /// as defined in the relevant RFCs and standards.
    ///
    /// # Arguments
    ///
    /// * `algo` - The hash algorithm to convert
    ///
    /// # Returns
    ///
    /// The ASN.1 Object Identifier for the hash algorithm.
    fn from(algo: DerDigestAlgo) -> Self {
        match algo {
            DerDigestAlgo::Sha1 => OID_SHA1,
            DerDigestAlgo::Sha256 => OID_SHA256,
            DerDigestAlgo::Sha384 => OID_SHA384,
            DerDigestAlgo::Sha512 => OID_SHA512,
        }
    }
}

impl From<DerDigestAlgo> for AlgorithmIdentifier {
    /// Converts a hash algorithm enum to an ASN.1 AlgorithmIdentifier.
    ///
    /// This conversion creates an `AlgorithmIdentifier` structure containing
    /// the OID of the hash algorithm and a DER NULL for parameters.
    ///
    /// # Arguments
    ///
    /// * `algo` - The hash algorithm to convert
    ///
    /// # Returns
    ///
    /// The corresponding `AlgorithmIdentifier` structure.
    fn from(algo: DerDigestAlgo) -> Self {
        AlgorithmIdentifier {
            algorithm: algo.into(),
            parameters: Some(()),
        }
    }
}

impl TryFrom<asn1::ObjectIdentifier> for DerDigestAlgo {
    type Error = CryptoError;

    /// Attempts to convert an ASN.1 Object Identifier to a hash algorithm enum.
    ///
    /// This conversion validates that the OID corresponds to a supported hash
    /// algorithm and returns the appropriate enum variant.
    ///
    /// # Arguments
    ///
    /// * `oid` - The ASN.1 Object Identifier to convert
    ///
    /// # Returns
    ///
    /// * `Ok(DerDigestAlgo)` - The corresponding hash algorithm
    /// * `Err(CryptoError::DerInvalidOid)` - If the OID is not recognized
    ///
    /// # Supported OIDs
    ///
    /// - SHA-1: 1.3.14.3.2.26
    /// - SHA-256: 2.16.840.1.101.3.4.2.1
    /// - SHA-384: 2.16.840.1.101.3.4.2.2
    /// - SHA-512: 2.16.840.1.101.3.4.2.3
    fn try_from(oid: asn1::ObjectIdentifier) -> Result<Self, Self::Error> {
        if oid == OID_SHA1 {
            Ok(DerDigestAlgo::Sha1)
        } else if oid == OID_SHA256 {
            Ok(DerDigestAlgo::Sha256)
        } else if oid == OID_SHA384 {
            Ok(DerDigestAlgo::Sha384)
        } else if oid == OID_SHA512 {
            Ok(DerDigestAlgo::Sha512)
        } else {
            Err(CryptoError::DerInvalidOid)
        }
    }
}
