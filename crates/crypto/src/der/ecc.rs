// Copyright (C) Microsoft Corporation. All rights reserved.

//! ECC (Elliptic Curve Cryptography) DER encoding and decoding utilities.
//!
//! This module provides functionality for encoding and decoding ECC private keys
//! in DER (Distinguished Encoding Rules) format according to RFC 5915 and SEC1.
//! It supports the following NIST curves:
//! - P-256 (secp256r1)
//! - P-384 (secp384r1)
//! - P-521 (secp521r1)

use super::*;

/// Object Identifier for the NIST P-256 (secp256r1) curve.
///
/// OID: 1.2.840.10045.3.1.7
pub const OID_P256: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 10045, 3, 1, 7);

/// Object Identifier for the NIST P-384 (secp384r1) curve.
///
/// OID: 1.3.132.0.34
pub const OID_P384: asn1::ObjectIdentifier = asn1::oid!(1, 3, 132, 0, 34);

/// Object Identifier for the NIST P-521 (secp521r1) curve.
///
/// OID: 1.3.132.0.35
pub const OID_P521: asn1::ObjectIdentifier = asn1::oid!(1, 3, 132, 0, 35);

/// Converts an ECC curve identifier to its corresponding ASN.1 Object Identifier.
impl From<EccCurve> for asn1::ObjectIdentifier {
    fn from(curve: EccCurve) -> Self {
        match curve {
            EccCurve::P256 => OID_P256,
            EccCurve::P384 => OID_P384,
            EccCurve::P521 => OID_P521,
        }
    }
}

/// Attempts to convert an ASN.1 Object Identifier to an ECC curve identifier.
///
/// # Errors
///
/// Returns `CryptoError::DerInvalidOid` if the OID does not match any supported curve.
impl TryFrom<asn1::ObjectIdentifier> for EccCurve {
    type Error = CryptoError;

    fn try_from(oid: asn1::ObjectIdentifier) -> Result<Self, Self::Error> {
        match oid {
            OID_P256 => Ok(EccCurve::P256),
            OID_P384 => Ok(EccCurve::P384),
            OID_P521 => Ok(EccCurve::P521),
            _ => Err(CryptoError::DerInvalidOid),
        }
    }
}

/// ASN.1 structure for EC private keys according to RFC 5915.
///
/// This structure represents the ASN.1 ECPrivateKey type:
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///   privateKey     OCTET STRING,
///   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///   publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
struct EcPrivateKey<'a> {
    version: u8,
    priv_key: &'a [u8],
    #[explicit(0)]
    parameters: Option<asn1::ObjectIdentifier>,
    #[explicit(1)]
    pub_key: Option<asn1::BitString<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct EcPrivateKeyInfo<'a> {
    version: u8,
    algo_id: AlgorithmIdentifier,
    priv_key: &'a [u8],
    #[implicit(0)]
    attrs: Option<asn1::ObjectIdentifier>,
}

/// Represents an ECC private key with optional public key components.
///
/// This structure holds the private key value and optionally the public key
/// coordinates (x, y) for serialization to/from DER format.
pub struct DerEccPrivateKey {
    curve: EccCurve,
    priv_key: Vec<u8>,
    x: Option<Vec<u8>>,
    y: Option<Vec<u8>>,
}

impl DerEccPrivateKey {
    /// Creates a new ECC private key without public key components.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve type (P-256, P-384, or P-521)
    /// * `priv_key` - The private key bytes
    pub fn new(curve: EccCurve, priv_key: &[u8]) -> Self {
        Self {
            curve,
            priv_key: priv_key.to_vec(),
            x: None,
            y: None,
        }
    }

    /// Creates a new ECC private key with public key components.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve type
    /// * `priv_key` - The private key bytes
    /// * `x` - The x-coordinate of the public key point
    /// * `y` - The y-coordinate of the public key point
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DerInvalidParameter` if any of the key components
    /// do not match the expected length for the curve.
    pub fn new_with_pub_key(
        curve: EccCurve,
        priv_key: &[u8],
        x: &[u8],
        y: &[u8],
    ) -> Result<Self, CryptoError> {
        let point_size = curve.point_size();

        if priv_key.len() != point_size || x.len() != point_size || y.len() != point_size {
            return Err(CryptoError::DerInvalidParameter);
        }

        Ok(Self {
            curve,
            priv_key: priv_key.to_vec(),
            x: Some(x.to_vec()),
            y: Some(y.to_vec()),
        })
    }

    /// Returns the elliptic curve type.
    pub fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Returns a reference to the private key bytes.
    pub fn priv_key(&self) -> &[u8] {
        &self.priv_key
    }

    /// Returns a reference to the x-coordinate of the public key, if present.
    pub fn x(&self) -> Option<&[u8]> {
        self.x.as_deref()
    }

    /// Returns a reference to the y-coordinate of the public key, if present.
    pub fn y(&self) -> Option<&[u8]> {
        self.y.as_deref()
    }

    /// Decodes an ECC private key from DER format.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The DER-encoded private key bytes
    ///
    /// # Returns
    ///
    /// Returns the decoded `EccPrivKeyDer` structure with the private key and
    /// optional public key components.
    ///
    /// # Errors
    ///
    /// * `CryptoError::DerAsn1DecodeError` - Failed to parse ASN.1 structure
    /// * `CryptoError::DerInvalidParameter` - Invalid key length for the curve
    /// * `CryptoError::DerInvalidPubKey` - Invalid public key encoding
    pub fn from_der(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key_info: EcPrivateKeyInfo<'_> =
            asn1::parse_single(bytes).map_err(|_| CryptoError::DerAsn1DecodeError)?;

        let key: EcPrivateKey<'_> =
            asn1::parse_single(key_info.priv_key).map_err(|_| CryptoError::DerAsn1DecodeError)?;

        if key_info.algo_id.algorithm != OID_EC_PUBLIC_KEY {
            return Err(CryptoError::DerInvalidOid);
        }

        let curve = EccCurve::try_from(key_info.algo_id.parameters)?;
        if key.priv_key.len() != curve.point_size() {
            return Err(CryptoError::DerInvalidParameter);
        }

        let (x, y) = match key.pub_key {
            Some(pub_key) => {
                let (x, y) = DerEccPublicKey::decode_pub_key(curve, &pub_key)?;
                (Some(x), Some(y))
            }
            None => (None, None),
        };

        Ok(Self {
            curve,
            priv_key: key.priv_key.to_vec(),
            x,
            y,
        })
    }

    /// Encodes the ECC private key to DER format.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, only calculates the required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written (or required if `bytes` is `None`).
    ///
    /// # Errors
    ///
    /// * `CryptoError::DerAsn1EncodeError` - Failed to encode ASN.1 structure
    /// * `CryptoError::DerBufferTooSmall` - Output buffer is too small
    pub fn to_der(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let mut buf = Vec::new();
        let pub_key = match (&self.x, &self.y) {
            (Some(x), Some(y)) => Some(DerEccPublicKey::encode_pub_key(&mut buf, x, y)?),
            _ => None,
        };

        let key = EcPrivateKey {
            version: 1,
            priv_key: &self.priv_key,
            parameters: None,
            pub_key,
        };

        let key_buf = asn1::write_single(&key).map_err(|_| CryptoError::DerAsn1EncodeError)?;

        let key_info = EcPrivateKeyInfo {
            version: 0,
            algo_id: AlgorithmIdentifier {
                algorithm: OID_EC_PUBLIC_KEY,
                parameters: self.curve.into(),
            },
            priv_key: &key_buf,
            attrs: None,
        };

        let der = asn1::write_single(&key_info).map_err(|_| CryptoError::DerAsn1EncodeError)?;

        if let Some(bytes) = bytes {
            if bytes.len() < der.len() {
                return Err(CryptoError::DerBufferTooSmall);
            }
            bytes[..der.len()].copy_from_slice(&der);
        }

        Ok(der.len())
    }

    /// Exports this ECC private key to a DER-encoded vector.
    ///
    /// This is a convenience method that allocates a vector of the appropriate size
    /// and exports the key to DER format.
    ///
    /// # Returns
    ///
    /// A vector containing the DER-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns an error if DER encoding fails.
    pub fn to_der_vec(&self) -> Result<Vec<u8>, CryptoError> {
        let der_len = self.to_der(None)?;
        let mut der_bytes = vec![0u8; der_len];
        self.to_der(Some(&mut der_bytes))?;
        Ok(der_bytes)
    }
}

/// Object Identifier for EC Public Key algorithm.
/// OID: 1.2.840.10045.2.1
/// Used in SubjectPublicKeyInfo structures.
const OID_EC_PUBLIC_KEY: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 10045, 2, 1);

/// ASN.1 AlgorithmIdentifier structure.
///
/// Represents the algorithm and its parameters in X.509 structures:
/// ```text
/// AlgorithmIdentifier ::= SEQUENCE {
///   algorithm   OBJECT IDENTIFIER,
///   parameters  ANY DEFINED BY algorithm OPTIONAL
/// }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct AlgorithmIdentifier {
    algorithm: asn1::ObjectIdentifier,
    parameters: asn1::ObjectIdentifier,
}

/// ASN.1 SubjectPublicKeyInfo structure for X.509 certificates.
///
/// This structure represents the ASN.1 SubjectPublicKeyInfo type:
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm         AlgorithmIdentifier,
///   subjectPublicKey  BIT STRING
/// }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct SubjectPublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier,
    subject_public_key: asn1::BitString<'a>,
}

/// Represents an ECC public key for DER encoding/decoding.
///
/// This structure holds the public key coordinates (x, y) and the curve type
/// for serialization to/from DER format in SubjectPublicKeyInfo structure.
pub struct DerEccPublicKey {
    curve: EccCurve,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl DerEccPublicKey {
    /// Creates a new ECC public key.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve type
    /// * `x` - The x-coordinate of the public key point
    /// * `y` - The y-coordinate of the public key point
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DerInvalidParameter` if any of the key components
    /// do not match the expected length for the curve.
    pub fn new(curve: EccCurve, x: &[u8], y: &[u8]) -> Result<Self, CryptoError> {
        let point_size = curve.point_size();

        if x.len() != point_size || y.len() != point_size {
            return Err(CryptoError::DerInvalidParameter);
        }

        Ok(Self {
            curve,
            x: x.to_vec(),
            y: y.to_vec(),
        })
    }

    /// Returns the elliptic curve type.
    pub fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Returns a reference to the x-coordinate of the public key, if present.
    pub fn x(&self) -> &[u8] {
        &self.x
    }

    /// Returns a reference to the y-coordinate of the public key, if present.
    pub fn y(&self) -> &[u8] {
        &self.y
    }

    /// Encodes the ECC public key to DER format (SubjectPublicKeyInfo).
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, only calculates the required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written (or required if `bytes` is `None`).
    ///
    /// # Errors
    ///
    /// * `CryptoError::DerAsn1EncodeError` - Failed to encode ASN.1 structure
    /// * `CryptoError::DerBufferTooSmall` - Output buffer is too small
    pub fn to_der(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let mut buf = Vec::new();
        let pub_key = Self::encode_pub_key(&mut buf, &self.x, &self.y)?;

        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: OID_EC_PUBLIC_KEY,
                parameters: self.curve.into(),
            },
            subject_public_key: pub_key,
        };

        let der = asn1::write_single(&spki).map_err(|_| CryptoError::DerAsn1EncodeError)?;

        if let Some(bytes) = bytes {
            if bytes.len() < der.len() {
                return Err(CryptoError::DerBufferTooSmall);
            }
            bytes[..der.len()].copy_from_slice(&der);
        }

        Ok(der.len())
    }

    /// Decodes an ECC public key from DER format (SubjectPublicKeyInfo).
    ///
    /// # Arguments
    ///
    /// * `bytes` - The DER-encoded SubjectPublicKeyInfo bytes
    ///
    /// # Returns
    ///
    /// Returns the decoded `EccPubKeyDer` structure with the public key coordinates.
    ///
    /// # Errors
    ///
    /// * `CryptoError::DerAsn1DecodeError` - Failed to parse ASN.1 structure
    /// * `CryptoError::DerInvalidOid` - Algorithm OID is not EC Public Key
    /// * `CryptoError::DerInvalidPubKey` - Invalid public key encoding
    pub fn from_der(bytes: &[u8]) -> Result<Self, CryptoError> {
        let spki: SubjectPublicKeyInfo<'_> =
            asn1::parse_single(bytes).map_err(|_| CryptoError::DerAsn1DecodeError)?;

        if spki.algorithm.algorithm != OID_EC_PUBLIC_KEY {
            return Err(CryptoError::DerInvalidOid);
        }

        let curve = EccCurve::try_from(spki.algorithm.parameters)?;

        let (x, y) = Self::decode_pub_key(curve, &spki.subject_public_key)?;

        Ok(Self { curve, x, y })
    }

    /// Encodes public key coordinates into uncompressed point format.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to store the encoded public key
    /// * `x` - The x-coordinate of the public key point
    /// * `y` - The y-coordinate of the public key point
    ///
    /// # Returns
    ///
    /// Returns an ASN.1 BitString containing the uncompressed point (0x04 || x || y).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DerAsn1EncodeError` if BitString creation fails.
    fn encode_pub_key<'a>(
        buf: &'a mut Vec<u8>,
        x: &[u8],
        y: &[u8],
    ) -> Result<asn1::BitString<'a>, CryptoError> {
        buf.reserve(1 + x.len() + y.len());
        buf.push(0x04); // Uncompressed form indicator
        buf.extend_from_slice(x);
        buf.extend_from_slice(y);
        asn1::BitString::new(buf, 0).ok_or(CryptoError::DerAsn1EncodeError)
    }

    /// Decodes a public key from uncompressed point format.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve type
    /// * `pub_key` - The encoded public key bytes (0x04 || x || y)
    ///
    /// # Returns
    ///
    /// Returns a tuple containing the x and y coordinates of the public key point.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DerInvalidPubKey` if:
    /// * The length doesn't match the expected size for the curve
    /// * The first byte is not 0x04 (uncompressed point indicator)
    fn decode_pub_key(
        curve: EccCurve,
        pub_key: &asn1::BitString<'_>,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let pub_key = pub_key.as_bytes();
        let point_size = curve.point_size();

        if pub_key.len() != 1 + 2 * point_size || pub_key[0] != 0x04 {
            return Err(CryptoError::DerInvalidPubKey);
        }

        let x = pub_key[1..1 + point_size].to_vec();
        let y = pub_key[1 + point_size..].to_vec();
        Ok((x, y))
    }
}

/// ASN.1 structure for ECDSA signatures.
///
/// This structure represents the ASN.1 ECDSA-Sig-Value type defined in RFC 3279:
/// ```text
/// ECDSA-Sig-Value ::= SEQUENCE {
///   r  INTEGER,
///   s  INTEGER
/// }
/// ```
///
/// The signature consists of two integers (r, s) that form the ECDSA signature.
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct EcSignature {
    r: asn1::OwnedBigInt,
    s: asn1::OwnedBigInt,
}

/// Represents an ECDSA signature in DER format.
///
/// This structure holds the two components (r, s) of an ECDSA signature
/// and provides methods for encoding to and decoding from DER format.
/// The signature is stored in a normalized fixed-length format based on
/// the curve's point size.
pub struct DerEccSignature {
    curve: EccCurve,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl DerEccSignature {
    /// Creates a new ECDSA signature.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve type
    /// * `r` - The r component of the signature
    /// * `s` - The s component of the signature
    ///
    /// # Returns
    ///
    /// A new `EccSignatureDer` instance.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DerInvalidParameter` if the r or s components
    /// do not match the expected length for the curve:
    /// - P-256: 32 bytes
    /// - P-384: 48 bytes
    /// - P-521: 66 bytes
    pub fn new(curve: EccCurve, r: &[u8], s: &[u8]) -> Result<Self, CryptoError> {
        let point_size = curve.point_size();

        if r.len() != point_size || s.len() != point_size {
            return Err(CryptoError::DerInvalidParameter);
        }

        Ok(Self {
            curve,
            r: r.to_vec(),
            s: s.to_vec(),
        })
    }

    /// Returns the elliptic curve type.
    pub fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Returns a reference to the r component of the signature.
    pub fn r(&self) -> &[u8] {
        &self.r
    }

    /// Returns a reference to the s component of the signature.
    pub fn s(&self) -> &[u8] {
        &self.s
    }

    /// Decodes an ECDSA signature from DER format.
    ///
    /// This method parses a DER-encoded ECDSA signature (SEQUENCE of two INTEGERs)
    /// and converts it to a fixed-length format based on the curve's point size.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve type for the signature
    /// * `bytes` - The DER-encoded signature bytes
    ///
    /// # Returns
    ///
    /// A new `EccSignatureDer` instance with normalized r and s components.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::DerAsn1DecodeError` - Failed to parse ASN.1 structure
    /// - `CryptoError::DerInvalidParameter` - Signature components are invalid for the curve
    pub fn from_der(curve: EccCurve, bytes: &[u8]) -> Result<Self, CryptoError> {
        let sig: EcSignature =
            asn1::parse_single(bytes).map_err(|_| CryptoError::DerAsn1DecodeError)?;
        Self::new(
            curve,
            &Vec::<u8>::try_from(EccBigInt(curve, sig.r))?,
            &Vec::<u8>::try_from(EccBigInt(curve, sig.s))?,
        )
    }

    /// Encodes the ECDSA signature to DER format.
    ///
    /// This method converts the fixed-length r and s components to DER encoding
    /// (SEQUENCE of two INTEGERs), properly handling leading zeros and sign bits.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, only calculates the required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer, or the required buffer size
    /// if `bytes` is `None`. The size varies based on the signature values,
    /// typically:
    /// - P-256: ~70-72 bytes
    /// - P-384: ~102-104 bytes
    /// - P-521: ~137-139 bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::DerAsn1EncodeError` - Failed to encode ASN.1 structure
    /// - `CryptoError::DerBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::DerInvalidParameter` - Signature component length is invalid
    pub fn to_der(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let sig = EcSignature {
            r: EccPoint(self.curve, &self.r).try_into()?,
            s: EccPoint(self.curve, &self.s).try_into()?,
        };

        let der = asn1::write_single(&sig).map_err(|_| CryptoError::DerAsn1EncodeError)?;

        if let Some(bytes) = bytes {
            if bytes.len() < der.len() {
                return Err(CryptoError::DerBufferTooSmall);
            }
            bytes[..der.len()].copy_from_slice(&der);
        }

        Ok(der.len())
    }
}

/// Internal helper for converting ECC point coordinates to ASN.1 integers.
///
/// This structure pairs an elliptic curve with a point coordinate (r or s)
/// and provides conversion to ASN.1 OwnedBigInt with proper encoding.
struct EccPoint<'a>(EccCurve, &'a Vec<u8>);

/// Internal helper for converting ASN.1 integers to ECC point coordinates.
///
/// This structure pairs an elliptic curve with an ASN.1 big integer
/// and provides conversion to fixed-length byte representation.
struct EccBigInt(EccCurve, asn1::OwnedBigInt);

/// Converts an ECC point coordinate to an ASN.1 big integer.
///
/// This conversion handles:
/// - Stripping leading zeros from the coordinate
/// - Adding padding byte if the high bit is set (to prevent negative interpretation)
/// - Creating a properly encoded ASN.1 integer
impl<'a> TryFrom<EccPoint<'a>> for asn1::OwnedBigInt {
    type Error = CryptoError;

    /// Converts an ECC coordinate to ASN.1 big integer format.
    ///
    /// # Arguments
    ///
    /// * `tuple` - EccPoint containing the curve and coordinate bytes
    ///
    /// # Returns
    ///
    /// An ASN.1 OwnedBigInt representing the coordinate.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::DerInvalidParameter` - Coordinate length is invalid
    /// - `CryptoError::DerAsn1EncodeError` - Failed to create big integer
    fn try_from(tuple: EccPoint<'a>) -> Result<Self, Self::Error> {
        let EccPoint(curve, bytes) = tuple;
        let point_size = curve.point_size();

        if bytes.len() != point_size {
            return Err(CryptoError::DerInvalidParameter);
        }

        let bytes = bytes
            .iter()
            .position(|&b| b != 0)
            .map_or(bytes.as_slice(), |pos| &bytes[pos..]);

        let needs_padding = bytes.first().is_some_and(|&b| b & 0x80 == 0x80);

        let mut vec = Vec::with_capacity(bytes.len() + needs_padding as usize);
        if needs_padding {
            vec.push(0);
        }

        vec.extend_from_slice(bytes);

        asn1::OwnedBigInt::new(vec).ok_or(CryptoError::DerAsn1EncodeError)
    }
}

/// Converts an ASN.1 big integer to an ECC point coordinate.
///
/// This conversion handles:
/// - Stripping padding zeros from the ASN.1 encoding
/// - Zero-padding to the expected length for the curve
/// - Validating the coordinate length
impl TryFrom<EccBigInt> for Vec<u8> {
    type Error = CryptoError;

    /// Converts an ASN.1 big integer to a fixed-length ECC coordinate.
    ///
    /// # Arguments
    ///
    /// * `tuple` - EccBigInt containing the curve and ASN.1 integer
    ///
    /// # Returns
    ///
    /// A fixed-length byte vector representing the coordinate, zero-padded
    /// to the curve's point size.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DerInvalidParameter` if the integer value is
    /// too large for the curve's point size.
    fn try_from(tuple: EccBigInt) -> Result<Self, Self::Error> {
        let EccBigInt(curve, bigint) = tuple;
        let point_size = curve.point_size();
        let bytes = bigint.as_bytes();

        let bytes = if !bytes.is_empty() && bytes[0] == 0 {
            &bytes[1..]
        } else {
            bytes
        };

        if bytes.len() > point_size {
            return Err(CryptoError::DerInvalidParameter);
        }

        let mut result = vec![0u8; point_size];
        result[point_size - bytes.len()..].copy_from_slice(bytes);
        Ok(result)
    }
}
