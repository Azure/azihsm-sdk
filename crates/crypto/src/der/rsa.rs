// Copyright (C) Microsoft Corporation. All rights reserved.

//! RSA DER encoding and decoding utilities.
//!
//! This module provides functionality for encoding and decoding RSA public and private
//! keys in DER (Distinguished Encoding Rules) format.
//!
//! Supported structures:
//! - **Public keys** are encoded/decoded as X.509 `SubjectPublicKeyInfo` (SPKI), where the
//!   subject public key payload is a PKCS#1 `RSAPublicKey`.
//! - **Private keys** are encoded/decoded using a PKCS#8-like wrapper that carries an
//!   `AlgorithmIdentifier` plus an embedded PKCS#1 `RSAPrivateKey`.

use super::*;

/// Object Identifier for rsaEncryption.
///
/// OID: 1.2.840.113549.1.1.1
const OID_RSA_ENCRYPTION: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 1, 1);

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

/// ASN.1 structure for X.509 SubjectPublicKeyInfo (SPKI).
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm            AlgorithmIdentifier,
///   subjectPublicKey     BIT STRING
/// }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct SubjectPublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier,
    subject_public_key: asn1::BitString<'a>,
}

/// ASN.1 structure for a PKCS#1 RSA public key.
///
/// ```text
/// RSAPublicKey ::= SEQUENCE {
///   modulus           INTEGER,  -- n
///   publicExponent    INTEGER   -- e
/// }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
struct RsaPublicKey {
    modulus: asn1::OwnedBigInt,
    public_exponent: asn1::OwnedBigInt,
}

/// Owned RSA public key representation used by this crate.
///
/// This type stores the integer components as raw big-endian byte strings and provides
/// DER encode/decode helpers for the X.509 SPKI format.
pub struct DerRsaPublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

/// RSA public key wrapper suitable for DER SPKI encoding/decoding.
impl DerRsaPublicKey {
    /// Creates a new RSA public key.
    ///
    /// # Arguments
    ///
    /// * `modulus` - RSA modulus ($n$) bytes.
    /// * `exponent` - RSA public exponent ($e$) bytes.
    pub fn new(n: &[u8], e: &[u8]) -> Self {
        DerRsaPublicKey {
            n: n.to_vec(),
            e: e.to_vec(),
        }
    }

    /// Returns a reference to the modulus ($n$) bytes.
    pub fn n(&self) -> &[u8] {
        &self.n
    }

    /// Returns a reference to the public exponent ($e$) bytes.
    pub fn e(&self) -> &[u8] {
        &self.e
    }

    /// Returns the key size in bytes.
    pub fn key_size(&self) -> usize {
        self.n.len()
    }

    /// Decodes an RSA public key from DER `SubjectPublicKeyInfo`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - DER-encoded `SubjectPublicKeyInfo` bytes.
    ///
    /// # Errors
    ///
    /// * `CryptoError::DerAsn1DecodeError` - Failed to parse ASN.1 structure
    /// * `CryptoError::DerInvalidOid` - The algorithm identifier is not `rsaEncryption`
    /// * `CryptoError::DerInvalidParameter` - The embedded key parameters are invalid
    pub fn from_der(bytes: &[u8]) -> Result<Self, CryptoError> {
        // verify algorithm identifier
        let spki: SubjectPublicKeyInfo<'_> =
            asn1::parse_single(bytes).map_err(|_| CryptoError::DerAsn1DecodeError)?;
        if spki.algorithm.algorithm != OID_RSA_ENCRYPTION {
            Err(CryptoError::DerInvalidOid)?;
        }

        // Per RFC 3279 the `rsaEncryption` AlgorithmIdentifier commonly carries a NULL
        // parameters field. Some encoders omit it; we accept either form.

        // extract rsa public key der from bit string
        let (modulus, exponent) = Self::decode_pub_key(&spki.subject_public_key)?;

        Ok(DerRsaPublicKey::new(&modulus, &exponent))
    }

    /// Encodes the RSA public key to DER `SubjectPublicKeyInfo`.
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
    /// * `CryptoError::DerInvalidParameter` - Invalid key parameters
    /// * `CryptoError::DerBufferTooSmall` - Output buffer is too small
    pub fn to_der(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        //1. construct RsaPublicKey (borrowed ASN.1 view)
        let mut buf = Vec::new();
        let pub_key = Self::encode_public_key(&mut buf, &self.n, &self.e)?;
        let subject_info = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: OID_RSA_ENCRYPTION,
                parameters: Some(()),
            },
            subject_public_key: pub_key,
        };

        let der = asn1::write_single(&subject_info).map_err(|_| CryptoError::DerAsn1EncodeError)?;
        if let Some(bytes) = bytes {
            if bytes.len() < der.len() {
                return Err(CryptoError::DerBufferTooSmall);
            }
            bytes[..der.len()].copy_from_slice(&der);
        }
        Ok(der.len())
    }

    /// Decodes the RSA public key from a BitString.
    ///
    /// This is an internal helper that extracts the PKCS#1 RSAPublicKey structure
    /// from the BitString contained in SubjectPublicKeyInfo.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - BitString containing the DER-encoded RSAPublicKey
    ///
    /// # Returns
    ///
    /// A tuple containing (modulus, exponent) as byte vectors.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DerAsn1DecodeError` if the BitString cannot be parsed.
    fn decode_pub_key(pub_key: &asn1::BitString<'_>) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let public_key: RsaPublicKey =
            asn1::parse_single(pub_key.as_bytes()).map_err(|_| CryptoError::DerAsn1DecodeError)?;

        Ok((
            DerBigInt(&public_key.modulus).try_into()?,
            DerBigInt(&public_key.public_exponent).try_into()?,
        ))
    }

    /// Encodes the RSA public key as a PKCS#1 RSAPublicKey structure.
    ///
    /// This is an internal helper that creates a BitString containing the DER-encoded
    /// PKCS#1 RSAPublicKey for use in SubjectPublicKeyInfo.
    ///
    /// # Arguments
    ///
    /// * `buf` - Mutable buffer to store the encoded public key bytes
    /// * `modulus` - RSA modulus (n) bytes
    /// * `exponent` - RSA public exponent (e) bytes
    ///
    /// # Returns
    ///
    /// A BitString containing the DER-encoded RSAPublicKey.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::DerInvalidParameter` - Invalid modulus or exponent
    /// - `CryptoError::DerAsn1EncodeError` - ASN.1 encoding fails
    fn encode_public_key<'a>(
        buf: &'a mut Vec<u8>,
        modulus: &[u8],
        exponent: &[u8],
    ) -> Result<asn1::BitString<'a>, CryptoError> {
        let rsa_public_key = RsaPublicKey {
            modulus: DerSlice(modulus).try_into()?,
            public_exponent: DerSlice(exponent).try_into()?,
        };
        let der =
            asn1::write_single(&rsa_public_key).map_err(|_| CryptoError::DerAsn1EncodeError)?;

        // Keep DER bytes alive by copying them into the caller-provided buffer.
        // (asn1::BitString borrows its backing storage.)
        buf.clear();
        buf.extend_from_slice(&der);
        let bit_string =
            asn1::BitString::new(buf.as_slice(), 0).ok_or(CryptoError::DerAsn1EncodeError)?;
        Ok(bit_string)
    }
}

/// ASN.1 structure for PKCS#8-like RSA private key wrapper.
///
/// This structure wraps a PKCS#1 RSAPrivateKey with algorithm identification
/// and optional attributes.
///
/// ```text
/// PrivateKeyInfo ::= SEQUENCE {
///   version         Version,
///   algorithm       AlgorithmIdentifier,
///   privateKey      OCTET STRING,
///   attributes      [0] Attributes OPTIONAL
/// }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct RsaPrivateKeyInfo<'a> {
    version: u8,
    algorithm: AlgorithmIdentifier,
    private_key: &'a [u8],
    #[implicit(0)]
    attributes: Option<asn1::SetOf<'a, asn1::Tlv<'a>>>,
}

/// ASN.1 structure for PKCS#1 RSA private key.
///
/// This structure represents the PKCS#1 RSAPrivateKey type defined in RFC 8017:
///
/// ```text
/// RSAPrivateKey ::= SEQUENCE {
///   version           Version,
///   modulus           INTEGER,  -- n
///   publicExponent    INTEGER,  -- e
///   privateExponent   INTEGER,  -- d
///   prime1            INTEGER,  -- p
///   prime2            INTEGER,  -- q
///   exponent1         INTEGER,  -- d mod (p-1)
///   exponent2         INTEGER,  -- d mod (q-1)
///   coefficient       INTEGER,  -- (inverse of q) mod p
///   otherPrimeInfos   OtherPrimeInfos OPTIONAL
/// }
/// ```
///
/// This implementation does not support multi-prime RSA (otherPrimeInfos is not included).
#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
struct RsaPrivateKey {
    version: u8,
    modulus: asn1::OwnedBigInt,
    public_exponent: asn1::OwnedBigInt,
    private_exponent: asn1::OwnedBigInt,
    prime1: asn1::OwnedBigInt,
    prime2: asn1::OwnedBigInt,
    exponent1: asn1::OwnedBigInt,
    exponent2: asn1::OwnedBigInt,
    coefficient: asn1::OwnedBigInt,
}

/// Owned RSA private key representation used by this crate.
///
/// This type stores the integer components as raw big-endian byte strings and provides
/// DER encode/decode helpers for a PKCS#8-like wrapper format.
pub struct DerRsaPrivateKey {
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    dp: Vec<u8>,
    dq: Vec<u8>,
    qi: Vec<u8>,
}

impl DerRsaPrivateKey {
    /// Creates a new RSA private key.
    ///
    /// # Arguments
    ///
    /// * `modulus` - RSA modulus (n) bytes
    /// * `public_exponent` - RSA public exponent (e) bytes
    /// * `private_exponent` - RSA private exponent (d) bytes
    /// * `prime1` - First prime factor (p) bytes
    /// * `prime2` - Second prime factor (q) bytes
    /// * `exponent1` - d mod (p-1) bytes
    /// * `exponent2` - d mod (q-1) bytes
    /// * `coefficient` - CRT coefficient (q^-1 mod p) bytes
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        e: &[u8],
        n: &[u8],
        d: &[u8],
        p: &[u8],
        q: &[u8],
        dp: &[u8],
        dq: &[u8],
        qi: &[u8],
    ) -> Self {
        Self {
            e: e.to_vec(),
            n: n.to_vec(),
            d: d.to_vec(),
            p: p.to_vec(),
            q: q.to_vec(),
            dp: dp.to_vec(),
            dq: dq.to_vec(),
            qi: qi.to_vec(),
        }
    }

    /// Returns a reference to the modulus ($n$) bytes.
    pub fn n(&self) -> &[u8] {
        &self.n
    }

    /// Returns a reference to the public exponent ($e$) bytes.
    pub fn e(&self) -> &[u8] {
        &self.e
    }

    /// Returns a reference to the private exponent ($d$) bytes.
    pub fn d(&self) -> &[u8] {
        &self.d
    }

    /// Returns a reference to the first prime factor ($p$) bytes.
    pub fn p(&self) -> &[u8] {
        &self.p
    }

    /// Returns a reference to the second prime factor ($q$) bytes.
    pub fn q(&self) -> &[u8] {
        &self.q
    }

    /// Returns a reference to $d \bmod (p-1)$ bytes.
    pub fn dp(&self) -> &[u8] {
        &self.dp
    }

    /// Returns a reference to $d \bmod (q-1)$ bytes.
    pub fn dq(&self) -> &[u8] {
        &self.dq
    }

    /// Returns a reference to the CRT coefficient ($q^{-1} \bmod p$) bytes.
    pub fn qi(&self) -> &[u8] {
        &self.qi
    }

    /// Returns the key size in bytes.
    pub fn key_size(&self) -> usize {
        self.n.len()
    }

    /// Decodes an RSA private key from a PKCS#8-like DER wrapper.
    ///
    /// # Arguments
    ///
    /// * `bytes` - DER-encoded private key wrapper bytes.
    ///
    /// # Errors
    ///
    /// * `CryptoError::DerAsn1DecodeError` - Failed to parse ASN.1 structure
    /// * `CryptoError::DerInvalidOid` - The algorithm identifier is not `rsaEncryption`
    pub fn from_der(bytes: &[u8]) -> Result<Self, CryptoError> {
        // decode PKCS#8 wrapper .
        let key_info: RsaPrivateKeyInfo<'_> =
            asn1::parse_single(bytes).map_err(|_| CryptoError::DerAsn1DecodeError)?;

        // check if algorithm is RSA
        if key_info.algorithm.algorithm != OID_RSA_ENCRYPTION {
            Err(CryptoError::DerInvalidOid)?;
        }
        // parse Private Key
        let key: RsaPrivateKey = asn1::parse_single(key_info.private_key)
            .map_err(|_| CryptoError::DerAsn1DecodeError)?;

        Ok(Self {
            n: DerBigInt(&key.modulus).try_into()?,
            e: DerBigInt(&key.public_exponent).try_into()?,
            d: DerBigInt(&key.private_exponent).try_into()?,
            p: DerBigInt(&key.prime1).try_into()?,
            q: DerBigInt(&key.prime2).try_into()?,
            dp: DerBigInt(&key.exponent1).try_into()?,
            dq: DerBigInt(&key.exponent2).try_into()?,
            qi: DerBigInt(&key.coefficient).try_into()?,
        })
    }

    /// Encodes the RSA private key as a PKCS#8-like DER wrapper.
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
    /// * `CryptoError::DerInvalidParameter` - Invalid key parameters
    /// * `CryptoError::DerBufferTooSmall` - Output buffer is too small
    pub fn to_der(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        //1. construct RsaPrivateKey (borrowed ASN.1 view)
        let private_key: RsaPrivateKey = RsaPrivateKey {
            version: 0,
            modulus: DerSlice(&self.n).try_into()?,
            public_exponent: DerSlice(&self.e).try_into()?,
            private_exponent: DerSlice(&self.d).try_into()?,
            prime1: DerSlice(&self.p).try_into()?,
            prime2: DerSlice(&self.q).try_into()?,
            exponent1: DerSlice(&self.dp).try_into()?,
            exponent2: DerSlice(&self.dq).try_into()?,
            coefficient: DerSlice(&self.qi).try_into()?,
        };
        //2. encode RsaPrivateKey to DER
        let private_key_der =
            asn1::write_single(&private_key).map_err(|_| CryptoError::DerAsn1EncodeError)?;
        //3. wrap in PKCS#8-like container and encode
        let private_key_info = RsaPrivateKeyInfo {
            version: 0,
            algorithm: AlgorithmIdentifier {
                algorithm: OID_RSA_ENCRYPTION,
                parameters: Some(()),
            },
            private_key: &private_key_der,
            attributes: None,
        };

        let der =
            asn1::write_single(&private_key_info).map_err(|_| CryptoError::DerAsn1EncodeError)?;
        if let Some(output) = bytes {
            if output.len() < der.len() {
                return Err(CryptoError::DerBufferTooSmall);
            }
            output[..der.len()].copy_from_slice(&der);
        }
        Ok(der.len())
    }
}

struct DerSlice<'a>(&'a [u8]);
struct DerBigInt<'a>(&'a asn1::OwnedBigInt);

impl<'a> TryFrom<DerSlice<'a>> for asn1::OwnedBigInt {
    type Error = CryptoError;

    fn try_from(value: DerSlice<'a>) -> Result<Self, CryptoError> {
        let bytes = value.0;
        let bytes = bytes
            .iter()
            .position(|&b| b != 0)
            .map_or(bytes, |pos| &bytes[pos..]);

        let needs_padding = bytes.first().is_some_and(|&b| b & 0x80 == 0x80);

        let mut vec = Vec::with_capacity(bytes.len() + needs_padding as usize);
        if needs_padding {
            vec.push(0);
        }

        vec.extend_from_slice(bytes);

        asn1::OwnedBigInt::new(vec).ok_or(CryptoError::DerAsn1EncodeError)
    }
}

impl<'a> TryFrom<DerBigInt<'a>> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(value: DerBigInt<'a>) -> Result<Self, CryptoError> {
        let bytes = value.0.as_bytes();

        let bytes = if !bytes.is_empty() && bytes[0] == 0 {
            &bytes[1..]
        } else {
            bytes
        };

        Ok(bytes.to_vec())
    }
}
