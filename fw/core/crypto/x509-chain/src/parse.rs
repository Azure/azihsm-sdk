// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 certificate DER parser.
//!
//! Extracts exactly the fields needed for chain validation from a
//! DER-encoded X.509 v3 certificate. All returned slices borrow from
//! the input buffer — zero allocation.
//!
//! ## Parsing strategy
//!
//! The outer Certificate SEQUENCE is entered, and the TBSCertificate
//! is first captured as raw DER bytes (preserving exact bytes for
//! signature verification), then parsed internally for individual
//! fields. Extensions are iterated lazily — only AKID, SKID,
//! BasicConstraints, and KeyUsage are decoded; all others are skipped
//! (but checked for unrecognized critical extensions).

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use der::asn1::BitStringRef;
use der::asn1::ObjectIdentifier;
use der::asn1::OctetStringRef;
use der::asn1::SequenceRef;
use der::asn1::UintRef;
use der::Reader;
use der::SliceReader;
use der::Tag;
use der::TagMode;
use der::TagNumber;

use crate::types::BasicConstraints;
use crate::types::CertInfo;
use crate::types::EcPubKey;
use crate::types::SigAlgo;

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

const OID_AKID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const OID_SKID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_CERT_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_CRL_DIST_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const OID_AUTH_INFO_ACCESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
const OID_SUBJECT_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.11");
const OID_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");
const OID_POLICY_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.36");
const OID_INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.54");
const OID_POLICY_MAPPINGS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.33");
const OID_ISSUER_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.18");

/// Known extension OIDs that we can safely skip even when critical.
/// These are recognized by RFC 5280 but not needed for our simplified
/// chain validation (no CRL, no policy).
const KNOWN_EXTENSION_OIDS: &[ObjectIdentifier] = &[
    OID_AKID,
    OID_SKID,
    OID_BASIC_CONSTRAINTS,
    OID_KEY_USAGE,
    OID_SUBJECT_ALT_NAME,
    OID_CERT_POLICIES,
    OID_EXT_KEY_USAGE,
    OID_CRL_DIST_POINTS,
    OID_AUTH_INFO_ACCESS,
    OID_SUBJECT_INFO_ACCESS,
    OID_NAME_CONSTRAINTS,
    OID_POLICY_CONSTRAINTS,
    OID_INHIBIT_ANY_POLICY,
    OID_POLICY_MAPPINGS,
    OID_ISSUER_ALT_NAME,
];

/// Internal error type for use inside `der` parser closures.
///
/// Wraps an [`HsmError`] so that both `der::Error` (via `?`) and
/// specific `HsmError` variants can flow through the same closure
/// return type. Converted back to `HsmError` at the public API
/// boundary.
#[derive(Debug, Clone, Copy)]
struct X509ParseError(HsmError);

type X509ParseResult<T> = Result<T, X509ParseError>;

impl From<der::Error> for X509ParseError {
    fn from(_: der::Error) -> Self {
        Self(HsmError::X509ParseError)
    }
}

impl From<HsmError> for X509ParseError {
    fn from(error: HsmError) -> Self {
        Self(error)
    }
}

impl From<X509ParseError> for HsmError {
    fn from(error: X509ParseError) -> Self {
        error.0
    }
}

/// Parse a DER-encoded X.509 certificate into a [`CertInfo`].
///
/// All returned slices borrow from `der`. The caller must keep
/// `der` alive for as long as the returned `CertInfo` is used.
///
/// # Parameters
/// * `der` — DMA-accessible buffer containing the raw DER bytes
///   of the complete Certificate SEQUENCE.
///
/// # Returns
/// * `Ok(CertInfo)` on success.
/// * `Err(HsmError::X509ParseError)` if the DER is malformed.
/// * `Err(HsmError::X509UnsupportedAlgorithm)` if the signature or
///   key algorithm is not a supported ECDSA/EC variant.
/// * `Err(HsmError::X509UnrecognizedCriticalExtension)` if a critical
///   extension is present that this parser does not recognize.
pub fn parse_cert(der: &DmaBuf) -> HsmResult<CertInfo<'_>> {
    let mut outer = SliceReader::new(der).map_err(X509ParseError::from)?;
    let cert = outer.sequence(|cert| -> X509ParseResult<_> {
        let tbs_raw = to_dma(der, cert.tlv_bytes()?);
        let sig_algo = parse_sig_algo_id(cert)?;
        let sig_bits = cert.decode::<BitStringRef<'_>>()?;
        let signature = to_dma(der, sig_bits.raw_bytes());
        cert.clone().finish()?;

        let (issuer_raw, subject_raw, pub_key, akid, skid, basic_constraints, key_usage) =
            parse_tbs(der, tbs_raw)?;

        Ok(CertInfo {
            tbs_raw,
            sig_algo,
            signature,
            issuer_raw,
            subject_raw,
            pub_key,
            akid,
            skid,
            basic_constraints,
            key_usage,
        })
    })?;
    outer.finish().map_err(X509ParseError::from)?;
    Ok(cert)
}

/// Convert a `&[u8]` sub-slice of a `&DmaBuf` back into a `&DmaBuf`
/// by computing its byte offset within the original buffer.
///
/// `der` parser callbacks return `&[u8]` views, but downstream
/// consumers (hash and ECC verify) require `&DmaBuf` to prove the
/// bytes live in DMA-accessible memory. Since the parser only ever
/// hands back sub-slices of the original DMA buffer, we can safely
/// re-borrow them through the `DmaBuf` type by computing the offset.
///
/// # Parameters
/// * `root` — the original DMA buffer the sub-slice was taken from.
/// * `sub` — a sub-slice that points strictly inside `root`.
///
/// # Returns
/// A `&DmaBuf` view covering the same bytes as `sub`.
///
/// # Panics
///
/// Panics if `sub` does not point within `root` (either starts before
/// `root` or extends past its end).
fn to_dma<'a>(root: &'a DmaBuf, sub: &'a [u8]) -> &'a DmaBuf {
    let root_ptr = root.as_ptr() as usize;
    let sub_ptr = sub.as_ptr() as usize;
    assert!(sub_ptr >= root_ptr, "sub-slice starts before root buffer");
    let offset = sub_ptr - root_ptr;
    assert!(
        offset + sub.len() <= root.len(),
        "sub-slice extends past root buffer"
    );
    &root[offset..offset + sub.len()]
}

/// Tuple of fields extracted from a parsed TBSCertificate, returned
/// by [`parse_tbs`].
///
/// In order:
/// 1. raw issuer Name (DER SEQUENCE bytes, in DMA memory)
/// 2. raw subject Name (DER SEQUENCE bytes, in DMA memory)
/// 3. parsed EC public key
/// 4. AuthorityKeyIdentifier `keyIdentifier`, if present
/// 5. SubjectKeyIdentifier value, if present
/// 6. parsed BasicConstraints, if present
/// 7. parsed KeyUsage bits, if present
type ParsedTbs<'a> = (
    &'a DmaBuf,
    &'a DmaBuf,
    EcPubKey<'a>,
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    Option<BasicConstraints>,
    Option<u16>,
);

/// Parse the TBSCertificate fields needed for chain validation.
///
/// Walks the TBSCertificate SEQUENCE in order, capturing the issuer
/// Name, subject Name, SubjectPublicKeyInfo, and (optionally) the
/// extensions block. Fields that are not used by the simplified
/// validator (version, serial, signature algo restated, validity,
/// issuer/subject UIDs) are skipped over but still consumed so the
/// reader stays in sync.
///
/// # Parameters
/// * `root` — the original certificate DMA buffer; used as the base
///   for [`to_dma`] when re-borrowing slices.
/// * `tbs_raw` — DMA slice covering the full TBSCertificate SEQUENCE
///   (tag + length + value).
///
/// # Returns
/// * `Ok(ParsedTbs)` — see [`ParsedTbs`] for field order.
/// * `Err(X509ParseError)` wrapping [`HsmError::X509ParseError`] on
///   malformed DER, or [`HsmError::X509UnsupportedAlgorithm`] /
///   [`HsmError::X509UnrecognizedCriticalExtension`] from the
///   nested SPKI / extension parsers.
fn parse_tbs<'a>(root: &'a DmaBuf, tbs_raw: &'a DmaBuf) -> X509ParseResult<ParsedTbs<'a>> {
    let mut reader = SliceReader::new(tbs_raw).map_err(X509ParseError::from)?;
    let parsed = reader.sequence(|tbs| -> X509ParseResult<_> {
        let _version: Option<u8> = tbs.context_specific(TagNumber(0), TagMode::Explicit)?;
        let _serial = tbs.decode::<UintRef<'_>>()?;
        let _sig_algo = tbs.tlv_bytes()?;
        let issuer_raw = to_dma(root, tbs.tlv_bytes()?);
        let _validity = tbs.tlv_bytes()?;
        let subject_raw = to_dma(root, tbs.tlv_bytes()?);
        let spki_raw = tbs.tlv_bytes()?;
        let pub_key = parse_ec_spki(root, spki_raw)?;
        let _issuer_uid: Option<BitStringRef<'_>> =
            tbs.context_specific(TagNumber(1), TagMode::Implicit)?;
        let _subject_uid: Option<BitStringRef<'_>> =
            tbs.context_specific(TagNumber(2), TagMode::Implicit)?;

        let mut akid = None;
        let mut skid = None;
        let mut basic_constraints = None;
        let mut key_usage = None;

        let extensions: Option<&SequenceRef> =
            tbs.context_specific(TagNumber(3), TagMode::Explicit)?;
        if let Some(exts) = extensions {
            parse_extensions(
                exts.as_bytes(),
                &mut akid,
                &mut skid,
                &mut basic_constraints,
                &mut key_usage,
            )?;
        }

        tbs.clone().finish()?;
        Ok((
            issuer_raw,
            subject_raw,
            pub_key,
            akid,
            skid,
            basic_constraints,
            key_usage,
        ))
    })?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(parsed)
}

/// Parse the outer signatureAlgorithm `AlgorithmIdentifier` and map
/// its OID to a [`SigAlgo`] variant.
///
/// Only the three ECDSA OIDs paired with the supported curves
/// (P-256, P-384, P-521) are accepted. RSA, EdDSA, and any other
/// algorithm are rejected.
///
/// # Parameters
/// * `reader` — a `SliceReader` positioned at the start of an
///   `AlgorithmIdentifier` SEQUENCE.
///
/// # Returns
/// * `Ok(SigAlgo)` — a recognized ECDSA signature algorithm.
/// * `Err` wrapping [`HsmError::X509UnsupportedAlgorithm`] for
///   unrecognized OIDs, or [`HsmError::X509ParseError`] on malformed
///   DER.
fn parse_sig_algo_id(reader: &mut SliceReader<'_>) -> X509ParseResult<SigAlgo> {
    reader.sequence(|algo| -> X509ParseResult<_> {
        let oid = algo.decode::<ObjectIdentifier>()?;
        algo.clone().finish()?;
        match oid {
            x if x == OID_ECDSA_SHA256 => Ok(SigAlgo::EcdsaSha256),
            x if x == OID_ECDSA_SHA384 => Ok(SigAlgo::EcdsaSha384),
            x if x == OID_ECDSA_SHA512 => Ok(SigAlgo::EcdsaSha512),
            _ => Err(HsmError::X509UnsupportedAlgorithm.into()),
        }
    })
}

/// Parse a SubjectPublicKeyInfo SEQUENCE for an EC public key.
///
/// Verifies that the algorithm OID is `id-ecPublicKey`, decodes the
/// named-curve OID into an [`HsmEccCurve`], and extracts the
/// uncompressed EC point (stripping the `0x04` prefix). The point
/// length is checked against `curve.priv_key_len() * 2`.
///
/// # Parameters
/// * `root` — the original certificate DMA buffer; used to re-borrow
///   the EC point bytes as `&DmaBuf` via [`to_dma`].
/// * `spki_raw` — the full SubjectPublicKeyInfo SEQUENCE bytes
///   (tag + length + value), borrowing from `root`.
///
/// # Returns
/// * `Ok(EcPubKey)` — a parsed EC public key with curve and raw
///   `X || Y` coordinate bytes.
/// * `Err` wrapping [`HsmError::X509UnsupportedAlgorithm`] for
///   non-EC keys or unsupported curves, or
///   [`HsmError::X509ParseError`] for malformed DER, missing the
///   `0x04` uncompressed-point marker, or wrong coordinate length.
fn parse_ec_spki<'a>(root: &'a DmaBuf, spki_raw: &'a [u8]) -> X509ParseResult<EcPubKey<'a>> {
    let mut reader = SliceReader::new(spki_raw).map_err(X509ParseError::from)?;
    let pub_key = reader.sequence(|seq| -> X509ParseResult<_> {
        let curve = seq.sequence(|algo| -> X509ParseResult<_> {
            let oid = algo.decode::<ObjectIdentifier>()?;
            if oid != OID_EC_PUBLIC_KEY {
                return Err(HsmError::X509UnsupportedAlgorithm.into());
            }

            let curve_oid = algo.decode::<ObjectIdentifier>()?;
            algo.clone().finish()?;

            match curve_oid {
                x if x == OID_P256 => Ok(HsmEccCurve::P256),
                x if x == OID_P384 => Ok(HsmEccCurve::P384),
                x if x == OID_P521 => Ok(HsmEccCurve::P521),
                _ => Err(HsmError::X509UnsupportedAlgorithm.into()),
            }
        })?;

        let pk_bits = seq.decode::<BitStringRef<'_>>()?;
        let pk_bytes = pk_bits.raw_bytes();

        if pk_bytes.is_empty() || pk_bytes[0] != 0x04 {
            return Err(HsmError::X509ParseError.into());
        }

        let point = &pk_bytes[1..];
        let expected_len = curve.priv_key_len() * 2;
        if point.len() != expected_len {
            return Err(HsmError::X509ParseError.into());
        }

        seq.clone().finish()?;
        Ok(EcPubKey {
            curve,
            point: to_dma(root, point),
        })
    })?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(pub_key)
}

/// Iterate the Extensions SEQUENCE-OF, decoding the four extensions
/// the validator cares about and rejecting unknown critical ones.
///
/// AKID, SKID, BasicConstraints, and KeyUsage are decoded into the
/// caller-supplied out-parameters when present. All other extensions
/// are ignored unless they are marked critical — critical extensions
/// not in [`KNOWN_EXTENSION_OIDS`] cause this function to fail per
/// RFC 5280 §4.2.
///
/// Extensions whose value bytes fail to decode are silently treated
/// as absent (the corresponding out-parameter remains unchanged).
///
/// # Parameters
/// * `extensions` — contents of the Extensions SEQUENCE-OF (i.e.
///   the inner bytes after the SEQUENCE tag/length).
/// * `akid` — receives the AuthorityKeyIdentifier `keyIdentifier`
///   bytes if the extension is present and well-formed.
/// * `skid` — receives the SubjectKeyIdentifier OCTET STRING bytes
///   if the extension is present and well-formed.
/// * `basic_constraints` — receives the parsed BasicConstraints if
///   the extension is present and well-formed.
/// * `key_usage` — receives the KeyUsage bits packed into a `u16`
///   if the extension is present and well-formed.
///
/// # Returns
/// * `Ok(())` if iteration completed (any of the out-parameters may
///   or may not have been populated).
/// * `Err` wrapping [`HsmError::X509UnrecognizedCriticalExtension`]
///   if an unrecognized extension is marked critical, or
///   [`HsmError::X509ParseError`] on malformed extension framing.
fn parse_extensions<'a>(
    extensions: &'a [u8],
    akid: &mut Option<&'a [u8]>,
    skid: &mut Option<&'a [u8]>,
    basic_constraints: &mut Option<BasicConstraints>,
    key_usage: &mut Option<u16>,
) -> X509ParseResult<()> {
    let mut exts = SliceReader::new(extensions).map_err(X509ParseError::from)?;

    while !exts.is_finished() {
        let (oid, critical, value_bytes) = exts.sequence(|ext| -> X509ParseResult<_> {
            let oid = ext.decode::<ObjectIdentifier>()?;
            let critical = match Tag::peek(ext)? {
                Tag::Boolean => ext.decode::<bool>()?,
                _ => false,
            };
            let value_bytes = ext.decode::<&OctetStringRef>()?;
            ext.clone().finish()?;
            Ok((oid, critical, value_bytes.as_bytes()))
        })?;

        match oid {
            x if x == OID_AKID => {
                if let Ok(parsed) = parse_akid(value_bytes) {
                    *akid = Some(parsed);
                }
            }
            x if x == OID_SKID => {
                if let Ok(parsed) = parse_skid(value_bytes) {
                    *skid = Some(parsed);
                }
            }
            x if x == OID_BASIC_CONSTRAINTS => {
                if let Ok(parsed) = parse_basic_constraints(value_bytes) {
                    *basic_constraints = Some(parsed);
                }
            }
            x if x == OID_KEY_USAGE => {
                if let Ok(parsed) = parse_key_usage(value_bytes) {
                    *key_usage = Some(parsed);
                }
            }
            _ if critical && !KNOWN_EXTENSION_OIDS.contains(&oid) => {
                return Err(HsmError::X509UnrecognizedCriticalExtension.into());
            }
            _ => {}
        }
    }

    exts.finish().map_err(X509ParseError::from)?;
    Ok(())
}

/// Parse the AuthorityKeyIdentifier extension and return the
/// `keyIdentifier` bytes.
///
/// AKID is a SEQUENCE that may contain three optional fields; only
/// the `[0] IMPLICIT OCTET STRING keyIdentifier` is needed for chain
/// validation. If the extension is present but omits the
/// `keyIdentifier`, this is treated as a parse error.
///
/// # Parameters
/// * `value` — the OCTET STRING contents of the AKID extension
///   (i.e. after the outer extnValue OCTET STRING wrapper has been
///   stripped).
///
/// # Returns
/// * `Ok(&[u8])` — the raw `keyIdentifier` bytes, borrowing from
///   `value`.
/// * `Err` wrapping [`HsmError::X509ParseError`] for malformed DER
///   or a missing `keyIdentifier`.
fn parse_akid(value: &[u8]) -> X509ParseResult<&[u8]> {
    let mut reader = SliceReader::new(value).map_err(X509ParseError::from)?;
    let key_id = reader.sequence(|seq| -> X509ParseResult<_> {
        let kid: Option<&OctetStringRef> = seq.context_specific(TagNumber(0), TagMode::Implicit)?;
        seq.clone().finish()?;
        kid.map(|key_id| key_id.as_bytes())
            .ok_or(HsmError::X509ParseError.into())
    })?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(key_id)
}

/// Parse the SubjectKeyIdentifier extension and return its raw
/// OCTET STRING bytes.
///
/// # Parameters
/// * `value` — the OCTET STRING contents of the SKID extension
///   (after the outer extnValue OCTET STRING wrapper has been
///   stripped).
///
/// # Returns
/// * `Ok(&[u8])` — the SKID bytes, borrowing from `value`.
/// * `Err` wrapping [`HsmError::X509ParseError`] on malformed DER.
fn parse_skid(value: &[u8]) -> X509ParseResult<&[u8]> {
    let mut reader = SliceReader::new(value).map_err(X509ParseError::from)?;
    let skid = reader.decode::<&OctetStringRef>()?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(skid.as_bytes())
}

/// Parse the BasicConstraints extension.
///
/// Per RFC 5280 §4.2.1.9 the syntax is
/// `SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }`.
/// The `cA` boolean is omitted when `FALSE`, so a missing boolean is
/// treated as `false`. The `pathLenConstraint` is optional and is
/// only meaningful when `cA` is `true`.
///
/// # Parameters
/// * `value` — the OCTET STRING contents of the BasicConstraints
///   extension.
///
/// # Returns
/// * `Ok(BasicConstraints)` populated from the parsed fields.
/// * `Err` wrapping [`HsmError::X509ParseError`] on malformed DER
///   or a `pathLenConstraint` that does not fit in a `u16`.
fn parse_basic_constraints(value: &[u8]) -> X509ParseResult<BasicConstraints> {
    let mut reader = SliceReader::new(value).map_err(X509ParseError::from)?;
    let constraints = reader.sequence(|seq| -> X509ParseResult<_> {
        let ca = match Tag::peek(seq)? {
            Tag::Boolean => seq.decode::<bool>()?,
            _ => false,
        };

        let path_len = if seq.is_finished() {
            None
        } else {
            Some(parse_small_uint(seq.decode::<UintRef<'_>>()?.as_bytes())? as u16)
        };

        seq.clone().finish()?;
        Ok(BasicConstraints { ca, path_len })
    })?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(constraints)
}

/// Parse the KeyUsage extension into a packed 16-bit field.
///
/// KeyUsage is a BIT STRING of up to nine bits. The first two bytes
/// of the value are loaded into the high and low halves of a `u16`
/// respectively, matching the layout documented on the [`key_usage`]
/// constants. Trailing zero-padding bits beyond byte 1 are ignored.
///
/// [`key_usage`]: crate::types::key_usage
///
/// # Parameters
/// * `value` — the OCTET STRING contents of the KeyUsage extension.
///
/// # Returns
/// * `Ok(u16)` — the packed KeyUsage bits.
/// * `Err` wrapping [`HsmError::X509ParseError`] on malformed DER.
fn parse_key_usage(value: &[u8]) -> X509ParseResult<u16> {
    let mut reader = SliceReader::new(value).map_err(X509ParseError::from)?;
    let bits = reader.decode::<BitStringRef<'_>>()?;
    reader.finish().map_err(X509ParseError::from)?;

    let bytes = bits.raw_bytes();
    let mut bits_value = 0u16;
    if let Some(first) = bytes.first() {
        bits_value = u16::from(*first) << 8;
    }
    if bytes.len() > 1 {
        bits_value |= u16::from(bytes[1]);
    }
    Ok(bits_value)
}

/// Decode a small DER INTEGER (≤ 8 bytes) as a big-endian unsigned
/// integer.
///
/// Used for `pathLenConstraint`, which is bounded in practice to
/// values that fit easily in a `u64` (and ultimately a `u16`).
///
/// # Parameters
/// * `bytes` — DER INTEGER content bytes (big-endian magnitude).
///
/// # Returns
/// * `Ok(u64)` — the decoded magnitude.
/// * `Err` wrapping [`HsmError::X509ParseError`] if more than 8
///   bytes were supplied (i.e. the value would not fit in a `u64`).
fn parse_small_uint(bytes: &[u8]) -> X509ParseResult<u64> {
    if bytes.len() > 8 {
        return Err(HsmError::X509ParseError.into());
    }

    let mut value = 0u64;
    for &byte in bytes {
        value = (value << 8) | u64::from(byte);
    }
    Ok(value)
}
