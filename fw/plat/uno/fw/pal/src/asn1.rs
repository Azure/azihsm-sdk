// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ASN.1 / DER decoders for imported private keys, built on the no-alloc
//! [`der`] crate (the same dependency `fw/core/crypto/x509-chain` already uses).
//!
//! The wrapped-key import paths (`RsaUnwrap`) recover a plaintext DER private
//! key and must decode it into the raw components the PKA vault operand is
//! assembled from. This module owns only the **pure ASN.1 decode** (PKCS#8 / PKCS#1, and — as they land — SEC1 EC); the
//! platform-specific little-endian PKA operand layout lives in the
//! per-algorithm modules ([`rsa`](crate::crypto::rsa), [`ecc`](crate::crypto::ecc)) so this
//! stays a small, hardware-agnostic parsing layer.
//!
//! ## Scope and forward-looking extension points
//!
//! - **RSA non-CRT (today):** [`parse_rsa_private_key`] →
//!   [`RsaPrivateKeyAsn1`]; `rsa` assembles `[d ‖ n ‖ e]`.
//! - **RSA CRT (#608):** reuses [`RsaPrivateKeyAsn1`] as-is — it already decodes
//!   the CRT fields (`prime1`, `prime2`, `exponent1`, `exponent2`,
//!   `coefficient`). Only the CRT operand assembly (and the derived `n1q`/`n2p`
//!   PKA math) is added in `rsa`; **no change is needed here**.
//! - **ECC (#604):** add the SEC1 `ECPrivateKey` / PKCS#8 EC `PrivateKeyInfo`
//!   decoders alongside the RSA ones below, plus a `parse_ec_private_key`
//!   returning the scalar + curve OID; consumed by `ecc`.

use der::Decode;
use der::Sequence;
use der::asn1::Null;
use der::asn1::ObjectIdentifier;
use der::asn1::OctetStringRef;
use der::asn1::UintRef;

// ── RSA (PKCS#8 PrivateKeyInfo / PKCS#1 RSAPrivateKey) ─────────────────────

/// rsaEncryption OID (1.2.840.113549.1.1.1) — the algorithm identifier of an
/// RSA key inside a PKCS#8 `PrivateKeyInfo`.
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// PKCS#8 `AlgorithmIdentifier` for RSA: the `rsaEncryption` OID with the
/// explicit `NULL` parameters required by RFC 3279 §2.3.1.
#[derive(Sequence)]
struct RsaAlgorithmIdentifier {
    oid: ObjectIdentifier,
    parameters: Null,
}

/// PKCS#8 `PrivateKeyInfo` (RFC 5208) whose `privateKey` OCTET STRING wraps a
/// PKCS#1 `RSAPrivateKey`.
#[derive(Sequence)]
struct RsaPrivateKeyInfo<'a> {
    version: u8,
    algorithm: RsaAlgorithmIdentifier,
    private_key: &'a OctetStringRef,
}

/// PKCS#1 `RSAPrivateKey` (RFC 8017 A.1.2), two-prime form (version 0).
///
/// The full SEQUENCE is decoded so the `der` reader validates every field. The
/// non-CRT import path reads only `modulus` / `public_exponent` /
/// `private_exponent`; the CRT import path (#608) additionally reads the CRT
/// quintuple (`prime1`, `prime2`, `exponent1`, `exponent2`, `coefficient`),
/// which is why they are decoded and exposed here rather than skipped.
#[derive(Sequence)]
pub(crate) struct RsaPrivateKeyAsn1<'a> {
    pub(crate) version: u8,
    pub(crate) modulus: UintRef<'a>,
    pub(crate) public_exponent: UintRef<'a>,
    pub(crate) private_exponent: UintRef<'a>,
    pub(crate) prime1: UintRef<'a>,
    pub(crate) prime2: UintRef<'a>,
    pub(crate) exponent1: UintRef<'a>,
    pub(crate) exponent2: UintRef<'a>,
    pub(crate) coefficient: UintRef<'a>,
}

/// Decodes a recovered RSA private key — a PKCS#8 `PrivateKeyInfo` wrapping a
/// PKCS#1 `RSAPrivateKey` — into the validated [`RsaPrivateKeyAsn1`].
///
/// The `der` crate enforces canonical DER (definite minimal-length encodings,
/// no trailing bytes via `from_der`) and rejects negative / non-minimal
/// INTEGERs. On top of that this rejects key versions the two-prime SEQUENCE
/// does not model, so callers get a fully-structurally-validated key. Field
/// sizes (modulus width, exponent width) are a PKA concern and are checked by
/// the caller during operand assembly.
pub(crate) fn parse_rsa_private_key(der_bytes: &[u8]) -> Option<RsaPrivateKeyAsn1<'_>> {
    // The recovered wire key is always a PKCS#8 PrivateKeyInfo (the format the
    // RsaUnwrap collateral is generated in); a bare PKCS#1 RSAPrivateKey is not
    // accepted.
    let pki = RsaPrivateKeyInfo::from_der(der_bytes).ok()?;
    // RFC 5208 §5: PrivateKeyInfo `version` is v1 (= 0). RFC 5958 adds v2
    // (= 1) with public-key / attributes, which this parser does not model
    // — reject rather than silently drop the extra fields.
    if pki.version != 0 || pki.algorithm.oid != RSA_ENCRYPTION {
        return None;
    }
    let key = RsaPrivateKeyAsn1::from_der(pki.private_key.as_bytes()).ok()?;
    // RFC 8017 §A.1.2: `version` is 0 for two-prime keys. Version 1 (multi-prime)
    // would require `otherPrimeInfos`, which our SEQUENCE does not declare.
    if key.version != 0 {
        return None;
    }
    Some(key)
}
