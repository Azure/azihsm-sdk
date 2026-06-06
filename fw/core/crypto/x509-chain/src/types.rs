// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Types for X.509 certificate chain validation.
//!
//! All types are `no_std`-compatible and zero-allocation. Parsed
//! certificate fields borrow from the input DER buffer.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;

/// Supported ECDSA signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlgo {
    /// ECDSA with SHA-256 (OID 1.2.840.10045.4.3.2).
    EcdsaSha256,

    /// ECDSA with SHA-384 (OID 1.2.840.10045.4.3.3).
    EcdsaSha384,

    /// ECDSA with SHA-512 (OID 1.2.840.10045.4.3.4).
    EcdsaSha512,
}

impl SigAlgo {
    /// Return the underlying hash algorithm of this signature
    /// algorithm.
    ///
    /// Used by the chain validator to know which digest to compute
    /// over the TBSCertificate before invoking ECDSA verify.
    ///
    /// # Parameters
    /// * `self` — the signature algorithm variant (consumed by value
    ///   since `SigAlgo` is `Copy`).
    ///
    /// # Returns
    /// The matching [`HsmHashAlgo`] (`Sha256`, `Sha384`, or `Sha512`).
    pub fn hash_algo(self) -> HsmHashAlgo {
        match self {
            SigAlgo::EcdsaSha256 => HsmHashAlgo::Sha256,
            SigAlgo::EcdsaSha384 => HsmHashAlgo::Sha384,
            SigAlgo::EcdsaSha512 => HsmHashAlgo::Sha512,
        }
    }

    /// Return the expected curve paired with this signature
    /// algorithm.
    ///
    /// Per RFC 5480 §3, the standard pairings are:
    /// - ECDSA-SHA-256 → P-256
    /// - ECDSA-SHA-384 → P-384
    /// - ECDSA-SHA-512 → P-521
    ///
    /// The validator uses this to reject certificates whose signer
    /// curve does not match the declared signature algorithm.
    ///
    /// # Parameters
    /// * `self` — the signature algorithm variant.
    ///
    /// # Returns
    /// The [`HsmEccCurve`] expected on the issuer's public key.
    pub fn expected_curve(self) -> HsmEccCurve {
        match self {
            SigAlgo::EcdsaSha256 => HsmEccCurve::P256,
            SigAlgo::EcdsaSha384 => HsmEccCurve::P384,
            SigAlgo::EcdsaSha512 => HsmEccCurve::P521,
        }
    }
}

/// ECC public key extracted from a certificate's SubjectPublicKeyInfo.
///
/// `point` is the uncompressed EC point **without** the 0x04 prefix —
/// just the raw X || Y coordinate bytes, matching the format expected
/// by [`HsmEcc::ecc_verify`].
#[derive(Debug)]
pub struct EcPubKey<'a> {
    /// The named curve.
    pub curve: HsmEccCurve,

    /// Raw X || Y coordinates (no 0x04 prefix), in DMA-accessible memory.
    pub point: &'a DmaBuf,
}

/// BasicConstraints extension fields.
#[derive(Debug, Clone, Copy)]
pub struct BasicConstraints {
    /// `true` if this certificate is a CA certificate.
    pub ca: bool,

    /// Maximum number of intermediate CA certificates that may
    /// follow this certificate in a valid chain. `None` means
    /// unlimited.
    pub path_len: Option<u16>,
}

/// KeyUsage bit positions (RFC 5280 §4.2.1.3).
///
/// Each constant is a 16-bit mask matching the layout used in
/// [`CertInfo::key_usage`]: the BIT STRING is loaded big-endian into
/// a `u16`, with byte 0 in the high byte and byte 1 in the low byte.
/// Use bitwise-AND to test whether a usage is asserted, e.g.
/// `key_usage & key_usage::KEY_CERT_SIGN != 0`.
pub mod key_usage {
    /// `digitalSignature` (bit 0): the subject public key may be
    /// used to verify digital signatures other than certificate or
    /// CRL signatures.
    pub const DIGITAL_SIGNATURE: u16 = 0x8000;

    /// `keyCertSign` (bit 5): the subject public key may sign
    /// certificates. Required on intermediate and root CA
    /// certificates.
    pub const KEY_CERT_SIGN: u16 = 0x0400;

    /// `cRLSign` (bit 6): the subject public key may sign
    /// Certificate Revocation Lists.
    pub const CRL_SIGN: u16 = 0x0200;
}

/// Fields extracted from one DER-encoded X.509 certificate.
///
/// All byte slices borrow from the input `DmaBuf`. The struct is
/// valid only as long as the DER buffer it was parsed from.
#[derive(Debug)]
pub struct CertInfo<'a> {
    /// Raw DER bytes of the TBSCertificate SEQUENCE (tag + length +
    /// value). This is the data that was signed and must be hashed
    /// for signature verification. Points into DMA-accessible memory.
    pub tbs_raw: &'a DmaBuf,

    /// Signature algorithm used to sign this certificate.
    pub sig_algo: SigAlgo,

    /// Raw ECDSA signature bytes from the certificate's signatureValue
    /// BIT STRING. DER-encoded SEQUENCE of two INTEGERs (r, s).
    /// Points into DMA-accessible memory.
    pub signature: &'a DmaBuf,

    /// Raw DER encoding of the issuer Name SEQUENCE.
    /// Used for byte-exact name chaining comparison.
    /// Points into DMA-accessible memory.
    pub issuer_raw: &'a DmaBuf,

    /// Raw DER encoding of the subject Name SEQUENCE.
    /// Used for byte-exact name chaining comparison.
    /// Points into DMA-accessible memory.
    pub subject_raw: &'a DmaBuf,

    /// The certificate's public key.
    pub pub_key: EcPubKey<'a>,

    /// Authority Key Identifier keyIdentifier value, if present.
    pub akid: Option<&'a [u8]>,

    /// Subject Key Identifier value, if present.
    pub skid: Option<&'a [u8]>,

    /// BasicConstraints extension, if present.
    pub basic_constraints: Option<BasicConstraints>,

    /// KeyUsage extension as a big-endian bit field, if present.
    /// Use constants from [`key_usage`] to test individual bits.
    pub key_usage: Option<u16>,
}

/// Result of processing one certificate in the chain.
#[derive(Debug)]
pub enum StepResult<'a> {
    /// Chain validation is not yet complete. The caller should
    /// provide the next certificate.
    NeedNext,

    /// The entire chain has been validated. The leaf certificate's
    /// public key and subject are available.
    Valid {
        /// The validated leaf certificate's EC public key.
        leaf_pub_key: &'a EcPubKey<'a>,

        /// Raw DER of the leaf certificate's subject Name.
        leaf_subject: &'a DmaBuf,
    },

    /// Validation failed.
    Invalid(HsmError),
}
