// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! minicbor codec structs for the COSE_Sign1 key-attestation report.
//!
//! These mirror the wire schema of `~/mcr-hsm` and the AZIHSM simulator
//! (`ddi/mbor/sim/src/report.rs`). Deriving [`Encode`] and [`CborLen`]
//! lets `minicbor::len` compute every encoded length exactly, so no
//! byte-counting constants are hand-maintained. Byte fields borrow
//! `&[u8]` (which `DmaBuf` derefs to) — encoding writes into `DmaBuf`
//! output, and the zero-copy decoder ([`crate::decode`]) is unaffected.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use minicbor::CborLen;
use minicbor::Encode;

/// Reborrow a `&mut DmaBuf` as its underlying mutable byte slice, so it
/// can be handed to `minicbor::encode` (whose `Write` bound is satisfied
/// by `&mut [u8]`, not `&mut DmaBuf`).
pub(crate) fn as_mut_slice(buf: &mut DmaBuf) -> &mut [u8] {
    buf
}

/// COSE_Sign1 `Sig_structure` (RFC 9052 §4.4):
/// `[ "Signature1", body_protected, external_aad, payload ]`.
#[derive(Encode, CborLen)]
#[cbor(array)]
pub(crate) struct SigStructure<'a> {
    /// Context string; always `"Signature1"`.
    #[n(0)]
    pub context: &'a str,
    /// Encoded protected header.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub body_protected: &'a [u8],
    /// External AAD; always empty for this report.
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
    /// Encoded payload bytes.
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub payload: &'a [u8],
}

/// Empty COSE unprotected header (`{}`).
#[derive(Encode, CborLen)]
#[cbor(map)]
pub(crate) struct UnprotectedHeader {}

/// Tagged COSE_Sign1 object body (the CBOR tag byte is written
/// separately): `[ protected, unprotected, payload, signature ]`.
#[derive(Encode, CborLen)]
#[cbor(array)]
pub(crate) struct CoseSign1<'a> {
    /// Encoded protected header (bstr-wrapped).
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected_header: &'a [u8],
    /// Empty unprotected header map.
    #[n(1)]
    pub unprotected: UnprotectedHeader,
    /// Encoded payload (bstr-wrapped).
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub payload: &'a [u8],
    /// ES384 signature `r || s`, big-endian per component (bstr-wrapped).
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub signature: &'a [u8],
}

/// Key-attestation report payload: an integer-keyed CBOR map. v1 reports
/// carry 7 entries (keys 0–6); v2 reports add an 8th entry (key 7) with the
/// `policy_hash`. `policy_hash` is `Option`: minicbor omits the entry when
/// `None`, so a v1 report's map is byte-identical to before.
#[derive(Encode, CborLen)]
#[cbor(map)]
pub(crate) struct KeyReportPayload<'a> {
    /// Report format version.
    #[n(0)]
    pub version: u16,
    /// Fixed-size `public_key` bstr wrapping the inner COSE_Key
    /// (`PUBLIC_KEY_MAX_SIZE` bytes, zero-padded).
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub public_key: &'a [u8],
    /// Real length of the COSE_Key within `public_key`.
    #[n(2)]
    pub public_key_size: u16,
    /// Capability flags.
    #[n(3)]
    pub flags: u32,
    /// Owning application UUID.
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    pub app_uuid: &'a [u8],
    /// Report data.
    #[n(5)]
    #[cbor(with = "minicbor::bytes")]
    pub report_data: &'a [u8],
    /// VM launch ID.
    #[n(6)]
    #[cbor(with = "minicbor::bytes")]
    pub vm_launch_id: &'a [u8],
    /// Optional SHA-384 digest of the PartPolicy (v2 only; map key 7).
    /// Present iff the report is v2; omitted from the wire map when `None`.
    #[n(7)]
    #[cbor(with = "minicbor::bytes")]
    pub policy_hash: Option<&'a [u8]>,
}

/// The `Sig_structure` context literal (`"Signature1"`).
pub(crate) const SIG_STRUCTURE_CONTEXT: &str = "Signature1";
