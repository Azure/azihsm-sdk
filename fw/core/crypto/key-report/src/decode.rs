// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Zero-copy decoder / verifier for COSE_Sign1 key-attestation reports.
//!
//! [`parse_key_report`] walks the CBOR with a minicbor `Decoder` only to
//! locate field boundaries, then returns a [`KeyReportView`] whose byte
//! fields are `&DmaBuf` sub-views of the input report buffer — no copies
//! and no owned arrays. [`verify_key_report`] rebuilds the COSE
//! `Sig_structure` and checks the ES384 signature.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use minicbor::Decoder;

use crate::codec::SigStructure;
use crate::codec::SIG_STRUCTURE_CONTEXT;
use crate::consts::*;
use crate::sig::reverse_signature_halves;

/// Zero-copy view over a decoded COSE_Sign1 key-attestation report.
///
/// Scalar fields are decoded by value; every byte field is a `&DmaBuf`
/// sub-view borrowing directly from the input report buffer.
pub struct KeyReportView<'a> {
    /// Report format version.
    pub version: u16,
    /// Real length of the COSE_Key within [`public_key`](Self::public_key).
    pub public_key_size: u16,
    /// Capability flags for the attested key.
    pub flags: u32,
    /// The `public_key` field (fixed [`PUBLIC_KEY_MAX_SIZE`] bytes; the
    /// COSE_Key occupies the first `public_key_size`, rest zero-padded).
    pub public_key: &'a DmaBuf,
    /// Owning application UUID.
    pub app_uuid: &'a DmaBuf,
    /// Report data.
    pub report_data: &'a DmaBuf,
    /// VM launch ID.
    pub vm_launch_id: &'a DmaBuf,
    /// Optional SHA-384 PartPolicy digest. `Some` iff the report is v2
    /// (carries map key 7); `None` for a v1 report.
    pub policy_hash: Option<&'a DmaBuf>,
    /// COSE_Sign1 protected header (signed input).
    pub protected_header: &'a DmaBuf,
    /// Encoded payload bytes (the Sig_structure input).
    pub payload: &'a DmaBuf,
    /// COSE_Sign1 signature (`r || s`, big-endian per half).
    pub signature: &'a DmaBuf,
}

/// Map a minicbor decode error to [`HsmError::InvalidArg`].
pub(crate) fn map_decode_err<T, E>(result: Result<T, E>) -> HsmResult<T> {
    result.map_err(|_| HsmError::InvalidArg)
}

/// Read a bstr at the decoder's current position and return the
/// `[start, end)` offsets of its content in the decoder's input.
pub(crate) fn bytes_span(d: &mut Decoder<'_>) -> HsmResult<(usize, usize)> {
    let len = map_decode_err(d.bytes())?.len();
    let end = d.position();
    let start = end.checked_sub(len).ok_or(HsmError::InvalidArg)?;
    Ok((start, end))
}

/// Parse a tagged COSE_Sign1 key-attestation report, returning a
/// zero-copy [`KeyReportView`] borrowing from `report`.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — malformed report (bad tag, structure, or
///   CBOR).
pub fn parse_key_report(report: &DmaBuf) -> HsmResult<KeyReportView<'_>> {
    if report.len() <= COSE_SIGN1_TAG_SIZE || report[0] != COSE_SIGN1_TAG {
        return Err(HsmError::InvalidArg);
    }
    let rest = &report[COSE_SIGN1_TAG_SIZE..];

    // COSE_Sign1 = [ protected, unprotected{}, payload, signature ].
    let (prot, payload_span, sig) = {
        let mut d = Decoder::new(rest);
        if map_decode_err(d.array())? != Some(4) {
            return Err(HsmError::InvalidArg);
        }
        let prot = bytes_span(&mut d)?;
        // unprotected header is an empty map.
        if map_decode_err(d.map())? != Some(0) {
            return Err(HsmError::InvalidArg);
        }
        let payload_span = bytes_span(&mut d)?;
        let sig = bytes_span(&mut d)?;
        // Reject trailing bytes after the COSE_Sign1 object.
        if d.position() != rest.len() {
            return Err(HsmError::InvalidArg);
        }
        (prot, payload_span, sig)
    };

    // Enforce the fixed COSE-envelope field lengths.
    if prot.1 - prot.0 != PROTECTED_HEADER.len() || sig.1 - sig.0 != SIGNATURE_LEN {
        return Err(HsmError::InvalidArg);
    }
    let protected_header = &rest[prot.0..prot.1];
    let payload = &rest[payload_span.0..payload_span.1];
    let signature = &rest[sig.0..sig.1];

    // Payload = integer-keyed map. v1 has 7 entries (keys 0..=6); v2 adds
    // an 8th (key 7 = policy_hash). All of keys 0..=6 are mandatory; key 7
    // is optional and, when present, marks the report as v2.
    let mut version = 0u16;
    let mut public_key_size = 0u16;
    let mut flags = 0u32;
    let mut pk = (0usize, 0usize);
    let mut uuid = (0usize, 0usize);
    let mut rd = (0usize, 0usize);
    let mut vm = (0usize, 0usize);
    let mut ph = (0usize, 0usize);
    let mut have_policy_hash = false;
    {
        let mut d = Decoder::new(payload);
        let entries = map_decode_err(d.map())?.ok_or(HsmError::InvalidArg)?;
        if entries != 7 && entries != 8 {
            return Err(HsmError::InvalidArg);
        }
        let mut seen = 0u8;
        for _ in 0..entries {
            let key = map_decode_err(d.u8())?;
            if key > 7 || seen & (1 << key) != 0 {
                // Unknown or duplicate key.
                return Err(HsmError::InvalidArg);
            }
            seen |= 1 << key;
            match key {
                0 => version = map_decode_err(d.u16())?,
                1 => pk = bytes_span(&mut d)?,
                2 => public_key_size = map_decode_err(d.u16())?,
                3 => flags = map_decode_err(d.u32())?,
                4 => uuid = bytes_span(&mut d)?,
                5 => rd = bytes_span(&mut d)?,
                6 => vm = bytes_span(&mut d)?,
                _ => {
                    // key == 7: policy_hash (v2 only).
                    ph = bytes_span(&mut d)?;
                    have_policy_hash = true;
                }
            }
        }
        // Keys 0..=6 must each appear exactly once.
        if seen & 0x7f != 0x7f {
            return Err(HsmError::InvalidArg);
        }
        // Reject trailing bytes inside the payload.
        if d.position() != payload.len() {
            return Err(HsmError::InvalidArg);
        }
    }

    // Enforce fixed payload field lengths and value bounds so callers can
    // slice the returned views (e.g. `public_key[..public_key_size]`)
    // without any risk of out-of-bounds panics on untrusted input. The
    // expected version is fixed by whether `policy_hash` is present, so a
    // v1 report claiming v2 (or vice versa) is rejected.
    let expected_version = if have_policy_hash {
        REPORT_VERSION_V2
    } else {
        REPORT_VERSION
    };
    if pk.1 - pk.0 != PUBLIC_KEY_MAX_SIZE
        || uuid.1 - uuid.0 != APP_UUID_LEN
        || rd.1 - rd.0 != REPORT_DATA_LEN
        || vm.1 - vm.0 != VM_LAUNCH_ID_LEN
        || version != expected_version
        || public_key_size as usize > PUBLIC_KEY_MAX_SIZE
        || (have_policy_hash && ph.1 - ph.0 != POLICY_HASH_LEN)
    {
        return Err(HsmError::InvalidArg);
    }

    let policy_hash = have_policy_hash.then(|| &payload[ph.0..ph.1]);

    Ok(KeyReportView {
        version,
        public_key_size,
        flags,
        public_key: &payload[pk.0..pk.1],
        app_uuid: &payload[uuid.0..uuid.1],
        report_data: &payload[rd.0..rd.1],
        vm_launch_id: &payload[vm.0..vm.1],
        policy_hash,
        protected_header,
        payload,
        signature,
    })
}

/// Verify the ES384 signature of a COSE_Sign1 key-attestation report.
///
/// Rebuilds the COSE `Sig_structure` over the report's protected header
/// and payload, hashes it (SHA-384), and verifies against `signer_pub`.
///
/// # Parameters
/// * `signer_pub` — signer's P-384 public key, `x || y` with each
///   coordinate little-endian (the `ecc_verify` wire form).
///
/// # Returns
/// * `Ok(true)` — signature is valid.
/// * `Ok(false)` — signature is invalid.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — malformed report.
/// * Other [`HsmError`] values propagated from the PAL.
pub async fn verify_key_report<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    report: &DmaBuf,
    signer_pub: &DmaBuf,
) -> HsmResult<bool>
where
    P: HsmCrypto + 'a,
{
    let view = parse_key_report(report)?;

    // The protected header is signed input. Our fixed wire format mandates
    // the canonical ES384 header, and the Sig_structure below is rebuilt
    // from that constant — so bind it by rejecting any report whose
    // protected header differs (otherwise a tampered header would not be
    // covered by the signature check below).
    let protected: &[u8] = view.protected_header;
    if protected != &PROTECTED_HEADER[..] {
        return Err(HsmError::InvalidArg);
    }

    // Rebuild the Sig_structure over (protected_header, payload) and
    // measure/encode it with `minicbor::len` — no hand byte-counting.
    let sig_struct_val = SigStructure {
        context: SIG_STRUCTURE_CONTEXT,
        body_protected: &PROTECTED_HEADER,
        external_aad: &[],
        payload: view.payload,
    };
    // Zeroed so any `len`/`encode` divergence can't feed stale DMA bytes
    // into the verified digest.
    let sig_struct = alloc.dma_alloc_zeroed(minicbor::len(&sig_struct_val))?;
    minicbor::encode(&sig_struct_val, crate::codec::as_mut_slice(sig_struct))
        .map_err(|_| HsmError::InternalError)?;

    // SHA-384. `ecc_verify` is PKA little-endian native, so hash
    // big-endian and then fully byte-reverse the digest into PKA-LE,
    // matching the other verify callers (establish_credential /
    // x509-chain). SHA's `big_endian = false` is only a per-word swap,
    // not the full-digest reversal the PKA needs.
    let digest = alloc.dma_alloc(SHA384_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha384, sig_struct, digest, true)
        .await?;
    digest[..SHA384_LEN].reverse();

    // The COSE signature stores `r || s` big-endian per half; convert
    // to the little-endian `ecc_verify` wire form.
    let sig_le = alloc.dma_alloc(SIGNATURE_LEN)?;
    reverse_signature_halves(sig_le, view.signature)?;

    let result = alloc.dma_alloc(4)?;
    pal.ecc_verify(io, HsmEccCurve::P384, signer_pub, digest, sig_le, result)
        .await?;

    // Per the trait contract, bit 0 clear indicates a valid signature.
    Ok(result[0] & 1 == 0)
}
