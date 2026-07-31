// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime builder for COSE_Sign1 key-attestation reports.
//!
//! The report is signed with ES384 (ECDSA-P384) using the supplied
//! attestation private key. The attested public key may be ECC, RSA, or
//! symmetric (see [`AttestedPubKey`]).
//!
//! All working buffers are [`DmaBuf`] allocations. Every encoded length
//! is computed by `minicbor::len` on the [`codec`](crate::codec) structs
//! — there is no hand-maintained byte-counting. The inner COSE_Key uses
//! negative integer map keys (which minicbor's derive cannot express), so
//! it alone is written with an imperative `Encoder` (see
//! [`to_cose_key`](crate::cose_key)).

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::codec::as_mut_slice;
use crate::codec::CoseSign1;
use crate::codec::KeyReportPayload;
use crate::codec::SigStructure;
use crate::codec::UnprotectedHeader;
use crate::codec::SIG_STRUCTURE_CONTEXT;
use crate::consts::*;
use crate::cose_key::to_cose_key;
use crate::cose_key::AttestedPubKey;
use crate::sig::reverse_signature_halves;

/// Caller-supplied inputs for the attestation report.
pub struct KeyReportParams<'a> {
    /// Public-key material for the attested key.
    pub key: AttestedPubKey<'a>,
    /// Capability flags for the attested key (build via [`KeyFlags`]).
    ///
    /// [`KeyFlags`]: crate::KeyFlags
    pub flags: u32,
    /// Owning application UUID; must be [`APP_UUID_LEN`] bytes.
    pub app_uuid: &'a DmaBuf,
    /// Report data; must be [`REPORT_DATA_LEN`] bytes.
    pub report_data: &'a DmaBuf,
    /// VM launch ID; must be [`VM_LAUNCH_ID_LEN`] bytes.
    pub vm_launch_id: &'a DmaBuf,
    /// Optional SHA-384 PartPolicy digest. When `Some`, the report is
    /// emitted as **v2** (carrying `policy_hash`); when `None`, as **v1**.
    /// Must be [`POLICY_HASH_LEN`] bytes when present.
    pub policy_hash: Option<&'a DmaBuf>,
}

impl KeyReportParams<'_> {
    fn validate(&self) -> HsmResult<()> {
        if self.app_uuid.len() != APP_UUID_LEN
            || self.report_data.len() != REPORT_DATA_LEN
            || self.vm_launch_id.len() != VM_LAUNCH_ID_LEN
        {
            return Err(HsmError::InvalidArg);
        }
        if let Some(policy_hash) = self.policy_hash {
            if policy_hash.len() != POLICY_HASH_LEN {
                return Err(HsmError::InvalidArg);
            }
        }
        self.key.validate()
    }
}

/// Build a COSE_Sign1 key-attestation report, signed ES384 with
/// `priv_key`.
///
/// Follows the codebase's query/copy convention:
///
/// * `out == None` — query mode: returns the exact report size. Encodes
///   the COSE_Key into scoped scratch to measure the report with
///   `minicbor::len`, then frees it; performs no signing.
/// * `out == Some(buf)` — copy mode: writes the tagged COSE_Sign1 report
///   into `buf[..size]` and returns `size`.
///
/// # Parameters
/// * `pal` — [`HsmCrypto`] (SHA-384 + ECDSA-P384) and [`HsmAlloc`].
/// * `io` — caller's IO scope.
/// * `alloc` — scoped allocator for internal `DmaBuf` scratch.
/// * `params` — attested key material, flags, UUIDs, report data.
/// * `priv_key` — P-384 attestation private key (raw scalar, exactly
///   [`PRIV_KEY_LEN`] bytes).
/// * `out` — output buffer, or `None` to query the required size.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — a `params` field or `priv_key` has the
///   wrong length, or `out` is shorter than the required size.
/// * Other [`HsmError`] values propagated from the PAL.
pub async fn key_report<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    params: &KeyReportParams<'_>,
    priv_key: &DmaBuf,
    out: Option<&mut [u8]>,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    params.validate()?;
    if priv_key.len() != PRIV_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }

    let Some(out) = out else {
        // Query pass: measure in a nested scope so the scratch frees
        // before returning (the size query retains nothing).
        return pal.alloc_scoped(io, |scoped| report_size(scoped, params));
    };

    do_build(pal, io, alloc, params, priv_key, out).await
}

/// Encode the inner COSE_Key into `cose_key` scratch and build the
/// payload codec struct describing it.
///
/// The report format version follows the presence of `policy_hash`:
/// [`REPORT_VERSION_V2`] when set (the payload carries the hash),
/// [`REPORT_VERSION`] otherwise — so there is no separate v1/v2 code path.
fn build_payload_struct<'a>(
    params: &'a KeyReportParams<'a>,
    cose_key: &'a DmaBuf,
    cose_len: usize,
) -> KeyReportPayload<'a> {
    let policy_hash = params.policy_hash.map(|d| &**d);
    let version = if policy_hash.is_some() {
        REPORT_VERSION_V2
    } else {
        REPORT_VERSION
    };
    KeyReportPayload {
        version,
        public_key: cose_key,
        public_key_size: cose_len as u16,
        flags: params.flags,
        app_uuid: params.app_uuid,
        report_data: params.report_data,
        vm_launch_id: params.vm_launch_id,
        policy_hash,
    }
}

/// Compute the exact tagged-report size for `params` using
/// `minicbor::len`, allocating only transient scratch from `scoped`.
fn report_size(scoped: &impl HsmScopedAlloc, params: &KeyReportParams<'_>) -> HsmResult<usize> {
    let cose_key = scoped.dma_alloc_zeroed(PUBLIC_KEY_MAX_SIZE)?;
    let cose_len = to_cose_key(&params.key, cose_key)?;
    let payload = build_payload_struct(params, cose_key, cose_len);
    let payload_len = minicbor::len(&payload);

    // The COSE_Sign1 wrapper length depends only on the payload and
    // signature lengths, so measure it against length-placeholder scratch.
    let payload_buf = scoped.dma_alloc(payload_len)?;
    let sig_buf = scoped.dma_alloc(SIGNATURE_LEN)?;
    let cose = CoseSign1 {
        protected_header: &PROTECTED_HEADER,
        unprotected: UnprotectedHeader {},
        payload: payload_buf,
        signature: sig_buf,
    };
    Ok(COSE_SIGN1_TAG_SIZE + minicbor::len(&cose))
}

async fn do_build<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    params: &KeyReportParams<'_>,
    priv_key: &DmaBuf,
    out: &mut [u8],
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    // 1. Encode the inner COSE_Key (zero-padded to the fixed field size).
    let cose_key = alloc.dma_alloc_zeroed(PUBLIC_KEY_MAX_SIZE)?;
    let cose_len = to_cose_key(&params.key, cose_key)?;

    // 2. Encode the payload map into DMA scratch. Zeroed so a short
    //    `minicbor::encode` write can't leave stale DMA bytes in the
    //    payload that is sent to the host.
    let payload_struct = build_payload_struct(params, cose_key, cose_len);
    let payload_len = minicbor::len(&payload_struct);
    let payload = alloc.dma_alloc_zeroed(payload_len)?;
    minicbor::encode(&payload_struct, as_mut_slice(payload))
        .map_err(|_| HsmError::InternalError)?;

    // 3. Encode the COSE Sig_structure over (protected_header, payload).
    let sig_struct_val = SigStructure {
        context: SIG_STRUCTURE_CONTEXT,
        body_protected: &PROTECTED_HEADER,
        external_aad: &[],
        payload,
    };
    let sig_struct_len = minicbor::len(&sig_struct_val);
    // Zeroed so any `len`/`encode` divergence can't feed stale DMA bytes
    // into the signed digest.
    let sig_struct = alloc.dma_alloc_zeroed(sig_struct_len)?;
    minicbor::encode(&sig_struct_val, as_mut_slice(sig_struct))
        .map_err(|_| HsmError::InternalError)?;

    // 4. SHA-384 digest (little-endian, matching `ecc_sign`'s input).
    let digest = alloc.dma_alloc(SHA384_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha384, sig_struct, digest, false)
        .await?;

    // 5. ECDSA-P384 sign — output is `r || s` in little-endian wire form.
    let sig_le = alloc.dma_alloc(SIGNATURE_LEN)?;
    pal.ecc_sign(io, HsmEccCurve::P384, priv_key, digest, sig_le)
        .await?;

    // 6. Convert the signature to big-endian per component for COSE.
    let sig_be = alloc.dma_alloc(SIGNATURE_LEN)?;
    reverse_signature_halves(sig_be, sig_le)?;

    // 7. Compose the tagged COSE_Sign1 envelope into `out`.
    let cose = CoseSign1 {
        protected_header: &PROTECTED_HEADER,
        unprotected: UnprotectedHeader {},
        payload,
        signature: sig_be,
    };
    let total = COSE_SIGN1_TAG_SIZE + minicbor::len(&cose);
    if out.len() < total {
        return Err(HsmError::InvalidArg);
    }
    // `out` may be uninitialised DMA memory; zero the report region so a
    // short `minicbor::encode` write can't expose stale bytes to the host.
    out[..total].fill(0);
    out[0] = COSE_SIGN1_TAG;
    minicbor::encode(&cose, &mut out[COSE_SIGN1_TAG_SIZE..total])
        .map_err(|_| HsmError::InternalError)?;
    Ok(total)
}
