// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for the security-domain backup commands
//! (`SdCreateRemoteBackup`, `SdResealRemoteBackup`).
//!
//! # Out-of-band evidence
//!
//! Bulk attestation evidence (DER cert chains and a COSE_Sign1 report)
//! travels out of band: each [`HsmSdEvidence`] is flattened into
//! `(index, length)` descriptors (via [`super::descriptor_utils`]) and its
//! DER bytes
//! are shipped as `oob_items`, mirroring the `PartFinal` cert-chain
//! transport.

use azihsm_ddi_tbor_types::*;

use super::*;

/// Decodes a caller-supplied unified `PartPolicy` image
/// ([`PART_POLICY_LEN`] bytes), failing fast with
/// [`HsmError::InvalidArgument`] on a wrong length or malformed image.
pub(crate) fn decode_policy(policy: &[u8]) -> HsmResult<PartPolicy> {
    if policy.len() != PART_POLICY_LEN {
        return Err(HsmError::InvalidArgument);
    }
    <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(policy)
        .map_err(|_| HsmError::InvalidArgument)
}

/// Wire descriptors for one attestation party: the three cert-chain
/// lists plus the report descriptor. Produced by [`push_evidence`].
pub(crate) struct EvidenceDescriptors {
    pub(crate) mfgr: Vec<CertDescriptor>,
    pub(crate) owner: Vec<CertDescriptor>,
    pub(crate) part_owner: Vec<CertDescriptor>,
    pub(crate) report: ReportDescriptor,
}

/// Flattens one [`HsmSdEvidence`] party into its wire descriptors,
/// appending all referenced DER bytes (the three cert chains, then the
/// report) to the shared `oob` list so their descriptor indices are
/// contiguous.
pub(crate) fn push_evidence<'a>(
    evidence: &HsmSdEvidence<'a>,
    oob: &mut Vec<&'a [u8]>,
) -> HsmResult<EvidenceDescriptors> {
    Ok(EvidenceDescriptors {
        mfgr: push_cert_chain(evidence.mfgr_cert_chain, oob, EVIDENCE_CHAIN_MAX_CERTS)?,
        owner: push_cert_chain(evidence.owner_cert_chain, oob, EVIDENCE_CHAIN_MAX_CERTS)?,
        part_owner: push_cert_chain(
            evidence.part_owner_cert_chain,
            oob,
            EVIDENCE_CHAIN_MAX_CERTS,
        )?,
        report: push_report(evidence.report, oob)?,
    })
}
