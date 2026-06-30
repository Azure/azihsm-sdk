// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition provisioning over the TBOR transport at the DDI layer.
//!
//! This module hosts the host-side dispatch for the in-session
//! Crypto-Officer `PartInit` command, mirroring the firmware handler:
//!
//! * **`PartInit`** (opcode `0x07`) — derive the partition PTA keypair,
//!   persist the caller-asserted unified `PartPolicy` plus the POTA /
//!   SATA / optional SAPOTA thumbprints, and return the PTA CSR +
//!   COSE_Sign1 attestation report.
//!
//! It runs **inside an already-open CO session** established by
//! [`super::session_ex::open_session_ex`]: the request carries the
//! active session id and seals its `mach_seed`
//! under the session `param_key`. The caller therefore supplies the
//! active session id (and, for `PartInit`, the session `param_key`)
//! alongside the partition handle.
//!
//! The wire schemas live in [`azihsm_ddi_tbor_types`]; the only crypto
//! performed here is the `PartInit` `mach_seed` AEAD-GCM seal, whose AAD
//! binds the envelope to the session id so the firmware's in-place open
//! rejects a seed minted for a different session.

use azihsm_crypto::*;
use azihsm_ddi_tbor_types::*;

use super::*;

/// API-layer result of a TBOR `PartInit` provisioning command.
///
/// Mirrors [`TborPartInitResp`] with owned bytes so the wire response
/// type stays confined to the DDI layer and never reaches `HsmSession`
/// callers.
#[derive(Debug, Clone, Default)]
pub struct PartInitResult {
    /// DER-encoded PKCS#10 CertificationRequest for the PTA pubkey.
    pub pta_csr: Vec<u8>,
    /// COSE_Sign1 PTA key-attestation report signed by the PID.
    pub pta_report: Vec<u8>,
}

impl From<TborPartInitResp> for PartInitResult {
    fn from(resp: TborPartInitResp) -> Self {
        Self {
            pta_csr: resp.pta_csr,
            pta_report: resp.pta_report,
        }
    }
}

/// Build the 32-byte AEAD AAD bound into a `PartInit` `mach_seed`
/// envelope.
///
/// Layout: [`PART_INIT_MACH_SEED_AAD_LABEL`] (17 B) ‖ `session_id`
/// (2 B little-endian) ‖ zero-padding to [`PART_INIT_MACH_SEED_AAD_LEN`].
/// The firmware reconstructs the identical bytes from the wire-pinned
/// constants and rejects any mismatch during the in-place AEAD open.
fn build_part_init_mach_seed_aad(session_id: u16) -> [u8; PART_INIT_MACH_SEED_AAD_LEN] {
    let mut aad = [0u8; PART_INIT_MACH_SEED_AAD_LEN];
    let label_len = PART_INIT_MACH_SEED_AAD_LABEL.len();
    aad[..label_len].copy_from_slice(PART_INIT_MACH_SEED_AAD_LABEL);
    aad[label_len..label_len + 2].copy_from_slice(&session_id.to_le_bytes());
    aad
}

/// Seal a 32-byte `mach_seed` under the active session's `param_key`
/// as the `mach_seed_envelope` wire blob.
///
/// Uses a fresh random 12-byte IV and the session-bound AAD from
/// [`build_part_init_mach_seed_aad`]. Returns the exact bytes that
/// occupy the `mach_seed_envelope` field of [`TborPartInitReq`].
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when `mach_seed` is not
/// [`MACH_SEED_LEN`] bytes, and [`HsmError::InternalError`] on any RNG
/// or AEAD failure.
fn seal_mach_seed_envelope(
    param_key: &AesKey,
    session_id: u16,
    mach_seed: &[u8],
) -> HsmResult<Vec<u8>> {
    if mach_seed.len() != MACH_SEED_LEN {
        return Err(HsmError::InvalidArgument);
    }

    let aad = build_part_init_mach_seed_aad(session_id);
    let iv = Rng::rand_vec(12).map_err(|_| HsmError::InternalError)?;

    // First pass sizes the output buffer; second pass writes the
    // sealed envelope into it.
    let total = aead_envelope::seal(
        aead_envelope::AeadAlg::AesGcm256,
        param_key,
        &iv,
        &aad,
        mach_seed,
        None,
    )
    .map_err(|_| HsmError::InternalError)?;
    let mut envelope = vec![0u8; total];
    let written = aead_envelope::seal(
        aead_envelope::AeadAlg::AesGcm256,
        param_key,
        &iv,
        &aad,
        mach_seed,
        Some(&mut envelope),
    )
    .map_err(|_| HsmError::InternalError)?;
    envelope.truncate(written);
    Ok(envelope)
}

/// Issue `PartInit` (opcode `0x07`) on the active CO session.
///
/// Seals `mach_seed` under the session `param_key` (AAD-bound to the
/// session id), then ships it alongside the unified `part_policy` and
/// the POTA / SATA / optional SAPOTA thumbprints. Returns the PTA CSR +
/// attestation report the firmware produced.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active CO session id this request binds to.
/// * `param_key` - The session's per-session AES wrap key used to seal
///   `mach_seed`.
/// * `mach_seed` - 32-byte machine seed ([`MACH_SEED_LEN`]).
/// * `part_policy` - Caller-asserted unified [`PartPolicy`] image
///   ([`PART_POLICY_LEN`] bytes).
/// * `pota_thumbprint` - SHA-384 POTA thumbprint
///   ([`POTA_THUMBPRINT_LEN`]).
/// * `sata_thumbprint` - SHA-384 SATA thumbprint
///   ([`SATA_THUMBPRINT_LEN`]).
/// * `sapota_thumbprint` - Optional SHA-384 SAPOTA thumbprint
///   ([`SAPOTA_THUMBPRINT_LEN`]); `None` when the security domain has
///   no SAPOTA binding.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when any fixed-size input has
/// the wrong length or `part_policy` fails to decode, propagates
/// [`HsmError::InternalError`] on a `mach_seed` seal failure, and
/// surfaces DDI/device failures from the round-trip.
pub(crate) fn init_part_ex(
    partition: &HsmPartition,
    session_id: u16,
    param_key: &AesKey,
    mach_seed: &[u8],
    part_policy: &[u8],
    pota_thumbprint: &[u8],
    sata_thumbprint: &[u8],
    sapota_thumbprint: Option<&[u8]>,
) -> HsmResult<PartInitResult> {
    if part_policy.len() != PART_POLICY_LEN
        || pota_thumbprint.len() != POTA_THUMBPRINT_LEN
        || sata_thumbprint.len() != SATA_THUMBPRINT_LEN
    {
        return Err(HsmError::InvalidArgument);
    }
    if sapota_thumbprint.is_some_and(|s| s.len() != SAPOTA_THUMBPRINT_LEN) {
        return Err(HsmError::InvalidArgument);
    }

    let mach_seed_envelope = seal_mach_seed_envelope(param_key, session_id, mach_seed)?;

    let mut req = TborPartInitReq {
        session_id,
        mach_seed_envelope,
        ..Default::default()
    };
    req.part_policy = <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(part_policy)
        .map_err(|_| HsmError::InvalidArgument)?;
    req.pota_thumbprint.copy_from_slice(pota_thumbprint);
    req.sata_thumbprint.copy_from_slice(sata_thumbprint);
    if let Some(s) = sapota_thumbprint {
        req.sapota_thumbprint = s.to_vec();
    }

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, &mut cookie)
        .map(PartInitResult::from)
        .map_err(HsmError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `mach_seed` AAD must be `label ‖ session_id_le ‖ zero-pad`,
    /// matching the firmware's reconstruction.
    #[test]
    fn mach_seed_aad_layout() {
        let aad = build_part_init_mach_seed_aad(0x1234);
        let label_len = PART_INIT_MACH_SEED_AAD_LABEL.len();

        assert_eq!(&aad[..label_len], PART_INIT_MACH_SEED_AAD_LABEL);
        assert_eq!(&aad[label_len..label_len + 2], &[0x34, 0x12]);
        assert!(aad[label_len + 2..].iter().all(|&b| b == 0));
        assert_eq!(aad.len(), PART_INIT_MACH_SEED_AAD_LEN);
    }
}
