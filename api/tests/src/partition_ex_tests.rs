// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR partition-provisioning session API
//! (`HsmSession::part_init_ex` and `HsmSession::part_final`).
//!
//! These exercise the input-validation guards through the *public*
//! `azihsm_api` surface against the FW emulator. Each guard returns
//! before the device round-trip, so the checks are deterministic and do
//! not require a FW-accepted policy / cert chain.

use azihsm_api::*;
use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_MAX_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::MAX_CERTS;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::SAPOTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;

use crate::emu_helpers::*;

/// Well-formed fixed-size inputs for the non-`part_policy` `PartInit`
/// fields.
fn valid_part_init_inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        vec![0u8; MACH_SEED_LEN],
        vec![0u8; POTA_THUMBPRINT_LEN],
        vec![0u8; SATA_THUMBPRINT_LEN],
    )
}

/// A minimal, well-formed one-entry PTA certificate chain (one DER cert).
fn one_cert() -> Vec<u8> {
    vec![0u8; 4]
}

// ── PartInit ────────────────────────────────────────────────────────────────

/// A wrong-length `part_policy` is rejected up front, before any device
/// round-trip.
#[test]
fn part_init_rejects_bad_part_policy_len() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let (mach_seed, pota, sata) = valid_part_init_inputs();
    let bad_policy = vec![0u8; PART_POLICY_LEN - 1];

    let res = session.part_init_ex(&mach_seed, &bad_policy, &pota, &sata, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// A wrong-length `pota_thumbprint` is rejected.
#[test]
fn part_init_rejects_bad_pota_thumbprint_len() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let (mach_seed, _pota, sata) = valid_part_init_inputs();
    let policy = vec![0u8; PART_POLICY_LEN];
    let bad_pota = vec![0u8; POTA_THUMBPRINT_LEN + 1];

    let res = session.part_init_ex(&mach_seed, &policy, &bad_pota, &sata, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// A wrong-length `sata_thumbprint` is rejected.
#[test]
fn part_init_rejects_bad_sata_thumbprint_len() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let (mach_seed, pota, _sata) = valid_part_init_inputs();
    let policy = vec![0u8; PART_POLICY_LEN];
    let bad_sata = vec![0u8; SATA_THUMBPRINT_LEN + 1];

    let res = session.part_init_ex(&mach_seed, &policy, &pota, &bad_sata, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// A present-but-wrong-length `sapota_thumbprint` is rejected.
#[test]
fn part_init_rejects_bad_sapota_thumbprint_len() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let (mach_seed, pota, sata) = valid_part_init_inputs();
    let policy = vec![0u8; PART_POLICY_LEN];
    let bad_sapota = vec![0u8; SAPOTA_THUMBPRINT_LEN + 1];

    let res = session.part_init_ex(&mach_seed, &policy, &pota, &sata, Some(&bad_sapota));
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects a wrong-length `part_policy` before any device
/// round-trip.
#[test]
fn part_final_rejects_bad_part_policy_len() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let bad_policy = vec![0u8; PART_POLICY_LEN - 1];

    let cert = one_cert();
    let chain = [HsmCertDescriptor { cert: &cert }];
    let res = session.part_final(&bad_policy, &chain, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects an empty cert chain.
#[test]
fn part_final_rejects_empty_cert_descriptors() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let policy = vec![0u8; PART_POLICY_LEN];

    let res = session.part_final(&policy, &[], None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects more than [`MAX_CERTS`] certificates.
#[test]
fn part_final_rejects_too_many_cert_descriptors() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let policy = vec![0u8; PART_POLICY_LEN];
    let cert = one_cert();
    let too_many = vec![HsmCertDescriptor { cert: cert.as_slice() }; MAX_CERTS + 1];

    let res = session.part_final(&policy, &too_many, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects an oversized `prev_local_mk_backup`.
#[test]
fn part_final_rejects_oversized_prev_local_mk_backup() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let policy = vec![0u8; PART_POLICY_LEN];
    let oversized = vec![0u8; LOCAL_MK_BACKUP_MAX_LEN + 1];

    let cert = one_cert();
    let chain = [HsmCertDescriptor { cert: &cert }];
    let res = session.part_final(&policy, &chain, Some(&oversized));
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}
