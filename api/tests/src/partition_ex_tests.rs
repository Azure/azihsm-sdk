// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR partition-provisioning session API
//! (`HsmSession::part_init_ex` and `HsmSession::part_final_ex`).
//!
//! These exercise the input-validation guards through the *public*
//! `azihsm_api` surface against the FW emulator. The negative-path guard
//! tests return before the device round-trip, so they are deterministic
//! and need no FW-accepted policy / cert chain; the
//! `*_valid_inputs_pass_host_guards` tests deliberately clear the guards
//! and reach the device to exercise the request-construction path.

use azihsm_api::*;
use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
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

/// A one-entry PTA cert placeholder (4 opaque bytes). The host-side
/// guards never parse DER, so its contents are irrelevant.
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
    let chain = [HsmCert { cert: &cert }];
    let res = session.part_final_ex(&bad_policy, &chain, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects an empty cert chain.
#[test]
fn part_final_rejects_empty_cert_descriptors() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let policy = vec![0u8; PART_POLICY_LEN];

    let res = session.part_final_ex(&policy, &[], None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects a cert chain containing an empty (zero-length)
/// certificate, which is not valid DER and would yield a zero-length
/// out-of-band descriptor.
#[test]
fn part_final_rejects_empty_cert() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let policy = vec![0u8; PART_POLICY_LEN];
    let empty_cert: Vec<u8> = Vec::new();
    let chain = [HsmCert {
        cert: empty_cert.as_slice(),
    }];

    let res = session.part_final_ex(&policy, &chain, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects more than [`MAX_CERTS`] certificates.
#[test]
fn part_final_rejects_too_many_cert_descriptors() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let policy = vec![0u8; PART_POLICY_LEN];
    let cert = one_cert();
    let too_many = vec![
        HsmCert {
            cert: cert.as_slice()
        };
        MAX_CERTS + 1
    ];

    let res = session.part_final_ex(&policy, &too_many, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects a `prev_local_mk_backup` whose length is not
/// exactly [`LOCAL_MK_BACKUP_LEN`] (near-miss under-length), exercising
/// the fixed-size guard rather than a coarse max-length check.
#[test]
fn part_final_rejects_wrong_len_prev_local_mk_backup() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let policy = vec![0u8; PART_POLICY_LEN];
    let wrong_len = vec![0u8; LOCAL_MK_BACKUP_LEN - 1];

    let cert = one_cert();
    let chain = [HsmCert { cert: &cert }];
    let res = session.part_final_ex(&policy, &chain, Some(&wrong_len));
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

// ── Host-guard pass-through (request-construction / round-trip) ──────────────

/// Valid-length `PartInit` inputs pass every host-side guard, so the
/// request is sealed, constructed, and shipped to the device. The call
/// is therefore never rejected with [`HsmError::InvalidArgument`] (the
/// host-guard error); it may still fail on-device with a different
/// error. This exercises the request-construction / TBOR wiring path
/// that the negative guard tests skip.
#[test]
fn part_init_valid_inputs_pass_host_guards() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let (mach_seed, pota, sata) = valid_part_init_inputs();
    let policy = vec![0u8; PART_POLICY_LEN];

    let res = session.part_init_ex(&mach_seed, &policy, &pota, &sata, None);
    assert!(!matches!(res, Err(HsmError::InvalidArgument)));
}

/// Valid-length `PartFinal` inputs pass every host-side guard, so the
/// request is built — each cert ships as its own out-of-band SGL Data
/// Block and its `(index, length)` descriptor is derived — and shipped
/// to the device. The call is therefore never rejected with
/// [`HsmError::InvalidArgument`]; it may still fail on-device. This
/// exercises the request-construction / TBOR-OOB wiring path.
#[test]
fn part_final_valid_inputs_pass_host_guards() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();
    let policy = vec![0u8; PART_POLICY_LEN];
    let cert = one_cert();
    let chain = [HsmCert { cert: &cert }];

    let res = session.part_final_ex(&policy, &chain, None);
    assert!(!matches!(res, Err(HsmError::InvalidArgument)));
}
