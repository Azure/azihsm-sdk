// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the security-domain sealing-key generation API
//! ([`HsmSealingKeyGenAlgo`] via [`HsmKeyManager::generate_key`]).
//!
//! These exercise the public `azihsm_api` surface against the FW
//! emulator. The property-validation guards return before the device
//! round-trip, so they are deterministic. The
//! `valid_props_pass_host_guards` test deliberately clears the host
//! guards and reaches the device to exercise the TBOR request-construction
//! path (`ddi::sd_sealing_key_gen`).
//!
//! A *complete* end-to-end generation (asserting the returned masked blob
//! and public key parse) is intentionally not covered here: the FW
//! `SdSealingKeyGen` handler requires the partition in the `Initialized`
//! lifecycle state (masking keys provisioned by `PartFinal` with a signed
//! PTA cert chain), which the emulator test harness does not set up. So a
//! freshly reset partition can only exercise the path up to the device
//! round-trip, matching the `partition_ex` host-guard tests.

use azihsm_api::*;

use crate::emu_helpers::*;

/// Well-formed sealing key props: a `Sealing`-kind P-384 secret key
/// permitted for derivation only, matching the wire contract.
fn sealing_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .build()
        .expect("build sealing props")
}

/// A `Sealing` key that is not P-384 sized is rejected up front, before
/// any device round-trip: `SdSealingKeyGen` always produces a 384-bit
/// scalar.
#[test]
fn sealing_key_gen_rejects_wrong_bits() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(256)
        .can_derive(true)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// A `Sealing` key without derive usage is rejected: derivation is the
/// only permitted usage for a sealing key.
#[test]
fn sealing_key_gen_rejects_missing_derive() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// Valid sealing props pass every host-side guard, so the request is
/// sealed, constructed, and shipped to the device. The call is therefore
/// never rejected with the host-guard errors ([`HsmError::InvalidKeyProps`]
/// / [`HsmError::InvalidArgument`]); it may still fail on-device because a
/// freshly reset partition is not provisioned. This exercises the
/// property-conversion and TBOR request-construction path that the
/// negative guard tests skip.
#[test]
fn sealing_key_gen_valid_props_pass_host_guards() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, sealing_props());

    // `HsmSealingKey` is not `Debug`, so inspect only the error variant.
    assert!(
        !matches!(
            res.as_ref().err(),
            Some(HsmError::InvalidKeyProps) | Some(HsmError::InvalidArgument)
        ),
        "valid sealing props must pass the host guards, got error: {:?}",
        res.err(),
    );
}
