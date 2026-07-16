// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the security-domain sealing-key generation API
//! ([`HsmSealingKeyGenAlgo`] via [`HsmKeyManager::generate_key`]) against
//! the FW emulator.
//!
//! Property-validation guards run before the device round-trip, so they are
//! deterministic. The `roundtrip_*` tests provision the partition to
//! `Initialized` via [`super::provision::finalized_co_session`], then
//! generate a sealing key end to end and validate the masked blob and
//! public key.

use azihsm_api::*;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;

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

/// A non-`Sealing` key kind is rejected, even with an otherwise valid
/// secret derive key.
#[test]
fn sealing_key_gen_rejects_wrong_kind() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_derive(true)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// A `Sealing` derive key that is not a `Secret` is rejected.
#[test]
fn sealing_key_gen_rejects_wrong_class() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// Derivation is the only permitted usage; an additional capability (here
/// `sign`) fails the supported-flags check.
#[test]
fn sealing_key_gen_rejects_extra_capability() {
    let _guard = EMU_LOCK.lock();
    let session = fresh_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .can_sign(true)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// Valid props pass the host-side guards and reach the device, so the call
/// is never rejected with [`HsmError::InvalidKeyProps`] /
/// [`HsmError::InvalidArgument`] (it may still fail on-device on an
/// unprovisioned partition).
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

/// Full round trip: on a fully provisioned partition, generating a sealing
/// key succeeds and yields a usable key — the pinned 180-byte masked blob
/// plus a P-384 public key — with the expected typed properties.
#[test]
fn sealing_key_gen_roundtrip_generates_usable_sealing_key() {
    let _guard = EMU_LOCK.lock();
    let session = super::provision::finalized_co_session();

    let mut algo = HsmSealingKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut algo, sealing_props())
        .expect("generate sealing key on a provisioned partition");

    // Typed properties describe a P-384 `Sealing` secret derive key.
    assert_eq!(key.kind(), HsmKeyKind::Sealing);
    assert_eq!(key.class(), HsmKeyClass::Secret);
    assert_eq!(key.bits(), 384);
    assert!(key.can_derive());

    // The masked private-key blob is the pinned wire length and non-zero.
    let masked = key.masked_key_vec().expect("masked key");
    assert_eq!(masked.len(), MASKED_SEALING_KEY_LEN);
    assert!(
        masked.iter().any(|&b| b != 0),
        "masked key must not be all-zero"
    );

    // The public key is retrievable as DER SubjectPublicKeyInfo.
    let pub_der = key.pub_key_der_vec().expect("public key der");
    assert!(!pub_der.is_empty());
}

/// Each `SdSealingKeyGen` call produces fresh key material: two keys
/// generated on the same provisioned session have distinct masked blobs
/// and distinct public keys.
#[test]
fn sealing_key_gen_roundtrip_yields_distinct_keys() {
    let _guard = EMU_LOCK.lock();
    let session = super::provision::finalized_co_session();

    let generate = || {
        let mut algo = HsmSealingKeyGenAlgo::default();
        let key = HsmKeyManager::generate_key(&session, &mut algo, sealing_props())
            .expect("generate sealing key");
        let masked = key.masked_key_vec().expect("masked key");
        let pub_der = key.pub_key_der_vec().expect("public key der");
        (masked, pub_der)
    };

    let (masked1, pub1) = generate();
    let (masked2, pub2) = generate();

    assert_eq!(masked1.len(), MASKED_SEALING_KEY_LEN);
    assert_eq!(masked2.len(), MASKED_SEALING_KEY_LEN);
    assert!(!pub1.is_empty());
    assert!(!pub2.is_empty());
    // Fresh randomness → distinct masked blobs and public keys.
    assert_ne!(masked1, masked2);
    assert_ne!(pub1, pub2);
}
