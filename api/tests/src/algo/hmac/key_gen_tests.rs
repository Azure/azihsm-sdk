// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the HMAC key-generation API
//! ([`HsmHmacKeyGenAlgo`] via [`HsmKeyManager::generate_key`]) against the
//! emulator or hardware backend.
//!
//! HMAC key generation is a TBOR-only (V2) capability, so these tests run
//! on a security-domain (`session_ex`) session and are gated out of the
//! mock backend by the parent module. Property-validation guards run
//! before the device round-trip, so the reject tests are deterministic.

use azihsm_api::*;

use crate::utils::partition_ex_helpers::*;

/// Canonical `(kind, bits, key bytes)` for each HMAC SHA variant. HMAC
/// keygen is fixed to the canonical per-variant length.
const HMAC_VARIANTS: [(HsmKeyKind, u32, usize); 3] = [
    (HsmKeyKind::HmacSha256, 256, 32),
    (HsmKeyKind::HmacSha384, 384, 48),
    (HsmKeyKind::HmacSha512, 512, 64),
];

/// TBOR masked HMAC-key envelope overhead: `header(8) + iv(12) + aad(192)
/// + tag(16)`; the total blob is this plus the raw key bytes.
const MASKED_HMAC_OVERHEAD: usize = 8 + 12 + 192 + 16;

/// Well-formed HMAC key props: a `Secret` HMAC key permitted for
/// sign/verify, session-scoped so it needs only an active session (no
/// partition finalize), and carrying a caller label.
fn hmac_props(kind: HsmKeyKind, bits: u32) -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(kind)
        .bits(bits)
        .label(b"hmac-keygen-label")
        .is_session(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("build hmac props")
}

/// A key size that is not a supported HMAC digest size is rejected up
/// front, before any device round-trip.
#[test]
fn hmac_key_gen_rejects_wrong_bits() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(200)
        .is_session(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("build props");

    let mut algo = HsmHmacKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// A non-HMAC key kind is rejected by the host guard.
#[test]
fn hmac_key_gen_rejects_wrong_kind() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .is_session(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("build props");

    let mut algo = HsmHmacKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// An HMAC key that is not a `Secret` is rejected.
#[test]
fn hmac_key_gen_rejects_wrong_class() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .is_session(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("build props");

    let mut algo = HsmHmacKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// Sign/verify are the only permitted usages; an additional capability
/// (here `encrypt`) fails the supported-flags check.
#[test]
fn hmac_key_gen_rejects_extra_capability() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .is_session(true)
        .can_sign(true)
        .can_verify(true)
        .can_encrypt(true)
        .build()
        .expect("build props");

    let mut algo = HsmHmacKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// Full round trip for every SHA variant: generation yields a masked HMAC
/// key with the expected typed properties, and the caller label round-trips
/// through the device (proving the label is honored, not a fixed firmware
/// label). Signing with the masked key is a separate (TBOR HMAC) capability
/// and is covered elsewhere.
#[test]
fn hmac_key_gen_roundtrip_generates_usable_key() {
    let _guard = PARTITION_LOCK.lock();
    let session = crate::utils::sd_provision::finalized_co_session();

    for (kind, bits, key_bytes) in HMAC_VARIANTS {
        let mut algo = HsmHmacKeyGenAlgo::default();
        let key = HsmKeyManager::generate_key(&session, &mut algo, hmac_props(kind, bits))
            .expect("generate HMAC key");

        // Typed properties describe the requested secret HMAC key.
        assert_eq!(key.kind(), kind);
        assert_eq!(key.class(), HsmKeyClass::Secret);
        assert_eq!(key.bits(), bits);
        assert!(key.can_sign());
        assert!(key.can_verify());

        // The caller-supplied label survived the device round-trip; a
        // hardcoded firmware label would have failed the props check.
        assert_eq!(key.label(), b"hmac-keygen-label".to_vec());

        // The masked blob is the expected wire length and non-zero.
        let masked = key.masked_key_vec().expect("masked key");
        assert_eq!(masked.len(), MASKED_HMAC_OVERHEAD + key_bytes);
        assert!(
            masked.iter().any(|&b| b != 0),
            "masked key must not be all-zero"
        );
    }
}

/// Each generation samples fresh randomness: two keys generated on the
/// same session have distinct masked blobs.
#[test]
fn hmac_key_gen_yields_distinct_keys() {
    let _guard = PARTITION_LOCK.lock();
    let session = crate::utils::sd_provision::finalized_co_session();

    let generate = || {
        let mut algo = HsmHmacKeyGenAlgo::default();
        HsmKeyManager::generate_key(&session, &mut algo, hmac_props(HsmKeyKind::HmacSha256, 256))
            .expect("generate HMAC key")
            .masked_key_vec()
            .expect("masked key")
    };

    assert_ne!(
        generate(),
        generate(),
        "each generation must yield a distinct masked key"
    );
}
