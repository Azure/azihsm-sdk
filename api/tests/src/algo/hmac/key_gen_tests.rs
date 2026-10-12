// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the HMAC key-generation API
//! ([`HsmHmacKeyGenAlgo`] via [`HsmKeyManager::generate_key`]).
//!
//! Property-validation tests use the selected session API in either build.
//! Successful random key generation requires `session_ex`. Property validation
//! runs before the key-generation command is sent; session setup still requires
//! a backend.

use azihsm_api::*;
use azihsm_api_tests_macro::*;

#[cfg(feature = "session-ex-tests")]
use crate::utils::partition_ex_helpers::*;

/// Canonical `(kind, bits, key bytes)` for each HMAC SHA variant. HMAC
/// keygen is fixed to the canonical per-variant length.
#[cfg(feature = "session-ex-tests")]
const HMAC_VARIANTS: [(HsmKeyKind, u32, usize); 3] = [
    (HsmKeyKind::HmacSha256, 256, 32),
    (HsmKeyKind::HmacSha384, 384, 48),
    (HsmKeyKind::HmacSha512, 512, 64),
];

/// TBOR masked HMAC-key envelope overhead: `header(8) + iv(12) + aad(192)
/// + tag(16)`; the total blob is this plus the raw key bytes.
#[cfg(feature = "session-ex-tests")]
const MASKED_HMAC_OVERHEAD: usize = 8 + 12 + 192 + 16;

/// Session-scoped secret HMAC key properties with sign/verify capabilities
/// and a caller-supplied label.
#[cfg(feature = "session-ex-tests")]
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
/// front, before sending a key-generation command.
#[session_test]
fn hmac_key_gen_rejects_wrong_bits(session: HsmSession) {
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
#[session_test]
fn hmac_key_gen_rejects_wrong_kind(session: HsmSession) {
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
#[session_test]
fn hmac_key_gen_rejects_wrong_class(session: HsmSession) {
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
#[session_test]
fn hmac_key_gen_rejects_extra_capability(session: HsmSession) {
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
#[cfg(feature = "session-ex-tests")]
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

/// Successive key generations on the same session return distinct masked blobs.
/// This comparison does not establish that the underlying key bytes differ.
#[cfg(feature = "session-ex-tests")]
#[test]
fn hmac_key_gen_yields_distinct_masked_blobs() {
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
