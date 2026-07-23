// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mach_seed_envelope` AEAD-GCM rejects.
//!
//! Each test rotates the CO PSK out of the default for its own session
//! (so the default-PSK gate doesn't fire first); both reject the
//! envelope BEFORE any partition-state mutation so they leave the
//! partition in `Enabled`.  Cross-test isolation is provided by
//! [`TestCtx::new`].

use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::TborPartInitReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;

use super::bootstrap_rotated_co;
use super::build_envelope;
use super::known_good_part_policy;
use super::mach_seed;
use super::pota_thumbprint;
use super::ROTATED_CO_PSK;
use crate::harness::build_part_init_mach_seed_aad;
use crate::harness::TestCtx;

/// Bit-flip the ciphertext of a valid `mach_seed_envelope`.  AEAD-GCM
/// tag verification must fail before any plaintext is exposed, and
/// the handler surfaces [`TborStatus::AeadEnvelopeAuthFailed`].
#[test]
fn part_init_envelope_tampered() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let seed = mach_seed();
    let mut envelope =
        encrypt_mach_seed_envelope(&session, &seed).expect("seal mach_seed envelope");
    // Envelope layout matches `psk_change`'s ciphertext-tamper test:
    // HEADER(4) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16).  Flip a byte in
    // the middle so AEAD tag verification fails.
    let target = envelope.len() / 2;
    envelope[target] ^= 0x01;

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Encrypt a `mach_seed` envelope under session A's `param_key` and
/// ship it through session B (with B's session id in the request).
/// FW uses B's `param_key` for AEAD-GCM verification, so the tag
/// mismatches and the handler surfaces
/// [`TborStatus::AeadEnvelopeAuthFailed`]. Mirrors the equivalent
/// `psk_change_envelope_from_other_session_emu` test.
#[test]
fn part_init_envelope_from_other_session() {
    let ctx = TestCtx::new();

    // Session A: rotated CO (clears default-PSK gate). Close it
    // immediately — the host still owns a copy of A's `param_key`
    // in the returned handshake, which is the only thing the test
    // needs. Closing also frees A's slot so opening session B
    // doesn't trip `VaultSessionLimitReached` (the FW caps
    // concurrent CO + Authenticated sessions tighter than CU
    // PlainText, so the equivalent two-CU pattern used by
    // `psk_change_envelope_from_other_session_emu` can't be reused
    // here verbatim).
    let session_a = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let param_key_a = session_a.param_key.clone();
    ctx.session_close(session_a.session_id)
        .expect("close session A before opening B");

    // Session B: a fresh rotated-CO session. FW assigns its own
    // `param_key`, distinct from A's snapshot.
    let session_b = super::open_co_with(&ctx, &ROTATED_CO_PSK);

    // AAD encodes session B's id (so the AAD-vs-request constant-time
    // compare path doesn't fire first), but seal under A's param_key.
    let aad_for_b = build_part_init_mach_seed_aad(session_b.session_id);
    let envelope = build_envelope(&param_key_a, &aad_for_b, &mach_seed());

    let mut req = TborPartInitReq {
        session_id: session_b.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// AAD bytes of arbitrary but valid AEAD granularity (64 bytes —
/// double the canonical [`PART_INIT_MACH_SEED_AAD_LEN`] of 32).  A
/// 64-byte AAD inflates the envelope past the fixed
/// [`MACH_SEED_ENVELOPE_LEN`] (100 B), so the FW schema's fixed-length
/// check rejects it at decode with
/// [`TborStatus::TborInvalidFixedLength`] before any AEAD work.
#[test]
fn part_init_wrong_aad_length() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let long_aad = vec![0u8; 64];
    let envelope = build_envelope(&session.param_key, &long_aad, &mach_seed());

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);
}

/// `mach_seed` plaintext length ≠ [`MACH_SEED_LEN`] (32) yields a wrong
/// *envelope* length (ciphertext tracks plaintext for GCM), so the FW
/// schema's fixed [`MACH_SEED_ENVELOPE_LEN`] (100 B) rejects both at
/// decode with [`TborStatus::TborInvalidFixedLength`]. Loop over
/// `MACH_SEED_LEN ± 1` to cover the shortest excursions on either side
/// of the canonical length. Mirrors
/// `psk_change_wrong_plaintext_length_emu`.
#[test]
fn part_init_wrong_mach_seed_length() {
    let ctx = TestCtx::new();
    // Hoist bootstrap out of the loop: PartInit's length check rejects
    // before any partition-state mutation, so the same rotated-CO
    // session can drive both iterations.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let aad = build_part_init_mach_seed_aad(session.session_id);

    for len in [MACH_SEED_LEN - 1, MACH_SEED_LEN + 1] {
        let bogus_seed = vec![0xCDu8; len];
        let envelope = build_envelope(&session.param_key, &aad, &bogus_seed);

        let mut req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope: envelope,
            ..Default::default()
        };
        req.part_policy =
            <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
                .expect("known-good policy parses");
        req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

        let err = ctx.tbor(&req).expect_err(&format!(
            "mach_seed length {len} (\u{2260} MACH_SEED_LEN={MACH_SEED_LEN}) must be rejected",
        ));
        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::TborInvalidFixedLength);
    }
}

/// Build a `mach_seed_envelope` whose AAD encodes a different session
/// id than the request carries.  AEAD-GCM tag verifies (the FW
/// recomputes the tag over *these* AAD bytes), but the FW then
/// constant-compares the AAD against
/// `build_part_init_mach_seed_aad(req.session_id)` and rejects with
/// [`TborStatus::AeadEnvelopeAuthFailed`].
#[test]
fn part_init_wrong_session_id_in_aad() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bogus_aad = build_part_init_mach_seed_aad(session.session_id ^ 0x1234);
    let envelope = build_envelope(&session.param_key, &bogus_aad, &mach_seed());

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Bit-flip the IV while keeping the ciphertext, AAD, and tag unchanged.
///
/// GCM authenticates the IV indirectly through tag generation. Firmware
/// decrypts using the modified IV, so authentication must fail before the
/// `mach_seed` plaintext is accepted.
#[test]
fn part_init_envelope_iv_tampered_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    // Envelope:
    // HEADER(4) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16)
    const HEADER_LEN: usize = 4;
    let iv_index = HEADER_LEN;
    envelope[iv_index] ^= 0x01;

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Bit-flip the authenticated AAD while leaving the request's session id
/// unchanged.
///
/// The stored GCM tag was calculated over the original AAD, so authentication
/// must fail before firmware reaches the explicit AAD-versus-request-session
/// comparison.
#[test]
fn part_init_envelope_aad_tampered_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    // Envelope:
    // HEADER(4) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16)
    const HEADER_LEN: usize = 4;
    const IV_LEN: usize = 12;
    let aad_index = HEADER_LEN + IV_LEN;
    envelope[aad_index] ^= 0x01;

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Bit-flip the authentication tag of an otherwise valid envelope.
///
/// This directly covers the tag-verification failure path independently from
/// IV, AAD, and ciphertext corruption.
#[test]
fn part_init_envelope_tag_tampered_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let tag_index = envelope
        .len()
        .checked_sub(1)
        .expect("valid envelope contains an authentication tag");
    envelope[tag_index] ^= 0x80;

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Explicitly exercise both sides of the fixed envelope-length boundary.
///
/// Removing or appending one byte must be rejected by TBOR fixed-length
/// validation before AEAD parsing or partition-state mutation.
#[test]
fn part_init_envelope_wrong_fixed_length_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    for delta in [-1isize, 1isize] {
        let mut envelope = valid_envelope.clone();

        match delta {
            -1 => {
                envelope.pop().expect("valid envelope is nonempty");
            }
            1 => {
                envelope.push(0x00);
            }
            _ => unreachable!("test only exercises one-byte length changes"),
        }

        let actual_len = envelope.len();

        let mut req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope: envelope,
            ..Default::default()
        };
        req.part_policy =
            <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
                .ok()
                .expect("known-good policy parses");
        req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

        let err = ctx.tbor(&req).expect_err(&format!(
            "mach_seed envelope with invalid length {actual_len} must be rejected"
        ));

        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::TborInvalidFixedLength);
    }
}

/// Verify that an AEAD failure does not consume the session or mutate the
/// partition.
///
/// The same malformed request is submitted twice. Both attempts must reach
/// the same AEAD rejection rather than failing later because the first request
/// partially initialized or disabled the partition.
#[test]
fn part_init_envelope_rejection_is_repeatable_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    // Corrupt the final tag byte.
    let last = envelope
        .len()
        .checked_sub(1)
        .expect("valid envelope is nonempty");
    envelope[last] ^= 0x01;

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    for attempt in 1..=2 {
        let err = ctx.tbor(&req).expect_err(&format!(
            "tampered envelope attempt {attempt} must be rejected"
        ));

        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);
    }
}

/// Verify that every byte after the envelope header is authenticated.
///
/// Envelope layout:
/// HEADER(4) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16)
///
/// The header is intentionally excluded because malformed header fields may
/// follow a separate structural-decoding path and return a status other than
/// `AeadEnvelopeAuthFailed`.
#[test]
fn part_init_every_authenticated_envelope_byte_tampered_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    const HEADER_LEN: usize = 4;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    assert!(
        valid_envelope.len() > HEADER_LEN,
        "valid envelope must contain authenticated bytes"
    );

    for index in HEADER_LEN..valid_envelope.len() {
        let mut tampered_envelope = valid_envelope.clone();
        tampered_envelope[index] ^= 0x01;

        let mut req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope: tampered_envelope,
            ..Default::default()
        };
        req.part_policy =
            <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
                .ok()
                .expect("known-good policy parses");
        req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

        let err = ctx
            .tbor(&req)
            .expect_err(&format!("tampering envelope byte {index} must be rejected"));

        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);
    }
}

/// Exercise a broader set of invalid envelope lengths.
///
/// This covers empty, very short, header-only, one-byte-short,
/// one-byte-long, and substantially oversized envelopes.
#[test]
fn part_init_envelope_invalid_length_matrix_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let valid_len = valid_envelope.len();
    assert!(
        valid_len > 4,
        "valid envelope length must exceed header length"
    );

    let invalid_lengths = [
        0,
        1,
        3,
        4,
        valid_len / 2,
        valid_len - 1,
        valid_len + 1,
        valid_len + 16,
        valid_len * 2,
    ];

    for invalid_len in invalid_lengths {
        assert_ne!(
            invalid_len, valid_len,
            "test matrix must not contain the valid envelope length"
        );

        let mut envelope = valid_envelope.clone();
        envelope.resize(invalid_len, 0xA5);

        let mut req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope: envelope,
            ..Default::default()
        };
        req.part_policy =
            <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
                .ok()
                .expect("known-good policy parses");
        req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

        let err = ctx.tbor(&req).expect_err(&format!(
            "mach_seed envelope length {invalid_len} must be rejected"
        ));

        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::TborInvalidFixedLength);
    }
}

/// Verify that corruption of any individual bit in the authentication tag
/// causes authentication failure.
///
/// The existing tag test checks one selected bit. This test covers all eight
/// bit positions in a tag byte.
#[test]
fn part_init_envelope_each_tag_bit_tampered_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let tag_byte_index = valid_envelope
        .len()
        .checked_sub(1)
        .expect("valid envelope must contain a tag");

    for bit in 0..8 {
        let mut envelope = valid_envelope.clone();
        envelope[tag_byte_index] ^= 1u8 << bit;

        let mut req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope: envelope,
            ..Default::default()
        };
        req.part_policy =
            <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
                .ok()
                .expect("known-good policy parses");
        req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

        let err = ctx
            .tbor(&req)
            .expect_err(&format!("tampering tag bit {bit} must be rejected"));

        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);
    }
}

/// Verify that AEAD rejection remains stable when different malformed
/// envelopes are sent consecutively through the same session.
///
/// This is slightly broader than submitting the exact same request twice:
/// each rejection must leave both the partition and session usable for the
/// next independently malformed request.
#[test]
fn part_init_multiple_distinct_envelope_rejections_are_isolated_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    const HEADER_LEN: usize = 4;
    const IV_LEN: usize = 12;
    const AAD_LEN: usize = 32;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let ciphertext_index = HEADER_LEN + IV_LEN + AAD_LEN;
    let tag_index = valid_envelope
        .len()
        .checked_sub(1)
        .expect("valid envelope contains a tag");

    let mutations = [
        ("iv", HEADER_LEN),
        ("aad", HEADER_LEN + IV_LEN),
        ("ciphertext", ciphertext_index),
        ("tag", tag_index),
    ];

    for (component, index) in mutations {
        let mut envelope = valid_envelope.clone();
        envelope[index] ^= 0x01;

        let mut req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope: envelope,
            ..Default::default()
        };
        req.part_policy =
            <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
                .ok()
                .expect("known-good policy parses");
        req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

        let err = ctx
            .tbor(&req)
            .expect_err(&format!("tampered {component} must be rejected"));

        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);
    }
}

/// Verify that rejecting a malformed envelope leaves the partition and
/// session usable for a subsequent valid PartInit request.
///
/// This is stronger than submitting two malformed requests: the second
/// request must complete the normal PartInit path successfully.
#[test]
fn part_init_valid_request_succeeds_after_envelope_rejection_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let seed = mach_seed();

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &seed).expect("seal mach_seed envelope");

    // First submit a corrupted copy.
    let mut tampered_envelope = valid_envelope.clone();
    let tag_index = tampered_envelope
        .len()
        .checked_sub(1)
        .expect("valid envelope contains a tag");
    tampered_envelope[tag_index] ^= 0x01;

    let mut invalid_req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: tampered_envelope,
        ..Default::default()
    };
    invalid_req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    invalid_req
        .pota_thumbprint
        .copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&invalid_req, TborStatus::AeadEnvelopeAuthFailed);

    // The same session and partition must still accept the corresponding
    // valid request.
    let mut valid_req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: valid_envelope,
        ..Default::default()
    };
    valid_req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    valid_req
        .pota_thumbprint
        .copy_from_slice(&pota_thumbprint());

    ctx.tbor(&valid_req)
        .expect("valid PartInit must succeed after rejected envelope");
}

/// Verify that representative failures from both validation stages leave
/// PartInit recoverable:
///
/// 1. TBOR fixed-length rejection.
/// 2. AEAD authentication rejection.
///
/// Each case uses its own TestCtx because the final valid request initializes
/// the partition.
#[test]
fn part_init_recovers_after_each_envelope_rejection_stage_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    enum RejectionCase {
        InvalidFixedLength,
        InvalidAuthentication,
    }

    for case in [
        RejectionCase::InvalidFixedLength,
        RejectionCase::InvalidAuthentication,
    ] {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        let valid_envelope =
            encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

        let mut invalid_envelope = valid_envelope.clone();

        let expected_status = match case {
            RejectionCase::InvalidFixedLength => {
                invalid_envelope
                    .pop()
                    .expect("valid envelope must be nonempty");
                TborStatus::TborInvalidFixedLength
            }
            RejectionCase::InvalidAuthentication => {
                let last = invalid_envelope
                    .len()
                    .checked_sub(1)
                    .expect("valid envelope contains a tag");
                invalid_envelope[last] ^= 0x01;
                TborStatus::AeadEnvelopeAuthFailed
            }
        };

        let make_req = |envelope| {
            let mut req = TborPartInitReq {
                session_id: session.session_id,
                mach_seed_envelope: envelope,
                ..Default::default()
            };
            req.part_policy = <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(
                &known_good_part_policy(),
            )
            .ok()
            .expect("known-good policy parses");
            req.pota_thumbprint.copy_from_slice(&pota_thumbprint());
            req
        };

        let invalid_req = make_req(invalid_envelope);
        ctx.expect_fw_reject(&invalid_req, expected_status);

        let valid_req = make_req(valid_envelope);
        ctx.tbor(&valid_req)
            .expect("valid PartInit must succeed after rejected request");
    }
}

/// Close the authenticated CO session after constructing a valid
/// `mach_seed_envelope`, then submit the original PartInit request.
///
/// The envelope was valid when it was created, but its session no longer
/// exists. Firmware must reject the request rather than accepting an
/// envelope associated with a closed session.
#[test]
fn part_init_envelope_rejected_after_session_closed_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.session_close(session.session_id)
        .expect("close session before PartInit");

    // Replace with the exact status used by your FW for a closed or
    // nonexistent session.
    ctx.expect_fw_reject(&req, TborStatus::SessionNotFound);
}

/// Submit a valid envelope using a request session id that does not identify
/// the active session.
///
/// Firmware must reject the request. The exact rejection status is determined
/// by the PartInit session-resolution path.
#[test]
fn part_init_unknown_request_session_id_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let unknown_session_id = session.session_id.wrapping_add(1);
    assert_ne!(
        unknown_session_id, session.session_id,
        "unknown session id must differ from the active session"
    );

    let mut req = TborPartInitReq {
        session_id: unknown_session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    let err = ctx
        .tbor(&req)
        .expect_err("unknown request session id must be rejected");

    eprintln!("unknown session rejection: {err:#?}");
}

/// Submit the same valid PartInit request twice.
///
/// The first request initializes the partition successfully. The second
/// request replays the identical authenticated envelope and must be rejected
/// because an initialized partition cannot be initialized again.
///
/// This verifies that a valid `mach_seed_envelope` is not replayable after
/// successful PartInit.
#[test]
fn part_init_valid_envelope_cannot_be_replayed_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.tbor(&req).expect("first PartInit must succeed");

    let err = ctx
        .tbor(&req)
        .expect_err("replaying successful PartInit must be rejected");

    eprintln!("PartInit replay error: {err:#?}");
}

/// Build a valid `mach_seed_envelope` for session A, close session A, open
/// session B, and submit A's stale envelope through session B.
///
/// Even if firmware reuses an internal session slot or session identifier,
/// session B must receive fresh cryptographic state. The stale envelope must
/// therefore fail authentication under B's `param_key`.
#[test]
fn part_init_stale_envelope_rejected_after_session_reopen_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();

    let session_a = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let stale_envelope =
        encrypt_mach_seed_envelope(&session_a, &mach_seed()).expect("seal envelope for session A");

    ctx.session_close(session_a.session_id)
        .expect("close session A");

    let session_b = super::open_co_with(&ctx, &ROTATED_CO_PSK);

    let mut req = TborPartInitReq {
        session_id: session_b.session_id,
        mach_seed_envelope: stale_envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Authenticate and encrypt an all-zero machine seed of the correct length.
///
/// This test verifies the firmware-defined policy for machine-seed contents
/// independently from envelope length and AEAD authentication. The envelope
/// itself is structurally valid and correctly authenticated.
///
/// Only expect rejection if firmware explicitly forbids an all-zero
/// `mach_seed`; otherwise the seed is treated as opaque input and may be
/// accepted.
#[test]
fn part_init_all_zero_mach_seed_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let aad = build_part_init_mach_seed_aad(session.session_id);
    let zero_seed = vec![0u8; MACH_SEED_LEN];

    let envelope = build_envelope(&session.param_key, &aad, &zero_seed);

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.tbor(&req)
        .expect("correctly authenticated all-zero mach_seed is accepted");
}

/// Verify that PartInit accepts a caller-supplied POTA thumbprint.
///
/// The thumbprint is input used during partition initialization rather than
/// a value validated against an existing firmware-side thumbprint. Changing
/// its contents therefore must not cause PartInit to reject an otherwise
/// valid request.
#[test]
fn part_init_accepts_nondefault_pota_thumbprint_emu() {
    use crate::harness::encrypt_mach_seed_envelope;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let mut modified_thumbprint = pota_thumbprint();
    modified_thumbprint[0] ^= 0x01;

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: valid_envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&modified_thumbprint);

    ctx.tbor(&req)
        .expect("PartInit accepts a caller-supplied POTA thumbprint");
}
