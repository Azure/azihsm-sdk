// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mach_seed_envelope` AEAD-GCM rejects.
//!
//! Each test rotates the CO PSK out of the default for its own session
//! (so the default-PSK gate doesn't fire first); both reject the
//! envelope BEFORE any partition-state mutation so they leave the
//! partition in `Enabled`.  Cross-test isolation is provided by
//! [`TestCtx::new`].

const ENVELOPE_HEADER_LEN: usize = azihsm_crypto::aead_envelope::HEADER_LEN;
const ENVELOPE_IV_LEN: usize = 12;
const PART_INIT_AAD_LEN: usize = 32;
const ENVELOPE_CIPHERTEXT_LEN: usize = MACH_SEED_LEN;
const ENVELOPE_TAG_LEN: usize = 16;
const ENVELOPE_MAGIC_OFFSET: usize = 0;
const ENVELOPE_MAGIC_LEN: usize = 4;
const ENVELOPE_ALG_OFFSET: usize = 4;
const ENVELOPE_RESERVED_OFFSET: usize = 5;

const MACH_SEED_ENVELOPE_LEN: usize = ENVELOPE_HEADER_LEN
    + ENVELOPE_IV_LEN
    + PART_INIT_AAD_LEN
    + ENVELOPE_CIPHERTEXT_LEN
    + ENVELOPE_TAG_LEN;

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
use azihsm_ddi_tbor_test_harness::build_part_init_mach_seed_aad;
use azihsm_ddi_tbor_test_harness::encrypt_mach_seed_envelope;
use azihsm_ddi_tbor_test_harness::TestCtx;

fn make_part_init_req(session_id: u16, mach_seed_envelope: Vec<u8>) -> TborPartInitReq {
    let mut req = TborPartInitReq {
        session_id,
        mach_seed_envelope,
        ..Default::default()
    };

    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .expect("known-good policy parses");

    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    req
}

/// Bit-flip the ciphertext of a valid `mach_seed_envelope`.  AEAD-GCM
/// tag verification must fail before any plaintext is exposed, and
/// the handler surfaces [`TborStatus::AeadEnvelopeAuthFailed`].
#[test]
fn part_init_envelope_tampered_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let seed = mach_seed();
    let mut envelope =
        encrypt_mach_seed_envelope(&session, &seed).expect("seal mach_seed envelope");
    // Envelope layout matches `psk_change`'s ciphertext-tamper test:
    // HEADER(8) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16).
    assert_eq!(
        envelope.len(),
        MACH_SEED_ENVELOPE_LEN,
        "unexpected mach_seed envelope length"
    );
    let ciphertext_start = ENVELOPE_HEADER_LEN + ENVELOPE_IV_LEN + PART_INIT_AAD_LEN;
    let target = ciphertext_start + ENVELOPE_CIPHERTEXT_LEN / 2;
    envelope[target] ^= 0x01;

    let req = make_part_init_req(session.session_id, envelope);

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

    let req = make_part_init_req(session_b.session_id, envelope);

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

    let req = make_part_init_req(session.session_id, envelope);

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

        let req = make_part_init_req(session.session_id, envelope);

        let err = ctx.tbor(&req).expect_err(&format!(
            "mach_seed length {len} (\u{2260} MACH_SEED_LEN={MACH_SEED_LEN}) must be rejected",
        ));
        azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(&err, TborStatus::TborInvalidFixedLength);
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

    let req = make_part_init_req(session.session_id, envelope);

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Bit-flip the IV while keeping the ciphertext, AAD, and tag unchanged.
///
/// GCM authenticates the IV indirectly through tag generation. Firmware
/// decrypts using the modified IV, so authentication must fail before the
/// `mach_seed` plaintext is accepted.
#[test]
fn part_init_envelope_iv_tampered_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    // Envelope:
    // HEADER(8) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16)
    assert_eq!(
        envelope.len(),
        MACH_SEED_ENVELOPE_LEN,
        "unexpected mach_seed envelope length"
    );
    let iv_index = ENVELOPE_HEADER_LEN;
    envelope[iv_index] ^= 0x01;

    let req = make_part_init_req(session.session_id, envelope);

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
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    // Envelope:
    // HEADER(8) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16)
    assert_eq!(
        envelope.len(),
        MACH_SEED_ENVELOPE_LEN,
        "unexpected mach_seed envelope length"
    );
    let aad_index = ENVELOPE_HEADER_LEN + ENVELOPE_IV_LEN;
    envelope[aad_index] ^= 0x01;

    let req = make_part_init_req(session.session_id, envelope);

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Bit-flip the authentication tag of an otherwise valid envelope.
///
/// This directly covers the tag-verification failure path independently from
/// IV, AAD, and ciphertext corruption.
#[test]
fn part_init_envelope_tag_tampered_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let tag_index = envelope
        .len()
        .checked_sub(1)
        .expect("valid envelope contains an authentication tag");
    envelope[tag_index] ^= 0x80;

    let req = make_part_init_req(session.session_id, envelope);

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Explicitly exercise both sides of the fixed envelope-length boundary.
///
/// Removing or appending one byte must be rejected by TBOR fixed-length
/// validation before AEAD parsing or partition-state mutation.
#[test]
fn part_init_envelope_wrong_fixed_length_emu() {
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

        let req = make_part_init_req(session.session_id, envelope);

        let err = ctx.tbor(&req).expect_err(&format!(
            "mach_seed envelope with invalid length {actual_len} must be rejected"
        ));

        azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(&err, TborStatus::TborInvalidFixedLength);
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

    let req = make_part_init_req(session.session_id, envelope);

    for attempt in 1..=2 {
        let err = ctx.tbor(&req).expect_err(&format!(
            "tampered envelope attempt {attempt} must be rejected"
        ));

        azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);
    }
}

/// Verify that every byte after the eight-byte envelope header is authenticated.
///
/// Envelope layout:
/// HEADER(8) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16)
///
/// The header is intentionally excluded because malformed header fields may
/// follow a separate structural-decoding path and return a status other than
/// `AeadEnvelopeAuthFailed`.
#[test]
fn part_init_every_authenticated_envelope_byte_tampered_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    assert!(
        valid_envelope.len() > ENVELOPE_HEADER_LEN,
        "valid envelope must contain authenticated bytes"
    );

    assert_eq!(
        valid_envelope.len(),
        MACH_SEED_ENVELOPE_LEN,
        "unexpected mach_seed envelope length"
    );

    for index in ENVELOPE_HEADER_LEN..valid_envelope.len() {
        let mut tampered_envelope = valid_envelope.clone();
        tampered_envelope[index] ^= 0x01;

        let req = make_part_init_req(session.session_id, tampered_envelope);

        let err = ctx
            .tbor(&req)
            .expect_err(&format!("tampering envelope byte {index} must be rejected"));

        azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);
    }
}

/// Exercise a broader set of invalid envelope lengths.
///
/// This covers empty, very short, header-only, one-byte-short,
/// one-byte-long, and substantially oversized envelopes.
#[test]
fn part_init_envelope_invalid_length_matrix_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let valid_len = valid_envelope.len();
    assert!(
        valid_len > ENVELOPE_HEADER_LEN,
        "valid envelope length must exceed header length"
    );

    let invalid_lengths = [
        0,
        1,
        ENVELOPE_HEADER_LEN - 1,
        ENVELOPE_HEADER_LEN,
        valid_len / 2,
        valid_len - 1,
        valid_len + 1,
        valid_len + 16,
        azihsm_ddi_tbor_types::MACH_SEED_ENVELOPE_MAX_LEN,
    ];

    for invalid_len in invalid_lengths {
        assert_ne!(
            invalid_len, valid_len,
            "test matrix must not contain the valid envelope length"
        );

        let mut envelope = valid_envelope.clone();
        envelope.resize(invalid_len, 0xA5);

        let req = make_part_init_req(session.session_id, envelope);

        let err = ctx.tbor(&req).expect_err(&format!(
            "mach_seed envelope length {invalid_len} must be rejected"
        ));

        azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(&err, TborStatus::TborInvalidFixedLength);
    }
}

/// Verify that corruption of any individual bit in the authentication tag
/// causes authentication failure.
///
/// The existing tag test checks one selected bit. This test covers all eight
/// bit positions in a tag byte.
#[test]
fn part_init_envelope_each_tag_bit_tampered_emu() {
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

        let req = make_part_init_req(session.session_id, envelope);

        let err = ctx
            .tbor(&req)
            .expect_err(&format!("tampering tag bit {bit} must be rejected"));

        azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);
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
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    assert_eq!(
        valid_envelope.len(),
        MACH_SEED_ENVELOPE_LEN,
        "unexpected mach_seed envelope length"
    );

    let ciphertext_index = ENVELOPE_HEADER_LEN + ENVELOPE_IV_LEN + PART_INIT_AAD_LEN;
    let tag_index = valid_envelope
        .len()
        .checked_sub(1)
        .expect("valid envelope contains a tag");

    let mutations = [
        ("iv", ENVELOPE_HEADER_LEN),
        ("aad", ENVELOPE_HEADER_LEN + ENVELOPE_IV_LEN),
        ("ciphertext", ciphertext_index),
        ("tag", tag_index),
    ];

    for (component, index) in mutations {
        let mut envelope = valid_envelope.clone();
        envelope[index] ^= 0x01;

        let req = make_part_init_req(session.session_id, envelope);

        let err = ctx
            .tbor(&req)
            .expect_err(&format!("tampered {component} must be rejected"));

        azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);
    }
}

/// Verify that rejecting a malformed envelope leaves the partition and
/// session usable for a subsequent valid PartInit request.
///
/// This is stronger than submitting two malformed requests: the second
/// request must complete the normal PartInit path successfully.
#[test]
fn part_init_valid_request_succeeds_after_envelope_rejection_emu() {
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

    let invalid_req = make_part_init_req(session.session_id, tampered_envelope);

    ctx.expect_fw_reject(&invalid_req, TborStatus::AeadEnvelopeAuthFailed);

    // The same session and partition must still accept the corresponding
    // valid request.
    let valid_req = make_part_init_req(session.session_id, valid_envelope);

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

        let invalid_req = make_part_init_req(session.session_id, invalid_envelope);
        ctx.expect_fw_reject(&invalid_req, expected_status);

        let valid_req = make_part_init_req(session.session_id, valid_envelope);
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
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let req = make_part_init_req(session.session_id, envelope);

    ctx.session_close(session.session_id)
        .expect("close session before PartInit");

    ctx.expect_fw_reject(&req, TborStatus::SessionNotFound);
}

/// Submit PartInit using a session id adjacent to the rotated CO session.
///
/// The alternate session resolves through the PartInit session path but is
/// still associated with the default PSK. Firmware must reject the request
/// at the default-PSK gate with [`TborStatus::DefaultPskMustRotate`].
///
/// This test asserts the exact firmware status so an unrelated rejection
/// cannot make the test pass.
#[test]
fn part_init_alternate_session_requires_psk_rotation_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    // `session_id` is a u16. Select a different in-range session id.
    let alternate_session_id = session
        .session_id
        .checked_add(1)
        .expect("test requires session_id to be less than u16::MAX");

    let req = make_part_init_req(alternate_session_id, envelope);

    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}

/// Submit the same valid PartInit request twice.
///
/// The first request initializes the partition successfully. The second
/// request replays the identical authenticated envelope and must be rejected
/// with [`TborStatus::PtaKeyAlreadySet`] because the PTA key was established
/// by the first successful PartInit.
///
/// This verifies that a valid `mach_seed_envelope` cannot be replayed after
/// successful partition initialization.
#[test]
fn part_init_valid_envelope_cannot_be_replayed_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let req = make_part_init_req(session.session_id, envelope);

    ctx.tbor(&req).expect("first PartInit must succeed");

    ctx.expect_fw_reject(&req, TborStatus::PtaKeyAlreadySet);
}

/// Build a `mach_seed_envelope` using session A's parameter key, close
/// session A, open session B, and submit the envelope through session B.
///
/// The envelope uses session B's id in its authenticated AAD, preventing an
/// AAD-versus-request mismatch from causing the rejection. Therefore, an
/// authentication failure demonstrates that session B received fresh
/// cryptographic key material rather than session A's parameter key.
#[test]
fn part_init_stale_envelope_rejected_after_session_reopen_emu() {
    let ctx = TestCtx::new();

    let session_a = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let param_key_a = session_a.param_key.clone();

    ctx.session_close(session_a.session_id)
        .expect("close session A");

    let session_b = super::open_co_with(&ctx, &ROTATED_CO_PSK);

    // Use session B's id in the AAD so the explicit AAD/session-id check
    // cannot be the reason for rejection, but seal with session A's key.
    let aad_for_b = build_part_init_mach_seed_aad(session_b.session_id);
    let stale_envelope = build_envelope(&param_key_a, &aad_for_b, &mach_seed());

    let req = make_part_init_req(session_b.session_id, stale_envelope);

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Authenticate and encrypt an all-zero machine seed of the correct length.
///
/// This test verifies the firmware-defined policy for machine-seed contents
/// independently from envelope length and AEAD authentication. The envelope
/// itself is structurally valid and correctly authenticated.
///
/// Firmware currently treats `mach_seed` as opaque input; an all-zero seed
/// should be accepted as long as the envelope authenticates correctly.
#[test]
fn part_init_all_zero_mach_seed_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let aad = build_part_init_mach_seed_aad(session.session_id);
    let zero_seed = vec![0u8; MACH_SEED_LEN];

    let envelope = build_envelope(&session.param_key, &aad, &zero_seed);

    let req = make_part_init_req(session.session_id, envelope);

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
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let valid_envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    let mut modified_thumbprint = pota_thumbprint();
    modified_thumbprint[0] ^= 0x01;

    let mut req = make_part_init_req(session.session_id, valid_envelope);
    req.pota_thumbprint.copy_from_slice(&modified_thumbprint);

    ctx.tbor(&req)
        .expect("PartInit accepts a caller-supplied POTA thumbprint");
}

/// Reject an envelope whose four-byte format magic does not match
/// [`azihsm_crypto::aead_envelope::FORMAT_TAG`].
#[test]
fn part_init_envelope_wrong_magic_rejected_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    assert_eq!(
        &envelope[ENVELOPE_MAGIC_OFFSET..ENVELOPE_MAGIC_OFFSET + ENVELOPE_MAGIC_LEN],
        azihsm_crypto::aead_envelope::FORMAT_TAG,
        "unexpected envelope format tag"
    );

    envelope[ENVELOPE_MAGIC_OFFSET] ^= 0x01;

    let req = make_part_init_req(session.session_id, envelope);

    ctx.tbor(&req)
        .expect_err("envelope with wrong magic must be rejected");
}

/// Reject an envelope advertising an unsupported format version.
///
/// AEAD envelope v1 does not have a separate version byte. The version is
/// encoded by the four-byte `FORMAT_TAG`, so changing the tag represents an
/// unsupported envelope version.
#[test]
fn part_init_envelope_unsupported_version_rejected_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    assert_eq!(
        &envelope[ENVELOPE_MAGIC_OFFSET..ENVELOPE_MAGIC_OFFSET + ENVELOPE_MAGIC_LEN],
        azihsm_crypto::aead_envelope::FORMAT_TAG,
        "unexpected envelope format tag"
    );

    // Replace the final byte of the v1 format tag with a hypothetical
    // version-2 marker while preserving the four-byte header field.
    envelope[ENVELOPE_MAGIC_OFFSET + ENVELOPE_MAGIC_LEN - 1] = b'2';

    let req = make_part_init_req(session.session_id, envelope);

    ctx.tbor(&req)
        .expect_err("envelope with unsupported format version must be rejected");
}

/// Reject an envelope whose algorithm discriminant is unsupported.
///
/// Version 1 supports only AES-256-GCM (`AeadAlg` discriminant `0x03`).
#[test]
fn part_init_envelope_unsupported_algorithm_rejected_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    assert_eq!(
        envelope[ENVELOPE_ALG_OFFSET], 0x03,
        "unexpected algorithm in valid AES-256-GCM envelope"
    );

    envelope[ENVELOPE_ALG_OFFSET] = 0xFF;

    let req = make_part_init_req(session.session_id, envelope);

    ctx.tbor(&req)
        .expect_err("envelope with unsupported algorithm must be rejected");
}

/// Reject an envelope whose reserved header byte is nonzero.
///
/// The v1 envelope format requires the reserved byte to remain zero.
#[test]
fn part_init_envelope_nonzero_reserved_byte_rejected_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut envelope =
        encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");

    assert_eq!(
        envelope[ENVELOPE_RESERVED_OFFSET], 0,
        "valid v1 envelope must have a zero reserved byte"
    );

    envelope[ENVELOPE_RESERVED_OFFSET] = 0x01;

    let req = make_part_init_req(session.session_id, envelope);

    ctx.tbor(&req)
        .expect_err("envelope with nonzero reserved byte must be rejected");
}
