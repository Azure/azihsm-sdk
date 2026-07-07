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
fn part_init_envelope_tampered_emu() {
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
            .ok()
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
fn part_init_envelope_from_other_session_emu() {
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
            .ok()
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
fn part_init_wrong_aad_length_emu() {
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
            .ok()
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
fn part_init_wrong_mach_seed_length_emu() {
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
                .ok()
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
fn part_init_wrong_session_id_in_aad_emu() {
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
            .ok()
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}
