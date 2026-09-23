// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` envelope rejects: malformed or tampered
//! `pok_local_backup` / `sd_mk_backup`.
//!
//! The two backups reach the parser by different routes --
//! `pok_local_backup` opens under the vaulted `PartLocalMK`,
//! `sd_mk_backup` under an SDBMK the command must first derive -- so
//! tamper detection on one says nothing about the other. Both are
//! covered. Every test here runs against a finalized partition so the
//! lifecycle gate cannot mask the result.

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use super::create_sd_on_first_device;
use super::reboot_and_restore_part_local_mk;
use super::CreatedSd;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::bootstrap_rotated_co;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::SessionHandshake;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

/// Bit-flip the last byte of a valid `pok_local_backup`. AEAD-GCM tag
/// verification must fail inside `unmask` before any key material is
/// recovered, and the handler surfaces
/// [`TborStatus::AesGcmDecryptTagDoesNotMatch`].
#[test]
fn sd_restore_local_backup_rejects_tampered_pok() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.pok_local_backup.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: tampered,
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Bit-flip the last byte of a valid `sd_mk_backup`. It opens under an
/// SDBMK derived from the recovered BKS3, so the tag check must fail on
/// that second unmask with
/// [`TborStatus::AesGcmDecryptTagDoesNotMatch`].
#[test]
fn sd_restore_local_backup_rejects_tampered_sd_mk() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.sd_mk_backup.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: tampered,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Backups are bound to the `PartLocalMK` that minted them, not merely to
/// the platform configuration.
///
/// The rebooted device is finalized **without** replaying
/// `local_mk_backup`, which mints a fresh random `PartLocalMK`. Machine
/// seed, policy and trust anchors are identical, so the masking-key
/// identity is the only variable and the unmask must fail with
/// [`TborStatus::AesGcmDecryptTagDoesNotMatch`].
#[test]
fn sd_restore_local_backup_rejects_foreign_part_local_mk() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, &seed, &created.policy, &pota_thumbprint())
        .expect("PartInit (foreign incarnation)");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &created.policy, &[], &chain.der_items())
        .expect("PartFinal must mint a fresh PartLocalMK");

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// An all-zero buffer of the correct width, tried against each envelope
/// in turn.
///
/// A blob of zeroes clears the decoder's fixed-length gate, so it must be
/// refused on its contents. Accepts either status in
/// [`HEADER_FAULT_STATUSES`].
#[test]
fn sd_restore_local_backup_rejects_all_zero_envelopes() {
    let (ctx, session, created) = restore_ready();

    // Zeroed POK: refused before `sd_mk_backup` is ever parsed.
    let err = expect_reject(
        &ctx,
        session.session_id,
        vec![0u8; MASKED_SD_LEN],
        created.sd_mk_backup.clone(),
    );
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);

    // Zeroed SDBMK backup behind a valid POK, which is the only way to
    // reach the second unmask. A rejection does not consume the one-shot
    // claim, so the same device serves both cases.
    let err = expect_reject(
        &ctx,
        session.session_id,
        created.pok_local_backup.clone(),
        vec![0u8; SD_MK_BACKUP_LEN],
    );
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

// ---- envelope wire layout -------------------------------------------
//
// Mirrored rather than imported: the AEAD envelope crate is firmware-side
// and is not a dependency of this host test crate, so these offsets are
// themselves part of the wire contract under test.
// `assert_envelope_layout` re-derives them from a real envelope before
// every tamper, so a format change fails loudly here instead of silently
// corrupting the wrong region. SDK #710 moved the metadata region from 96
// to 192 bytes; that is the drift this guards against.

/// Envelope magic, `FORMAT_TAG` in the firmware envelope crate.
const ENVELOPE_MAGIC: [u8; 4] = *b"AEAD";
/// `AeadAlg::AesGcm256` wire byte.
const AEAD_ALG_AES_GCM_256: u8 = 0x03;
const ALG_OFFSET: usize = 4;
const RESERVED_OFFSET: usize = 5;
const AAD_LEN_OFFSET: usize = 6;
const HEADER_LEN: usize = 8;
const IV_OFFSET: usize = HEADER_LEN;
const IV_LEN: usize = 12;
const AAD_OFFSET: usize = IV_OFFSET + IV_LEN;
/// 192 B masked-key metadata, the AEAD additional-authenticated data.
const AAD_LEN: usize = 192;
const CIPHERTEXT_OFFSET: usize = AAD_OFFSET + AAD_LEN;
const TAG_LEN: usize = 16;

/// Refusals for a fault in the 8-byte header.
///
/// The header is parsed first, so neither backend reaches the AEAD.
/// mcr-hsm raises [`TborStatus::MaskedKeyDecodeFailed`] from its own
/// magic / algorithm / reserved / `aad_len` check. The emulator's
/// `aead_envelope::read_header` returns `Error::InvalidFormat`, and
/// `From<Error> for HsmError` collapses that and five sibling framing
/// faults to [`TborStatus::InvalidArg`]. Both refuse; only the reported
/// reason differs, so the tests accept either.
const HEADER_FAULT_STATUSES: [TborStatus; 2] =
    [TborStatus::MaskedKeyDecodeFailed, TborStatus::InvalidArg];

/// Refusals for a fault in the metadata region.
///
/// The metadata is both a parsed structure and the AEAD's AAD, so which
/// status fires depends on check order: mcr-hsm validates the metadata
/// before opening the AEAD, the emulator opens first. The five commands
/// that specify a malformed masked key (`ecc_sign`, `ecdh_derive`,
/// `hkdf_derive`, `rsa_mod_exp`, `concat_kdf_derive`) list these two
/// together on one row.
const MALFORMED_METADATA_STATUSES: [TborStatus; 2] = [
    TborStatus::MaskedKeyDecodeFailed,
    TborStatus::AesGcmDecryptTagDoesNotMatch,
];

/// Confirm a freshly minted envelope has the layout the tamper helpers
/// assume. Called by every test that edits envelope bytes.
fn assert_envelope_layout(envelope: &[u8]) {
    assert!(
        envelope.len() > CIPHERTEXT_OFFSET + TAG_LEN,
        "envelope shorter than header + iv + aad + tag",
    );
    assert_eq!(&envelope[..ENVELOPE_MAGIC.len()], &ENVELOPE_MAGIC, "magic");
    assert_eq!(envelope[ALG_OFFSET], AEAD_ALG_AES_GCM_256, "aead algorithm");
    assert_eq!(envelope[RESERVED_OFFSET], 0, "reserved byte");
    assert_eq!(
        u16::from_be_bytes([envelope[AAD_LEN_OFFSET], envelope[AAD_LEN_OFFSET + 1]]) as usize,
        AAD_LEN,
        "aad length",
    );
}

/// `envelope` with byte `idx` inverted.
fn flip_byte(envelope: &[u8], idx: usize) -> Vec<u8> {
    let mut out = envelope.to_vec();
    out[idx] ^= 0xFF;
    out
}

/// Assert the firmware refused with one of `expected`.
#[track_caller]
fn assert_rejects_one_of(err: &DdiError, expected: &[TborStatus]) {
    match err {
        DdiError::TborStatus(status) => assert!(
            expected.contains(status),
            "expected one of {expected:?}, got {status:?} (0x{:08X})",
            status.0,
        ),
        other => panic!("expected DdiError::TborStatus, got {other:?}"),
    }
}

/// A second device holding a restored `PartLocalMK`, ready to attempt a
/// security-domain restore, plus the backups captured from the first.
///
/// A rejected restore does not consume the one-shot claim, so one device
/// can serve many requests.
fn restore_ready() -> (TestCtx, SessionHandshake, CreatedSd) {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let created = create_sd_on_first_device(&seed, &sata, &pota);
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);
    (ctx, session, created)
}

/// Issue a restore that must be refused, returning the refusal.
fn expect_reject(ctx: &TestCtx, session_id: u16, pok: Vec<u8>, sd_mk: Vec<u8>) -> DdiError {
    ctx.tbor(&TborSdRestoreLocalBackupReq {
        session_id,
        pok_local_backup: pok,
        sd_mk_backup: sd_mk,
    })
    .expect_err("a malformed restore must be rejected")
}

/// The first gate any envelope parser reaches: a blob of the right width
/// whose magic does not spell `AEAD` is not an envelope at all.
#[test]
fn sd_restore_local_backup_rejects_pok_wrong_magic() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        flip_byte(&created.pok_local_backup, 0),
        created.sd_mk_backup.clone(),
    );
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

/// The `alg` byte selects key, IV and tag widths, so an unknown value
/// leaves the parser unable to locate any other field.
#[test]
fn sd_restore_local_backup_rejects_pok_unsupported_algorithm() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let mut pok = created.pok_local_backup.clone();
    pok[ALG_OFFSET] = 0xFF;

    let err = expect_reject(&ctx, session.session_id, pok, created.sd_mk_backup.clone());
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

/// Reserved must be zero. Accepting a non-zero value would silently
/// consume wire space a future format revision needs.
#[test]
fn sd_restore_local_backup_rejects_pok_nonzero_reserved_byte() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let mut pok = created.pok_local_backup.clone();
    pok[RESERVED_OFFSET] = 1;

    let err = expect_reject(&ctx, session.session_id, pok, created.sd_mk_backup.clone());
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

/// `aad_len` positions the ciphertext, so a wrong value slides every
/// later field. The envelope is a fixed 276 B, so the declared length and
/// the real one must agree.
#[test]
fn sd_restore_local_backup_rejects_pok_wrong_aad_len() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let mut pok = created.pok_local_backup.clone();
    let wrong = (AAD_LEN as u16) + 16;
    pok[AAD_LEN_OFFSET..AAD_LEN_OFFSET + 2].copy_from_slice(&wrong.to_be_bytes());

    let err = expect_reject(&ctx, session.session_id, pok, created.sd_mk_backup.clone());
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

/// The IV is not covered by the tag, but changing it changes the
/// keystream, so the tag no longer verifies. The envelope still parses,
/// so both backends agree on
/// [`TborStatus::AesGcmDecryptTagDoesNotMatch`].
#[test]
fn sd_restore_local_backup_rejects_pok_tampered_iv() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        flip_byte(&created.pok_local_backup, IV_OFFSET),
        created.sd_mk_backup.clone(),
    );
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

/// A flipped ciphertext byte is covered by the tag, so this must fail
/// authentication rather than decrypt to a corrupted BKS3.
#[test]
fn sd_restore_local_backup_rejects_pok_tampered_ciphertext() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        flip_byte(&created.pok_local_backup, CIPHERTEXT_OFFSET),
        created.sd_mk_backup.clone(),
    );
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

/// The metadata is the AEAD's AAD and also carries the key kind, usage
/// flags and `{svn, owner}` bindings the command acts on, so it must be
/// refused whether it is checked as metadata or as AAD. Accepts either
/// status in [`MALFORMED_METADATA_STATUSES`].
#[test]
fn sd_restore_local_backup_rejects_pok_tampered_metadata() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        flip_byte(&created.pok_local_backup, AAD_OFFSET),
        created.sd_mk_backup.clone(),
    );
    assert_rejects_one_of(&err, &MALFORMED_METADATA_STATUSES);
}

/// Sweep every byte of the 8-byte header. All eight are load-bearing, so
/// flipping any one of them must be refused.
#[test]
fn sd_restore_local_backup_rejects_pok_every_header_byte_tampered() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    for idx in 0..HEADER_LEN {
        let err = expect_reject(
            &ctx,
            session.session_id,
            flip_byte(&created.pok_local_backup, idx),
            created.sd_mk_backup.clone(),
        );
        assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
    }
}

/// Sweep every byte of the 16-byte tag. A truncated-tag comparison would
/// accept a flip in the bytes it stopped checking.
#[test]
fn sd_restore_local_backup_rejects_pok_every_tag_byte_tampered() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let tag_offset = created.pok_local_backup.len() - TAG_LEN;
    for idx in tag_offset..created.pok_local_backup.len() {
        let err = expect_reject(
            &ctx,
            session.session_id,
            flip_byte(&created.pok_local_backup, idx),
            created.sd_mk_backup.clone(),
        );
        assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);
    }
}

/// Corrupt the magic of `sd_mk_backup`, which the command parses under a
/// derived SDBMK. Accepts either status in [`HEADER_FAULT_STATUSES`].
#[test]
fn sd_restore_local_backup_rejects_sd_mk_wrong_magic() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.sd_mk_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        created.pok_local_backup.clone(),
        flip_byte(&created.sd_mk_backup, 0),
    );
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

/// Reaching the `sd_mk_backup` ciphertext means BKS3 was recovered and
/// SDBMK derived, so this exercises the second unmask specifically.
#[test]
fn sd_restore_local_backup_rejects_sd_mk_tampered_ciphertext() {
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.sd_mk_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        created.pok_local_backup.clone(),
        flip_byte(&created.sd_mk_backup, CIPHERTEXT_OFFSET),
    );
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

/// The same malformed request must report the same status every time. A
/// status that drifted across attempts would mean the first rejection
/// left state behind.
#[test]
fn sd_restore_local_backup_envelope_rejection_is_repeatable() {
    let (ctx, session, created) = restore_ready();
    let tampered = flip_byte(&created.pok_local_backup, 0);

    let first = expect_reject(
        &ctx,
        session.session_id,
        tampered.clone(),
        created.sd_mk_backup.clone(),
    );
    for _ in 0..2 {
        let again = expect_reject(
            &ctx,
            session.session_id,
            tampered.clone(),
            created.sd_mk_backup.clone(),
        );
        assert_eq!(
            format!("{again:?}"),
            format!("{first:?}"),
            "repeated malformed restores must report the same status",
        );
    }
}
