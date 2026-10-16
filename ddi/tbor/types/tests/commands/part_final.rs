// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for the TBOR `PartFinal` command.
//!
//! `PartFinal` completes partition provisioning: it validates the supplied
//! `PartPolicy` and the POTA-anchored PTA certificate chain, advances the
//! partition from `Initializing` to `Initialized`, and returns the
//! `PartLocalMK` backup envelope. Coverage spans the happy path, prior-backup
//! acceptance, partition I/O once initialized, and the exact rejection status
//! for a tampered backup, a backup from a different machine seed, a policy or
//! PTA mismatch, the wrong lifecycle state, a Crypto-User attempt, and a
//! second finalize.
//!
//! Backend is selected at compile time by
//! [`azihsm_ddi::AzihsmDdi::default`]. **Both backends now carry the PTA
//! chain out of band and the firmware consumes it on either**, so the
//! tests below send real POTA-to-PTA chains on hardware as well as under
//! the emulator. Only the two rejects that fire before the chain walk —
//! wrong lifecycle state and policy mismatch — pass an empty `certs`
//! slice.
//!
//! The two chain-integrity rejects that used to live here behind
//! `#[cfg(feature = "emu")]` now live in [`chain_path`], un-gated. Those
//! versions assert the specific `TborStatus` rather than calling bare
//! `expect_err`, which would also have accepted a transport failure.
//!
//! The prior-backup acceptance case is intentionally a smoke test. M1.0 has no
//! public command that consumes a Local-scope masked artifact, so accepting the
//! backup cannot by itself prove that the original `PartLocalMK` plaintext was
//! restored. That stronger continuity test must be added when such an API is
//! available.

// `chain_path` holds the two chain-integrity rejects — the only cases
// that need a *well-formed but wrong* chain to reach
// `validate_pta_chain`. `fw_rejects` holds the gates that fire before
// the chain is ever dereferenced. Both run on hardware, and neither
// duplicates a test in this file.
mod chain_path;
mod fw_rejects;

use std::sync::Barrier;

use azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_cu;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain_csr_subject;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::PotaFixture;
use azihsm_ddi_tbor_test_harness::x509_fixture::PtaChain;
use azihsm_ddi_tbor_test_harness::x509_fixture::SEC1_PUB_LEN;
use azihsm_ddi_tbor_test_harness::SessionHandshake;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::ROTATED_CU_PSK;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborPartInfoResp;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;

use crate::commands::part_info::PART_STATE_INITIALIZING;
use crate::commands::part_init::known_good_part_policy;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::open_co_with;
use crate::commands::part_init::part_policy_with_pota;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::part_init::sata_thumbprint;

const PART_STATE_INITIALIZED: u8 = 5;

/// Slot 2 serves a fresh PTA-signed PID certificate, generated on demand,
/// only after the partition is finalized with a PTA chain that preserves
/// the deterministic CSR subject. Each read regenerates the leaf (so its
/// DER / thumbprint change) but the single-cert chain still validates to
/// the PTA/POTA anchors every time.
#[test]
fn slot2_pid_cert_after_finalization() {
    use azihsm_ddi_tbor_types::TborGetCertChainInfoReq;
    use azihsm_ddi_tbor_types::TborGetCertReq;
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    let ctx = TestCtx::new();
    // Slot 2 is empty until the partition is finalized.
    ctx.expect_fw_reject(&TborGetCertChainInfoReq::new(2), TborStatus::InvalidArg);

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");
    let chain = make_pta_chain_csr_subject(&pota, &init.pta_csr);

    // Still empty before finalization completes.
    ctx.expect_fw_reject(&TborGetCertChainInfoReq::new(2), TborStatus::InvalidArg);
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    let info = ctx
        .tbor(&TborGetCertChainInfoReq::new(2))
        .expect("slot 2 metadata");
    assert_eq!(info.num_certs, 1);

    let first = ctx
        .tbor(&TborGetCertReq::new(2, 0))
        .expect("slot 2 index 0");
    let second = ctx
        .tbor(&TborGetCertReq::new(2, 0))
        .expect("regenerated PID");
    assert_ne!(
        first.certificate, second.certificate,
        "each slot-2 read must regenerate a fresh PID leaf",
    );

    let fresh_info = ctx
        .tbor(&TborGetCertChainInfoReq::new(2))
        .expect("fresh thumbprint");
    assert_eq!(fresh_info.num_certs, 1);
    assert_ne!(
        info.thumbprint, fresh_info.thumbprint,
        "a regenerated leaf changes the reported thumbprint",
    );

    // Only cert index 0 exists at slot 2, and slot 1 is still unused.
    ctx.expect_fw_reject(&TborGetCertReq::new(2, 1), TborStatus::InvalidArg);
    ctx.expect_fw_reject(&TborGetCertChainInfoReq::new(1), TborStatus::InvalidArg);

    // The PTA/POTA issuers, leaf-last → root-first for the host validator.
    let issuers: Vec<_> = chain
        .der_items()
        .iter()
        .rev()
        .map(|der| X509Certificate::from_der(der).expect("PTA DER"))
        .collect();
    for _ in 0..16 {
        let fresh = ctx.tbor(&TborGetCertReq::new(2, 0)).expect("fresh PID");
        let leaf = X509Certificate::from_der(&fresh.certificate).expect("PID DER");
        assert!(
            leaf.validate_chain(&issuers).expect("POTA/PTA/PID chain"),
            "every regenerated PID leaf must chain to the PTA/POTA anchors",
        );
    }
}

/// The on-demand slot-2 PID leaf derives its serial from the SHA-1 subject
/// key identifier of the PID public key, masked to a positive DER INTEGER
/// (`serial[0] = (serial[0] & 0x3f) | 0x40`). A real SHA-1 digest is never
/// zero, so the serial must carry entropy beyond the masked leading byte.
/// This guards against a degenerate all-zero serial.
#[test]
fn slot2_pid_cert_serial_is_not_all_zeros() {
    use azihsm_ddi_tbor_types::TborGetCertReq;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");
    let chain = make_pta_chain_csr_subject(&pota, &init.pta_csr);
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    let resp = ctx
        .tbor(&TborGetCertReq::new(2, 0))
        .expect("slot 2 PID cert");
    let serial = cert_serial_number(&resp.certificate);

    assert_eq!(
        serial.len(),
        20,
        "PID serial must be the 20-byte masked SHA-1 SKI",
    );
    assert_eq!(
        serial[0] & 0xc0,
        0x40,
        "leading byte must be masked to a positive DER INTEGER (bit 7 clear, bit 6 set)",
    );
    assert!(
        serial.iter().any(|&b| b != 0),
        "serial must not be all zeros",
    );
    assert!(
        serial[1..].iter().any(|&b| b != 0),
        "serial must carry SKI entropy beyond the masked leading byte",
    );
}

/// The on-demand slot-2 PID leaf is an end-entity certificate, so its
/// `BasicConstraints` extension must omit `pathLenConstraint` entirely:
/// RFC 5280 §4.2.1.9 forbids `pathLenConstraint` unless `cA` is asserted,
/// and strict validators reject a `pathLenConstraint` paired with the
/// default `cA=false`. The leaf template therefore encodes `BasicConstraints`
/// as an empty `SEQUENCE` (`30 00`). This regression test parses the
/// generated DER and asserts that empty encoding so a future template edit
/// cannot silently reintroduce the invalid `cA=false` + `pathLenConstraint`
/// combination.
#[test]
fn slot2_pid_cert_basic_constraints_has_no_path_len() {
    use azihsm_ddi_tbor_types::TborGetCertReq;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");
    let chain = make_pta_chain_csr_subject(&pota, &init.pta_csr);
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    let resp = ctx
        .tbor(&TborGetCertReq::new(2, 0))
        .expect("slot 2 PID cert");
    let basic_constraints = cert_basic_constraints(&resp.certificate);

    assert_eq!(
        basic_constraints,
        [0x30, 0x00],
        "BasicConstraints must be an empty SEQUENCE (cA=false by default, no pathLenConstraint)",
    );
}

/// Read one DER length field starting at `*i`, advancing `*i` past it.
fn der_read_len(der: &[u8], i: &mut usize) -> usize {
    let b = der[*i];
    *i += 1;
    if b & 0x80 == 0 {
        b as usize
    } else {
        let n = (b & 0x7f) as usize;
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | der[*i] as usize;
            *i += 1;
        }
        len
    }
}

/// Extract the raw `serialNumber` INTEGER value bytes from a DER-encoded
/// X.509 certificate: `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE {
/// [0] version, serialNumber INTEGER, ... } }`.
fn cert_serial_number(der: &[u8]) -> Vec<u8> {
    let mut i = 0usize;
    assert_eq!(der[i], 0x30, "Certificate must be a SEQUENCE");
    i += 1;
    der_read_len(der, &mut i);
    assert_eq!(der[i], 0x30, "tbsCertificate must be a SEQUENCE");
    i += 1;
    der_read_len(der, &mut i);
    // Optional EXPLICIT [0] version precedes the serial.
    if der[i] == 0xa0 {
        i += 1;
        let vlen = der_read_len(der, &mut i);
        i += vlen;
    }
    assert_eq!(der[i], 0x02, "serialNumber must be an INTEGER");
    i += 1;
    let slen = der_read_len(der, &mut i);
    der[i..i + slen].to_vec()
}

/// Extract the inner `BasicConstraints ::= SEQUENCE` value from the
/// `extnValue` OCTET STRING of a DER-encoded certificate. Locates the
/// extension by its OID (`2.5.29.19`, DER `06 03 55 1D 13`), skips the
/// optional `critical` BOOLEAN, and returns the OCTET STRING contents.
fn cert_basic_constraints(der: &[u8]) -> Vec<u8> {
    // OID 2.5.29.19 (id-ce-basicConstraints): tag 06, len 03, 55 1D 13.
    const BC_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x13];
    let pos = der
        .windows(BC_OID.len())
        .position(|w| w == BC_OID)
        .expect("BasicConstraints OID must be present");
    let mut i = pos + BC_OID.len();
    // Optional `critical` BOOLEAN precedes the extnValue.
    if der[i] == 0x01 {
        i += 1;
        let blen = der_read_len(der, &mut i);
        i += blen;
    }
    assert_eq!(der[i], 0x04, "extnValue must be an OCTET STRING");
    i += 1;
    let olen = der_read_len(der, &mut i);
    der[i..i + olen].to_vec()
}

/// Run `PartInit` on `session` and issue the resulting PTA chain: read
/// the PTA public key from the returned CSR and certify it under `pota`
/// (a POTA root → PTA-intermediate chain).
fn issue_pta_chain(
    ctx: &TestCtx,
    session: &SessionHandshake,
    pota: &CaKey,
    seed: &[u8],
    policy: &[u8],
    thumb: &[u8],
) -> PtaChain {
    let init = ctx
        .part_init(session, seed, policy, thumb)
        .expect("PartInit roundtrip");
    make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr))
}

/// Build the `PartPolicy` bound to `fixture`'s POTA public key.
fn pota_policy(fixture: &PotaFixture) -> [u8; PART_POLICY_LEN] {
    part_policy_with_pota(&fixture.raw_pub())
}

/// Read the current `PartInfo` view of the bound partition.
fn read_part_info(ctx: &TestCtx) -> TborPartInfoResp {
    ctx.tbor(&TborPartInfoReq::new())
        .expect("PartInfo roundtrip")
}

/// Assert the reported partition lifecycle state. `context` identifies the
/// call site in the failure message.
fn assert_part_state(info: &TborPartInfoResp, expected: u8, context: &str) {
    assert_eq!(
        info.part_state, expected,
        "{context}: unexpected partition lifecycle state",
    );
}

/// Assert the partition identity fields — PID, PID public key, and the owner
/// and manufacturer SVNs — are unchanged across an operation.
fn assert_identity_stable(before: &TborPartInfoResp, after: &TborPartInfoResp, context: &str) {
    assert_eq!(after.pid, before.pid, "{context}: PID changed");
    assert_eq!(
        after.pid_pub_key, before.pid_pub_key,
        "{context}: PID public key changed",
    );
    assert_eq!(
        after.owner_svn, before.owner_svn,
        "{context}: owner SVN changed",
    );
    assert_eq!(
        after.mfgr_svn, before.mfgr_svn,
        "{context}: manufacturer SVN changed",
    );
}

/// Assert the owner and manufacturer SVN lineage is unchanged across an
/// operation.
fn assert_svn_lineage_stable(before: &TborPartInfoResp, after: &TborPartInfoResp, context: &str) {
    assert_eq!(
        after.owner_svn, before.owner_svn,
        "{context}: owner SVN lineage changed",
    );
    assert_eq!(
        after.mfgr_svn, before.mfgr_svn,
        "{context}: manufacturer SVN lineage changed",
    );
}

/// Run `PartInit` under `fixture`'s POTA policy and return the PTA public key
/// read back from the returned CSR.
fn run_part_init(
    ctx: &TestCtx,
    session: &SessionHandshake,
    fixture: &PotaFixture,
    seed: &[u8; MACH_SEED_LEN],
) -> [u8; SEC1_PUB_LEN] {
    let policy = pota_policy(fixture);
    let resp = ctx
        .part_init_sd(
            session,
            seed,
            &policy,
            fixture.thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect("PartInit roundtrip");
    pta_pub_from_csr(&resp.pta_csr)
}

/// Run `PartFinal` and return its `local_mk_backup`, asserting the wire-pinned
/// envelope length.
fn finalize(
    ctx: &TestCtx,
    session: &SessionHandshake,
    fixture: &PotaFixture,
    previous_backup: &[u8],
    chain: &PtaChain,
) -> Vec<u8> {
    let policy = pota_policy(fixture);
    let resp = ctx
        .part_final(session, &policy, previous_backup, &chain.der_items())
        .expect("PartFinal roundtrip");
    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "PartFinal backup must have the wire-pinned envelope length",
    );
    resp.local_mk_backup
}

/// Happy path: `PartInit` then a first-instantiation `PartFinal`
/// (no prior backup) with a valid POTA-anchored PTA chain returns a
/// `local_mk_backup` of the pinned length.
#[test]
fn part_final_smoke_roundtrip() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // The partition owner's POTA trust anchor: its public key is bound
    // into the policy so the chain can be validated against it.
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let chain = issue_pta_chain(
        &ctx,
        &session,
        &pota,
        &mach_seed(),
        &policy,
        &pota_thumbprint(),
    );

    let resp = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal roundtrip");

    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "local_mk_backup must be the masked-envelope length",
    );
}

/// Restore path: a `local_mk_backup` minted on one (fresh) device is
/// accepted on a second device that re-initializes with the same machine
/// seed/owner.  The PTA key is derived deterministically from the seed +
/// policy, so the same chain re-validates on the second device.
#[test]
fn part_final_restore_prev_backup() {
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    // First device: mint a backup, then release the device (drops the
    // process-global test lock so a second device can be opened).
    let (backup, chain) = {
        let ctx1 = TestCtx::new();
        let session1 = bootstrap_rotated_co(&ctx1, &ROTATED_CO_PSK);
        let chain = issue_pta_chain(&ctx1, &session1, &pota, &seed, &policy, &thumb);
        let backup = ctx1
            .part_final(&session1, &policy, &[], &chain.der_items())
            .expect("PartFinal roundtrip")
            .local_mk_backup;
        (backup, chain)
    };
    assert_eq!(backup.len(), LOCAL_MK_BACKUP_LEN);

    // Second device, same seed/owner: restore from the prior backup.
    let ctx2 = TestCtx::new();
    let session2 = bootstrap_rotated_co(&ctx2, &ROTATED_CO_PSK);
    ctx2.part_init(&session2, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");
    let resp = ctx2
        .part_final(&session2, &policy, &backup, &chain.der_items())
        .expect("PartFinal must restore PartLocalMK from a valid prior backup");
    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "restored backup must be re-masked to the envelope length",
    );
}

/// A tampered `prev_local_mk_backup` must be rejected: flipping a byte in
/// the tag-bound metadata makes the re-derived `PartLocalBMK` unmask fail
/// the AEAD tag check, so restore must error rather than mint blindly.
#[test]
fn part_final_reject_tampered_backup() {
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    // First device: mint a backup, then release the test lock.
    let (mut backup, chain) = {
        let ctx1 = TestCtx::new();
        let session1 = bootstrap_rotated_co(&ctx1, &ROTATED_CO_PSK);
        let chain = issue_pta_chain(&ctx1, &session1, &pota, &seed, &policy, &thumb);
        let backup = ctx1
            .part_final(&session1, &policy, &[], &chain.der_items())
            .expect("PartFinal roundtrip")
            .local_mk_backup;
        (backup, chain)
    };

    // Corrupt the ciphertext/tag region; AEAD verification must fail.
    let last = backup.len() - 1;
    backup[last] ^= 0x01;

    let ctx2 = TestCtx::new();
    let session2 = bootstrap_rotated_co(&ctx2, &ROTATED_CO_PSK);
    ctx2.part_init(&session2, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");
    ctx2.part_final(&session2, &policy, &backup, &chain.der_items())
        .expect_err("PartFinal with a tampered backup must fail the AEAD tag check");
}

/// `PartFinal` before `PartInit` must be rejected: the partition is not
/// in the `Initializing` lifecycle state.  This gate fires before the
/// cert-chain walk, so no chain is supplied.
#[test]
fn part_final_reject_wrong_state() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();

    ctx.part_final(&session, &policy, &[], &[])
        .expect_err("PartFinal without PartInit must be rejected by the state gate");
}

/// `PartFinal` re-supplying a policy that does not match the one bound at
/// `PartInit` must be rejected (`SHA-384(part_policy) != policy_hash`).
/// This gate fires before the cert-chain walk, so no chain is supplied.
#[test]
fn part_final_reject_policy_mismatch() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());

    ctx.part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");

    // Flip a byte in the `info` tail (still a structurally valid policy,
    // but a different SHA-384 digest).
    let mut wrong = policy;
    let last = wrong.len() - 2;
    wrong[last] ^= 0x01;

    ctx.part_final(&session, &wrong, &[], &[])
        .expect_err("PartFinal with a mismatched policy must be rejected");
}

/// Regression: after `PartFinal` the partition is `Initialized`, and an
/// `Initialized` partition must continue to serve host IO (the dispatch
/// enable gate includes `Initialized`).  Before that fix any
/// post-finalize command — here `PartInfo` — was silently dropped as a
/// "disabled partition".
#[test]
fn part_final_partition_serves_io_when_initialized() {
    use azihsm_ddi_tbor_types::TborPartInfoReq;

    /// `PartState::Initialized` wire discriminant.
    const PART_STATE_INITIALIZED: u8 = 5;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let chain = issue_pta_chain(
        &ctx,
        &session,
        &pota,
        &mach_seed(),
        &policy,
        &pota_thumbprint(),
    );

    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    // The partition is now Initialized; a follow-up command must still be
    // served rather than dropped as a disabled partition.
    let info = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after PartFinal must be served");
    assert_eq!(
        info.part_state, PART_STATE_INITIALIZED,
        "PartInfo must report Initialized after PartFinal",
    );
}

/// A `local_mk_backup` is bound to the machine-seed identity that
/// created it. Replaying the backup after re-initializing with a
/// different machine seed must return
/// [`TborStatus::AesGcmDecryptTagDoesNotMatch`], preserve the new
/// identity in `Initializing`, and still allow a fresh `PartFinal`.
#[test]
fn part_final_rejects_backup_from_different_mach_seed() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let seed_a = mach_seed();

    let first_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let first_pta_pub = run_part_init(&ctx, &first_session, &fixture, &seed_a);
    let chain_a = fixture.chain_for(&first_pta_pub);
    let first_lineage = read_part_info(&ctx);
    let backup = finalize(&ctx, &first_session, &fixture, &[], &chain_a);
    ctx.session_close(first_session.session_id)
        .expect("close first CO session");

    ctx.erase().expect("NSSR before different-seed replay");

    let mut seed_b = seed_a;
    seed_b[0] ^= 0x01;
    let second_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let second_pta_pub = run_part_init(&ctx, &second_session, &fixture, &seed_b);
    assert_ne!(
        second_pta_pub, first_pta_pub,
        "changing the machine seed must change the derived PTA public key",
    );
    let chain_b = fixture.chain_for(&second_pta_pub);
    let before_reject = read_part_info(&ctx);
    assert_svn_lineage_stable(
        &first_lineage,
        &before_reject,
        "different-machine-seed replay",
    );

    let err = ctx
        .part_final(
            &second_session,
            &pota_policy(&fixture),
            &backup,
            &chain_b.der_items(),
        )
        .expect_err("backup from another machine-seed identity must be rejected");
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);

    let after_reject = read_part_info(&ctx);
    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZING,
        "after cross-identity backup rejection",
    );
    assert_identity_stable(
        &before_reject,
        &after_reject,
        "cross-identity backup rejection",
    );

    finalize(&ctx, &second_session, &fixture, &[], &chain_b);
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after fresh finalization for the new identity",
    );
}

/// `PartFinal` is CO-only: a rotated CU session must be rejected with
/// [`TborStatus::InvalidPermissions`] without changing the partition
/// identity or `Initializing` state. A subsequent CO session must be
/// able to retry the same finalization and reach `Initialized`.
#[test]
fn part_final_rejects_cu_and_allows_co_retry() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let co_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &co_session, &fixture, &mach_seed());
    let chain = fixture.chain_for(&pta_pub);
    let before_reject = read_part_info(&ctx);
    ctx.session_close(co_session.session_id)
        .expect("close PartInit CO session");

    let cu_session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let err = ctx
        .part_final(&cu_session, &pota_policy(&fixture), &[], &chain.der_items())
        .expect_err("CU PartFinal must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
    ctx.session_close(cu_session.session_id)
        .expect("close rejected CU session");

    let after_reject = read_part_info(&ctx);
    assert_part_state(&after_reject, PART_STATE_INITIALIZING, "after CU rejection");
    assert_identity_stable(&before_reject, &after_reject, "CU rejection");

    let retry_session = open_co_with(&ctx, &ROTATED_CO_PSK);
    finalize(&ctx, &retry_session, &fixture, &[], &chain);
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after CO retry",
    );
}

/// `PartFinal` is a one-shot lifecycle transition. Calling it after
/// the partition is already `Initialized` must return
/// [`TborStatus::InvalidArg`], preserve the partition identity and
/// state, and leave the partition usable after reopening a CO session.
#[test]
fn part_final_rejects_second_finalize() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &session, &fixture, &mach_seed());
    let chain = fixture.chain_for(&pta_pub);
    finalize(&ctx, &session, &fixture, &[], &chain);
    let before_reject = read_part_info(&ctx);

    let err = ctx
        .part_final(&session, &pota_policy(&fixture), &[], &chain.der_items())
        .expect_err("a second PartFinal must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
    let after_reject = read_part_info(&ctx);
    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZED,
        "after second PartFinal rejection",
    );
    assert_identity_stable(&before_reject, &after_reject, "second PartFinal rejection");

    ctx.session_close(session.session_id)
        .expect("close finalized CO session");
    let _reopened = open_co_with(&ctx, &ROTATED_CO_PSK);
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after reopening CO following second-finalize rejection",
    );
}

/// Concurrent requests share the same active CO session. The lifecycle
/// transition to `Initialized` is published by `commit_part_final_state`
/// before the response is built, so only one request can commit and every
/// later contender fails the `Initializing` gate in `on_start`.
///
/// It follows the concurrency shape of
/// `open_session::open_session_multi_threaded_all_should_open`, and pins the
/// claim that motivated removing `PartFinalTransaction`: the command holds no
/// cross-request state, so the write-once behaviour comes from the partition's
/// lifecycle byte rather than from any in-FSM flag.
#[test]
fn part_final_multi_threaded_single_winner() {
    const THREAD_COUNT: usize = 16;

    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &session, &fixture, &mach_seed());
    let chain = fixture.chain_for(&pta_pub);
    let policy = pota_policy(&fixture);
    let barrier = Barrier::new(THREAD_COUNT);

    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREAD_COUNT)
            .map(|_| {
                let barrier = &barrier;
                let worker_ctx = &ctx;
                let handshake = &session;
                let policy = &policy;
                let chain = &chain;

                scope.spawn(move || {
                    barrier.wait();
                    worker_ctx.part_final(handshake, policy, &[], &chain.der_items())
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|handle| handle.join().expect("worker thread must not panic"))
            .collect()
    });

    let (winners, rejections): (Vec<_>, Vec<_>) = results.into_iter().partition(Result::is_ok);

    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent PartFinal request must succeed",
    );
    assert_eq!(
        rejections.len(),
        THREAD_COUNT - 1,
        "every non-winning PartFinal request must be rejected",
    );

    // Same status the sequential `part_final_rejects_second_finalize` pins:
    // the losers see a partition that is already `Initialized`.
    for err in rejections.into_iter().map(Result::unwrap_err) {
        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }

    // A losing request must not have torn down the winner's work. Rollback
    // unwinds past PartInit when it runs, so a loser that wrongly reached
    // the staging path would drop the partition to `Enabled` here.
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after the concurrent PartFinal race",
    );
}

/// A previous LocalMK backup shorter than the wire-pinned masked-envelope
/// length must be rejected without advancing the partition out of
/// `Initializing`. A fresh PartFinal must still succeed afterward.
#[test]
fn part_final_rejects_truncated_backup_and_allows_retry() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let seed = mach_seed();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &session, &fixture, &seed);
    let chain = fixture.chain_for(&pta_pub);

    let before_reject = read_part_info(&ctx);

    let truncated = vec![0u8; LOCAL_MK_BACKUP_LEN - 1];

    ctx.part_final(
        &session,
        &pota_policy(&fixture),
        &truncated,
        &chain.der_items(),
    )
    .expect_err("truncated previous LocalMK backup must be rejected");

    let after_reject = read_part_info(&ctx);
    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZING,
        "after truncated-backup rejection",
    );
    assert_identity_stable(&before_reject, &after_reject, "truncated-backup rejection");

    finalize(&ctx, &session, &fixture, &[], &chain);

    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after retry following truncated-backup rejection",
    );
}

/// A previous LocalMK backup longer than the wire-pinned masked-envelope
/// length must be rejected without mutating PartInit state.
#[test]
fn part_final_rejects_oversized_backup_and_allows_retry() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let seed = mach_seed();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &session, &fixture, &seed);
    let chain = fixture.chain_for(&pta_pub);

    let before_reject = read_part_info(&ctx);

    let oversized = vec![0u8; LOCAL_MK_BACKUP_LEN + 1];

    ctx.part_final(
        &session,
        &pota_policy(&fixture),
        &oversized,
        &chain.der_items(),
    )
    .expect_err("oversized previous LocalMK backup must be rejected");

    let after_reject = read_part_info(&ctx);
    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZING,
        "after oversized-backup rejection",
    );
    assert_identity_stable(&before_reject, &after_reject, "oversized-backup rejection");

    finalize(&ctx, &session, &fixture, &[], &chain);

    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after retry following oversized-backup rejection",
    );
}

/// A failed restore must be atomic: rejecting a corrupted previous backup
/// must leave the partition in `Initializing`, preserve its identity, and
/// allow the genuine backup to be retried successfully.
#[test]
fn part_final_tampered_backup_failure_allows_valid_backup_retry() {
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let (backup, chain) = {
        let ctx1 = TestCtx::new();
        let session1 = bootstrap_rotated_co(&ctx1, &ROTATED_CO_PSK);

        let chain = issue_pta_chain(&ctx1, &session1, &pota, &seed, &policy, &thumb);

        let backup = ctx1
            .part_final(&session1, &policy, &[], &chain.der_items())
            .expect("PartFinal roundtrip")
            .local_mk_backup;

        (backup, chain)
    };

    let ctx2 = TestCtx::new();
    let session2 = bootstrap_rotated_co(&ctx2, &ROTATED_CO_PSK);

    ctx2.part_init(&session2, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");

    let before_reject = read_part_info(&ctx2);

    let mut tampered = backup.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    ctx2.part_final(&session2, &policy, &tampered, &chain.der_items())
        .expect_err("tampered backup must be rejected");

    let after_reject = read_part_info(&ctx2);

    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZING,
        "after tampered backup rejection",
    );
    assert_identity_stable(&before_reject, &after_reject, "tampered backup rejection");

    let retry = ctx2
        .part_final(&session2, &policy, &backup, &chain.der_items())
        .expect("valid backup must remain usable after failed restore");

    assert_eq!(retry.local_mk_backup.len(), LOCAL_MK_BACKUP_LEN);

    assert_part_state(
        &read_part_info(&ctx2),
        PART_STATE_INITIALIZED,
        "after valid backup retry",
    );
}

/// Separate fresh PartFinal operations must produce full-sized backup
/// envelopes and must not deterministically reuse the same masked envelope.
#[test]
fn part_final_fresh_devices_produce_distinct_backup_envelopes() {
    let fixture = PotaFixture::generate();
    let seed = mach_seed();

    let backup_a = {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        let pta_pub = run_part_init(&ctx, &session, &fixture, &seed);
        let chain = fixture.chain_for(&pta_pub);

        finalize(&ctx, &session, &fixture, &[], &chain)
    };

    let backup_b = {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        let pta_pub = run_part_init(&ctx, &session, &fixture, &seed);
        let chain = fixture.chain_for(&pta_pub);

        finalize(&ctx, &session, &fixture, &[], &chain)
    };

    assert_eq!(backup_a.len(), LOCAL_MK_BACKUP_LEN);
    assert_eq!(backup_b.len(), LOCAL_MK_BACKUP_LEN);

    assert_ne!(
        backup_a, backup_b,
        "fresh PartFinal operations must not reuse an identical masked backup envelope",
    );
}

/// PartInit state is partition-scoped rather than session-scoped. Closing the
/// CO session that issued PartInit and opening a new CO session must not lose
/// the pending provisioning state; PartFinal must still succeed.
#[test]
fn part_final_succeeds_after_co_session_reopen() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let seed = mach_seed();

    let init_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let pta_pub = run_part_init(&ctx, &init_session, &fixture, &seed);
    let chain = fixture.chain_for(&pta_pub);

    let before_close = read_part_info(&ctx);
    assert_part_state(&before_close, PART_STATE_INITIALIZING, "after PartInit");

    ctx.session_close(init_session.session_id)
        .expect("close PartInit CO session");

    let final_session = open_co_with(&ctx, &ROTATED_CO_PSK);

    let before_final = read_part_info(&ctx);

    assert_part_state(
        &before_final,
        PART_STATE_INITIALIZING,
        "after reopening CO before PartFinal",
    );

    assert_identity_stable(
        &before_close,
        &before_final,
        "CO session reopen before PartFinal",
    );

    finalize(&ctx, &final_session, &fixture, &[], &chain);

    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after PartFinal from reopened CO session",
    );
}

/// Once PartInit has succeeded, PartFinal still requires a usable PTA chain.
/// Supplying no certificates must fail without consuming the lifecycle
/// transition, and a subsequent call with the valid chain must succeed.
#[test]
fn part_final_rejects_empty_chain_and_allows_retry() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let seed = mach_seed();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let pta_pub = run_part_init(&ctx, &session, &fixture, &seed);
    let chain = fixture.chain_for(&pta_pub);

    let before_reject = read_part_info(&ctx);

    ctx.part_final(&session, &pota_policy(&fixture), &[], &[])
        .expect_err("PartFinal without a PTA certificate chain must fail");

    let after_reject = read_part_info(&ctx);

    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZING,
        "after empty-chain rejection",
    );

    assert_identity_stable(&before_reject, &after_reject, "empty-chain rejection");

    finalize(&ctx, &session, &fixture, &[], &chain);

    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after valid-chain retry",
    );
}

/// Rejecting a mismatched PartPolicy must be side-effect free. The partition
/// must remain in `Initializing` with the same identity, and retrying
/// PartFinal with the policy bound by PartInit must succeed.
#[test]
fn part_final_policy_mismatch_preserves_state_and_allows_retry() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let seed = mach_seed();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let policy = pota_policy(&fixture);
    let pta_pub = run_part_init(&ctx, &session, &fixture, &seed);
    let chain = fixture.chain_for(&pta_pub);

    let before_reject = read_part_info(&ctx);

    let mut wrong_policy = policy;
    let last = wrong_policy.len() - 2;
    wrong_policy[last] ^= 0x01;

    ctx.part_final(&session, &wrong_policy, &[], &chain.der_items())
        .expect_err("mismatched PartPolicy must be rejected");

    let after_reject = read_part_info(&ctx);

    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZING,
        "after policy mismatch",
    );

    assert_identity_stable(&before_reject, &after_reject, "policy mismatch rejection");

    finalize(&ctx, &session, &fixture, &[], &chain);

    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after retry with correct policy",
    );
}
