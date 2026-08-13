// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `PartInit` rejects that fire **before** any partition-state
//! mutation: default-PSK dispatcher gate, CU-role handler gate, and
//! malformed-policy decode gate.  Each test asserts the canonical
//! [`TborStatus`] surfaced by the FW and relies on
//! [`super::bootstrap_rotated_co`] (where needed) to clear the
//! default-PSK arm before reaching the path under test.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;

use super::bootstrap_rotated_co;
use super::known_good_part_policy;
use super::mach_seed;
use super::pota_thumbprint;
use super::CO;
use super::CU;
use super::ROTATED_CO_PSK;
use super::ROTATED_CU_PSK;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::session_guard::SessionGuard;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;

// Replace these with the canonical offsets/constants from the PartPolicy
// encoder or firmware policy structure.
const POLICY_PUB_KEY_KIND_OFFSET: usize = 2;
const POLICY_PUB_KEY_LEN_OFFSET: usize = 4;

const PART_POLICY_FLAGS_OFFSET: usize = 418;

const RESERVED_POLICY_FLAG_BITS: [u8; 5] = [1 << 3, 1 << 4, 1 << 5, 1 << 6, 1 << 7];

const BACKUP_PART_PUB_KEY_KIND_OFFSET: usize = 318;
const BACKUP_PART_PUB_KEY_LEN_OFFSET: usize = 320;
const BACKUP_PART_PUB_KEY_DATA_OFFSET: usize = 322;

const EXPECTED_BACKUP_PUB_KEY_LEN: u16 = 96;
const ECC384_POLICY_KEY_KIND: u16 = 0;

const SATA_PUB_KEY_KIND_OFFSET: usize = 102;
const SATA_PUB_KEY_LEN_OFFSET: usize = 104;

fn set_u16_le(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn set_backup_part_pub_key_present(policy: &mut [u8; PART_POLICY_LEN]) {
    set_u16_le(
        policy,
        BACKUP_PART_PUB_KEY_KIND_OFFSET,
        ECC384_POLICY_KEY_KIND,
    );
    set_u16_le(
        policy,
        BACKUP_PART_PUB_KEY_LEN_OFFSET,
        EXPECTED_BACKUP_PUB_KEY_LEN,
    );

    // Supply deterministic nonzero P-384-sized key bytes.
    policy[BACKUP_PART_PUB_KEY_DATA_OFFSET
        ..BACKUP_PART_PUB_KEY_DATA_OFFSET + EXPECTED_BACKUP_PUB_KEY_LEN as usize]
        .fill(0xA5);
}

fn set_backup_part_pub_key_kind(policy: &mut [u8; PART_POLICY_LEN], kind: u16) {
    set_u16_le(policy, BACKUP_PART_PUB_KEY_KIND_OFFSET, kind);
}

fn set_backup_part_pub_key_len(policy: &mut [u8; PART_POLICY_LEN], len: u16) {
    set_u16_le(policy, BACKUP_PART_PUB_KEY_LEN_OFFSET, len);
}

fn set_valid_backup_part_pub_key(policy: &mut [u8; PART_POLICY_LEN]) {
    set_backup_part_pub_key_present(policy);
}

/// Opens a session for the supplied role and session type using a custom
/// PSK.
///
/// The completed handshake is wrapped in [`SessionGuard`] so the emulator
/// session is automatically closed when the guard is dropped, including
/// when a test panics.
fn open_role_with<'a>(
    ctx: &'a TestCtx,
    role: u8,
    sty: SessionType,
    psk: &[u8; PSK_LEN],
) -> SessionGuard<'a> {
    let opts = SessionOpenInitOptions::new(role, sty).with_psk(psk);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("session_open_init under custom PSK");
    let handshake = ctx
        .session_open_finish(pending)
        .expect("session_open_finish under custom PSK");
    SessionGuard::new(ctx, handshake)
}

/// Rotates the PSK for the supplied role, closes the bootstrap session,
/// and opens a new guarded session using the rotated credential.
///
/// The returned [`SessionGuard`] automatically closes the new session when
/// dropped, including when the calling test panics.
fn rotate_psk_and_open_role<'a>(
    ctx: &'a TestCtx,
    role: u8,
    sty: SessionType,
    rotated_psk: &[u8; PSK_LEN],
) -> SessionGuard<'a> {
    let bootstrap = ctx.open_session(role, sty).expect("open bootstrap session");

    ctx.psk_change(bootstrap.handshake(), rotated_psk)
        .expect("rotate role PSK");

    bootstrap
        .close()
        .expect("close bootstrap session after PSK rotation");

    open_role_with(ctx, role, sty, rotated_psk)
}

/// Default-PSK CO session: the TBOR dispatcher must reject `PartInit`
/// with [`TborStatus::DefaultPskMustRotate`] **before** the handler
/// runs.  Independent of partition state: the rejection lives in the
/// dispatcher gate, not in any setter.
#[test]
fn part_init_reject_default_psk_co() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(session.handshake(), &seed, &policy, &thumb)
        .expect_err("PartInit under default CO PSK must be rejected");
    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// CU session under a rotated PSK: the handler's CO-only role gate
/// must surface [`TborStatus::InvalidPermissions`].
///
/// [`rotate_psk_and_open_role`] rotates the CU PSK first so the request
/// bypasses the default-PSK dispatcher gate and reaches the role check.
#[test]
fn part_init_reject_cu_session() {
    let ctx = TestCtx::new();

    let session = rotate_psk_and_open_role(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(session.handshake(), &seed, &policy, &thumb)
        .expect_err("PartInit on CU session must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
}

/// A malformed partition policy must be rejected before firmware
/// applies any partition configuration.
///
/// The rotated CO session is wrapped in [`SessionGuard`] so the session
/// is closed automatically if an assertion or request unexpectedly
/// panics.
#[test]
fn part_init_reject_bad_policy() {
    let ctx = TestCtx::new();

    let session = SessionGuard::new(&ctx, bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK));

    let seed = mach_seed();
    let bad_policy = [0u8; PART_POLICY_LEN];
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(session.handshake(), &seed, &bad_policy, &thumb)
        .expect_err("PartInit with malformed PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// The dispatcher's default-PSK gate must run before policy decoding.
///
/// Even though the supplied policy is malformed, a CO session still using
/// the default PSK must receive `DefaultPskMustRotate`, not `InvalidArg`.
#[test]
fn part_init_default_psk_gate_precedes_policy_decode_emu() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open default-PSK CO session");
    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(session.handshake(), &seed, &bad_policy, &thumb)
        .expect_err("default-PSK gate must reject before policy decoding");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// The default-PSK dispatcher gate must run before the CU role-permission
/// gate.
///
/// The caller is a CU, which normally cannot execute `PartInit`, but the
/// CU session is still using its default PSK. Therefore, the dispatcher
/// must reject the request with `DefaultPskMustRotate` before the handler
/// can return `InvalidPermissions`.
#[test]
fn part_init_default_psk_gate_precedes_cu_role_gate_emu() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open default-PSK CU session");
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(session.handshake(), &seed, &policy, &thumb)
        .expect_err("default-PSK CU session must be rejected");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// The handler's CO-only role gate must run before policy decoding.
///
/// Although the policy is malformed, the rotated CU session must be
/// rejected with `InvalidPermissions` before policy decoding occurs.
#[test]
fn part_init_cu_role_gate_precedes_policy_decode_emu() {
    let ctx = TestCtx::new();

    let session = rotate_psk_and_open_role(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);
    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(session.handshake(), &seed, &bad_policy, &thumb)
        .expect_err("CU role gate must reject before policy decoding");

    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
}

/// A policy containing only `0xFF` bytes must fail canonical policy
/// decoding with `InvalidArg`.
///
/// This complements the all-zero policy test and exercises a malformed
/// policy whose fields decode to their maximum encoded values.
#[test]
fn part_init_reject_all_ff_policy_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = [0xFFu8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("PartInit with all-0xFF PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// Corrupt only the policy major-version byte while preserving the rest
/// of an otherwise valid policy.
///
/// This provides a more targeted version of the all-zero-policy test and
/// verifies that `version.major == 0` is independently rejected.
#[test]
fn part_init_reject_zero_policy_major_version_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let mut bad_policy = known_good_part_policy();

    // PartPolicy begins with its encoded version. The canonical decoder
    // rejects a policy whose major version is zero.
    bad_policy[0] = 0;

    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("PartInit with zero policy major version must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// Repeating the same malformed-policy request must return the same
/// canonical status each time.
///
/// This also helps detect accidental state mutation after the first
/// rejected request.
#[test]
fn part_init_bad_policy_rejection_is_repeatable_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    for attempt in 1..=2 {
        let result = ctx.part_init(&session, &seed, &bad_policy, &thumb);

        let err = match result {
            Ok(_) => panic!(
                "malformed PartPolicy unexpectedly succeeded on attempt {}",
                attempt
            ),
            Err(err) => err,
        };

        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }
}

/// A malformed-policy rejection must occur before partition-state
/// mutation.
///
/// After the invalid request is rejected, a valid `PartInit` on the same
/// rotated CO session must still succeed. If the failed request partially
/// changed partition state, the valid retry would be rejected.
#[test]
fn part_init_bad_policy_does_not_mutate_partition_state_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = [0u8; PART_POLICY_LEN];
    let good_policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("malformed PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);

    ctx.part_init(&session, &seed, &good_policy, &thumb)
        .expect("valid PartInit must succeed after malformed-policy rejection");
}

/// A valid PartInit request from an authenticated CO session using a
/// rotated PSK must succeed.
///
/// This is the basic positive-path test for PartInit. The other tests
/// depend on this combination representing a valid initialization request.
#[test]
fn part_init_valid_rotated_co_request_succeeds_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    ctx.part_init(&session, &seed, &policy, &thumb)
        .expect("valid PartInit from rotated authenticated CO must succeed");
}

/// A rejection caused by the CU permission gate must not mutate partition state.
///
/// After the CU request is rejected with `InvalidPermissions`, a valid rotated-CO
/// `PartInit` request must still succeed.
#[test]
fn part_init_cu_rejection_does_not_mutate_partition_state_emu() {
    let ctx = TestCtx::new();

    let cu_session = rotate_psk_and_open_role(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);

    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(cu_session.handshake(), &seed, &policy, &thumb)
        .expect_err("PartInit from a CU session must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidPermissions);

    let co_ctx = TestCtx::new_with_path(ctx.path());
    let co_session = bootstrap_rotated_co(&co_ctx, &ROTATED_CO_PSK);

    co_ctx
        .part_init(&co_session, &seed, &policy, &thumb)
        .expect("valid CO PartInit must succeed after CU rejection");
}

/// After successful partition initialization, a second `PartInit` request
/// must be rejected because the partition's PTA key has already been set.
///
/// The second request reuses the authenticated CO session that performed
/// the first initialization. Opening a new session with the pre-init
/// rotated CO PSK is not valid after `PartInit` changes partition
/// authentication state.
#[test]
fn part_init_rejects_second_initialization_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    ctx.part_init(&session, &seed, &policy, &thumb)
        .expect("first valid PartInit must succeed");

    let err = ctx
        .part_init(&session, &seed, &policy, &thumb)
        .expect_err("second PartInit on an initialized partition must be rejected");

    assert_fw_rejects(&err, TborStatus::PtaKeyAlreadySet);
}

/// Verify that several malformed policy representations are independently
/// rejected and that no rejection changes partition state.
///
/// A separate `TestCtx` is used for each case because the final valid request
/// initializes that case's partition.
#[test]
fn part_init_policy_rejection_matrix_does_not_mutate_state_emu() {
    enum BadPolicyCase {
        AllZero,
        AllOnes,
        ZeroMajorVersion,
    }

    for case in [
        BadPolicyCase::AllZero,
        BadPolicyCase::AllOnes,
        BadPolicyCase::ZeroMajorVersion,
    ] {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        let bad_policy = match case {
            BadPolicyCase::AllZero => [0u8; PART_POLICY_LEN],
            BadPolicyCase::AllOnes => [0xFFu8; PART_POLICY_LEN],
            BadPolicyCase::ZeroMajorVersion => {
                let mut policy = known_good_part_policy();
                policy[0] = 0;
                policy
            }
        };

        let good_policy = known_good_part_policy();
        let seed = mach_seed();
        let thumb = pota_thumbprint();

        let err = ctx
            .part_init(&session, &seed, &bad_policy, &thumb)
            .expect_err("malformed PartPolicy must be rejected");

        assert_fw_rejects(&err, TborStatus::InvalidArg);

        ctx.part_init(&session, &seed, &good_policy, &thumb)
            .expect("valid PartInit must succeed after policy rejection");
    }
}

/// Policy rejection must not invalidate the authenticated CO session.
///
/// Submit multiple malformed policies through the same session, followed
/// by one valid request.
#[test]
fn part_init_session_remains_usable_after_policy_rejections_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let mut zero_major_policy = known_good_part_policy();
    zero_major_policy[0] = 0;

    let bad_policies = [
        [0u8; PART_POLICY_LEN],
        [0xFFu8; PART_POLICY_LEN],
        zero_major_policy,
    ];

    for (index, bad_policy) in bad_policies.iter().enumerate() {
        let result = ctx.part_init(&session, &seed, bad_policy, &thumb);

        let err = match result {
            Ok(_) => panic!(
                "malformed PartPolicy unexpectedly succeeded at index {}",
                index
            ),
            Err(err) => err,
        };

        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }

    let good_policy = known_good_part_policy();

    ctx.part_init(&session, &seed, &good_policy, &thumb)
        .expect("session must remain usable after policy rejections");
}

/// A rejection caused by the default-PSK dispatcher gate must not mutate
/// partition state.
///
/// The first request uses the default CO PSK and must be rejected before
/// the `PartInit` handler performs any state mutation. After closing that
/// session and rotating the CO PSK, a valid `PartInit` request must still
/// succeed.
#[test]
fn part_init_default_psk_rejection_does_not_mutate_partition_state_emu() {
    let ctx = TestCtx::new();

    let default_session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open default-PSK CO session");

    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(default_session.handshake(), &seed, &policy, &thumb)
        .expect_err("PartInit under default CO PSK must be rejected");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);

    default_session
        .close()
        .expect("close default-PSK CO session");

    let rotated_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.part_init(&rotated_session, &seed, &policy, &thumb)
        .expect("valid PartInit must succeed after default-PSK rejection");
}

/// Multiple rejection classes must not collectively contaminate partition
/// state.
///
/// This test exercises three distinct rejection paths in order:
///
/// 1. Default CO PSK rejection.
/// 2. CU permission rejection.
/// 3. Malformed policy rejection.
///
/// A valid rotated-CO `PartInit` request must still succeed afterward.
#[test]
fn part_init_multiple_rejections_do_not_mutate_partition_state_emu() {
    let ctx = TestCtx::new();

    let policy = known_good_part_policy();
    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    // First rejection: default CO PSK.
    let default_co = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open default-PSK CO session");
    let err = ctx
        .part_init(default_co.handshake(), &seed, &policy, &thumb)
        .expect_err("PartInit under default CO PSK must be rejected");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);

    default_co.close().expect("close default-PSK CO session");

    // Second rejection: CU role.
    let cu_session = rotate_psk_and_open_role(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);

    let err = ctx
        .part_init(cu_session.handshake(), &seed, &policy, &thumb)
        .expect_err("PartInit from CU must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidPermissions);

    // Open an authorized CO session on a separate handle: the CU session
    // remains live, and each hardware handle permits only one session.
    let co_ctx = TestCtx::new_with_path(ctx.path());
    let co_session = bootstrap_rotated_co(&co_ctx, &ROTATED_CO_PSK);

    // Third rejection: malformed policy.
    let err = co_ctx
        .part_init(&co_session, &seed, &bad_policy, &thumb)
        .expect_err("malformed PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);

    // None of the preceding rejections may have initialized or otherwise
    // mutated the partition.
    co_ctx
        .part_init(&co_session, &seed, &policy, &thumb)
        .expect("valid PartInit must succeed after multiple rejected requests");
}

/// A malformed-policy rejection must not modify any caller-owned input
/// buffer.
///
/// `PartInit` receives the seed, policy, and thumbprint by shared
/// reference. This test confirms the harness and serialization path do
/// not unexpectedly alter those buffers when firmware rejects the
/// request.
#[test]
fn part_init_rejection_does_not_modify_input_buffers_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let expected_policy = bad_policy;
    let expected_seed = seed;
    let expected_thumb = thumb;

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("malformed PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);

    assert_eq!(
        bad_policy, expected_policy,
        "PartInit rejection modified the caller-owned policy buffer",
    );

    assert_eq!(
        seed, expected_seed,
        "PartInit rejection modified the caller-owned seed buffer",
    );

    assert_eq!(
        thumb, expected_thumb,
        "PartInit rejection modified the caller-owned thumbprint buffer",
    );
}

/// A policy rejection must remain deterministic across several requests,
/// and the same authenticated CO session must still be usable afterward.
///
/// Every malformed request must return the canonical
/// [`TborStatus::InvalidArg`] status. After the rejected requests, a valid
/// policy must still initialize the partition successfully.
#[test]
fn part_init_repeated_policy_rejections_preserve_session_and_state_emu() {
    const ATTEMPTS: usize = 5;

    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = [0u8; PART_POLICY_LEN];
    let good_policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    for attempt in 1..=ATTEMPTS {
        let result = ctx.part_init(&session, &seed, &bad_policy, &thumb);

        let err = match result {
            Ok(_) => panic!(
                "malformed PartPolicy unexpectedly succeeded on attempt {}",
                attempt,
            ),
            Err(err) => err,
        };

        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }

    ctx.part_init(&session, &seed, &good_policy, &thumb)
        .expect("valid PartInit must succeed after repeated policy rejections");
}

/// A CO session cannot be opened with [`SessionType::PlainText`].
///
/// CO commands require an authenticated session, so the session-open
/// request must fail with [`TborStatus::InvalidSessionType`] before a
/// `PartInit` request can be submitted.
#[test]
fn part_init_co_plaintext_session_rejected_emu() {
    let ctx = TestCtx::new();

    let err = ctx
        .session_open_init(0, SessionType::PlainText)
        .expect_err("CO PlainText session must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

/// A valid-version policy must reject an unsupported POTA public-key kind.
#[test]
fn part_init_rejects_invalid_pub_key_kind_with_valid_version_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let mut bad_policy = known_good_part_policy();

    bad_policy[POLICY_PUB_KEY_KIND_OFFSET..POLICY_PUB_KEY_KIND_OFFSET + 2]
        .copy_from_slice(&u16::MAX.to_le_bytes());

    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("unsupported public-key kind must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// A valid-version policy must reject an invalid POTA public-key length.
#[test]
fn part_init_rejects_invalid_pub_key_len_with_valid_version_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let mut bad_policy = known_good_part_policy();

    bad_policy[POLICY_PUB_KEY_LEN_OFFSET..POLICY_PUB_KEY_LEN_OFFSET + 2]
        .copy_from_slice(&95u16.to_le_bytes());

    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("invalid public-key length must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// A correctly encoded optional backup partition public key must be
/// accepted as part of an otherwise valid policy.
#[test]
fn part_init_accepts_valid_backup_pub_key_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let mut policy = known_good_part_policy();

    set_valid_backup_part_pub_key(&mut policy);

    let seed = mach_seed();
    let thumb = pota_thumbprint();

    ctx.part_init(&session, &seed, &policy, &thumb)
        .expect("valid optional backup public key must be accepted");
}

/// Every reserved policy-flag bit must be rejected independently.
#[test]
fn part_init_rejects_each_reserved_policy_flag_bit_emu() {
    for reserved_bit in RESERVED_POLICY_FLAG_BITS {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        let mut bad_policy = known_good_part_policy();

        bad_policy[PART_POLICY_FLAGS_OFFSET] |= reserved_bit;

        let seed = mach_seed();
        let thumb = pota_thumbprint();

        let err = ctx
            .part_init(&session, &seed, &bad_policy, &thumb)
            .expect_err("reserved policy flag bit must be rejected");

        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }
}

/// A present backup partition public key with an unsupported key kind
/// must be rejected.
#[test]
fn part_init_rejects_backup_pub_key_with_invalid_kind_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let mut bad_policy = known_good_part_policy();

    set_backup_part_pub_key_present(&mut bad_policy);
    set_backup_part_pub_key_kind(&mut bad_policy, u16::MAX);

    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("backup public key with invalid kind must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// A present backup partition public key with a nonzero length other
/// than the required P-384 length must be rejected.
///
/// A zero length is intentionally not tested here because `len == 0`
/// represents an absent optional backup key and is valid.
#[test]
fn part_init_rejects_backup_pub_key_with_wrong_length_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let mut bad_policy = known_good_part_policy();

    set_backup_part_pub_key_present(&mut bad_policy);
    set_backup_part_pub_key_len(&mut bad_policy, EXPECTED_BACKUP_PUB_KEY_LEN - 1);

    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("backup public key with invalid nonzero length must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// Backup partition public-key lengths immediately below and above the
/// required P-384 length must be rejected.
#[test]
fn part_init_rejects_backup_pub_key_boundary_lengths_emu() {
    for bad_len in [
        EXPECTED_BACKUP_PUB_KEY_LEN - 1,
        EXPECTED_BACKUP_PUB_KEY_LEN + 1,
    ] {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        let mut bad_policy = known_good_part_policy();

        set_backup_part_pub_key_present(&mut bad_policy);
        set_backup_part_pub_key_len(&mut bad_policy, bad_len);

        let seed = mach_seed();
        let thumb = pota_thumbprint();

        let err = ctx
            .part_init(&session, &seed, &bad_policy, &thumb)
            .expect_err("backup public key with invalid length must be rejected");

        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }
}

/// An otherwise valid policy with an unsupported SATA public-key kind
/// must be rejected.
///
/// Starting from the known-good policy keeps the version, POTA key,
/// SATA length, and all unrelated fields valid, so the rejection
/// directly exercises SATA key-kind validation.
#[test]
fn part_init_rejects_invalid_sata_pub_key_kind_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let mut bad_policy = known_good_part_policy();

    bad_policy[SATA_PUB_KEY_KIND_OFFSET..SATA_PUB_KEY_KIND_OFFSET + 2]
        .copy_from_slice(&u16::MAX.to_le_bytes());

    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("unsupported SATA public-key kind must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// SATA public-key lengths immediately below and above the required
/// P-384 length must both be rejected.
#[test]
fn part_init_rejects_invalid_sata_pub_key_boundary_lengths_emu() {
    for bad_len in [95u16, 97u16] {
        let ctx = TestCtx::new();

        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        let mut bad_policy = known_good_part_policy();

        bad_policy[SATA_PUB_KEY_LEN_OFFSET..SATA_PUB_KEY_LEN_OFFSET + 2]
            .copy_from_slice(&bad_len.to_le_bytes());

        let seed = mach_seed();
        let thumb = pota_thumbprint();

        let err = ctx
            .part_init(&session, &seed, &bad_policy, &thumb)
            .expect_err("invalid SATA public-key length must be rejected");

        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }
}
