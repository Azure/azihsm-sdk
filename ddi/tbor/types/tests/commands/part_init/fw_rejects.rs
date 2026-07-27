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
use super::ROTATED_CO_PSK;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::SessionHandshake;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;

const CU: u8 = 1;

/// Non-default 32-byte CU PSK, used to clear the default-PSK gate
/// before exercising the CU role-reject path.  Distinct bytes from
/// [`ROTATED_CO_PSK`] so a copy/paste swap is loud.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

/// Open a session of `role` + `sty` under the supplied PSK
/// (bypassing the partition default).
fn open_role_with(
    ctx: &TestCtx,
    role: u8,
    sty: SessionType,
    psk: &[u8; PSK_LEN],
) -> SessionHandshake {
    let opts = SessionOpenInitOptions::new(role, sty).with_psk(psk);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("session_open_init under custom PSK");
    ctx.session_open_finish(pending)
        .expect("session_open_finish under custom PSK")
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
/// must surface [`TborStatus::InvalidPermissions`].  The CU PSK is
/// rotated up-front so the dispatcher's default-PSK gate does not
/// fire first.
#[test]
fn part_init_reject_cu_session() {
    let ctx = TestCtx::new();

    // Rotate CU PSK out of the default so we exercise the role gate,
    // not the default-PSK gate.  CU sessions are pinned to
    // `SessionType::PlainText` (CO-only is `Authenticated`).
    let bootstrap = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU session");

    let session = open_role_with(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &policy, &thumb)
        .expect_err("PartInit on CU session must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
}

/// Rotated CO session with a syntactically invalid `PartPolicy`
/// (all-zero bytes — `version.major == 0` fails the canonical decode
/// gate in `policy::from_bytes`): the handler must reject with
/// [`TborStatus::InvalidArg`] **before** any setter runs, leaving
/// partition state untouched.
#[test]
fn part_init_reject_bad_policy() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
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

    let session = ctx.open_session(CO, SessionType::Authenticated);
    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(session.handshake(), &seed, &bad_policy, &thumb)
        .expect_err("default-PSK gate must reject before policy decoding");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// The handler's CO-only role gate must run before policy decoding.
///
/// The CU PSK is rotated first so the dispatcher allows the command to
/// reach the handler. Although the policy is malformed, the CU role must
/// be rejected with `InvalidPermissions` before the policy is decoded.
#[test]
fn part_init_cu_role_gate_precedes_policy_decode_emu() {
    let ctx = TestCtx::new();

    let bootstrap = ctx.open_session(CU, SessionType::PlainText);
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU session");

    let session = open_role_with(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);
    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
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

/// A rejection caused by the default-PSK dispatcher gate must not mutate
/// partition state.
///
/// After the default-PSK request is rejected, rotate the CO PSK and submit
/// a valid request. The valid request must still succeed.

#[test]
fn part_init_cu_rejection_does_not_mutate_partition_state_emu() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK so the request reaches the role-permission gate.
    let bootstrap_cu = ctx.open_session(CU, SessionType::PlainText);
    ctx.psk_change(bootstrap_cu.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap_cu.close().expect("close bootstrap CU session");

    let cu_session = open_role_with(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);

    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&cu_session, &seed, &policy, &thumb)
        .expect_err("PartInit from a CU session must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidPermissions);

    // `cu_session` is only a SessionHandshake, so it has no close method.
    let co_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.part_init(&co_session, &seed, &policy, &thumb)
        .expect("valid CO PartInit must succeed after CU rejection");
}

/// After a successful PartInit, the same partition must not accept another
/// initialization request.
///
/// This version intentionally checks only that the second request is
/// rejected. Add `assert_fw_rejects` after confirming the canonical status
/// returned by the current firmware implementation.
#[test]
fn part_init_rejects_second_initialization_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    ctx.part_init(&session, &seed, &policy, &thumb)
        .expect("first valid PartInit must succeed");

    let _err = ctx
        .part_init(&session, &seed, &policy, &thumb)
        .expect_err("second PartInit on an initialized partition must be rejected");
}

/// Verify that several malformed policy representations are independently
/// rejected and that no rejection changes partition state.
///
/// A separate TestCtx is used for each case because the final valid request
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

        let mut bad_policy = match case {
            BadPolicyCase::AllZero => [0u8; PART_POLICY_LEN],
            BadPolicyCase::AllOnes => [0xFFu8; PART_POLICY_LEN],
            BadPolicyCase::ZeroMajorVersion => known_good_part_policy(),
        };

        if matches!(case, BadPolicyCase::ZeroMajorVersion) {
            bad_policy[0] = 0;
        }

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

    let default_session = ctx.open_session(CO, SessionType::Authenticated);

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
    let default_co = ctx.open_session(CO, SessionType::Authenticated);

    let err = ctx
        .part_init(default_co.handshake(), &seed, &policy, &thumb)
        .expect_err("PartInit under default CO PSK must be rejected");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);

    default_co.close().expect("close default-PSK CO session");

    // Second rejection: CU role.
    let bootstrap_cu = ctx.open_session(CU, SessionType::PlainText);

    ctx.psk_change(bootstrap_cu.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");

    bootstrap_cu.close().expect("close bootstrap CU session");

    let cu_session = open_role_with(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);

    let err = ctx
        .part_init(&cu_session, &seed, &policy, &thumb)
        .expect_err("PartInit from CU must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidPermissions);

    // Open an authorized CO session for handler-level validation.
    let co_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // Third rejection: malformed policy.
    let err = ctx
        .part_init(&co_session, &seed, &bad_policy, &thumb)
        .expect_err("malformed PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);

    // None of the preceding rejections may have initialized or otherwise
    // mutated the partition.
    ctx.part_init(&co_session, &seed, &policy, &thumb)
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
/// This extends the two-attempt repeatability check by issuing several
/// malformed requests through one session before submitting a valid
/// policy.
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
