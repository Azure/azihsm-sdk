// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdSealingKeyGen` command.
//!
//! Cross-test isolation comes from `open_dev`'s factory reset; no
//! per-test cleanup is required (see [`crate::harness::fixture`]).
//!
//! The command generates a P-384 sealing keypair and returns the
//! **masked** private key (masked under the requested scope's masking
//! key) plus the public key — nothing is stored on the device.  The
//! Ephemeral/Local masking keys are provisioned by `PartFinal`, so the
//! happy-path tests first drive `PartInit → PartFinal`.
//!
//! Coverage:
//! * Happy path (Ephemeral + Local) — returns a non-zero 180-byte masked
//!   key + 96-byte public key; a second call yields a distinct keypair.
//! * Unsupported scope (Session + SecurityDomain) → `UnsupportedKeyScope`.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;
use azihsm_ddi_tbor_types::SD_SEALING_PUB_KEY_LEN;

use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::part_policy_with_pota;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::part_init::CO;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::SessionHandshake;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;

/// `KeyScope` discriminants (wire mirror of the firmware `HsmKeyScope`).
const SCOPE_SESSION: u8 = 0b001;
const SCOPE_EPHEMERAL: u8 = 0b010;
const SCOPE_LOCAL: u8 = 0b011;
const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// Crypto-User PSK id.
const CU: u8 = 1;

/// Non-default 32-byte CU PSK, used to clear the default-PSK gate so the
/// CU-role reject path — not the default-PSK gate — is exercised.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

/// Bring a partition to `Initialized` on a rotated CO session:
/// bootstrap → `PartInit` → `PartFinal`.  Post-condition: the
/// Ephemeral/Local masking keys exist, so `SdSealingKeyGen` can mask
/// under them.  Returns the live CO session.
///
/// `PartFinal` validates the supplied PTA certificate chain against the
/// POTA trust anchor bound into the policy, so this mints a POTA CA, binds
/// its public key into the policy, and issues a POTA-anchored PTA chain
/// from the `PartInit` CSR (mirrors the `part_final` happy-path setup).
fn finalized_co_session(ctx: &TestCtx) -> SessionHandshake {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");
    session
}

/// Happy path for a supported `scope`: the masked key + public key are
/// full/non-zero, and a second call yields a distinct keypair.
fn roundtrip_for_scope(scope: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id,
        scope,
    };
    let resp = ctx.tbor(&req).expect("SdSealingKeyGen roundtrip");

    // Masked private key: exactly the pinned length, non-zero.
    assert_eq!(resp.masked_key.len(), MASKED_SEALING_KEY_LEN);
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );
    // Public key: a full, non-zero P-384 point.
    assert_eq!(resp.pub_key.len(), SD_SEALING_PUB_KEY_LEN);
    assert!(
        resp.pub_key.iter().any(|&b| b != 0),
        "pub_key must not be all-zero",
    );

    // Each call generates fresh randomness → a distinct keypair.
    let resp2 = ctx.tbor(&req).expect("second SdSealingKeyGen");
    assert_ne!(
        resp.masked_key, resp2.masked_key,
        "each generation must yield a distinct masked key",
    );
    assert_ne!(
        resp.pub_key, resp2.pub_key,
        "each generation must yield a distinct public key",
    );
}

#[test]
fn sd_sealing_key_gen_ephemeral_roundtrip_emu() {
    roundtrip_for_scope(SCOPE_EPHEMERAL);
}

#[test]
fn sd_sealing_key_gen_local_roundtrip_emu() {
    roundtrip_for_scope(SCOPE_LOCAL);
}

#[test]
fn sd_sealing_key_gen_rejects_unsupported_scope_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Session and SecurityDomain masking keys are not yet provisioned
    // (session-key masking / CreateSD's SDKMK), so both must be rejected
    // with the dedicated UnsupportedKeyScope error.
    for scope in [SCOPE_SESSION, SCOPE_SECURITY_DOMAIN] {
        let req = TborSdSealingKeyGenReq {
            session_id: session.session_id,
            scope,
        };
        ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
    }
}

#[test]
fn sd_sealing_key_gen_rejects_before_finalize_emu() {
    let ctx = TestCtx::new();
    // Rotated CO session but no PartInit/PartFinal → the partition is not
    // Initialized, so the scope's masking key does not exist yet.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn sd_sealing_key_gen_rejected_on_cu_session_emu() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK out of the default so the dispatcher's default-PSK
    // gate does not fire first; then reopen a CU session under the rotated
    // PSK.  CU sessions are pinned to `SessionType::PlainText` (CO-only is
    // `Authenticated`).
    let bootstrap = ctx.open_session(CU, SessionType::PlainText);
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU session");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("CU session_open_init under rotated PSK");
    let session = ctx
        .session_open_finish(pending)
        .expect("CU session_open_finish under rotated PSK");

    // SdSealingKeyGen is Crypto-Officer-only: the handler's role gate
    // (checked before the scope/state gates) rejects a CU session.
    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
}

#[test]
fn sd_sealing_key_gen_rejected_on_default_psk_emu() {
    let ctx = TestCtx::new();
    // Open a CO session WITHOUT rotating the PSK (still the public
    // default) — the dispatcher's default-PSK gate must reject the command
    // before the handler runs.
    let session = ctx.open_session(CO, SessionType::Authenticated);

    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id(),
        scope: SCOPE_EPHEMERAL,
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}
