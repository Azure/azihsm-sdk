// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `EccGenerateKey` command.
//!
//! `EccGenerateKey` generates a fresh ECC keypair on the requested NIST
//! curve and returns the private key **masked** under the requested scope
//! plus the wire public key (nothing is persisted on-device). These tests
//! check the masked-blob / public-key lengths per curve, fresh generation,
//! masking-scope lifecycle rules, and rejection of an unknown curve.
//!
//! Signing / deriving with the generated key is exercised by the
//! [`ecc_sign`](super::ecc_sign) and [`ecdh_derive`](super::ecdh_derive)
//! tests, which build on this command.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::KEY_USAGE_DERIVE;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;

use crate::commands::common::CU;
use crate::commands::common::SCOPE_EPHEMERAL;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SECURITY_DOMAIN;
use crate::commands::common::SCOPE_SESSION;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::bootstrap_rotated_co;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;
use crate::harness::ROTATED_CU_PSK;

/// All supported NIST ECC curves.
const SUPPORTED_CURVES: [u8; 3] = [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521];

/// Expected wire public-key length (`x ‖ y`, P-521 padded) per curve.
fn wire_pub_len(curve: u8) -> usize {
    match curve {
        ECC_CURVE_P256 => 64,
        ECC_CURVE_P384 => 96,
        ECC_CURVE_P521 => 136,
        _ => unreachable!(),
    }
}

/// Expected masked private-key envelope length per curve:
/// `header(8) ‖ iv(12) ‖ aad(192) ‖ pt(wire_priv) ‖ tag(16)` = 228 + priv.
fn masked_key_len(curve: u8) -> usize {
    match curve {
        ECC_CURVE_P256 => 228 + 32,
        ECC_CURVE_P384 => 228 + 48,
        ECC_CURVE_P521 => 228 + 68,
        _ => unreachable!(),
    }
}

/// Generate an ECC key on `curve` under `scope` and assert well-formedness.
fn generate(ctx: &TestCtx, session_id: u16, scope: u8, curve: u8) -> (Vec<u8>, Vec<u8>) {
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope,
            curve,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");

    assert_eq!(
        resp.pub_key.len(),
        wire_pub_len(curve),
        "public key length must match the curve",
    );
    assert_eq!(
        resp.masked_key.len(),
        masked_key_len(curve),
        "masked private key envelope length must match the curve",
    );
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked private key must not be all-zero",
    );
    assert!(
        resp.pub_key.iter().any(|&b| b != 0),
        "public key must not be all-zero",
    );

    (resp.masked_key, resp.pub_key)
}

/// Generates fresh, correctly sized keypairs on every supported NIST curve.
#[test]
fn ecc_generate_key_all_curves() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for curve in SUPPORTED_CURVES {
        let (masked_key, pub_key) = generate(&ctx, session.session_id, SCOPE_LOCAL, curve);
        let (masked_key2, pub_key2) = generate(&ctx, session.session_id, SCOPE_LOCAL, curve);

        assert_ne!(
            masked_key, masked_key2,
            "each generation must yield a distinct masked private key",
        );
        assert_ne!(
            pub_key, pub_key2,
            "each generation must yield a distinct public key",
        );
    }
}

/// Allows Session-scoped generation before partition finalization on every supported curve.
#[test]
fn ecc_generate_key_session_scope_before_finalize() {
    // Session-scoped keys only require the per-session masking key; the
    // partition's Ephemeral and Local masking keys need not exist yet.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    for curve in SUPPORTED_CURVES {
        generate(&ctx, session.session_id, SCOPE_SESSION, curve);
    }
}

/// Allows ECC key generation from an authenticated Crypto-User session.
#[test]
fn ecc_generate_key_allowed_on_crypto_user_session() {
    // Rotate away from the default CU PSK so the dispatcher's default-PSK
    // gate does not obscure the command's role authorization.
    let ctx = TestCtx::new();
    let bootstrap = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open bootstrap CU session");

    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");

    bootstrap.close().expect("close bootstrap CU session");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open CU session under rotated PSK");

    let session = ctx
        .session_open_finish(pending)
        .expect("finish CU session open");

    for curve in SUPPORTED_CURVES {
        generate(&ctx, session.session_id, SCOPE_SESSION, curve);
    }
}

/// Rejects SecurityDomain scope when its masking key is not provisioned.
#[test]
fn ecc_generate_key_security_domain_scope_rejected() {
    // The SecurityDomain masking key is unavailable until CreateSD.
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SECURITY_DOMAIN,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects Ephemeral scope before partition finalization provisions its key.
#[test]
fn ecc_generate_key_ephemeral_scope_before_finalize_rejected() {
    // PartFinal provisions the Ephemeral and Local masking keys; until then,
    // ECC generation reports that the requested scope is unsupported.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_EPHEMERAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Generates a well-formed keypair on every supported curve under every provisioned scope.
#[test]
fn ecc_generate_key_scopes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // `finalized_co_session` provisions the Ephemeral and Local masking
    // keys; the Session masking key exists for any active session.
    for curve in SUPPORTED_CURVES {
        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            generate(&ctx, session.session_id, scope, curve);
        }
    }
}

/// Rejects curve discriminants outside the supported range.
#[test]
fn ecc_generate_key_unknown_curve_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Exercise values immediately below/above the valid range and the
    // largest possible wire discriminant.
    for curve in [0, ECC_CURVE_P521 + 1, u8::MAX] {
        ctx.expect_fw_reject(
            &TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                curve,
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            },
            TborStatus::InvalidArg,
        );
    }
}

/// Rejects an unknown masking-scope discriminant.
#[test]
fn ecc_generate_key_unknown_scope_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: u8::MAX,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects a mismatched `session_id` on every supported ECC curve.
#[test]
fn ecc_generate_key_mismatched_session_id_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    assert_ne!(
        session.session_id,
        u16::MAX,
        "test requires an unused session id",
    );

    for curve in SUPPORTED_CURVES {
        ctx.expect_fw_reject(
            &TborEccGenerateKeyReq {
                session_id: u16::MAX,
                scope: SCOPE_LOCAL,
                curve,
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            },
            TborStatus::FileHandleSessionIdDoesNotMatch,
        );
    }
}

/// Allows generation of a derive-capable ECC key.
#[test]
fn ecc_generate_key_derive_usage() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey with DERIVE usage");

    assert_eq!(resp.pub_key.len(), wire_pub_len(ECC_CURVE_P256));
    assert_eq!(resp.masked_key.len(), masked_key_len(ECC_CURVE_P256));
}

/// Allows generation with a non-empty key label.
#[test]
fn ecc_generate_key_non_empty_label() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: b"ecc-test-key".to_vec(),
        })
        .expect("EccGenerateKey with key label");

    assert_eq!(resp.pub_key.len(), wire_pub_len(ECC_CURVE_P256));
    assert_eq!(resp.masked_key.len(), masked_key_len(ECC_CURVE_P256));
}

/// Allows the maximum supported TBOR ECC key-label length.
#[test]
fn ecc_generate_key_max_label_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: vec![b'L'; TBOR_KEY_LABEL_MAX_LEN],
        })
        .expect("EccGenerateKey with maximum key-label length");

    assert_eq!(resp.pub_key.len(), wire_pub_len(ECC_CURVE_P256));
    assert_eq!(resp.masked_key.len(), masked_key_len(ECC_CURVE_P256));
}

/// Rejects ECC generation while the CO PSK is still the default.
#[test]
fn ecc_generate_key_rejects_default_co_psk() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(0, SessionType::Authenticated)
        .expect("open CO session under default PSK");

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id(),
            scope: SCOPE_SESSION,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        },
        TborStatus::DefaultPskMustRotate,
    );
}

/// Rejects Local scope before partition finalization provisions its key.
#[test]
fn ecc_generate_key_local_scope_before_finalize_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects combined SIGN and DERIVE usage.
#[test]
fn ecc_generate_key_sign_and_derive_usage_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN | KEY_USAGE_DERIVE,
            key_label: Vec::new(),
        },
        TborStatus::InvalidPermissions,
    );
}

/// Allows derive-capable generation on every supported ECC curve.
#[test]
fn ecc_generate_key_derive_usage_all_curves() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        let resp = ctx
            .tbor(&TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                curve,
                key_usage: KEY_USAGE_DERIVE,
                key_label: Vec::new(),
            })
            .expect("EccGenerateKey with DERIVE usage");

        assert_eq!(resp.pub_key.len(), wire_pub_len(curve));
        assert_eq!(resp.masked_key.len(), masked_key_len(curve));
    }
}

/// Allows the smallest non-empty key label.
#[test]
fn ecc_generate_key_one_byte_label() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: vec![b'A'],
        })
        .expect("EccGenerateKey with one-byte key label");

    assert_eq!(resp.pub_key.len(), wire_pub_len(ECC_CURVE_P256));
    assert_eq!(resp.masked_key.len(), masked_key_len(ECC_CURVE_P256));
}

/// Allows Session-scoped generation after closing and reopening the CO session.
#[test]
fn ecc_generate_key_session_scope_after_reopen() {
    let ctx = TestCtx::new();
    let session_a = finalized_co_session(&ctx);

    ctx.session_close(session_a.session_id)
        .expect("close first CO session");

    let opts = SessionOpenInitOptions::new(0, SessionType::Authenticated).with_psk(&ROTATED_CO_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open replacement CO session");

    let session_b = ctx
        .session_open_finish(pending)
        .expect("finish replacement CO session");

    generate(&ctx, session_b.session_id, SCOPE_SESSION, ECC_CURVE_P256);
}

/// Rejects a key label longer than the TBOR maximum.
#[test]
fn ecc_generate_key_label_too_long_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: vec![b'L'; TBOR_KEY_LABEL_MAX_LEN + 1],
        },
        TborStatus::TborInvalidFixedLength,
    );
}

/// Rejects an empty key-usage bitfield.
#[test]
fn ecc_generate_key_zero_usage_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: 0,
            key_label: Vec::new(),
        },
        TborStatus::InvalidPermissions,
    );
}

/// Rejects unsupported key-usage bits.
#[test]
fn ecc_generate_key_unknown_usage_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: 1u64 << 63,
            key_label: Vec::new(),
        },
        TborStatus::InvalidPermissions,
    );
}

/// Allows maximum key-label length with DERIVE usage.
#[test]
fn ecc_generate_key_max_label_with_derive_usage() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_DERIVE,
            key_label: vec![b'L'; TBOR_KEY_LABEL_MAX_LEN],
        })
        .expect("EccGenerateKey with DERIVE usage and maximum label");

    assert_eq!(resp.pub_key.len(), wire_pub_len(ECC_CURVE_P256));
    assert_eq!(resp.masked_key.len(), masked_key_len(ECC_CURVE_P256));
}
/// Allows an arbitrary byte sequence as the key label.
#[test]
fn ecc_generate_key_binary_label() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: vec![0x00, 0x80, 0xff, 0x41],
        })
        .expect("EccGenerateKey with binary label");

    assert_eq!(resp.pub_key.len(), wire_pub_len(ECC_CURVE_P256));
    assert_eq!(resp.masked_key.len(), masked_key_len(ECC_CURVE_P256));
}
