// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured ECC key-generation fuzzing with a strict, state-aware oracle.
//!
//! Frequent session-scoped successes reach key generation and masking cheaply;
//! selected iterations provision partition/security-domain keys or exercise
//! single-field rejects, combined-invalid precedence, and raw request fields.
//! Successful keys are selectively used for signing (host-verified) or ECDH.
//! PAL fault injection and DMA private-key wiping require separate tests.

#![no_main]

#[path = "../../common.rs"]
mod common;

use arbitrary::*;
use azihsm_crypto::*;
use azihsm_ddi_tbor_test_harness::*;
use azihsm_ddi_tbor_types::*;
use common::EccCurve;
use libfuzzer_sys::*;

/// Partition/session lifecycle established before issuing the fuzzed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    Unfinalized,
    Finalized,
    SecurityDomain,
    Closed,
    DefaultPsk,
}

/// Compact selectors plus unrestricted scalar fields and bounded binary labels.
///
/// The corpus layout is a 16-byte little-endian header: scenario, role, usage
/// selector, label selector (one byte each), session id (u16), scope, curve
/// (one byte each), usage (u64), followed by at most 129 label bytes.
#[derive(Debug)]
struct FuzzInput {
    scenario: u8,
    role: u8,
    usage_selector: u8,
    label_selector: u8,
    session_id: u16,
    scope: u8,
    curve: u8,
    key_usage: u64,
    label: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    /// Decode a fixed scalar header and consume at most one oversized label.
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            scenario: u.arbitrary()?,
            role: u.arbitrary()?,
            usage_selector: u.arbitrary()?,
            label_selector: u.arbitrary()?,
            session_id: u.arbitrary()?,
            scope: u.arbitrary()?,
            curve: u.arbitrary()?,
            key_usage: u.arbitrary()?,
            label: u.bytes(u.len().min(TBOR_KEY_LABEL_MAX_LEN + 1))?.to_vec(),
        })
    }
}

impl FuzzInput {
    /// Bias toward cheap active-session paths while retaining every lifecycle.
    fn lifecycle(&self) -> Lifecycle {
        match self.scenario % 16 {
            4 => Lifecycle::Finalized,
            5 => Lifecycle::SecurityDomain,
            11 => Lifecycle::Closed,
            12 => Lifecycle::DefaultPsk,
            15 => match self.scope % 5 {
                0 => Lifecycle::Unfinalized,
                1 => Lifecycle::Finalized,
                2 => Lifecycle::SecurityDomain,
                3 => Lifecycle::Closed,
                _ => Lifecycle::DefaultPsk,
            },
            _ => Lifecycle::Unfinalized,
        }
    }

    /// Select a supported curve without discarding the independent raw path.
    fn valid_curve(&self) -> EccCurve {
        match self.curve % 3 {
            0 => EccCurve::P256,
            1 => EccCurve::P384,
            _ => EccCurve::P521,
        }
    }

    /// Emphasize forbidden combinations and still retain arbitrary 64-bit usage.
    fn fuzzed_usage(&self) -> u64 {
        match self.usage_selector % 12 {
            0 => 0,
            1 => KEY_USAGE_SIGN | KEY_USAGE_DERIVE,
            2 => KEY_USAGE_ENCRYPT,
            3 => KEY_USAGE_DECRYPT,
            4 => KEY_USAGE_VERIFY,
            5 => KEY_USAGE_WRAP,
            6 => KEY_USAGE_UNWRAP,
            7 => KEY_USAGE_SIGN | KEY_USAGE_ENCRYPT,
            8 => KEY_USAGE_DERIVE | KEY_USAGE_WRAP,
            9 => KEY_USAGE_SIGN | (1u64 << (self.key_usage % 64)),
            _ => self.key_usage,
        }
    }

    /// Build a binary label with explicit empty, boundary, and oversized cases.
    fn key_label(&self, include_oversized: bool) -> Vec<u8> {
        let len = match self.label_selector % 6 {
            0 => 0,
            1 => 1,
            2 => TBOR_KEY_LABEL_MAX_LEN - 1,
            3 => TBOR_KEY_LABEL_MAX_LEN,
            4 if include_oversized => TBOR_KEY_LABEL_MAX_LEN + 1,
            _ => self.label.len().min(TBOR_KEY_LABEL_MAX_LEN),
        };
        let mut label = self.label.clone();
        label.resize(len, 0);
        label
    }

    /// Construct valid baselines, isolated rejects, or combined arbitrary fields.
    fn request(&self, session_id: u16, lifecycle: Lifecycle) -> TborEccGenerateKeyReq {
        let mut req = TborEccGenerateKeyReq {
            session_id,
            scope: match lifecycle {
                Lifecycle::Finalized => [
                    common::KEY_SCOPE_SESSION,
                    common::KEY_SCOPE_EPHEMERAL,
                    common::KEY_SCOPE_LOCAL,
                ][usize::from(self.scope % 3)],
                Lifecycle::SecurityDomain => common::KEY_SCOPE_SECURITY_DOMAIN,
                _ => common::KEY_SCOPE_SESSION,
            },
            curve: self.valid_curve().to_tbor(),
            key_usage: if self.usage_selector & 1 == 0 {
                KEY_USAGE_SIGN
            } else {
                KEY_USAGE_DERIVE
            },
            key_label: self.key_label(false),
        };
        match self.scenario % 16 {
            6 => {
                req.scope = match self.scope % 8 {
                    0..=5 => common::derive_valid_key_scope(self.scope % 8),
                    _ => self.scope,
                };
            }
            7 => {
                req.curve = match self.curve {
                    ECC_CURVE_P256 | ECC_CURVE_P384 | ECC_CURVE_P521 => 0,
                    other => other,
                };
            }
            8 => req.key_usage = self.fuzzed_usage(),
            9 => req.key_label.resize(TBOR_KEY_LABEL_MAX_LEN + 1, 0),
            10 => req.session_id ^= 1u16 << (self.session_id % 16),
            13 | 15 => {
                req.scope = self.scope;
                req.curve = self.curve;
                req.key_usage = self.fuzzed_usage();
                req.key_label = self.key_label(true);
            }
            14 => {
                req.session_id = self.session_id;
                req.scope = self.scope;
                req.curve = self.curve;
                req.key_usage = self.key_usage;
                req.key_label = self.label.clone();
            }
            _ => {}
        }
        req
    }
}

/// Establish administrative state with CO before switching to CU when selected.
///
/// A default-PSK session must not pass through either rotation helper.
fn open_session<'a>(ctx: &'a TestCtx, input: &FuzzInput, lifecycle: Lifecycle) -> SessionGuard<'a> {
    let role = if input.role & 1 == 0 {
        common::FuzzRole::Co
    } else {
        common::FuzzRole::Cu
    };
    if lifecycle == Lifecycle::DefaultPsk {
        return ctx
            .open_session(role.psk_id(), role.session_type())
            .expect("open default-PSK session");
    }

    if matches!(lifecycle, Lifecycle::Finalized | Lifecycle::SecurityDomain) {
        let co = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        if lifecycle == Lifecycle::SecurityDomain {
            common::create_test_security_domain(ctx, &co);
        } else {
            common::finalize_partition(ctx, &co);
        }
        if matches!(role, common::FuzzRole::Co) {
            return SessionGuard::new(ctx, co);
        }
        ctx.session_close(co.session_id)
            .expect("close administrative CO session before opening CU");
    }

    let session = match role {
        common::FuzzRole::Co => bootstrap_rotated_co(ctx, &ROTATED_CO_PSK),
        common::FuzzRole::Cu => bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK),
    };
    SessionGuard::new(ctx, session)
}

/// Predict the first rejection from fixture state and the actual request.
///
/// Handle validation precedes the default-PSK gate, then schema decoding,
/// curve selection, usage validation, and finally masking-key resolution.
fn expected_rejection(
    req: &TborEccGenerateKeyReq,
    session_id: u16,
    lifecycle: Lifecycle,
) -> Option<TborStatus> {
    if lifecycle == Lifecycle::Closed {
        Some(TborStatus::SessionNotFound)
    } else if req.session_id != session_id {
        Some(TborStatus::FileHandleSessionIdDoesNotMatch)
    } else if lifecycle == Lifecycle::DefaultPsk {
        Some(TborStatus::DefaultPskMustRotate)
    } else if req.key_label.len() > TBOR_KEY_LABEL_MAX_LEN {
        Some(TborStatus::TborInvalidFixedLength)
    } else if !matches!(req.curve, ECC_CURVE_P256 | ECC_CURVE_P384 | ECC_CURVE_P521) {
        Some(TborStatus::InvalidArg)
    } else if req.key_usage != KEY_USAGE_SIGN && req.key_usage != KEY_USAGE_DERIVE {
        Some(TborStatus::InvalidPermissions)
    } else {
        let available = match req.scope {
            common::KEY_SCOPE_SESSION => true,
            common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => {
                matches!(lifecycle, Lifecycle::Finalized | Lifecycle::SecurityDomain)
            }
            common::KEY_SCOPE_SECURITY_DOMAIN => lifecycle == Lifecycle::SecurityDomain,
            _ => false,
        };
        if available {
            None
        } else {
            Some(TborStatus::UnsupportedKeyScope)
        }
    }
}

/// Check exact response sizes and reject uninitialized, all-zero outputs.
fn check_response(req: &TborEccGenerateKeyReq, resp: &TborEccGenerateKeyResp) -> EccCurve {
    let curve = match req.curve {
        ECC_CURVE_P256 => EccCurve::P256,
        ECC_CURVE_P384 => EccCurve::P384,
        ECC_CURVE_P521 => EccCurve::P521,
        _ => panic!("unsupported curve unexpectedly succeeded"),
    };
    assert_eq!(resp.pub_key.len(), curve.wire_pub_key_len());
    assert_eq!(
        resp.masked_key.len(),
        MASKED_ECC_KEY_MIN_LEN - EccCurve::P256.wire_pub_key_len() / 2
            + curve.wire_pub_key_len() / 2,
    );
    assert!(resp.masked_key.iter().any(|&byte| byte != 0));
    assert!(resp.pub_key.iter().any(|&byte| byte != 0));
    curve
}

/// Sign a bounded digest and verify it against the returned public key.
///
/// Reverse padded wire coordinates into host order, stripping only signature
/// padding as in the existing ECC-sign target (P-521: 68 -> 66 bytes).
fn check_signing_key(
    ctx: &TestCtx,
    req: &TborEccGenerateKeyReq,
    resp: &TborEccGenerateKeyResp,
    curve: EccCurve,
) {
    let mut digest = req.key_label.clone();
    digest.resize(32, 0);
    let signature = ctx
        .tbor(&TborEccSignReq {
            session_id: req.session_id,
            masked_key: resp.masked_key.clone(),
            digest: digest.clone(),
        })
        .expect("generated signing key must be usable")
        .signature;
    assert_eq!(signature.len(), curve.wire_sig_len());

    let wire_coord = curve.wire_pub_key_len() / 2;
    let mut pub_be = Vec::with_capacity(resp.pub_key.len());
    for coord in resp.pub_key.chunks_exact(wire_coord) {
        pub_be.extend(coord.iter().rev().copied());
    }
    let public = EccPublicKey::from_hsm_bytes(&pub_be).expect("import generated public key");
    let mut sig_be = Vec::with_capacity(curve.coord_len() * 2);
    for coord in signature.chunks_exact(wire_coord) {
        sig_be.extend(coord[..curve.coord_len()].iter().rev().copied());
    }
    digest.reverse();
    assert!(
        Verifier::verify(&mut EccAlgo::default(), &public, &digest, &sig_be)
            .expect("host verification must run"),
        "generated private key must match returned public key",
    );
}

/// Exercise a derivation key using its own valid public point as the peer.
///
/// Self-ECDH avoids generating another keypair; also verify that the generated
/// DERIVE-only attributes prohibit signing with the same masked key.
fn check_derivation_key(
    ctx: &TestCtx,
    req: &TborEccGenerateKeyReq,
    resp: &TborEccGenerateKeyResp,
    curve: EccCurve,
) {
    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: req.session_id,
            masked_key: resp.masked_key.clone(),
            digest: vec![0; 32],
        },
        TborStatus::InvalidPermissions,
    );
    let derived = ctx
        .tbor(&TborEcdhDeriveReq {
            session_id: req.session_id,
            scope: req.scope,
            masked_key: resp.masked_key.clone(),
            peer_pub_key: resp.pub_key.clone(),
            key_label: req.key_label.clone(),
        })
        .expect("generated derivation key must be usable");
    assert_eq!(
        derived.masked_secret.len(),
        MASKED_SECRET_MIN_LEN - EccCurve::P256.coord_len() + curve.coord_len(),
    );
    assert!(derived.masked_secret.iter().any(|&byte| byte != 0));
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx, _path| {
        let lifecycle = input.lifecycle();
        let session = open_session(ctx, &input, lifecycle);
        let session_id = session.session_id();
        let live_session = if lifecycle == Lifecycle::Closed {
            session.close().expect("close session before negative test");
            None
        } else {
            Some(session)
        };

        let req = input.request(session_id, lifecycle);
        let expected = expected_rejection(&req, session_id, lifecycle);
        if let Some(status) = expected {
            ctx.expect_fw_reject(&req, status);
        } else {
            let resp = ctx.tbor(&req).expect("valid ECC generation must succeed");
            let curve = check_response(&req, &resp);
            if input.usage_selector & 2 != 0 {
                if req.key_usage == KEY_USAGE_SIGN {
                    check_signing_key(ctx, &req, &resp, curve);
                } else {
                    check_derivation_key(ctx, &req, &resp, curve);
                }
            }
        }

        if let Some(session) = live_session {
            session.close().expect("close fuzz session");
        }
    });
});
