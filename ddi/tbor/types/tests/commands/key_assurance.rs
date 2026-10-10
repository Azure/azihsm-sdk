// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FIPS 140-3 key-assurance tests for the TBOR import and key
//! generation paths, written to run on hardware as well as the emulator.
//!
//! Unlike the emulator-only command tests, this module has no `emu` gate, so
//! it runs against a real device. It covers:
//!
//! * Imports through `UnwrapKey` for every ECC curve and usage, and every RSA
//!   size, layout (plain and CRT), and usage, then uses each imported key.
//!   On Uno these imports pass the embedded-public-key check and the
//!   usage-matched pairwise consistency test (PCT) before the key is stored.
//! * Malformed imports that the firmware must reject. ECC keys whose
//!   embedded public key is wrong, missing, compressed, or hybrid, or that
//!   carry `[0]` curve parameters, fail the structure check. RSA keys with an
//!   inconsistent private component fail the pairwise consistency test.
//!   Only hardware firmware runs either check.
//! * Imports of ECC keys whose private value is 0 or the curve order, which
//!   every firmware rejects with `InvalidArg`.
//! * On-device ECC key generation for every curve and usage, then use of the
//!   returned blob.
//! * The partition unwrapping key: availability and stability.
//!
//! The emulator, mock, and socket backends don't run the structure check or
//! pairwise consistency tests, so the tests that need one are ignored under
//! the `emu`, `mock`, and `sock` features.
//!
//! The SP publishes the unwrapping key asynchronously, so tests wait up to
//! `UNWRAP_KEY_WAIT_SECS` seconds (default 900) for `GetUnwrappingKey`.

use std::time::Duration;
use std::time::Instant;

use azihsm_crypto::Key;
use azihsm_crypto::KeyGenerationOp;
use azihsm_crypto::PrivateKey;
use azihsm_crypto::RsaPrivateKey;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_mbor_test_helpers::ecc_pkcs8;
use azihsm_ddi_mbor_test_helpers::plus_two;
use azihsm_ddi_mbor_test_helpers::EccTestCurve;
use azihsm_ddi_mbor_test_helpers::HostEcc;
use azihsm_ddi_mbor_test_helpers::RsaParts;
use azihsm_ddi_mbor_test_helpers::ECC_TEST_P256;
use azihsm_ddi_mbor_test_helpers::ECC_TEST_P384;
use azihsm_ddi_mbor_test_helpers::ECC_TEST_P521;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborGetUnwrappingKeyReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::KEY_CLASS_ECC;
use azihsm_ddi_tbor_types::KEY_CLASS_RSA;
use azihsm_ddi_tbor_types::KEY_CLASS_RSA_CRT;
use azihsm_ddi_tbor_types::KEY_USAGE_DECRYPT;
use azihsm_ddi_tbor_types::KEY_USAGE_DERIVE;
use azihsm_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::KEY_USAGE_VERIFY;

use crate::commands::common::assert_ecc_signs;
use crate::commands::common::assert_rsa_decrypts;
use crate::commands::common::assert_rsa_signs;
use crate::commands::common::derive;
use crate::commands::common::import_ok;
use crate::commands::common::unwrap_req;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// Sign usage as the TBOR import expects it (ECC and RSA).
const SIGN_VERIFY: u64 = KEY_USAGE_SIGN | KEY_USAGE_VERIFY;
/// RSA encrypt/decrypt usage.
const RSA_DECRYPT: u64 = KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT;
/// The status of an ECC key that fails the structure check.
const BAD_STRUCTURE: TborStatus = TborStatus::KeyStructuralValidationFailed;
/// The status every firmware returns for an ECC private value outside `[1, n-1]`.
const BAD_SCALAR: TborStatus = TborStatus::InvalidArg;

// ───────────────────────── device helpers ─────────────────────────

/// How long to wait for the SP to publish the unwrapping key.
fn unwrap_wait() -> Duration {
    let secs = std::env::var("UNWRAP_KEY_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(900);
    Duration::from_secs(secs)
}

/// Returns the unwrapping public key (`n_le ‖ e_le`), waiting while the
/// device reports `PendingKeyGeneration`.
fn unwrapping_pub(ctx: &TestCtx, session_id: u16) -> Vec<u8> {
    let deadline = Instant::now() + unwrap_wait();
    loop {
        match ctx.tbor(&TborGetUnwrappingKeyReq { session_id }) {
            Ok(resp) => return resp.pub_key.to_vec(),
            Err(DdiError::TborStatus(TborStatus::PendingKeyGeneration))
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_secs(5));
            }
            Err(e) => panic!("GetUnwrappingKey failed: {e:?}"),
        }
    }
}

/// Wraps and imports `der`, expecting the firmware to reject it with `status`.
fn import_rejected(
    ctx: &TestCtx,
    session_id: u16,
    hsm_pub: &[u8],
    class: u8,
    usage: u64,
    der: &[u8],
    status: TborStatus,
) {
    ctx.expect_fw_reject(&unwrap_req(session_id, hsm_pub, class, usage, der), status);
}

// ───────────────────────── host keys ─────────────────────────

#[derive(Clone, Copy, Debug)]
struct Curve {
    wire: u8,
    ecc: EccTestCurve,
    digest_len: usize,
}

const P256: Curve = Curve {
    wire: ECC_CURVE_P256,
    ecc: ECC_TEST_P256,
    digest_len: 32,
};
const P384: Curve = Curve {
    wire: ECC_CURVE_P384,
    ecc: ECC_TEST_P384,
    digest_len: 48,
};
const P521: Curve = Curve {
    wire: ECC_CURVE_P521,
    ecc: ECC_TEST_P521,
    digest_len: 64,
};

fn host_rsa(k: usize) -> (RsaPrivateKey, RsaParts) {
    let key = RsaPrivateKey::generate(k).expect("generate host RSA key");
    let parts = RsaParts::from_key(&key);
    (key, parts)
}

// ───────────────────────── key use ─────────────────────────

/// Runs ECDH with `masked_key` against a fresh host peer key.
fn assert_derives(ctx: &TestCtx, session_id: u16, curve: Curve, masked_key: Vec<u8>) {
    let peer = HostEcc::generate(curve.ecc);
    let secret = derive(ctx, session_id, SCOPE_LOCAL, masked_key, peer.wire_pub());
    assert_eq!(
        secret.len(),
        228 + curve.ecc.raw,
        "masked shared-secret length"
    );
}

/// Uses an ECC key for its usage: signs if `usage` is [`SIGN_VERIFY`], and
/// derives otherwise.
fn assert_ecc_works(
    ctx: &TestCtx,
    session_id: u16,
    curve: Curve,
    usage: u64,
    masked_key: Vec<u8>,
    pub_le: &[u8],
) {
    if usage == SIGN_VERIFY {
        assert_ecc_signs(ctx, session_id, masked_key, pub_le, curve.digest_len);
    } else {
        assert_derives(ctx, session_id, curve, masked_key);
    }
}

/// Uses an imported RSA key for its usage and checks the result on the host.
fn assert_rsa_works(
    ctx: &TestCtx,
    session_id: u16,
    key: &RsaPrivateKey,
    masked_key: Vec<u8>,
    usage: u64,
) {
    let pubkey = key.public_key().expect("host RSA public key");
    if usage == SIGN_VERIFY {
        assert_rsa_signs(ctx, session_id, masked_key, &pubkey, key.size());
    } else {
        assert_rsa_decrypts(ctx, session_id, masked_key, &pubkey, key.size());
    }
}

// ───────────────────────── positive imports ─────────────────────────

fn import_ecc_roundtrip(curve: Curve, usage: u64) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let hsm_pub = unwrapping_pub(&ctx, session.session_id);
    let key = HostEcc::generate(curve.ecc);

    let resp = import_ok(
        &ctx,
        session.session_id,
        &hsm_pub,
        KEY_CLASS_ECC,
        usage,
        &key.pkcs8(),
    );
    assert_eq!(
        resp.pub_key,
        key.wire_pub(),
        "re-derived public key must match the host key"
    );
    assert_ecc_works(
        &ctx,
        session.session_id,
        curve,
        usage,
        resp.masked_key,
        &resp.pub_key,
    );
}

#[test]
fn import_ecc_p256_sign() {
    import_ecc_roundtrip(P256, SIGN_VERIFY);
}

#[test]
fn import_ecc_p256_derive() {
    import_ecc_roundtrip(P256, KEY_USAGE_DERIVE);
}

#[test]
fn import_ecc_p384_sign() {
    import_ecc_roundtrip(P384, SIGN_VERIFY);
}

#[test]
fn import_ecc_p384_derive() {
    import_ecc_roundtrip(P384, KEY_USAGE_DERIVE);
}

#[test]
fn import_ecc_p521_sign() {
    import_ecc_roundtrip(P521, SIGN_VERIFY);
}

#[test]
fn import_ecc_p521_derive() {
    import_ecc_roundtrip(P521, KEY_USAGE_DERIVE);
}

fn import_rsa_roundtrip(k: usize, crt: bool, usage: u64) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let hsm_pub = unwrapping_pub(&ctx, session.session_id);
    let (key, parts) = host_rsa(k);
    let class = if crt {
        KEY_CLASS_RSA_CRT
    } else {
        KEY_CLASS_RSA
    };

    let resp = import_ok(
        &ctx,
        session.session_id,
        &hsm_pub,
        class,
        usage,
        &parts.pkcs8(),
    );
    assert_eq!(
        resp.pub_key,
        parts.wire_pub(),
        "re-derived n ‖ e must match the host key"
    );
    assert_rsa_works(&ctx, session.session_id, &key, resp.masked_key, usage);
}

#[test]
fn import_rsa_2k_plain_sign() {
    import_rsa_roundtrip(256, false, SIGN_VERIFY);
}

#[test]
fn import_rsa_2k_plain_decrypt() {
    import_rsa_roundtrip(256, false, RSA_DECRYPT);
}

#[test]
fn import_rsa_2k_crt_sign() {
    import_rsa_roundtrip(256, true, SIGN_VERIFY);
}

#[test]
fn import_rsa_2k_crt_decrypt() {
    import_rsa_roundtrip(256, true, RSA_DECRYPT);
}

#[test]
fn import_rsa_3k_plain_sign() {
    import_rsa_roundtrip(384, false, SIGN_VERIFY);
}

#[test]
fn import_rsa_3k_plain_decrypt() {
    import_rsa_roundtrip(384, false, RSA_DECRYPT);
}

#[test]
fn import_rsa_3k_crt_sign() {
    import_rsa_roundtrip(384, true, SIGN_VERIFY);
}

#[test]
fn import_rsa_3k_crt_decrypt() {
    import_rsa_roundtrip(384, true, RSA_DECRYPT);
}

#[test]
fn import_rsa_4k_plain_sign() {
    import_rsa_roundtrip(512, false, SIGN_VERIFY);
}

#[test]
fn import_rsa_4k_plain_decrypt() {
    import_rsa_roundtrip(512, false, RSA_DECRYPT);
}

#[test]
fn import_rsa_4k_crt_sign() {
    import_rsa_roundtrip(512, true, SIGN_VERIFY);
}

#[test]
fn import_rsa_4k_crt_decrypt() {
    import_rsa_roundtrip(512, true, RSA_DECRYPT);
}

// ───────────────────────── rejected imports ─────────────────────────

/// Imports `bad`, expects `status`, then proves the session still imports a
/// valid key of the same class and usage.
fn reject_then_recover(class: u8, usage: u64, bad: &[u8], good: &[u8], status: TborStatus) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let hsm_pub = unwrapping_pub(&ctx, session.session_id);
    import_rejected(
        &ctx,
        session.session_id,
        &hsm_pub,
        class,
        usage,
        bad,
        status,
    );
    import_ok(&ctx, session.session_id, &hsm_pub, class, usage, good);
}

fn reject_ecc(curve: Curve, usage: u64, status: TborStatus, bad: impl Fn(&HostEcc) -> Vec<u8>) {
    let key = HostEcc::generate(curve.ecc);
    reject_then_recover(KEY_CLASS_ECC, usage, &bad(&key), &key.pkcs8(), status);
}

/// The embedded public key belongs to a different key on the same curve.
fn mismatched_q(key: &HostEcc) -> Vec<u8> {
    let other = HostEcc::generate(key.curve);
    ecc_pkcs8(key.curve.oid, &key.d, false, Some(&other.point(0x04)))
}

fn missing_q(key: &HostEcc) -> Vec<u8> {
    ecc_pkcs8(key.curve.oid, &key.d, false, None)
}

/// The correct embedded public key, after `[0]` curve parameters.
fn params_then_q(key: &HostEcc) -> Vec<u8> {
    ecc_pkcs8(key.curve.oid, &key.d, true, Some(&key.point(0x04)))
}

/// A private value of 0, with the key's own public key.
fn zero_d(key: &HostEcc) -> Vec<u8> {
    let d = vec![0; key.curve.raw];
    ecc_pkcs8(key.curve.oid, &d, false, Some(&key.point(0x04)))
}

/// A private value equal to the curve order, with the key's own public key.
fn order_d(key: &HostEcc) -> Vec<u8> {
    ecc_pkcs8(
        key.curve.oid,
        key.curve.order,
        false,
        Some(&key.point(0x04)),
    )
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_mismatched_q_p256_sign() {
    reject_ecc(P256, SIGN_VERIFY, BAD_STRUCTURE, mismatched_q);
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_mismatched_q_p384_derive() {
    reject_ecc(P384, KEY_USAGE_DERIVE, BAD_STRUCTURE, mismatched_q);
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_mismatched_q_p521_sign() {
    reject_ecc(P521, SIGN_VERIFY, BAD_STRUCTURE, mismatched_q);
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_missing_q_p256_derive() {
    reject_ecc(P256, KEY_USAGE_DERIVE, BAD_STRUCTURE, missing_q);
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_missing_q_p384_sign() {
    reject_ecc(P384, SIGN_VERIFY, BAD_STRUCTURE, missing_q);
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_missing_q_p521_derive() {
    reject_ecc(P521, KEY_USAGE_DERIVE, BAD_STRUCTURE, missing_q);
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_compressed_q_02_p256() {
    reject_ecc(P256, SIGN_VERIFY, BAD_STRUCTURE, |k| {
        ecc_pkcs8(k.curve.oid, &k.d, false, Some(&k.compressed(0x02)))
    });
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_compressed_q_03_p384() {
    reject_ecc(P384, SIGN_VERIFY, BAD_STRUCTURE, |k| {
        ecc_pkcs8(k.curve.oid, &k.d, false, Some(&k.compressed(0x03)))
    });
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_hybrid_q_06_p256() {
    reject_ecc(P256, SIGN_VERIFY, BAD_STRUCTURE, |k| {
        ecc_pkcs8(k.curve.oid, &k.d, false, Some(&k.point(0x06)))
    });
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_hybrid_q_07_p521() {
    reject_ecc(P521, KEY_USAGE_DERIVE, BAD_STRUCTURE, |k| {
        ecc_pkcs8(k.curve.oid, &k.d, false, Some(&k.point(0x07)))
    });
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_params_p256_sign() {
    reject_ecc(P256, SIGN_VERIFY, BAD_STRUCTURE, params_then_q);
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_params_p384_derive() {
    reject_ecc(P384, KEY_USAGE_DERIVE, BAD_STRUCTURE, params_then_q);
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_ecc_params_p521_sign() {
    reject_ecc(P521, SIGN_VERIFY, BAD_STRUCTURE, params_then_q);
}

#[test]
fn reject_ecc_d_zero_p256_sign() {
    reject_ecc(P256, SIGN_VERIFY, BAD_SCALAR, zero_d);
}

#[test]
fn reject_ecc_d_zero_p384_derive() {
    reject_ecc(P384, KEY_USAGE_DERIVE, BAD_SCALAR, zero_d);
}

#[test]
fn reject_ecc_d_zero_p521_sign() {
    reject_ecc(P521, SIGN_VERIFY, BAD_SCALAR, zero_d);
}

#[test]
fn reject_ecc_d_order_p256_derive() {
    reject_ecc(P256, KEY_USAGE_DERIVE, BAD_SCALAR, order_d);
}

#[test]
fn reject_ecc_d_order_p384_sign() {
    reject_ecc(P384, SIGN_VERIFY, BAD_SCALAR, order_d);
}

#[test]
fn reject_ecc_d_order_p521_derive() {
    reject_ecc(P521, KEY_USAGE_DERIVE, BAD_SCALAR, order_d);
}

/// Corrupts one RSA component so the key pair is inconsistent but still
/// decodes, and expects the PCT to reject it.
fn reject_rsa(k: usize, crt: bool, usage: u64, corrupt: impl Fn(&mut RsaParts)) {
    let (_, parts) = host_rsa(k);
    let mut bad = parts.clone();
    corrupt(&mut bad);
    let class = if crt {
        KEY_CLASS_RSA_CRT
    } else {
        KEY_CLASS_RSA
    };
    reject_then_recover(
        class,
        usage,
        &bad.pkcs8(),
        &parts.pkcs8(),
        TborStatus::PctValidationRsaUnwrapRsaKeyFailed,
    );
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_rsa_2k_plain_d_sign() {
    reject_rsa(256, false, SIGN_VERIFY, |p| p.d = plus_two(&p.d));
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_rsa_2k_plain_d_decrypt() {
    reject_rsa(256, false, RSA_DECRYPT, |p| p.d = plus_two(&p.d));
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_rsa_4k_plain_d_sign() {
    reject_rsa(512, false, SIGN_VERIFY, |p| p.d = plus_two(&p.d));
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_rsa_2k_crt_dp_sign() {
    reject_rsa(256, true, SIGN_VERIFY, |p| p.dp = plus_two(&p.dp));
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_rsa_2k_crt_dq_decrypt() {
    reject_rsa(256, true, RSA_DECRYPT, |p| p.dq = plus_two(&p.dq));
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_rsa_3k_crt_dp_decrypt() {
    reject_rsa(384, true, RSA_DECRYPT, |p| p.dp = plus_two(&p.dp));
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_rsa_4k_crt_dq_sign() {
    reject_rsa(512, true, SIGN_VERIFY, |p| p.dq = plus_two(&p.dq));
}

/// Replaces one CRT prime with the same-position prime of another key, so
/// the pair no longer matches `n`.
fn swap_prime(k: usize, crt_p: bool) -> impl Fn(&mut RsaParts) {
    let (_, other) = host_rsa(k);
    move |p: &mut RsaParts| {
        if crt_p {
            p.p = other.p.clone();
        } else {
            p.q = other.q.clone();
        }
    }
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_rsa_2k_crt_p_sign() {
    reject_rsa(256, true, SIGN_VERIFY, swap_prime(256, true));
}

#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_rsa_2k_crt_q_decrypt() {
    reject_rsa(256, true, RSA_DECRYPT, swap_prime(256, false));
}

/// A wrong CRT coefficient. Uno derives its CRT operand from `p` and `q`, so
/// the result shows whether `qInv` reaches the key at all: either the PCT
/// rejects the key or the imported key is consistent and works.
#[test]
fn rsa_2k_crt_qinv_corrupted() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let hsm_pub = unwrapping_pub(&ctx, session.session_id);
    let (key, parts) = host_rsa(256);
    let mut bad = parts.clone();
    bad.qinv = plus_two(&bad.qinv);
    let req = unwrap_req(
        session.session_id,
        &hsm_pub,
        KEY_CLASS_RSA_CRT,
        SIGN_VERIFY,
        &bad.pkcs8(),
    );
    match ctx.tbor(&req) {
        Ok(resp) => assert_rsa_works(&ctx, session.session_id, &key, resp.masked_key, SIGN_VERIFY),
        Err(DdiError::TborStatus(TborStatus::PctValidationRsaUnwrapRsaKeyFailed)) => {}
        Err(e) => panic!("unexpected result for a wrong qInv: {e:?}"),
    }
}

/// Rejects an inconsistent RSA-4096 CRT key 330 times, more than the vault
/// could hold if each rejection leaked a stored key, and returns the
/// consistent host key it came from.
fn reject_rsa_4k_repeatedly(
    ctx: &TestCtx,
    session_id: u16,
    hsm_pub: &[u8],
) -> (RsaPrivateKey, RsaParts) {
    let (key, parts) = host_rsa(512);
    let mut bad = parts.clone();
    bad.dq = plus_two(&bad.dq);
    let bad_der = bad.pkcs8();
    for _ in 0..330 {
        import_rejected(
            ctx,
            session_id,
            hsm_pub,
            KEY_CLASS_RSA_CRT,
            SIGN_VERIFY,
            &bad_der,
            TborStatus::PctValidationRsaUnwrapRsaKeyFailed,
        );
    }
    (key, parts)
}

/// Rejected imports must not leave key material in the vault. A stored
/// RSA-4096 CRT key takes about 2,600 bytes, so a partition's tables hold at
/// most about 325 of them. This rejects 330 inconsistent RSA-4096 CRT keys in
/// a row, then imports the valid key: if each rejection had stored its key,
/// the vault would have run out of space first.
#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_repeated_then_valid() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let hsm_pub = unwrapping_pub(&ctx, session.session_id);
    let (key, parts) = reject_rsa_4k_repeatedly(&ctx, session.session_id, &hsm_pub);
    for _ in 0..3 {
        let resp = import_ok(
            &ctx,
            session.session_id,
            &hsm_pub,
            KEY_CLASS_RSA_CRT,
            SIGN_VERIFY,
            &parts.pkcs8(),
        );
        assert_rsa_works(&ctx, session.session_id, &key, resp.masked_key, SIGN_VERIFY);
    }
}

/// Like [`reject_repeated_then_valid`], but proves recovery with P-256
/// imports, whose masked blobs are a whole number of AES blocks.
#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_repeated_then_ecc_valid() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let hsm_pub = unwrapping_pub(&ctx, session.session_id);
    reject_rsa_4k_repeatedly(&ctx, session.session_id, &hsm_pub);
    for _ in 0..3 {
        let key = HostEcc::generate(P256.ecc);
        let resp = import_ok(
            &ctx,
            session.session_id,
            &hsm_pub,
            KEY_CLASS_ECC,
            SIGN_VERIFY,
            &key.pkcs8(),
        );
        assert_eq!(resp.pub_key, key.wire_pub(), "re-derived public key");
        assert_ecc_signs(
            &ctx,
            session.session_id,
            resp.masked_key,
            &resp.pub_key,
            P256.digest_len,
        );
    }
}

/// Every malformed-import leaf in one test, with no valid import in between:
/// ECC 3 curves × 2 usages × 9 variants, and RSA 3 sizes × 2 usages × 6
/// component errors. Each must be rejected with its check's exact status.
/// Valid P-256 imports must still work afterwards.
#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock", feature = "sock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn reject_matrix() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;
    let hsm_pub = unwrapping_pub(&ctx, sid);
    let mut failures = Vec::new();
    let mut leaves = 0;
    let mut expect_rejected =
        |leaf: String, class: u8, usage: u64, der: &[u8], want: TborStatus| {
            leaves += 1;
            let req = unwrap_req(sid, &hsm_pub, class, usage, der);
            match ctx.tbor(&req) {
                Err(DdiError::TborStatus(got)) if got == want => {}
                Ok(_) => failures.push(format!("{leaf}: accepted")),
                Err(e) => failures.push(format!("{leaf}: {e:?}")),
            }
        };

    for curve in [P256, P384, P521] {
        for usage in [SIGN_VERIFY, KEY_USAGE_DERIVE] {
            let key = HostEcc::generate(curve.ecc);
            let other = HostEcc::generate(curve.ecc);
            let point = |q: &[u8]| ecc_pkcs8(curve.ecc.oid, &key.d, false, Some(q));
            let variants = [
                ("mismatched", point(&other.point(0x04)), BAD_STRUCTURE),
                (
                    "missing",
                    ecc_pkcs8(curve.ecc.oid, &key.d, false, None),
                    BAD_STRUCTURE,
                ),
                ("compressed-02", point(&key.compressed(0x02)), BAD_STRUCTURE),
                ("compressed-03", point(&key.compressed(0x03)), BAD_STRUCTURE),
                ("hybrid-06", point(&key.point(0x06)), BAD_STRUCTURE),
                ("hybrid-07", point(&key.point(0x07)), BAD_STRUCTURE),
                ("[0] parameters", params_then_q(&key), BAD_STRUCTURE),
                ("d = 0", zero_d(&key), BAD_SCALAR),
                ("d = n", order_d(&key), BAD_SCALAR),
            ];
            for (name, der, want) in variants {
                expect_rejected(
                    format!("ecc {:?} usage={usage:#x} {name}", curve.ecc.host),
                    KEY_CLASS_ECC,
                    usage,
                    &der,
                    want,
                );
            }
        }
    }

    for k in [256, 384, 512] {
        for usage in [SIGN_VERIFY, RSA_DECRYPT] {
            let (_, parts) = host_rsa(k);
            let (_, donor) = host_rsa(k);
            let corrupt = |f: &dyn Fn(&mut RsaParts)| {
                let mut bad = parts.clone();
                f(&mut bad);
                bad.pkcs8()
            };
            let cases = [
                (
                    "plain d+2",
                    KEY_CLASS_RSA,
                    corrupt(&|p| p.d = plus_two(&p.d)),
                ),
                (
                    "crt p swapped",
                    KEY_CLASS_RSA_CRT,
                    corrupt(&|p| p.p = donor.p.clone()),
                ),
                (
                    "crt q swapped",
                    KEY_CLASS_RSA_CRT,
                    corrupt(&|p| p.q = donor.q.clone()),
                ),
                (
                    "crt dp+2",
                    KEY_CLASS_RSA_CRT,
                    corrupt(&|p| p.dp = plus_two(&p.dp)),
                ),
                (
                    "crt dq+2",
                    KEY_CLASS_RSA_CRT,
                    corrupt(&|p| p.dq = plus_two(&p.dq)),
                ),
                (
                    "crt qinv+2",
                    KEY_CLASS_RSA_CRT,
                    corrupt(&|p| p.qinv = plus_two(&p.qinv)),
                ),
            ];
            for (name, class, der) in cases {
                expect_rejected(
                    format!("rsa {}-bit usage={usage:#x} {name}", k * 8),
                    class,
                    usage,
                    &der,
                    TborStatus::PctValidationRsaUnwrapRsaKeyFailed,
                );
            }
        }
    }

    let key = HostEcc::generate(P256.ecc);
    let resp = import_ok(
        &ctx,
        sid,
        &hsm_pub,
        KEY_CLASS_ECC,
        SIGN_VERIFY,
        &key.pkcs8(),
    );
    assert_ecc_signs(&ctx, sid, resp.masked_key, &resp.pub_key, P256.digest_len);

    assert!(
        failures.is_empty(),
        "{} of {leaves} malformed imports were not rejected as expected:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ───────────────────────── generation ─────────────────────────

fn generate_roundtrip(curve: Curve, usage: u64) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: curve.wire,
            key_usage: if usage == SIGN_VERIFY {
                KEY_USAGE_SIGN
            } else {
                KEY_USAGE_DERIVE
            },
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    assert_eq!(
        resp.pub_key.len(),
        2 * curve.ecc.wire_coord,
        "wire public key length"
    );
    assert_ecc_works(
        &ctx,
        session.session_id,
        curve,
        usage,
        resp.masked_key,
        &resp.pub_key,
    );
}

#[test]
fn generate_ecc_p256_sign() {
    generate_roundtrip(P256, SIGN_VERIFY);
}

#[test]
fn generate_ecc_p256_derive() {
    generate_roundtrip(P256, KEY_USAGE_DERIVE);
}

#[test]
fn generate_ecc_p384_sign() {
    generate_roundtrip(P384, SIGN_VERIFY);
}

#[test]
fn generate_ecc_p384_derive() {
    generate_roundtrip(P384, KEY_USAGE_DERIVE);
}

#[test]
fn generate_ecc_p521_sign() {
    generate_roundtrip(P521, SIGN_VERIFY);
}

#[test]
fn generate_ecc_p521_derive() {
    generate_roundtrip(P521, KEY_USAGE_DERIVE);
}

// ───────────────────────── unwrapping key ─────────────────────────

/// The unwrapping key becomes available and stays the same across calls.
#[test]
fn unwrapping_key_available_and_stable() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let first = unwrapping_pub(&ctx, session.session_id);
    let second = unwrapping_pub(&ctx, session.session_id);
    assert_eq!(first.len(), 260, "RSA-2048 n_le ‖ e_le");
    assert_eq!(first, second, "the unwrapping key must be stable");
    assert!(first.iter().any(|&b| b != 0), "a published key is non-zero");
}
