// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_crypto::EccAlgo;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::Verifier;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_types::*;
use common::EccCurve;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// MBOR key availability. TBOR key-generation responses are masked blobs,
/// not persistent key IDs, so only session-scoped valid keys are generated.
#[derive(Arbitrary, Debug)]
enum KeyAvailability {
    App,
    Session,
}

/// Hash selector from the MBOR request; TBOR identifies the digest algorithm
/// by its byte length instead.
#[derive(Arbitrary, Debug)]
enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Unknown(u32),
}

impl DigestAlgorithm {
    fn digest_len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Unknown(value) => *value as usize % (ECC_DIGEST_MAX_LEN + 1),
        }
    }
}

/// Fuzz input corresponding to the MBOR `EccSign` target.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a valid session-scoped ECC key when the legacy availability
    /// setting can be represented by TBOR.
    use_valid_key_id: bool,
    /// Legacy key availability; TBOR's caller-held masked keys have no App
    /// key-ID lifecycle equivalent.
    key_availability: KeyAvailability,
    /// Curve for valid key generation.
    curve: EccCurve,
    /// Request parameters corresponding to the MBOR request.
    cmdreq_data: FuzzEccSignReq,
}

#[derive(Arbitrary, Debug)]
struct FuzzEccSignReq {
    /// Legacy MBOR key ID, folded into the arbitrary masked-key bytes since
    /// TBOR carries the masked key itself instead.
    key_id: u16,
    /// Host-order digest bytes.
    digest: Vec<u8>,
    /// MBOR hash selector, mapped to TBOR's digest-length selector.
    digest_algo: DigestAlgorithm,
    /// Arbitrary masked-key bytes used when a valid key is not generated.
    masked_key: Vec<u8>,
}

const KEY_SCOPE_SESSION: u8 = 0b001;

fn wire_digest(input: &FuzzEccSignReq) -> Vec<u8> {
    let digest_len = input.digest_algo.digest_len();
    let mut digest = input.digest.clone();
    digest.truncate(digest_len);
    digest.resize(digest_len, 0);
    digest.reverse();
    digest
}

fn fuzzed_masked_key(input: &FuzzEccSignReq) -> Vec<u8> {
    let mut masked_key = input.masked_key.clone();
    masked_key.extend_from_slice(&input.key_id.to_le_bytes());
    masked_key
}

/// Reverse the low `len` bytes of `src` into a fresh big-endian vec.
fn rev(src: &[u8], len: usize) -> Vec<u8> {
    src[..len].iter().rev().copied().collect()
}

/// Verify a device wire-LE ECDSA signature on the host, mirroring the
/// `EccSign` integration-test helper.
///
/// * `pub_le` — `x_le ‖ y_le`, each padded to the curve's wire coordinate.
/// * `sig_le` — `r_le ‖ s_le`, each padded to the curve's wire coordinate.
/// * `digest_le` — the wire-LE digest that was handed to `EccSign`.
fn verify_wire_ecdsa(curve: EccCurve, pub_le: &[u8], sig_le: &[u8], digest_le: &[u8]) -> bool {
    let wire_coord = curve.wire_sig_len() / 2;
    let raw_coord = curve.coord_len();
    assert_eq!(
        pub_le.len(),
        wire_coord * 2,
        "public key length must match the curve wire length"
    );

    // Reverse each full padded coordinate; trailing LE pad becomes leading
    // BE zeros, which `from_hsm_bytes` tolerates.
    let (x_le, y_le) = pub_le.split_at(wire_coord);
    let mut pub_be = rev(x_le, wire_coord);
    pub_be.extend(rev(y_le, wire_coord));
    let pub_key = EccPublicKey::from_hsm_bytes(&pub_be).expect("import generated public key");

    let (r_le, s_le) = sig_le.split_at(wire_coord);
    let mut sig_be = rev(r_le, raw_coord);
    sig_be.extend(rev(s_le, raw_coord));

    // The device reverses the wire-LE digest to big-endian before signing.
    let digest_be = rev(digest_le, digest_le.len());

    Verifier::verify(&mut EccAlgo::default(), &pub_key, &digest_be, &sig_be)
        .expect("host ECDSA verify should run")
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let generate_valid_key =
            input.use_valid_key_id && matches!(input.key_availability, KeyAvailability::Session);

        let (masked_key, pub_key) = if generate_valid_key {
            let resp = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id: session.session_id,
                    scope: KEY_SCOPE_SESSION,
                    curve: input.curve.to_tbor(),
                    key_usage: KEY_USAGE_SIGN,
                    key_label: Vec::new(),
                })
                .expect("session-scoped ECC key generation should succeed");
            (resp.masked_key, Some(resp.pub_key))
        } else {
            (fuzzed_masked_key(&input.cmdreq_data), None)
        };

        let digest = wire_digest(&input.cmdreq_data);
        let expect_success = generate_valid_key
            && matches!(digest.len(), 32 | 48 | 64)
            && digest.len() <= input.curve.max_digest_len();

        let req = TborEccSignReq {
            session_id: session.session_id,
            masked_key,
            digest,
        };
        let result = ctx.tbor(&req);

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                assert_eq!(
                    resp.signature.len(),
                    input.curve.wire_sig_len(),
                    "signature length must match the curve wire length"
                );
                let pub_key = pub_key
                    .as_deref()
                    .expect("valid request always carries a generated public key");
                assert!(
                    verify_wire_ecdsa(input.curve, pub_key, &resp.signature, &req.digest),
                    "signature must verify under the generated public key"
                );
            }
            (Ok(resp), false) => {
                panic!("invalid ECC sign request unexpectedly succeeded")
            }
            (Err(err), true) => panic!("valid ECC sign request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
