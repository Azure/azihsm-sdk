// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::AesKey;
use azihsm_ddi::Ddi;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::build_psk_change_aad;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPskChangeReq;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CO;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
use azihsm_ddi_tbor_types::PSK_CHANGE_AAD_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use crate::common::DdiTest;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

/// Fuzz input for the TBOR `PskChange` handler.
///
/// The handler bails almost immediately when the wire envelope fails
/// to open under the session's `param_key`, so this input is
/// structured to always emit a properly-sealed envelope of exactly
/// `PSK_CHANGE_ENVELOPE_LEN` (100 B). That anchors coverage past
/// `aead_open` and lets the fuzzer drive the AAD-length / AAD-equality
/// / default-PSK / persist branches inside the handler body.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// AES-GCM nonce fed to the AEAD seal.
    iv: [u8; 12],
    /// Envelope shape — sizes aad/payload so the sealed envelope is
    /// always exactly 100 B on the wire.
    shape: Shape,
    /// Optional post-seal single-byte flip that drives the AEAD tag
    /// verification failure branch.
    tamper: Option<Tamper>,
}

/// Sizes the sealed envelope's AAD and payload regions. The three
/// variants correspond to the three `aad_len` values (0, 32, 64) that
/// the AES-GCM `aad_granularity` allows while still totalling 100 wire
/// bytes.
#[derive(Arbitrary, Debug)]
enum Shape {
    /// AAD=32 B, payload=32 B — the only shape that can drive the
    /// successful persist path. `canonical_aad = true` uses the
    /// FW-expected AAD (`build_psk_change_aad(session_id)`) so the
    /// handler advances past the AAD equality check; `false` ships a
    /// fuzzer-supplied AAD.
    Canonical {
        canonical_aad: bool,
        aad: [u8; PSK_CHANGE_AAD_LEN],
        psk: FuzzPsk,
    },
    /// AAD=0 B, payload=64 B — envelope opens successfully; handler
    /// rejects at the AAD length check.
    EmptyAad { payload: [u8; 64] },
    /// AAD=64 B, payload=0 B — envelope opens successfully; handler
    /// rejects at the AAD length check (and also at the payload
    /// length check, but AAD is validated first).
    OversizedAad { aad: [u8; 64] },
}

/// Candidate PSK plaintext choices. The two default variants trip the
/// public-default-PSK gate; `Custom` almost always passes it and
/// drives the persist path.
#[derive(Arbitrary, Debug)]
enum FuzzPsk {
    DefaultCo,
    DefaultCu,
    Custom([u8; PSK_LEN]),
}

/// Post-seal byte flip: pick an offset (modulo envelope length) and an
/// XOR mask (coerced to non-zero) so the mutation is always observable.
#[derive(Arbitrary, Debug)]
struct Tamper {
    offset: u16,
    mask: u8,
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|_dev: &mut <DdiTest as Ddi>::Dev, _path: &str| {
        let ctx = CTX.get_or_init(TestCtx::new);
        ctx.erase().expect("erase should succeed");

        let session = ctx
            .open_session(CU, SessionType::PlainText)
            .expect("session open should succeed");
        let handshake = session.handshake();

        let (aad, payload) = match &input.shape {
            Shape::Canonical {
                canonical_aad,
                aad,
                psk,
            } => {
                let aad_bytes = if *canonical_aad {
                    build_psk_change_aad(handshake.session_id).to_vec()
                } else {
                    aad.to_vec()
                };
                let payload_bytes = match psk {
                    FuzzPsk::DefaultCo => DEFAULT_PSK_CO.to_vec(),
                    FuzzPsk::DefaultCu => DEFAULT_PSK_CU.to_vec(),
                    FuzzPsk::Custom(bytes) => bytes.to_vec(),
                };
                (aad_bytes, payload_bytes)
            }
            Shape::EmptyAad { payload } => (Vec::new(), payload.to_vec()),
            Shape::OversizedAad { aad } => (aad.to_vec(), Vec::new()),
        };

        let mut envelope = seal_envelope(&handshake.param_key, &input.iv, &aad, &payload);

        if let Some(t) = &input.tamper {
            if !envelope.is_empty() {
                let idx = (t.offset as usize) % envelope.len();
                envelope[idx] ^= t.mask | 1;
            }
        }

        let psk_change_req = TborPskChangeReq {
            session_id: session.session_id(),
            psk_envelope: envelope,
        };
        let _ = ctx.tbor(&psk_change_req);

        session.close().expect("session close should succeed");
    });
});

/// AEAD-seal `pt` under `key` with the fuzz-controlled `iv` and `aad`.
/// Panics only on programmer error (crypto layer returning `Err` for a
/// shape we've validated above); an AEAD seal cannot fail on well-sized
/// inputs with a supported alg.
fn seal_envelope(key: &AesKey, iv: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let total = aead_envelope::seal(AeadAlg::AesGcm256, key, iv, aad, pt, None)
        .expect("aead seal size query should succeed");
    let mut buf = vec![0u8; total];
    let written = aead_envelope::seal(AeadAlg::AesGcm256, key, iv, aad, pt, Some(&mut buf))
        .expect("aead seal should succeed");
    buf.truncate(written);
    buf
}
