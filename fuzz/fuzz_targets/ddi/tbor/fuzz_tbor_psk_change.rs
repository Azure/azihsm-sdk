// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

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

/// CO PSK id — pairs with an `Authenticated` session, mapping to the
/// `CryptoOfficer` role branch of `target_psk_for_role`.
const CO: u8 = 0;
/// CU PSK id — pairs with a `PlainText` session, mapping to the
/// `CryptoUser` role branch.
const CU: u8 = 1;

/// Fuzz input for the TBOR `PskChange` handler.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Session role
    role: FuzzRole,
    /// AES-GCM nonce fed to the AEAD seal.
    iv: [u8; 12],
    /// Envelope shape
    shape: Shape,
    /// Optional post-seal single-byte flip
    tamper: Option<Tamper>,
}

/// Which role's session to open for this iteration.
#[derive(Arbitrary, Debug)]
enum FuzzRole {
    /// `psk_id = 0`, `SessionType::Authenticated`
    Co,
    /// `psk_id = 1`, `SessionType::PlainText`
    Cu,
}

impl FuzzRole {
    fn psk_id(&self) -> u8 {
        match self {
            FuzzRole::Co => CO,
            FuzzRole::Cu => CU,
        }
    }

    fn session_type(&self) -> SessionType {
        match self {
            FuzzRole::Co => SessionType::Authenticated,
            FuzzRole::Cu => SessionType::PlainText,
        }
    }
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
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = ctx
            .open_session(input.role.psk_id(), input.role.session_type())
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

        let mut envelope =
            common::seal_aead_envelope(&handshake.param_key, &input.iv, &aad, &payload);

        if let Some(t) = &input.tamper
            && !envelope.is_empty() {
                let idx = (t.offset as usize) % envelope.len();
                envelope[idx] ^= t.mask | 1;
            }

        let psk_change_req = TborPskChangeReq {
            session_id: session.session_id(),
            psk_envelope: envelope,
        };
        let _ = ctx.tbor(&psk_change_req);

        session.close().expect("session close should succeed");
    });
});
