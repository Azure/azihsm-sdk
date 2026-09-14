// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `MlDsaSign` / `MlDsaVerify` commands.
//!
//! These exercise both directions of the post-quantum signature path
//! against a device that speaks **ML-DSA-44** (FIPS 204):
//!
//! * **device signs, host verifies** — generate a keypair on the host,
//!   import the signing key per call, and check the returned signature
//!   with the independent `ml-dsa` implementation.
//! * **host signs, device verifies** — sign on the host and have the
//!   device confirm it.
//!
//! The device signs **deterministically**, so a fixed key and message
//! always produce the same signature.  That is what lets the first test
//! assert byte equality against a host-computed signature rather than
//! settling for "it verifies".
//!
//! These run on every backend: in-process on the emulator, and over the
//! native OS backend against real silicon.
//!
//! Both commands persist nothing and touch no partition state, so they
//! need only an open session whose PSK has been rotated off the public
//! default -- `bootstrap_rotated_co`, not the heavier
//! `finalized_co_session`. Requiring a finalized partition would pull in
//! `PartFinal` PTA-chain validation, which these commands do not use.
//!
//! A signature that does not verify comes back as
//! [`TborStatus::MlDsaVerifyFailed`], not as a flag inside a successful
//! response, so the negative tests assert on the status.

use azihsm_ddi_tbor_types::TborMlDsaSignReq;
use azihsm_ddi_tbor_types::TborMlDsaVerifyReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ML_DSA_44_SIGNATURE_LEN;
use azihsm_ddi_tbor_types::ML_DSA_44_SIGNING_KEY_LEN;
use azihsm_ddi_tbor_types::ML_DSA_44_VERIFYING_KEY_LEN;
use ml_dsa::signature::Keypair;
use ml_dsa::signature::Verifier;
use ml_dsa::MlDsa44;
use ml_dsa::Signature;
use ml_dsa::SigningKey;
use ml_dsa::VerifyingKey;

use crate::harness::bootstrap_rotated_co;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

/// A deterministic 32-byte seed, so a failing run is reproducible.
const SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Host-side ML-DSA-44 keypair as the wire encodings the device consumes:
/// `(encoded_signing_key, encoded_verifying_key)`.
///
/// The device imports the **expanded** signing key (FIPS 204 Algorithm 25),
/// not the 32-byte seed — expanding a seed means re-running key generation,
/// which is exactly what does not fit in the device's RAM.
fn host_keypair() -> (Vec<u8>, Vec<u8>) {
    let sk = SigningKey::<MlDsa44>::from_seed(&SEED.into());
    // `to_expanded` is deprecated in favour of `to_seed`, but the seed is
    // exactly what this device cannot consume: expanding it means running
    // key generation, which does not fit in its RAM.
    #[allow(deprecated)]
    (
        sk.expanded_key().to_expanded().to_vec(),
        sk.verifying_key().encode().to_vec(),
    )
}

/// Sign `msg` on the host with the same deterministic variant the device
/// uses, returning the encoded signature.
fn host_sign(msg: &[u8]) -> Vec<u8> {
    let sk = SigningKey::<MlDsa44>::from_seed(&SEED.into());
    sk.expanded_key()
        .sign_deterministic(msg, &[])
        .expect("host ML-DSA sign")
        .encode()
        .to_vec()
}

/// Verify an encoded signature on the host against an encoded verifying key.
fn host_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pk_enc) = pk.try_into() else {
        return false;
    };
    let Ok(sig_enc) = sig.try_into() else {
        return false;
    };
    let Some(decoded) = Signature::<MlDsa44>::decode(sig_enc) else {
        return false;
    };
    VerifyingKey::<MlDsa44>::decode(pk_enc)
        .verify(msg, &decoded)
        .is_ok()
}

#[test]
fn ml_dsa_sign_verifies_on_host() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (sk, pk) = host_keypair();
    assert_eq!(sk.len(), ML_DSA_44_SIGNING_KEY_LEN);
    assert_eq!(pk.len(), ML_DSA_44_VERIFYING_KEY_LEN);

    let msg = b"post-quantum signature over the DDI".to_vec();
    let resp = ctx
        .tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            signing_key: sk,
            msg: msg.clone(),
        })
        .expect("MlDsaSign");

    assert_eq!(resp.signature.len(), ML_DSA_44_SIGNATURE_LEN);
    assert!(
        host_verify(&pk, &msg, &resp.signature),
        "the device signature must verify under the host verifying key",
    );

    // Signing is deterministic, so the device must reproduce the host's
    // signature byte for byte — a stronger claim than "it verifies", and
    // one that would catch a device that silently signed a different
    // message or used a different variant.
    assert_eq!(
        resp.signature,
        host_sign(&msg),
        "deterministic signing must be reproducible off-device",
    );
}

#[test]
fn ml_dsa_verify_accepts_host_signature() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (_sk, pk) = host_keypair();

    let msg = b"host signs, device verifies".to_vec();
    let sig = host_sign(&msg);

    ctx.tbor(&TborMlDsaVerifyReq {
        session_id: session.session_id,
        verifying_key: pk,
        msg,
        signature: sig,
    })
    .expect("MlDsaVerify must accept a valid host signature");
}

#[test]
fn ml_dsa_verify_rejects_tampered_message() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (_sk, pk) = host_keypair();

    let sig = host_sign(b"the original message");

    ctx.expect_fw_reject(
        &TborMlDsaVerifyReq {
            session_id: session.session_id,
            verifying_key: pk,
            msg: b"the tampered message".to_vec(),
            signature: sig,
        },
        TborStatus::MlDsaVerifyFailed,
    );
}

#[test]
fn ml_dsa_verify_rejects_tampered_signature() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (_sk, pk) = host_keypair();

    let msg = b"a message whose signature gets corrupted".to_vec();
    let mut sig = host_sign(&msg);
    // Flip a bit in the middle of the signature: still the right length and
    // so still schema-valid, but no longer a valid signature.
    sig[ML_DSA_44_SIGNATURE_LEN / 2] ^= 0x01;

    ctx.expect_fw_reject(
        &TborMlDsaVerifyReq {
            session_id: session.session_id,
            verifying_key: pk,
            msg,
            signature: sig,
        },
        TborStatus::MlDsaVerifyFailed,
    );
}

#[test]
fn ml_dsa_sign_rejects_wrong_key_length() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // The wire schema admits 2560..=4032 B so it covers both parameter
    // sets, but this device is built for ML-DSA-44 and must accept only
    // exactly 2560 B rather than misreading a differently-sized key.
    //
    // Note this uses 2561 B, not a real 4032 B ML-DSA-65 key: a full
    // ML-DSA-65 signing key does not fit the 4 KiB TBOR request buffer at
    // all, even with an empty message, so it cannot be put on the wire in
    // the first place. That transport limit — not just the 322 KiB signing
    // stack frame — is a second, independent blocker for ML-DSA-65 signing.
    ctx.expect_fw_reject(
        &TborMlDsaSignReq {
            session_id: session.session_id,
            signing_key: vec![0xAB; 2561],
            msg: Vec::new(),
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn ml_dsa_sign_rejects_out_of_range_coefficients() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mut sk, _pk) = host_keypair();

    // Saturate the packed `s1`/`s2` region. FIPS 204 carries an eta = 2
    // coefficient in 3 bits, so the field can encode 0..=7 while only
    // 0..=4 are legal; 0xFF therefore produces out-of-range coefficients.
    // The decoder asserts on exactly this, so without the pre-validation
    // the device would panic — and firmware is `panic = "abort"`.
    for b in sk.iter_mut().skip(128) {
        *b = 0xFF;
    }

    ctx.expect_fw_reject(
        &TborMlDsaSignReq {
            session_id: session.session_id,
            signing_key: sk,
            msg: b"saturated key".to_vec(),
        },
        TborStatus::MlDsaInvalidSigningKey,
    );

    // The device must still be healthy afterwards — a rejection, not a reset.
    let (sk2, pk2) = host_keypair();
    let msg = b"still alive".to_vec();
    let resp = ctx
        .tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            signing_key: sk2,
            msg: msg.clone(),
        })
        .expect("device must remain usable after a malformed key");
    assert!(host_verify(&pk2, &msg, &resp.signature));
}
