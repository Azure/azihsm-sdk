// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE key schedule (RFC 9180 §5.1).
//!
//! Both [`key_schedule`] and [`key_schedule_export`] start by deriving
//! `secret`, the `key_schedule_context` (`KSC`), and the per-suite
//! `hpke_suite_id` from the shared inputs. They then diverge:
//!
//! * [`key_schedule`] expands `secret` into the AEAD `key` and
//!   `base_nonce`.
//! * [`key_schedule_export`] expands `secret` into the `exporter_secret`.

use super::kdf::labeled_expand;
use super::kdf::labeled_extract;
use super::suite::HpkeSuite;
use crate::CryptoError;

/// Outputs of [`derive_secret_and_ksc`].
struct ScheduleState {
    /// Cached HPKE suite identifier (`b"HPKE" || kem_id || kdf_id || aead_id`).
    suite_id: [u8; 10],
    /// `secret = LabeledExtract(shared_secret, "secret", psk)` (`Nh` bytes).
    secret: Vec<u8>,
    /// `key_schedule_context = mode || psk_id_hash || info_hash`
    /// (`1 + 2*Nh` bytes).
    ksc: Vec<u8>,
}

/// Compute the shared `(secret, ksc)` pair used by every HPKE key
/// schedule (export and AEAD).
fn derive_secret_and_ksc(
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<ScheduleState, CryptoError> {
    let algo = suite.kdf_hash();
    let nh = suite.nh();
    let suite_id = suite.hpke_suite_id();

    let psk_id_hash = labeled_extract(&algo, &suite_id, &[], b"psk_id_hash", psk_id)?;
    let info_hash = labeled_extract(&algo, &suite_id, &[], b"info_hash", info)?;

    let mut ksc = Vec::with_capacity(1 + 2 * nh);
    ksc.push(mode);
    ksc.extend_from_slice(&psk_id_hash);
    ksc.extend_from_slice(&info_hash);

    let secret = labeled_extract(&algo, &suite_id, shared_secret, b"secret", psk)?;

    Ok(ScheduleState {
        suite_id,
        secret,
        ksc,
    })
}

/// Derive `(key, base_nonce)` from `shared_secret + info` per RFC 9180
/// §5.1. For Base / Auth modes pass empty `psk` / `psk_id`.
pub(crate) fn key_schedule(
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let st = derive_secret_and_ksc(suite, mode, shared_secret, info, psk, psk_id)?;
    let algo = suite.kdf_hash();
    let key = labeled_expand(&algo, &st.suite_id, &st.secret, b"key", &st.ksc, suite.nk())?;
    let base_nonce = labeled_expand(
        &algo,
        &st.suite_id,
        &st.secret,
        b"base_nonce",
        &st.ksc,
        suite.nn(),
    )?;
    Ok((key, base_nonce))
}

/// Derive `exporter_secret` from `shared_secret + info` per RFC 9180
/// §5.1 (only the secret/KSC step, then `Expand("exp", ksc, Nh)`).
pub(crate) fn key_schedule_export(
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let st = derive_secret_and_ksc(suite, mode, shared_secret, info, psk, psk_id)?;
    let algo = suite.kdf_hash();
    labeled_expand(&algo, &st.suite_id, &st.secret, b"exp", &st.ksc, suite.nh())
}
