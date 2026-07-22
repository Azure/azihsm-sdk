// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-session key-availability access tests.
//!
//! Verifies the `availability` semantics across sessions via two probes:
//!
//! - **Use by key id** — create a key in one session, note its key id,
//!   open a second session, and try to use that id there.
//! - **Masked-blob re-import** — create a key, take its host-persisted
//!   masked blob, and try to `UnmaskKey` it from a second session
//!   (including one opened with the same or a different session seed).
//!
//! In both cases: `App` keys are partition-wide and accessible from any
//! session; `Session` keys are scoped to their creating session and
//! rejected everywhere else. Session isolation is unconditional — a
//! `Session` key's blob is never re-importable elsewhere, because its
//! masking key (`MK_SESSION`) is fresh-random per session, not derived
//! from the seed.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

const REV: Option<DdiApiRev> = Some(DdiApiRev { major: 1, minor: 0 });

/// Open a second, independent session (fresh device handle) on the
/// already-provisioned partition and return its handle + session id.
fn open_second_session(ddi: &DdiTest, path: &str) -> (<DdiTest as Ddi>::Dev, u16) {
    let handle = ddi.open_dev(path).unwrap();
    let (cred, pub_key) = encrypt_userid_pin_for_open_session(
        &handle,
        TEST_CRED_ID,
        TEST_CRED_PIN,
        TEST_SESSION_SEED,
    );
    let resp = helper_open_session(&handle, None, REV, cred, pub_key)
        .expect("second OpenSession must succeed");
    let sid = resp.hdr.sess_id.expect("second session must have an id");
    (handle, sid)
}

/// Create an AES-256 key in `sess_id` with the given availability and
/// return its key id.
fn create_aes_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: u16,
    availability: DdiKeyAvailability,
) -> u16 {
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, availability);
    let resp = helper_aes_generate(
        dev,
        Some(sess_id),
        REV,
        DdiAesKeySize::Aes256,
        None,
        key_props,
    )
    .expect("AES key gen must succeed");
    resp.data.key_id
}

/// Use `key_id` in `sess_id` by encrypting a block — the "access the key
/// by id" probe.
fn use_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: u16,
    key_id: u16,
) -> Result<DdiAesEncryptDecryptCmdResp, DdiError> {
    helper_aes_encrypt_decrypt(
        dev,
        Some(sess_id),
        REV,
        key_id,
        DdiAesOp::Encrypt,
        MborByteArray::from_slice(&[0xA5u8; 32]).expect("msg byte array"),
        MborByteArray::from_slice(&[0x11u8; 16]).expect("iv byte array"),
    )
}

#[test]
fn test_app_key_usable_across_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id_a| {
            let key_id = create_aes_key(dev, session_id_a, DdiKeyAvailability::App);

            // Sanity: usable in its own session.
            assert!(
                use_key(dev, session_id_a, key_id).is_ok(),
                "App key must be usable in its creating session"
            );

            // A second, independent session must also be able to use it.
            let (handle_b, session_id_b) = open_second_session(ddi, path);
            let resp = use_key(&handle_b, session_id_b, key_id);
            assert!(
                resp.is_ok(),
                "App-availability key must be usable from another session, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_session_key_not_usable_across_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id_a| {
            let key_id = create_aes_key(dev, session_id_a, DdiKeyAvailability::Session);

            // Sanity: usable in its own session.
            assert!(
                use_key(dev, session_id_a, key_id).is_ok(),
                "Session key must be usable in its creating session"
            );

            // A second, independent session must NOT be able to use it.
            let (handle_b, session_id_b) = open_second_session(ddi, path);
            let resp = use_key(&handle_b, session_id_b, key_id);
            assert!(
                resp.is_err(),
                "Session-availability key must NOT be usable from another session, got {:?}",
                resp
            );
        },
    );
}

/// Fetch the partition unwrapping key (works from any session — it is a
/// partition-scoped key), wrap a known AES-256 key to it, and RSA-unwrap
/// it in `sess_id` with the given availability. Returns the imported
/// key's id.
fn rsa_unwrap_aes_key(
    dev: &mut <DdiTest as Ddi>::Dev,
    sess_id: u16,
    availability: DdiKeyAvailability,
) -> u16 {
    let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, sess_id);
    let wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, availability);
    let resp = helper_rsa_unwrap(
        dev,
        Some(sess_id),
        REV,
        unwrap_key_id,
        MborByteArray::from_slice(&wrapped).expect("wrapped blob byte array"),
        DdiKeyClass::Aes,
        DdiRsaCryptoPadding::Oaep,
        DdiHashAlgorithm::Sha256,
        None,
        key_props,
    )
    .expect("RSA unwrap must succeed");
    resp.data.key_id
}

#[test]
fn test_rsa_unwrapped_app_key_usable_across_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id_a| {
            let (mut handle_b, session_id_b) = open_second_session(ddi, path);

            // The unwrapping key is partition-wide, so both sessions can
            // unwrap; import an App key in each.
            let key_a = rsa_unwrap_aes_key(dev, session_id_a, DdiKeyAvailability::App);
            let key_b = rsa_unwrap_aes_key(&mut handle_b, session_id_b, DdiKeyAvailability::App);

            // Each App key is usable from the other session.
            assert!(
                use_key(&handle_b, session_id_b, key_a).is_ok(),
                "App key unwrapped in session A must be usable in session B"
            );
            assert!(
                use_key(dev, session_id_a, key_b).is_ok(),
                "App key unwrapped in session B must be usable in session A"
            );
        },
    );
}

#[test]
fn test_rsa_unwrapped_session_key_not_usable_across_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id_a| {
            let (mut handle_b, session_id_b) = open_second_session(ddi, path);

            // Both sessions can unwrap; import a Session-scoped key in each.
            let key_a = rsa_unwrap_aes_key(dev, session_id_a, DdiKeyAvailability::Session);
            let key_b =
                rsa_unwrap_aes_key(&mut handle_b, session_id_b, DdiKeyAvailability::Session);

            // Sanity: each is usable in its own creating session.
            assert!(
                use_key(dev, session_id_a, key_a).is_ok(),
                "Session key must be usable in its creating session A"
            );
            assert!(
                use_key(&handle_b, session_id_b, key_b).is_ok(),
                "Session key must be usable in its creating session B"
            );

            // But NOT from the other session.
            assert!(
                use_key(&handle_b, session_id_b, key_a).is_err(),
                "Session key unwrapped in session A must NOT be usable in session B"
            );
            assert!(
                use_key(dev, session_id_a, key_b).is_err(),
                "Session key unwrapped in session B must NOT be usable in session A"
            );
        },
    );
}

/// Open a second session on the provisioned partition using a specific
/// session `seed`, returning its handle + id.
fn open_session_with_seed(
    ddi: &DdiTest,
    path: &str,
    seed: [u8; 48],
) -> (<DdiTest as Ddi>::Dev, u16) {
    let handle = ddi.open_dev(path).unwrap();
    let (cred, pub_key) =
        encrypt_userid_pin_for_open_session(&handle, TEST_CRED_ID, TEST_CRED_PIN, seed);
    let resp =
        helper_open_session(&handle, None, REV, cred, pub_key).expect("OpenSession must succeed");
    (handle, resp.hdr.sess_id.expect("session id"))
}

/// A session seed distinct from `TEST_SESSION_SEED`.
fn different_seed() -> [u8; 48] {
    let mut seed = TEST_SESSION_SEED;
    seed[0] ^= 0xFF;
    seed[47] ^= 0xFF;
    seed
}

/// Create an AES-256 key in `sess_id` with the given availability and
/// return its host-persisted masked-key blob.
fn create_aes_masked(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: u16,
    availability: DdiKeyAvailability,
) -> MborByteArray<3072> {
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, availability);
    helper_aes_generate(
        dev,
        Some(sess_id),
        REV,
        DdiAesKeySize::Aes256,
        None,
        key_props,
    )
    .expect("AES key gen must succeed")
    .data
    .masked_key
}

/// Try to re-import (`UnmaskKey`) a masked blob in `sess_id`.
fn unmask_in(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: u16,
    blob: MborByteArray<3072>,
) -> Result<DdiUnmaskKeyCmdResp, DdiError> {
    helper_unmask_key(dev, Some(sess_id), REV, blob)
}

#[test]
fn test_app_key_unmaskable_across_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id_a| {
            // App keys are enveloped under the partition MK, so their masked
            // blob is re-importable from any session -- regardless of the
            // session seed.
            let (handle_same, sid_same) = open_session_with_seed(ddi, path, TEST_SESSION_SEED);
            let blob_same = create_aes_masked(dev, session_id_a, DdiKeyAvailability::App);
            assert!(
                unmask_in(&handle_same, sid_same, blob_same).is_ok(),
                "App key must be unmaskable in a same-seed session"
            );

            let (handle_diff, sid_diff) = open_session_with_seed(ddi, path, different_seed());
            let blob_diff = create_aes_masked(dev, session_id_a, DdiKeyAvailability::App);
            assert!(
                unmask_in(&handle_diff, sid_diff, blob_diff).is_ok(),
                "App key must be unmaskable in a different-seed session"
            );
        },
    );
}

#[test]
fn test_session_key_not_unmaskable_across_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id_a| {
            // Sanity: a Session key is unmaskable in its own creating session.
            let own = create_aes_masked(dev, session_id_a, DdiKeyAvailability::Session);
            assert!(
                unmask_in(dev, session_id_a, own).is_ok(),
                "Session key must be unmaskable in its own session"
            );

            // Session keys are enveloped under the session's own random
            // MK_SESSION (not seed-derived), so their masked blob is NOT
            // re-importable from another session -- even one opened with the
            // same seed.
            let (handle_same, sid_same) = open_session_with_seed(ddi, path, TEST_SESSION_SEED);
            let blob_same = create_aes_masked(dev, session_id_a, DdiKeyAvailability::Session);
            assert!(
                unmask_in(&handle_same, sid_same, blob_same).is_err(),
                "Session key must NOT be unmaskable in another same-seed session"
            );

            let (handle_diff, sid_diff) = open_session_with_seed(ddi, path, different_seed());
            let blob_diff = create_aes_masked(dev, session_id_a, DdiKeyAvailability::Session);
            assert!(
                unmask_in(&handle_diff, sid_diff, blob_diff).is_err(),
                "Session key must NOT be unmaskable in a different-seed session"
            );
        },
    );
}

/// Create a P-256 ECC signing key in `sess_id` with the given
/// availability and return its private key id.
fn create_ecc_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: u16,
    availability: DdiKeyAvailability,
) -> u16 {
    let key_props = helper_key_properties(DdiKeyUsage::SignVerify, availability);
    helper_ecc_generate_key_pair(dev, Some(sess_id), REV, DdiEccCurve::P256, None, key_props)
        .expect("ECC key gen must succeed")
        .data
        .private_key_id
}

/// Sign a fixed digest with `key_id` in `sess_id` — the "use the key by
/// id" probe for ECC keys.
fn ecc_sign_with(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: u16,
    key_id: u16,
) -> Result<DdiEccSignCmdResp, DdiError> {
    helper_ecc_sign(
        dev,
        Some(sess_id),
        REV,
        key_id,
        MborByteArray::from_slice(&[1u8; 32]).expect("digest byte array"),
        DdiHashAlgorithm::Sha256,
    )
}

#[test]
fn test_session_key_not_deletable_across_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id_a| {
            let key_id = create_aes_key(dev, session_id_a, DdiKeyAvailability::Session);

            // A second session must not be able to delete session A's
            // Session key (DeleteKey resolves attrs through the guarded
            // vault path, so cross-session delete is rejected).
            let (handle_b, session_id_b) = open_second_session(ddi, path);
            assert!(
                helper_delete_key(&handle_b, Some(session_id_b), REV, key_id).is_err(),
                "Session key must NOT be deletable from another session"
            );

            // The key survives the rejected cross-session delete.
            assert!(
                use_key(dev, session_id_a, key_id).is_ok(),
                "Session key must remain usable in its own session after a rejected cross-session delete"
            );
        },
    );
}

#[test]
fn test_app_key_deletable_across_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id_a| {
            let key_id = create_aes_key(dev, session_id_a, DdiKeyAvailability::App);

            // A second session can delete session A's App key: App keys
            // are partition-wide, so DeleteKey resolves and succeeds
            // regardless of which session issues it.
            let (handle_b, session_id_b) = open_second_session(ddi, path);
            assert!(
                helper_delete_key(&handle_b, Some(session_id_b), REV, key_id).is_ok(),
                "App key must be deletable from another session"
            );

            // The key is gone: it is no longer usable in its own session.
            assert!(
                use_key(dev, session_id_a, key_id).is_err(),
                "App key must be unusable after being deleted from another session"
            );
        },
    );
}

#[test]
fn test_ecc_key_availability_across_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id_a| {
            let (handle_b, session_id_b) = open_second_session(ddi, path);

            // App ECC key: signable from another session (partition-wide).
            let app_key = create_ecc_key(dev, session_id_a, DdiKeyAvailability::App);
            assert!(
                ecc_sign_with(&handle_b, session_id_b, app_key).is_ok(),
                "App ECC key must be signable from another session"
            );

            // Session ECC key: signable in its own session, but not another.
            let sess_key = create_ecc_key(dev, session_id_a, DdiKeyAvailability::Session);
            assert!(
                ecc_sign_with(dev, session_id_a, sess_key).is_ok(),
                "Session ECC key must be signable in its creating session"
            );
            assert!(
                ecc_sign_with(&handle_b, session_id_b, sess_key).is_err(),
                "Session ECC key must NOT be signable from another session"
            );
        },
    );
}
