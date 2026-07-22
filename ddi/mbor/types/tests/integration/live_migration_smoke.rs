// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Live-migration smoke test for the emu backend.
//!
//! Exercises the full live-migration session lifecycle end-to-end,
//! covering the firmware behaviour that is emu-specific (the sim echoes
//! rather than re-keys):
//!
//! 1. An in-session op (AES key gen) succeeds on the open session.
//! 2. A simulated NSSR (`erase`) migrates the partition; the session
//!    slot is preserved as renegotiation-pending.
//! 3. The same in-session op is now rejected with
//!    `SessionNeedsRenegotiation` by the central session-liveness gate.
//! 4. After re-establishing the credential and `ReopenSession`, the slot
//!    is re-keyed under the same id and the in-session op works again.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_live_migration_renegotiation_smoke() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let setup_res = common_setup_for_lm(dev, ddi, path);
            let session_id = setup_res.session_id;
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            // 1. In-session op succeeds before migration.
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes256,
                Some(0x1234),
                key_props,
            );
            assert!(
                resp.is_ok(),
                "AES key gen before migration must succeed: {:?}",
                resp
            );

            // 2. Simulate the live-migration NSSR.
            let result = dev.erase();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            // 3. In-session op on the migrated slot is rejected as
            //    needing renegotiation.
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                Some(0x5678),
                key_props,
            );
            assert!(
                matches!(
                    resp,
                    Err(DdiError::DdiStatus(DdiStatus::SessionNeedsRenegotiation))
                ),
                "In-session op after migration must return SessionNeedsRenegotiation, got {:?}",
                resp
            );

            // 4a. Re-establish the credential and reopen the session.
            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let reopen_resp = helper_reopen_session(
                dev,
                session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            )
            .expect("ReopenSession must succeed after migration");
            assert_eq!(
                reopen_resp.data.sess_id, session_id,
                "Reopened session must keep the same id"
            );

            // 4b. In-session op works again after reopen.
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes192,
                Some(0x9abc),
                key_props,
            );
            assert!(
                resp.is_ok(),
                "AES key gen after reopen must succeed: {:?}",
                resp
            );
        },
    );
}

/// Fill the whole session table, migrate the partition (NSSR), then
/// confirm the device is "out of sessions" for a fresh `OpenSession`
/// while `ReopenSession` can still re-key a migrated slot.
///
/// After the NSSR every slot is renegotiation-pending, and those slots
/// are reopen-only: a brand-new `OpenSession` must be rejected with
/// `VaultSessionLimitReached` (the table is full of migrated slots that
/// a fresh open may not reclaim), yet `ReopenSession` succeeds for the
/// same migrated ids.
///
/// Each session is held on its own device handle so the partition holds
/// `MAX_SESSIONS` sessions open at once (a handle rejects a second
/// `OpenSession` while it already owns a session).
#[test]
fn test_live_migration_full_table_reopen_smoke() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });

            // Session 0 (on `dev`), plus the partition credential / BK3 /
            // BMK needed to re-establish after the migration.
            let setup_res = common_setup_for_lm(dev, ddi, path);

            // Fill the remaining slots, each on its own handle, so the
            // whole table is occupied when the migration happens.
            let mut extra_handles = Vec::new();
            for _ in 0..(MAX_SESSIONS - 1) {
                let handle = ddi.open_dev(path).unwrap();
                let (cred, pub_key) = encrypt_userid_pin_for_open_session(
                    &handle,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );
                helper_open_session(&handle, None, rev, cred, pub_key)
                    .expect("OpenSession must succeed until the table is full");
                extra_handles.push(handle);
            }

            // Simulate the live-migration NSSR: every slot is preserved as
            // renegotiation-pending.
            dev.erase()
                .expect("Migration simulation (erase) must succeed");

            // Re-establish the partition credential (carrying the BMK
            // forward) so post-migration session commands can authenticate.
            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            // A fresh OpenSession must NOT reclaim a renegotiation-pending
            // slot: with the whole table migrated, the device is out of
            // sessions.
            let spare = ddi.open_dev(path).unwrap();
            let (cred, pub_key) = encrypt_userid_pin_for_open_session(
                &spare,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            let resp = helper_open_session(&spare, None, rev, cred, pub_key);
            assert!(
                matches!(
                    resp,
                    Err(DdiError::DdiStatus(DdiStatus::VaultSessionLimitReached))
                ),
                "OpenSession on a fully-migrated table must return \
                 VaultSessionLimitReached, got {:?}",
                resp
            );

            // ReopenSession, however, re-keys a migrated slot under the same
            // id and succeeds even though the table is otherwise full.
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );
            let reopen = helper_reopen_session(
                dev,
                setup_res.session_id,
                rev,
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            )
            .expect("ReopenSession must succeed for a migrated slot");
            assert_eq!(reopen.hdr.status, DdiStatus::Success);
            assert_eq!(
                reopen.data.sess_id, setup_res.session_id,
                "ReopenSession must reuse the migrated session id"
            );
        },
    );
}
