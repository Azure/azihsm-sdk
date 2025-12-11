// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_flush_app_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            let mut new_dev = ddi.open_dev(path).unwrap();
            set_device_kind(&mut new_dev);
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &new_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                &new_dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            // Skip closing the session, so flush happens.
            // Confirm via debugging
        },
    );
}
