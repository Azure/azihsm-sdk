// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AttestKey smoke test for the emu backend.
//!
//! Exercises the firmware `AttestKey` handler end-to-end: generate an ECC
//! key, attest it, verify the ES384/PID-signed COSE_Sign1 report against
//! the partition cert chain, and confirm the attested public key
//! round-trips. Named `*smoke*` so the smoke-filtered emu CI runs it.

#![cfg(test)]

use azihsm_crypto::*;
use azihsm_ddi_mbor_test_helpers::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::attest_key::decode_cose_key;
use super::attest_key::helper_get_cert_chain;
use super::attest_key::normalized_key;
use super::attest_key::verify_report;
use super::attest_key::CoseKey;
use super::common::*;

#[test]
fn test_attest_ecc_key_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // The cert-chain verification path requires a physical/emu
            // device; skip on backends that don't support it.
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_attest_ecc_key_smoke for virtual device");
                return;
            }

            let (private_key_id, pub_key_der, _) = ecc_gen_key_mcr(
                dev,
                DdiEccCurve::P256,
                None,
                Some(session_id),
                DdiKeyUsage::SignVerify,
            );

            let report_data = [7u8; REPORT_DATA_SIZE];
            let resp = helper_attest_key_cmd(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                report_data,
                private_key_id,
            )
            .expect("AttestKey must succeed for an ECC key");

            let report = resp.data.report.data_take();
            let report_len = resp.data.report.len();
            assert!(report_len <= TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE);

            // The report must verify (ES384) against the PID key in the
            // partition cert chain.
            let cert_chain = helper_get_cert_chain(dev);
            assert!(helper_verify_cert_chain(&cert_chain).is_ok());
            let report_payload = verify_report(&report, &cert_chain);

            assert_eq!(report_payload.report_data, report_data);

            // The attested public key round-trips against the generated key.
            let attested_key = decode_cose_key(
                &report_payload.public_key[..report_payload.public_key_size.into()],
            );
            let ecc_pub =
                EccPublicKey::from_bytes(&pub_key_der.der.data()[..pub_key_der.der.len()]).unwrap();
            let CoseKey::EccPublic { crv, x, y } = attested_key else {
                panic!("Should be CoseKey::EccPublic")
            };
            let (expected_x, expected_y) = ecc_pub.coord_vec().unwrap();
            assert_eq!(normalized_key(&x), normalized_key(&expected_x));
            assert_eq!(normalized_key(&y), normalized_key(&expected_y));
            assert_eq!(crv, 1 /* P-256 */);
        },
    );
}
