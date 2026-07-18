// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GetCertChainInfo / GetCertificate smoke tests.
//!
//! Exercises the certificate-chain DDI commands end-to-end on both the
//! emu and mock backends:
//!
//! - `GetCertChainInfo` reports a provisioned chain (non-zero count and a
//!   non-zero thumbprint).
//! - Every advertised certificate is fetchable and non-empty, and the
//!   thumbprint is stable across the multi-call fetch -- the change-
//!   detection property the host SDK relies on to catch a chain rotation
//!   or live migration mid-fetch. The thumbprint is an opaque token, so
//!   these tests never recompute it with a fixed hash formula.

#![cfg(test)]

use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_get_cert_chain_info_smoke() {
    ddi_dev_test(common_setup, common_cleanup, |dev, _ddi, _path, _| {
        let resp = helper_get_cert_chain_info(dev).expect("GetCertChainInfo must succeed");

        assert_eq!(resp.hdr.op, DdiOp::GetCertChainInfo);
        assert!(resp.hdr.sess_id.is_none());
        assert_eq!(resp.hdr.status, DdiStatus::Success);

        assert!(
            resp.data.num_certs > 0,
            "a provisioned partition must report at least one certificate"
        );
        assert!(
            resp.data.thumbprint.as_slice().iter().any(|&b| b != 0),
            "thumbprint must not be all zeros"
        );
    });
}

#[test]
fn test_get_cert_chain_fetch_and_stability_smoke() {
    ddi_dev_test(common_setup, common_cleanup, |dev, _ddi, _path, _| {
        let (num_certs, thumbprint) = helper_get_cert_chain_info_data(dev);
        assert!(num_certs > 0, "cert count must be non-zero");

        // Every advertised certificate must be fetchable and non-empty.
        for cert_id in 0..num_certs {
            let resp = helper_get_certificate(dev, cert_id)
                .unwrap_or_else(|e| panic!("GetCertificate({}) must succeed: {:?}", cert_id, e));
            assert!(
                !resp.data.certificate.as_slice().is_empty(),
                "certificate {} must not be empty",
                cert_id
            );
        }

        // The thumbprint is a change-detection token: re-reading it after
        // the fetch must yield the same count and thumbprint (a chain
        // rotation / live migration mid-fetch would move it).
        let (num_certs_after, thumbprint_after) = helper_get_cert_chain_info_data(dev);
        assert_eq!(num_certs, num_certs_after, "cert count must be stable");
        assert_eq!(thumbprint, thumbprint_after, "thumbprint must be stable");
    });
}
