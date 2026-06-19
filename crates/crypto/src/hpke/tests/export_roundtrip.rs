// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Export round-trips for all (suite × mode) combinations — send and
//! receive sides must produce identical exported bytes.

use super::helpers::all_suites;
use super::helpers::gen_keypair;
use crate::HpkeReceiveExportConfig;
use crate::HpkeSendExportConfig;
use crate::PskParams;
use crate::receive_export_vec;
use crate::send_export_vec;

const INFO: &[u8] = b"hpke-test/export/info";
const EXP_CTX: &[u8] = b"exporter-context-bytes";
const L: usize = 64;
const PSK_BYTES: &[u8] = b"a-pre-shared-key-with-decent-entropy!!!";
const PSK_ID: &[u8] = b"psk-id-42";

#[test]
fn base_export_roundtrip_all_suites() {
    for suite in all_suites() {
        let (sk_r, pk_r) = gen_keypair(suite);

        let s_cfg = HpkeSendExportConfig::base(suite, &pk_r, INFO, EXP_CTX);
        let sent = send_export_vec(&s_cfg, L).expect("send_export");

        let r_cfg = HpkeReceiveExportConfig::base(suite, &sk_r, &pk_r, INFO, EXP_CTX);
        let recv = receive_export_vec(&r_cfg, &sent.enc, L).expect("receive_export");

        assert_eq!(sent.exported, recv, "Base export mismatch for {:?}", suite);
        assert_eq!(recv.len(), L);
    }
}

#[test]
fn psk_export_roundtrip_all_suites() {
    for suite in all_suites() {
        let (sk_r, pk_r) = gen_keypair(suite);
        let psk = PskParams {
            psk: PSK_BYTES,
            psk_id: PSK_ID,
        };

        let s_cfg = HpkeSendExportConfig::psk(suite, &pk_r, INFO, EXP_CTX, psk);
        let sent = send_export_vec(&s_cfg, L).unwrap();
        let r_cfg = HpkeReceiveExportConfig::psk(suite, &sk_r, &pk_r, INFO, EXP_CTX, psk);
        let recv = receive_export_vec(&r_cfg, &sent.enc, L).unwrap();
        assert_eq!(sent.exported, recv, "PSK export mismatch for {:?}", suite);
    }
}

#[test]
fn auth_export_roundtrip_all_suites() {
    for suite in all_suites() {
        let (sk_r, pk_r) = gen_keypair(suite);
        let (sk_s, pk_s) = gen_keypair(suite);

        let s_cfg = HpkeSendExportConfig::auth(suite, &pk_r, INFO, EXP_CTX, &sk_s);
        let sent = send_export_vec(&s_cfg, L).unwrap();
        let r_cfg = HpkeReceiveExportConfig::auth(suite, &sk_r, &pk_r, INFO, EXP_CTX, &pk_s);
        let recv = receive_export_vec(&r_cfg, &sent.enc, L).unwrap();
        assert_eq!(sent.exported, recv, "Auth export mismatch for {:?}", suite);
    }
}

#[test]
fn auth_psk_export_roundtrip_all_suites() {
    for suite in all_suites() {
        let (sk_r, pk_r) = gen_keypair(suite);
        let (sk_s, pk_s) = gen_keypair(suite);
        let psk = PskParams {
            psk: PSK_BYTES,
            psk_id: PSK_ID,
        };

        let s_cfg = HpkeSendExportConfig::auth_psk(suite, &pk_r, INFO, EXP_CTX, &sk_s, psk);
        let sent = send_export_vec(&s_cfg, L).unwrap();
        let r_cfg =
            HpkeReceiveExportConfig::auth_psk(suite, &sk_r, &pk_r, INFO, EXP_CTX, &pk_s, psk);
        let recv = receive_export_vec(&r_cfg, &sent.enc, L).unwrap();
        assert_eq!(
            sent.exported, recv,
            "AuthPSK export mismatch for {:?}",
            suite
        );
    }
}

#[test]
fn different_contexts_diverge() {
    let suite = crate::HpkeSuite::DHKemP256Sha256AesGcm256;
    let (sk_r, pk_r) = gen_keypair(suite);

    let s = HpkeSendExportConfig::base(suite, &pk_r, INFO, b"context-A");
    let sent = send_export_vec(&s, L).unwrap();
    let r = HpkeReceiveExportConfig::base(suite, &sk_r, &pk_r, INFO, b"context-B");
    let recv = receive_export_vec(&r, &sent.enc, L).unwrap();
    assert_ne!(
        sent.exported, recv,
        "different exporter_context must yield different bytes"
    );
}
