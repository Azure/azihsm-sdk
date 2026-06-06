// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end seal/open round-trips for all (suite × mode) combinations.

use super::helpers::all_suites;
use super::helpers::gen_keypair;
use crate::HpkeOpenConfig;
use crate::HpkeSealConfig;
use crate::PskParams;
use crate::open_vec;
use crate::seal_vec;

const INFO: &[u8] = b"hpke-test/info";
const AAD: &[u8] = b"some aad";
const PSK_BYTES: &[u8] = b"a-pre-shared-key-with-decent-entropy!!!";
const PSK_ID: &[u8] = b"psk-id-42";

#[test]
fn base_roundtrip_all_suites() {
    for suite in all_suites() {
        let (sk_r, pk_r) = gen_keypair(suite);
        let pt = b"plaintext payload";

        let cfg = HpkeSealConfig::base(suite, &pk_r, INFO, AAD);
        let sealed = seal_vec(&cfg, pt).expect("seal");

        let open_cfg = HpkeOpenConfig::base(suite, &sk_r, &pk_r, INFO, AAD);
        let recovered = open_vec(&open_cfg, &sealed.enc, &sealed.ct).expect("open");
        assert_eq!(recovered, pt, "Base round-trip failed for {:?}", suite);
    }
}

#[test]
fn psk_roundtrip_all_suites() {
    for suite in all_suites() {
        let (sk_r, pk_r) = gen_keypair(suite);
        let pt = b"psk payload";
        let psk = PskParams {
            psk: PSK_BYTES,
            psk_id: PSK_ID,
        };

        let cfg = HpkeSealConfig::psk(suite, &pk_r, INFO, AAD, psk);
        let sealed = seal_vec(&cfg, pt).unwrap();

        let open_cfg = HpkeOpenConfig::psk(suite, &sk_r, &pk_r, INFO, AAD, psk);
        let recovered = open_vec(&open_cfg, &sealed.enc, &sealed.ct).unwrap();
        assert_eq!(recovered, pt, "PSK round-trip failed for {:?}", suite);
    }
}

#[test]
fn auth_roundtrip_all_suites() {
    for suite in all_suites() {
        let (sk_r, pk_r) = gen_keypair(suite);
        let (sk_s, pk_s) = gen_keypair(suite);
        let pt = b"auth payload";

        let cfg = HpkeSealConfig::auth(suite, &pk_r, INFO, AAD, &sk_s);
        let sealed = seal_vec(&cfg, pt).unwrap();

        let open_cfg = HpkeOpenConfig::auth(suite, &sk_r, &pk_r, INFO, AAD, &pk_s);
        let recovered = open_vec(&open_cfg, &sealed.enc, &sealed.ct).unwrap();
        assert_eq!(recovered, pt, "Auth round-trip failed for {:?}", suite);
    }
}

#[test]
fn auth_psk_roundtrip_all_suites() {
    for suite in all_suites() {
        let (sk_r, pk_r) = gen_keypair(suite);
        let (sk_s, pk_s) = gen_keypair(suite);
        let pt = b"auth_psk payload";
        let psk = PskParams {
            psk: PSK_BYTES,
            psk_id: PSK_ID,
        };

        let cfg = HpkeSealConfig::auth_psk(suite, &pk_r, INFO, AAD, &sk_s, psk);
        let sealed = seal_vec(&cfg, pt).unwrap();

        let open_cfg = HpkeOpenConfig::auth_psk(suite, &sk_r, &pk_r, INFO, AAD, &pk_s, psk);
        let recovered = open_vec(&open_cfg, &sealed.enc, &sealed.ct).unwrap();
        assert_eq!(recovered, pt, "AuthPSK round-trip failed for {:?}", suite);
    }
}

#[test]
fn cross_mode_open_fails() {
    // A ciphertext sealed in PSK mode must not open under Base mode.
    let suite = crate::HpkeSuite::DHKemP256Sha256AesGcm256;
    let (sk_r, pk_r) = gen_keypair(suite);
    let pt = b"mode-binding test";
    let psk = PskParams {
        psk: PSK_BYTES,
        psk_id: PSK_ID,
    };

    let cfg = HpkeSealConfig::psk(suite, &pk_r, INFO, AAD, psk);
    let sealed = seal_vec(&cfg, pt).unwrap();

    let wrong = HpkeOpenConfig::base(suite, &sk_r, &pk_r, INFO, AAD);
    let err = open_vec(&wrong, &sealed.enc, &sealed.ct).unwrap_err();
    assert_eq!(err, crate::CryptoError::HpkeAeadOpenFailed);
}
