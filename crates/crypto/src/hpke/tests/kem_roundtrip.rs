// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! KEM round-trip tests for all three DHKEM variants.

use super::helpers::all_suites;
use super::helpers::gen_keypair;
use crate::HpkeSuite;
use crate::hpke::kem;

#[test]
fn base_encap_decap_matches_per_curve() {
    let curves = [
        HpkeSuite::DHKemP256Sha256AesGcm256,
        HpkeSuite::DHKemP384Sha384AesGcm256,
        HpkeSuite::DHKemP521Sha512AesGcm256,
    ];
    for suite in curves {
        let (sk_r, pk_r) = gen_keypair(suite);
        let (enc, ss_sender) = kem::encap(suite, &pk_r).expect("encap");
        let ss_receiver = kem::decap(suite, &enc, &sk_r, &pk_r).expect("decap");
        assert_eq!(
            ss_sender, ss_receiver,
            "KEM shared secret mismatch for suite {:?}",
            suite
        );
        assert_eq!(ss_sender.len(), suite.nsecret());
    }
}

#[test]
fn auth_encap_decap_matches_per_curve() {
    let curves = [
        HpkeSuite::DHKemP256Sha256AesGcm256,
        HpkeSuite::DHKemP384Sha384AesGcm256,
        HpkeSuite::DHKemP521Sha512AesGcm256,
    ];
    for suite in curves {
        let (sk_r, pk_r) = gen_keypair(suite);
        let (sk_s, pk_s) = gen_keypair(suite);

        let (enc, ss_sender) = kem::auth_encap(suite, &pk_r, &sk_s).expect("auth_encap");
        let ss_receiver = kem::auth_decap(suite, &enc, &sk_r, &pk_r, &pk_s).expect("auth_decap");
        assert_eq!(ss_sender, ss_receiver, "Auth KEM mismatch for {:?}", suite);
    }
}

#[test]
fn decap_with_wrong_sk_diverges() {
    let suite = HpkeSuite::DHKemP256Sha256AesGcm256;
    let (_, pk_r) = gen_keypair(suite);
    let (wrong_sk, wrong_pk) = gen_keypair(suite);

    let (enc, ss_sender) = kem::encap(suite, &pk_r).expect("encap");
    let ss_wrong = kem::decap(suite, &enc, &wrong_sk, &wrong_pk).expect("decap");
    assert_ne!(ss_sender, ss_wrong);
}

#[test]
fn all_suites_iter_smoke() {
    assert_eq!(all_suites().len(), 6);
}
