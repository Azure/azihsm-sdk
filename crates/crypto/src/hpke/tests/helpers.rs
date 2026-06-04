// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-cutting helpers for HPKE tests.

use crate::EccCurve;
use crate::EccPrivateKey;
use crate::EccPublicKey;
use crate::HpkeSuite;
use crate::PrivateKey;
use crate::Rng;

/// All six suites — driven by the `suite × mode` round-trip tests.
pub fn all_suites() -> [HpkeSuite; 6] {
    [
        HpkeSuite::DHKemP256Sha256AesGcm256,
        HpkeSuite::DHKemP256Sha256Aes256Cbc,
        HpkeSuite::DHKemP384Sha384AesGcm256,
        HpkeSuite::DHKemP384Sha384Aes256Cbc,
        HpkeSuite::DHKemP521Sha512AesGcm256,
        HpkeSuite::DHKemP521Sha512Aes256Cbc,
    ]
}

/// Generate a fresh `(sk, pk)` keypair as typed `EccPrivateKey` /
/// `EccPublicKey` for the suite's curve. The P-521 branch masks the
/// top 7 bits of the leading scalar byte — biased toward small values
/// but acceptable for tests.
pub fn gen_keypair(suite: HpkeSuite) -> (EccPrivateKey, EccPublicKey) {
    let curve = suite.kem_curve();
    let nsk = suite.nsk();
    let mut scalar = vec![0u8; nsk];

    let sk = loop {
        Rng::rand_bytes(&mut scalar).expect("rand");
        if curve == EccCurve::P521 {
            scalar[0] &= 0x01;
        }
        if let Ok(sk) = EccPrivateKey::from_scalar(curve, &scalar) {
            break sk;
        }
    };
    let pk = sk.public_key().expect("public_key");
    (sk, pk)
}

/// hex-decode helper used by RFC vector tests.
pub fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
