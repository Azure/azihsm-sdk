// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FIPS 140-3 key assurance on the MBOR `RsaUnwrap` import path.
//!
//! For every ECC curve and usage, and every RSA size, layout, and usage, the
//! tests import a valid key and then malformed variants of it: ECC keys whose
//! private value is 0 or the curve order, whose embedded public key is
//! mismatched, missing, compressed, or hybrid, or that carry `[0]` curve
//! parameters, and RSA keys with one inconsistent private component. Every
//! firmware rejects the out-of-range private values with `InvalidArg`. Only
//! hardware firmware runs the structure check that rejects the other ECC keys
//! and the pairwise consistency test that rejects the RSA keys, so every test
//! here is ignored under `emu`. The `mock` feature tests the MBOR simulator
//! instead of the firmware, and the simulator runs neither check, so every
//! test here is ignored under `mock` too.

#![cfg(test)]

use azihsm_ddi::Ddi;
use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

// ───────────────────────── curves ─────────────────────────

#[derive(Clone, Copy)]
struct Curve {
    name: &'static str,
    ecc: EccTestCurve,
}

const CURVES: [Curve; 3] = [
    Curve {
        name: "P-256",
        ecc: ECC_TEST_P256,
    },
    Curve {
        name: "P-384",
        ecc: ECC_TEST_P384,
    },
    Curve {
        name: "P-521",
        ecc: ECC_TEST_P521,
    },
];

// ───────────────────────── the matrix ─────────────────────────

/// Imports one wrapped key and records a failure unless the result matches
/// `want`: `None` expects a successful import, `Some(status)` expects that
/// exact rejection. Imported keys are deleted so the vault doesn't fill up,
/// and a failed deletion is recorded as a failure too.
#[allow(clippy::too_many_arguments)]
fn check_import(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    unwrap_key_id: u16,
    unwrap_pub_der: &[u8],
    leaf: String,
    class: DdiKeyClass,
    usage: DdiKeyUsage,
    der: &[u8],
    want: Option<DdiStatus>,
    failures: &mut Vec<String>,
) {
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let wrapped = wrap_data(unwrap_pub_der.to_vec(), der);
    let result = helper_rsa_unwrap(
        dev,
        Some(session_id),
        rev,
        unwrap_key_id,
        MborByteArray::from_slice(&wrapped).expect("wrapped blob fits"),
        class,
        DdiRsaCryptoPadding::Oaep,
        DdiHashAlgorithm::Sha256,
        None,
        helper_key_properties(usage, DdiKeyAvailability::App),
    );
    let mut delete = |key_id: u16| {
        if let Err(e) = helper_delete_key(dev, Some(session_id), rev, key_id) {
            failures.push(format!("{leaf}: deleting the imported key failed: {e:?}"));
        }
    };
    match (result, want) {
        (Ok(resp), None) => delete(resp.data.key_id),
        (Err(DdiError::DdiStatus(got)), Some(want)) if got == want => {}
        (Ok(resp), Some(_)) => {
            delete(resp.data.key_id);
            failures.push(format!("{leaf}: accepted"));
        }
        (Err(e), _) => failures.push(format!("{leaf}: {e:?}")),
    }
}

/// Runs `body` with a closure that checks one import and counts it, then
/// fails the test if any import didn't give the expected result.
fn run_import_matrix(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    body: impl FnOnce(&mut dyn FnMut(String, DdiKeyClass, DdiKeyUsage, &[u8], Option<DdiStatus>)),
) {
    let (unwrap_key_id, unwrap_pub_der, _) = get_unwrapping_key(dev, session_id);
    let dev = &*dev;
    let mut failures = Vec::new();
    let mut leaves = 0;
    body(&mut |leaf, class, usage, der, want| {
        leaves += 1;
        check_import(
            dev,
            session_id,
            unwrap_key_id,
            &unwrap_pub_der,
            leaf,
            class,
            usage,
            der,
            want,
            &mut failures,
        );
    });
    assert!(
        failures.is_empty(),
        "{} of {leaves} imports did not give the expected result:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// ECC structure and private-value checks through MBOR `RsaUnwrap`: 6 valid
/// ECC keys with 54 malformed variants. Only hardware firmware checks an
/// imported ECC key's structure.
#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn rsa_unwrap_ecc_structure_matrix() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            run_import_matrix(dev, session_id, |check| {
                let bad_structure = Some(DdiStatus::KeyStructuralValidationFailed);
                let bad_scalar = Some(DdiStatus::InvalidArg);
                for curve in CURVES {
                    for (uname, usage) in [
                        ("sign", DdiKeyUsage::SignVerify),
                        ("derive", DdiKeyUsage::Derive),
                    ] {
                        let key = HostEcc::generate(curve.ecc);
                        let other = HostEcc::generate(curve.ecc);
                        let tag = format!("ecc {} {uname}", curve.name);
                        let pkcs8 = |q: Option<&[u8]>| ecc_pkcs8(curve.ecc.oid, &key.d, false, q);
                        let with_d =
                            |d: &[u8]| ecc_pkcs8(curve.ecc.oid, d, false, Some(&key.point(0x04)));
                        let ecc = DdiKeyClass::Ecc;
                        check(
                            format!("{tag} valid"),
                            ecc,
                            usage,
                            &pkcs8(Some(&key.point(0x04))),
                            None,
                        );
                        let bad = [
                            ("mismatched", pkcs8(Some(&other.point(0x04))), bad_structure),
                            ("missing", pkcs8(None), bad_structure),
                            (
                                "compressed-02",
                                pkcs8(Some(&key.compressed(0x02))),
                                bad_structure,
                            ),
                            (
                                "compressed-03",
                                pkcs8(Some(&key.compressed(0x03))),
                                bad_structure,
                            ),
                            ("hybrid-06", pkcs8(Some(&key.point(0x06))), bad_structure),
                            ("hybrid-07", pkcs8(Some(&key.point(0x07))), bad_structure),
                            ("d = 0", with_d(&vec![0; curve.ecc.raw]), bad_scalar),
                            ("d = n", with_d(curve.ecc.order), bad_scalar),
                            (
                                "[0] parameters",
                                ecc_pkcs8(curve.ecc.oid, &key.d, true, Some(&key.point(0x04))),
                                bad_structure,
                            ),
                        ];
                        for (name, der, want) in bad {
                            check(format!("{tag} {name}"), ecc, usage, &der, want);
                        }
                    }
                }
            });
        },
    );
}

/// RSA pairwise consistency tests through MBOR `RsaUnwrap`: 12 valid RSA keys
/// with 36 malformed variants.
#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn rsa_unwrap_rsa_pct_matrix() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            run_import_matrix(dev, session_id, |check| {
                let bad_rsa = Some(DdiStatus::PctValidationRsaUnwrapRsaKeyFailed);
                for k in [256, 384, 512] {
                    for (uname, usage) in [
                        ("sign", DdiKeyUsage::SignVerify),
                        ("decrypt", DdiKeyUsage::EncryptDecrypt),
                    ] {
                        let key = RsaParts::generate(k);
                        let donor = RsaParts::generate(k);
                        let tag = format!("rsa {} {uname}", k * 8);
                        let (plain, crt) = (DdiKeyClass::Rsa, DdiKeyClass::RsaCrt);
                        check(
                            format!("{tag} plain valid"),
                            plain,
                            usage,
                            &key.pkcs8(),
                            None,
                        );
                        check(format!("{tag} crt valid"), crt, usage, &key.pkcs8(), None);
                        let bad = [
                            ("plain d+2", plain, key.with(|p| p.d = plus_two(&p.d))),
                            ("crt p swapped", crt, key.with(|p| p.p = donor.p.clone())),
                            ("crt q swapped", crt, key.with(|p| p.q = donor.q.clone())),
                            ("crt dp+2", crt, key.with(|p| p.dp = plus_two(&p.dp))),
                            ("crt dq+2", crt, key.with(|p| p.dq = plus_two(&p.dq))),
                            ("crt qinv+2", crt, key.with(|p| p.qinv = plus_two(&p.qinv))),
                        ];
                        for (name, class, der) in bad {
                            check(format!("{tag} {name}"), class, usage, &der, bad_rsa);
                        }
                    }
                }
            });
        },
    );
}

/// Rejected imports must not leave key material in the vault. A stored
/// RSA-4096 CRT key takes about 2,600 bytes, so the PF's tables hold at most
/// about 325 of them. This rejects 330 inconsistent RSA-4096 CRT keys in a row,
/// then imports a valid one: if each rejection had leaked a stored key, the
/// vault would have run out of space first.
#[test]
#[cfg_attr(
    any(feature = "emu", feature = "mock"),
    ignore = "only hardware firmware performs FIPS key assurance"
)]
fn rsa_unwrap_rejected_imports_store_nothing() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_der, _) = get_unwrapping_key(dev, session_id);
            let dev = &*dev;
            let key = RsaParts::generate(512);
            let bad = key.with(|p| p.dq = plus_two(&p.dq));
            let mut failures = Vec::new();
            for i in 0..330 {
                check_import(
                    dev,
                    session_id,
                    unwrap_key_id,
                    &unwrap_pub_der,
                    format!("rejection {i}"),
                    DdiKeyClass::RsaCrt,
                    DdiKeyUsage::SignVerify,
                    &bad,
                    Some(DdiStatus::PctValidationRsaUnwrapRsaKeyFailed),
                    &mut failures,
                );
                if !failures.is_empty() {
                    break;
                }
            }
            check_import(
                dev,
                session_id,
                unwrap_key_id,
                &unwrap_pub_der,
                "valid import afterwards".to_string(),
                DdiKeyClass::RsaCrt,
                DdiKeyUsage::SignVerify,
                &key.pkcs8(),
                None,
                &mut failures,
            );
            assert!(failures.is_empty(), "{}", failures.join("\n"));
        },
    );
}
