// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "integration")]

use std::path::PathBuf;

use serial_test::serial;

const CLEANUP: &str = "true";

/// Build an absolute path to a testfiles subdirectory anchored at the
/// crate manifest directory, independent of the process working directory.
fn search_path(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    path.to_str().expect("path is not valid UTF-8").to_owned()
}

#[test]
#[serial]
fn test_ec_create_key() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];
    let sessions = [true, false];
    let usages = vec!["digitalSignature".to_string(), "keyAgreement".to_string()];

    for session in sessions {
        for curve in &curves {
            for usage in &usages {
                lit::run::tests(lit::event_handler::Default::default(), |config| {
                    config.add_search_path(search_path("testfiles/ec/create_key"));
                    config.add_extension("sh");
                    config
                        .constants
                        .insert("bash".to_owned(), "/bin/bash".to_string());
                    config
                        .constants
                        .insert("provider".to_owned(), "azihsm".to_string());
                    config.constants.insert("algo".to_owned(), "EC".to_string());
                    config.constants.insert("curve".to_owned(), curve.clone());
                    config
                        .constants
                        .insert("session_bool".to_owned(), session.to_string());
                    config.constants.insert(
                        "session".to_owned(),
                        if session { "yes" } else { "no" }.to_string(),
                    );
                    config
                        .constants
                        .insert("cleanup".to_owned(), CLEANUP.to_string());
                    config.constants.insert("usage".to_owned(), usage.clone());
                })
                .expect("Lit test failed");
            }
        }
    }
}

#[test]
#[serial]
fn test_ec_import_key() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];

    for curve in &curves {
        lit::run::tests(lit::event_handler::Default::default(), |config| {
            config.add_search_path(search_path("testfiles/ec/import_key"));
            config.add_extension("sh");
            config
                .constants
                .insert("bash".to_owned(), "/bin/bash".to_string());
            config.constants.insert("curve".to_owned(), curve.clone());
            config
                .constants
                .insert("cleanup".to_owned(), CLEANUP.to_string());
        })
        .expect("Lit test failed");
    }
}

#[test]
#[serial]
fn test_ec_import_wrapped_key() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for curve in &curves {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/ec/import_wrapped_key"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("curve".to_owned(), curve.clone());
                config.constants.insert("dgst".to_owned(), dgst.to_owned());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_ec_certificate() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for curve in &curves {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/ec/certificate"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("curve".to_owned(), curve.clone());
                config.constants.insert("dgst".to_owned(), dgst.to_owned());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_ec_import_key_sec() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];

    let sec1: std::collections::HashMap<String, String> = curves
        .iter()
        .zip(["prime256v1", "secp384r1", "secp521r1"].iter())
        .map(|(curve, sec)| (curve.clone(), sec.to_string()))
        .collect();

    for curve in &curves {
        lit::run::tests(lit::event_handler::Default::default(), |config| {
            config.add_search_path(search_path("testfiles/ec/import_key_sec1"));
            config.add_extension("sh");
            config
                .constants
                .insert("bash".to_owned(), "/bin/bash".to_string());
            config.constants.insert("curve".to_owned(), curve.clone());
            config.constants.insert(
                "sec_one".to_owned(),
                sec1.get(curve).expect("unknown curve").clone(),
            );
            config
                .constants
                .insert("cleanup".to_owned(), CLEANUP.to_string());
        })
        .expect("Lit test failed");
    }
}

#[test]
#[serial]
fn test_ec_sign() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for curve in &curves {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/ec/sign"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("curve".to_owned(), curve.clone());
                config.constants.insert("dgst".to_owned(), dgst.to_owned());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_ecdh_key_exchange() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];

    for curve in &curves {
        lit::run::tests(lit::event_handler::Default::default(), |config| {
            config.add_search_path(search_path("testfiles/ec/ecdh_key_exchange"));
            config.add_extension("sh");
            config
                .constants
                .insert("bash".to_owned(), "/bin/bash".to_string());
            config.constants.insert("curve".to_owned(), curve.clone());
            config
                .constants
                .insert("cleanup".to_owned(), CLEANUP.to_string());
        })
        .expect("Lit test failed");
    }
}

#[test]
#[serial]
fn test_hkdf_key_derivation() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];
    let dgst_algos = vec!["256".to_string(), "384".to_string(), "512".to_string()];
    let test_hexsalt = [true, false];

    for curve in &curves {
        for dgst in &dgst_algos {
            for hexsalt_bool in test_hexsalt {
                lit::run::tests(lit::event_handler::Default::default(), |config| {
                    config.add_search_path(search_path("testfiles/ec/hkdf_key_derivation"));
                    config.add_extension("sh");
                    config
                        .constants
                        .insert("bash".to_owned(), "/bin/bash".to_string());
                    config.constants.insert("curve".to_owned(), curve.clone());
                    config.constants.insert("dgst".to_owned(), dgst.clone());
                    config
                        .constants
                        .insert("hexsalt".to_owned(), hexsalt_bool.to_string());
                    config
                        .constants
                        .insert("cleanup".to_owned(), CLEANUP.to_string());
                })
                .expect("Lit test failed");
            }
        }
    }
}

#[test]
#[serial]
fn test_hmac() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];
    let dgst_algos = vec!["256".to_string(), "384".to_string(), "512".to_string()];

    for curve in &curves {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/ec/hmac"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("curve".to_owned(), curve.clone());
                config.constants.insert("dgst".to_owned(), dgst.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_ecdh_hkdf_hmac_roundtrip() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];
    let dgst_algos = vec!["256".to_string(), "384".to_string(), "512".to_string()];

    for curve in &curves {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/ec/ecdh_hkdf_hmac_roundtrip"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("curve".to_owned(), curve.clone());
                config.constants.insert("dgst".to_owned(), dgst.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_digest() {
    let dgst_algos = vec![
        "1".to_string(),
        "256".to_string(),
        "384".to_string(),
        "512".to_string(),
    ];

    for dgst in &dgst_algos {
        lit::run::tests(lit::event_handler::Default::default(), |config| {
            config.add_search_path(search_path("testfiles/digest"));
            config.add_extension("sh");
            config
                .constants
                .insert("bash".to_owned(), "/bin/bash".to_string());
            config.constants.insert("dgst".to_owned(), dgst.to_owned());
            config
                .constants
                .insert("cleanup".to_owned(), CLEANUP.to_string());
        })
        .expect("Lit test failed");
    }
}

#[test]
#[serial]
fn test_aes_cbc() {
    let keybits = vec!["128".to_string(), "192".to_string(), "256".to_string()];

    for kb in &keybits {
        lit::run::tests(lit::event_handler::Default::default(), |config| {
            config.add_search_path(search_path("testfiles/aes/cbc"));
            config.add_extension("sh");
            config
                .constants
                .insert("bash".to_owned(), "/bin/bash".to_string());
            config.constants.insert("keybits".to_owned(), kb.clone());
            config
                .constants
                .insert("cleanup".to_owned(), CLEANUP.to_string());
        })
        .expect("Lit test failed");
    }
}

#[test]
#[serial]
fn test_ec_verify() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for curve in &curves {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/ec/verify"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("curve".to_owned(), curve.clone());
                config.constants.insert("dgst".to_owned(), dgst.to_owned());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_ec_round_trip() {
    let curves = vec!["256".to_string(), "384".to_string(), "521".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for curve in &curves {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/ec/round_trip"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("curve".to_owned(), curve.clone());
                config.constants.insert("dgst".to_owned(), dgst.to_owned());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_import_key() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let algorithms = vec!["RSA".to_string(), "RSA-PSS".to_string()];

    for bits in &key_bits {
        for algo in &algorithms {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/rsa/import_key"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("keybits".to_owned(), bits.clone());
                config
                    .constants
                    .insert("algorithm".to_owned(), algo.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_import_wrapped_key() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/rsa/import_wrapped_key"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("keybits".to_owned(), bits.clone());
                config.constants.insert("dgst".to_owned(), dgst.to_owned());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_certificate() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/rsa/certificate"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("keybits".to_owned(), bits.clone());
                config.constants.insert("dgst".to_owned(), dgst.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_sign() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let algorithms = vec!["RSA".to_string(), "RSA-PSS".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for algo in &algorithms {
            for dgst in &dgst_algos {
                lit::run::tests(lit::event_handler::Default::default(), |config| {
                    config.add_search_path(search_path("testfiles/rsa/sign"));
                    config.add_extension("sh");
                    config
                        .constants
                        .insert("bash".to_owned(), "/bin/bash".to_string());
                    config.constants.insert("keybits".to_owned(), bits.clone());
                    config
                        .constants
                        .insert("algorithm".to_owned(), algo.clone());
                    config.constants.insert("dgst".to_owned(), dgst.clone());
                    config
                        .constants
                        .insert("cleanup".to_owned(), CLEANUP.to_string());
                })
                .expect("Lit test failed");
            }
        }
    }
}

#[test]
#[serial]
fn test_rsa_pss_specific() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let saltlengths = vec!["digest".to_string(), "max".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];
    let explicit_mgf1_values = [true, false];

    for bits in &key_bits {
        for saltlength in &saltlengths {
            for dgst in &dgst_algos {
                for explicit_mgf1 in explicit_mgf1_values {
                    lit::run::tests(lit::event_handler::Default::default(), |config| {
                        config.add_search_path(search_path("testfiles/rsa/rsa-pss-specific"));
                        config.add_extension("sh");
                        config
                            .constants
                            .insert("bash".to_owned(), "/bin/bash".to_string());
                        config.constants.insert("keybits".to_owned(), bits.clone());
                        config
                            .constants
                            .insert("saltlength".to_owned(), saltlength.clone());
                        config.constants.insert("dgst".to_owned(), dgst.clone());
                        config
                            .constants
                            .insert("explicit_mgfone".to_owned(), explicit_mgf1.to_string());
                        config
                            .constants
                            .insert("cleanup".to_owned(), CLEANUP.to_string());
                    })
                    .expect("Lit test failed");
                }
            }
        }
    }
}

#[test]
#[serial]
fn test_rsa_default_padding() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/rsa/default_padding"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("keybits".to_owned(), bits.clone());
                config.constants.insert("dgst".to_owned(), dgst.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_pss_default_padding() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/rsa/rsa_pss_default_padding"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("keybits".to_owned(), bits.clone());
                config.constants.insert("dgst".to_owned(), dgst.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_oneshot_sign() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/rsa/oneshot_sign"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("keybits".to_owned(), bits.clone());
                config
                    .constants
                    .insert("algorithm".to_owned(), "RSA-PSS".to_owned());
                config.constants.insert("dgst".to_owned(), dgst.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_verify() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let algorithms = vec!["RSA".to_string(), "RSA-PSS".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for algo in &algorithms {
            for dgst in &dgst_algos {
                lit::run::tests(lit::event_handler::Default::default(), |config| {
                    config.add_search_path(search_path("testfiles/rsa/verify"));
                    config.add_extension("sh");
                    config
                        .constants
                        .insert("bash".to_owned(), "/bin/bash".to_string());
                    config.constants.insert("keybits".to_owned(), bits.clone());
                    config
                        .constants
                        .insert("algorithm".to_owned(), algo.clone());
                    config.constants.insert("dgst".to_owned(), dgst.clone());
                    config
                        .constants
                        .insert("cleanup".to_owned(), CLEANUP.to_string());
                })
                .expect("Lit test failed");
            }
        }
    }
}

#[test]
#[serial]
fn test_rsa_oneshot_verify() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/rsa/oneshot_verify"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("keybits".to_owned(), bits.clone());
                config
                    .constants
                    .insert("algorithm".to_owned(), "RSA-PSS".to_owned());
                config.constants.insert("dgst".to_owned(), dgst.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_round_trip() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let algorithms = vec!["RSA".to_string(), "RSA-PSS".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for algo in &algorithms {
            for dgst in &dgst_algos {
                lit::run::tests(lit::event_handler::Default::default(), |config| {
                    config.add_search_path(search_path("testfiles/rsa/round_trip"));
                    config.add_extension("sh");
                    config
                        .constants
                        .insert("bash".to_owned(), "/bin/bash".to_string());
                    config.constants.insert("keybits".to_owned(), bits.clone());
                    config
                        .constants
                        .insert("algorithm".to_owned(), algo.clone());
                    config.constants.insert("dgst".to_owned(), dgst.clone());
                    config
                        .constants
                        .insert("cleanup".to_owned(), CLEANUP.to_string());
                })
                .expect("Lit test failed");
            }
        }
    }
}

#[test]
#[serial]
fn test_rsa_oneshot_round_trip() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/rsa/oneshot_round_trip"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("keybits".to_owned(), bits.clone());
                config
                    .constants
                    .insert("algorithm".to_owned(), "RSA-PSS".to_owned());
                config.constants.insert("dgst".to_owned(), dgst.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_oaep_encryption() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];
    let dgst_algos = vec![
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
    ];

    for bits in &key_bits {
        for dgst in &dgst_algos {
            lit::run::tests(lit::event_handler::Default::default(), |config| {
                config.add_search_path(search_path("testfiles/rsa/oaep_encryption"));
                config.add_extension("sh");
                config
                    .constants
                    .insert("bash".to_owned(), "/bin/bash".to_string());
                config.constants.insert("keybits".to_owned(), bits.clone());
                config
                    .constants
                    .insert("algorithm".to_owned(), "RSA".to_owned());
                config.constants.insert("dgst".to_owned(), dgst.clone());
                config
                    .constants
                    .insert("cleanup".to_owned(), CLEANUP.to_string());
            })
            .expect("Lit test failed");
        }
    }
}

#[test]
#[serial]
fn test_rsa_pkcs1_encryption() {
    let key_bits = vec!["2048".to_string(), "3072".to_string(), "4096".to_string()];

    for bits in &key_bits {
        lit::run::tests(lit::event_handler::Default::default(), |config| {
            config.add_search_path(search_path("testfiles/rsa/pkcs1_encryption"));
            config.add_extension("sh");
            config
                .constants
                .insert("bash".to_owned(), "/bin/bash".to_string());
            config.constants.insert("keybits".to_owned(), bits.clone());
            config
                .constants
                .insert("algorithm".to_owned(), "RSA".to_owned());
            config
                .constants
                .insert("cleanup".to_owned(), CLEANUP.to_string());
        })
        .expect("Lit test failed");
    }
}
