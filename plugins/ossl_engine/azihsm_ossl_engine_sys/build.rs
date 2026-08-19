// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for azihsm_ossl_engine_sys.
//!
//! Discovers a system OpenSSL 1.1.x via pkg-config (honoring an externally
//! set `PKG_CONFIG_PATH`) and runs bindgen to generate Rust FFI bindings
//! from `wrapper.h`.

#[cfg(target_os = "linux")]
fn main() {
    use std::env;
    use std::path::PathBuf;

    println!("cargo::rerun-if-changed=wrapper.h");
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_PATH");

    // Without the `engine` feature this crate is an empty stub: skip the
    // OpenSSL probe and bindgen so plain workspace builds work on hosts
    // without OpenSSL 1.1.x.
    if env::var_os("CARGO_FEATURE_ENGINE").is_none() {
        let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
        std::fs::write(out.join("bindings.rs"), "").expect("failed to write bindings.rs");
        return;
    }

    // pkg-config may report zero or several include/link dirs; zero is valid
    // (default-prefix installs need no -I / -L).
    struct OpensslPaths {
        include: Vec<PathBuf>,
        lib: Vec<PathBuf>,
    }

    fn find_pkgconfig_openssl() -> OpensslPaths {
        let lib = pkg_config::Config::new()
            .atleast_version("1.1.0")
            .probe("libcrypto")
            .expect(
                "Could not find libcrypto. \
                 Set PKG_CONFIG_PATH to an OpenSSL 1.1.x installation.",
            );

        let major: u32 = lib
            .version
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("Could not parse OpenSSL version: {}", lib.version));

        if major != 1 {
            panic!(
                "Found OpenSSL {} but this engine requires 1.1.x. \
                 For OpenSSL 3.x, use the provider at plugins/ossl_prov instead.",
                lib.version
            );
        }

        OpensslPaths {
            include: lib.include_paths,
            lib: lib.link_paths,
        }
    }

    let paths = find_pkgconfig_openssl();

    println!("cargo::rustc-link-lib=crypto");
    for p in &paths.lib {
        println!("cargo::rustc-link-search=native={}", p.display());
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(paths.include.iter().map(|p| format!("-I{}", p.display())))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("ENGINE_.*")
        .allowlist_function("EVP_.*")
        .allowlist_function("RSA_meth_.*")
        .allowlist_function("RSA_get_ex_data")
        .allowlist_function("RSA_set_ex_data")
        .allowlist_function("RSA_get_ex_new_index")
        .allowlist_function("EC_KEY_METHOD_.*")
        .allowlist_function("EC_KEY_.*")
        .allowlist_function("EC_POINT_.*")
        .allowlist_function("EC_GROUP_.*")
        .allowlist_function("ECDSA_SIG_.*")
        .allowlist_function("BN_bin2bn")
        .allowlist_function("BN_free")
        .allowlist_function("OBJ_nid2obj")
        .allowlist_function("OBJ_obj2nid")
        .allowlist_function("OBJ_length")
        .allowlist_function("i2d_ECPrivateKey")
        .allowlist_function("d2i_ECPrivateKey")
        .allowlist_function("i2d_ECParameters")
        .allowlist_function("d2i_ECParameters")
        .allowlist_function("PKCS8_PRIV_KEY_INFO_new")
        .allowlist_function("PKCS8_PRIV_KEY_INFO_free")
        .allowlist_function("i2d_PKCS8_PRIV_KEY_INFO")
        .allowlist_function("PKCS8_pkey_set0")
        .allowlist_function("PKCS8_pkey_get0")
        .allowlist_function("X509_ALGOR_get0")
        .allowlist_function("ASN1_STRING_new")
        .allowlist_function("ASN1_STRING_free")
        .allowlist_function("ASN1_STRING_set0")
        .allowlist_function("BIO_new")
        .allowlist_function("BIO_s_mem")
        .allowlist_function("BIO_free")
        .allowlist_function("BIO_ctrl")
        .allowlist_function("ASN1_STRING_get0_data")
        .allowlist_function("ASN1_STRING_length")
        .allowlist_function("BIO_write")
        .allowlist_function("CRYPTO_free")
        .allowlist_function("ERR_put_error")
        .allowlist_function("ERR_add_error_data")
        .allowlist_function("ERR_get_error")
        .allowlist_function("ERR_clear_error")
        .allowlist_function("CRYPTO_get_ex_new_index")
        .allowlist_function("CRYPTO_set_mem_functions")
        .allowlist_function("OPENSSL_init_crypto")
        .allowlist_type("ENGINE")
        .allowlist_type("EVP_PKEY")
        .allowlist_type("EVP_PKEY_CTX")
        .allowlist_type("EVP_MD")
        .allowlist_type("EVP_CIPHER")
        .allowlist_type("RSA")
        .allowlist_type("RSA_METHOD")
        .allowlist_type("EC_KEY")
        .allowlist_type("EC_KEY_METHOD")
        .allowlist_type("UI_METHOD")
        .allowlist_type("ECDSA_SIG")
        .allowlist_type("BIGNUM")
        .allowlist_type("dynamic_fns")
        .allowlist_type("dynamic_MEM_fns")
        .allowlist_var("OSSL_DYNAMIC_.*")
        .allowlist_var("NID_.*")
        .allowlist_var("V_ASN1_.*")
        .allowlist_var("OPENSSL_EC_NAMED_CURVE")
        .allowlist_var("EC_PKEY_NO_PARAMETERS")
        .allowlist_var("BIO_CTRL_INFO")
        .allowlist_var("EVP_PKEY_.*")
        .allowlist_var("ERR_LIB_ENGINE")
        .allowlist_var("ERR_R_.*")
        .allowlist_var("CRYPTO_EX_INDEX_ENGINE")
        .allowlist_var("CRYPTO_EX_INDEX_RSA")
        .allowlist_var("CRYPTO_EX_INDEX_EC_KEY")
        .allowlist_var("OPENSSL_INIT_NO_ATEXIT")
        .allowlist_var("ENGINE_CMD_FLAG_.*")
        .layout_tests(false)
        .generate()
        .expect("bindgen failed");

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("failed to write bindings.rs");
}

#[cfg(not(target_os = "linux"))]
fn main() {}
