// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for openssl-sys-engine.
//!
//! Discovers OpenSSL 1.1.x and runs bindgen to generate Rust FFI bindings
//! from `wrapper.h`.
//!
//! Discovery order:
//! 1. `PKG_CONFIG_PATH` (if set externally, use pkg-config as-is)
//! 2. `target/openssl-1.1.1w/` at the workspace root (installed by `cargo xtask setup`)

#[cfg(target_os = "linux")]
fn main() {
    use std::env;
    use std::path::PathBuf;

    println!("cargo::rerun-if-changed=wrapper.h");
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_PATH");

    const OPENSSL_1_1_VERSION: &str = "1.1.1w";

    struct OpensslPaths {
        include: PathBuf,
        lib: PathBuf,
    }

    /// Finds the workspace root by walking up from CARGO_MANIFEST_DIR.
    fn workspace_root() -> PathBuf {
        let manifest_dir =
            PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
        manifest_dir
            .ancestors()
            .find(|p| p.join("Cargo.lock").exists())
            .expect("could not find workspace root")
            .to_path_buf()
    }

    fn find_xtask_openssl() -> Option<OpensslPaths> {
        let dir = workspace_root()
            .join("target")
            .join(format!("openssl-{OPENSSL_1_1_VERSION}"));
        let include = dir.join("include");
        let lib = dir.join("lib");
        if include.is_dir() && lib.is_dir() {
            Some(OpensslPaths { include, lib })
        } else {
            None
        }
    }

    fn find_pkgconfig_openssl() -> OpensslPaths {
        let lib = pkg_config::Config::new()
            .atleast_version("1.1.0")
            .probe("libcrypto")
            .expect(
                "Could not find libcrypto. \
                 Run 'cargo xtask setup' or set PKG_CONFIG_PATH to an OpenSSL 1.1.x installation.",
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
            include: lib
                .include_paths
                .into_iter()
                .next()
                .expect("pkg-config returned no include paths for libcrypto"),
            lib: lib
                .link_paths
                .into_iter()
                .next()
                .expect("pkg-config returned no link paths for libcrypto"),
        }
    }

    let paths = if env::var_os("PKG_CONFIG_PATH").is_some() {
        find_pkgconfig_openssl()
    } else {
        find_xtask_openssl().unwrap_or_else(find_pkgconfig_openssl)
    };

    println!("cargo::rustc-link-lib=crypto");
    println!("cargo::rustc-link-search=native={}", paths.lib.display());

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", paths.include.display()))
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
        .allowlist_function("ERR_put_error")
        .allowlist_function("ERR_add_error_data")
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
