// Copyright (C) Microsoft Corporation. All rights reserved.

use std::env;
use std::path::Path;
use std::process::Command;

fn openssl_inc_flag() -> Option<Vec<String>> {
    let result = Command::new("pkg-config")
        .arg("libcrypto")
        .arg("--cflags-only-I")
        .output();
    let output = match result {
        Ok(output) => output,
        Err(_) => return None,
    };

    if !output.status.success() {
        // fall back
        return None;
    }

    let flag = String::from_utf8(output.stdout)
        .expect("Failed to convert output")
        .trim()
        .to_owned();
    Some(vec![flag])
}

fn main() {
    let inc_flags = openssl_inc_flag();
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let mut bindings = bindgen::Builder::default()
        .header("azihsm_engine.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_type("AziHsmDigestKind")
        .allowlist_type("AziHsmEngineCommand")
        .allowlist_type("AziHsmEngineFlags")
        .allowlist_type("AziHsmEngineInfo")
        .allowlist_type("AziHsmKeyImport")
        .allowlist_type("AziHsmKeyUsage")
        .allowlist_type("AziHsmUnwrappingKey")
        .allowlist_type("AziHsmWrappingKeyType")
        .allowlist_type("AziHsmAttestKey")
        .allowlist_type("AziHsmCollateral")
        .allowlist_type("AziHsmKeyAvailability")
        .allowlist_type("AziHsmEngineVersion")
        .allowlist_var("REPORT_DATA_SIZE")
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: true,
        })
        .derive_default(true)
        .bitfield_enum("AziHsmEngineFlagsE");

    if let Some(inc_flags) = inc_flags {
        bindings = bindings.clang_args(inc_flags);
    }

    let bindings = bindings.generate().expect("Could not generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
