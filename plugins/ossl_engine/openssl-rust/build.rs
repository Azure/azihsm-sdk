// Copyright (C) Microsoft Corporation. All rights reserved.

use std::env;
use std::path::Path;
use std::process::Command;

fn openssl_lib_flag() -> Option<Vec<String>> {
    let result = Command::new("pkg-config")
        .arg("libcrypto")
        .arg("--libs-only-l")
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

fn get_openssl_version() -> Option<String> {
    let result = Command::new("pkg-config")
        .arg("--modversion")
        .arg("openssl")
        .output();
    let output = match result {
        Ok(output) => output,
        Err(_) => return None,
    };

    if !output.status.success() {
        println!("Failed to find OpenSSL version using pkg-config");
        return None;
    }

    Some(
        String::from_utf8(output.stdout)
            .expect("Invalid UTF8 in OpenSSL version string")
            .trim()
            .to_string(),
    )
}

fn main() {
    let lib_flags = openssl_lib_flag();
    let inc_flags = openssl_inc_flag();
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is not set");
    let out_path = Path::new(&out_dir);

    if let Some(openssl_version) = get_openssl_version() {
        if openssl_version.starts_with("1.1.1") {
            println!("openssl version starts with 1.1.1 {}", openssl_version);
            println!("cargo:rustc-cfg=feature=\"openssl_111\"")
        } else if openssl_version.starts_with("3.") {
            println!("openssl version starts with 3+ {}", openssl_version);
            println!("cargo:rustc-cfg=feature=\"openssl_3\"")
        } else {
            println!("unsupported openssl version");
        }
    }

    println!("lib_flags: {:?}", lib_flags);
    println!("inc_flags: {:?}", inc_flags);
    println!("out_dir: {:?}", out_dir);
    println!("out_path: {:?}", out_path);

    // Output for cargo
    if let Some(lib_flags) = lib_flags {
        for out in &lib_flags {
            let out = out.chars().skip(2).collect::<String>();
            if !out.is_empty() {
                println!("cargo:rustc-link-search={}", out);
            }
        }
    }

    println!("cargo:rustc-link-lib=crypto");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let mut bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    if let Some(inc_flags) = inc_flags {
        bindings = bindings.clang_args(inc_flags);
    }

    let bindings = bindings.generate().expect("Could not generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
