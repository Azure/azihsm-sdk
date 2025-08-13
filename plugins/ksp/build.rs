// Copyright (C) Microsoft Corporation. All rights reserved.

const BCRYPT_PROVIDER_LIB_PATH: &str =
    "C:\\Program Files (x86)\\Windows Kits\\10\\Cryptographic Provider Development Kit\\Lib\\x64";

extern crate winres;

fn main() {
    println!(
        "cargo:rustc-link-search=native={}",
        BCRYPT_PROVIDER_LIB_PATH
    );
    println!("cargo:rustc-link-lib=bcrypt_provider");

    // Use winres to create resource with version info struct
    // https://docs.rs/winres/latest/winres/struct.WindowsResource.html#method.new
    let res = winres::WindowsResource::new();
    res.compile().unwrap();
}
