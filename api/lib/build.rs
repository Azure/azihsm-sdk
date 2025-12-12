// Copyright (C) Microsoft Corporation. All rights reserved.

use std::env;
use std::path::Path;

use cbindgen::Config;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let cbindgen_config_path = Path::new(&manifest_dir).join("cbindgen.toml");

    let out_dir = env::var("OUT_DIR").unwrap();
    let header_path = Path::new(&out_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("azihsm.h");

    cbindgen::Builder::new()
        .with_crate(manifest_dir)
        .with_config(Config::from_file(cbindgen_config_path).unwrap())
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(header_path);
}
