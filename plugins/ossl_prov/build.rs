// Copyright (C) Microsoft Corporation. All rights reserved.

#[cfg(target_os = "linux")]
fn main() {
    let mut features = Vec::new();
    if std::env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }
    cmake::Config::new(".")
        .define("AZIHSM_CARGO_FEATURES", features.join(" "))
        .build();
}

#[cfg(not(target_os = "linux"))]
fn main() {}
