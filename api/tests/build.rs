// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    let mut features = Vec::new();
    if std::env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }
    let _dst = cmake::Config::new("cpp")
        .define("TEST_FEATURES", features.join(" "))
        .build();
}
