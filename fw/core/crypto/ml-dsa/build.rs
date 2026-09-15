fn main() {
    println!("cargo::rustc-check-cfg=cfg(param65)");
    let m44 = std::env::var("CARGO_FEATURE_PARAM_MLDSA44").is_ok();
    let m87 = std::env::var("CARGO_FEATURE_PARAM_MLDSA87").is_ok();
    if m44 && m87 {
        panic!("param-mldsa44 and param-mldsa87 are mutually exclusive");
    }
    if !m44 && !m87 {
        println!("cargo::rustc-cfg=param65");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
