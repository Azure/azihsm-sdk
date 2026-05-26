// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use resiliency_macro::resiliency_cert_chain;
use resiliency_macro::resiliency_init_part;
use resiliency_macro::resiliency_key_gen;
use resiliency_macro::resiliency_key_op;
use resiliency_macro::resiliency_open_part;
use resiliency_macro::resiliency_open_session;
use resiliency_macro::retry_with_backoff;

#[derive(Debug)]
pub struct HsmError;

pub type HsmResult<T> = Result<T, HsmError>;

pub mod resiliency {
    pub const MAX_RETRIES: u32 = 3;
    pub const BACKOFF_BASE_MS: u64 = 10;
    pub const BACKOFF_JITTER_MS: u64 = 1;

    pub fn is_io_abort_error<T>(_result: &crate::HsmResult<T>) -> bool {
        false
    }

    pub fn is_init_retryable_error<T>(_result: &crate::HsmResult<T>) -> bool {
        false
    }

    pub fn is_key_op_retryable_error<T>(_result: &crate::HsmResult<T>) -> bool {
        false
    }

    pub fn is_open_session_retryable_error<T>(_result: &crate::HsmResult<T>) -> bool {
        false
    }

    pub fn is_cert_chain_retryable_error<T>(_result: &crate::HsmResult<T>) -> bool {
        false
    }

    pub fn execute_with_retry<T, F, P>(
        mut operation: F,
        _predicate: P,
        _max_retries: u32,
        _backoff_base_ms: u64,
        _backoff_jitter_ms: u64,
    ) -> crate::HsmResult<T>
    where
        F: FnMut(Option<&crate::HsmError>) -> crate::HsmResult<T>,
        P: Fn(&crate::HsmResult<T>) -> bool,
    {
        operation(None)
    }

    pub fn execute_key_gen_with_retry<T, F>(
        mut operation: F,
        _session: &crate::HsmSession,
        _partition: &crate::HsmPartition,
        _max_retries: u32,
        _backoff_base_ms: u64,
    ) -> crate::HsmResult<T>
    where
        F: FnMut() -> crate::HsmResult<T>,
    {
        operation()
    }

    pub fn execute_open_session_with_retry<T, F>(
        mut operation: F,
        _partition: &crate::HsmPartition,
        _max_retries: u32,
        _backoff_base_ms: u64,
    ) -> crate::HsmResult<T>
    where
        F: FnMut() -> crate::HsmResult<T>,
    {
        operation()
    }

    pub fn execute_key_op_with_retry<T, F, R, E>(
        mut operation: F,
        _session: &crate::HsmSession,
        _partition: &crate::HsmPartition,
        mut restore: R,
        _last_restore_epoch: E,
        _max_retries: u32,
        _backoff_base_ms: u64,
    ) -> crate::HsmResult<T>
    where
        F: FnMut() -> crate::HsmResult<T>,
        R: FnMut() -> crate::HsmResult<()>,
        E: Fn() -> u64,
    {
        restore()?;
        operation()
    }
}

#[derive(Clone)]
struct Payload(u8);

pub struct HsmPartition;

impl HsmPartition {
    fn resiliency_enabled(&self) -> bool {
        true
    }
}

pub struct HsmSession;

impl HsmSession {
    fn partition(&self) -> HsmPartition {
        HsmPartition
    }
}

pub struct HsmKey;

impl HsmKey {
    fn session(&self) -> HsmSession {
        HsmSession
    }

    fn restore_from_masked(&self) -> HsmResult<()> {
        Ok(())
    }

    fn last_restore_epoch(&self) -> u64 {
        0
    }
}

struct TestMethods;

impl TestMethods {
    #[retry_with_backoff(
        predicate = crate::resiliency::is_io_abort_error,
        max_retries = 2,
        backoff_base_ms = 20,
        backoff_jitter_ms = 5,
        condition = "enabled"
    )]
    fn generic_retry_with_overrides(&mut self, enabled: bool) -> HsmResult<u8> {
        Ok(if __prev_error.is_some() || enabled {
            1
        } else {
            0
        })
    }

    #[retry_with_backoff(predicate = crate::resiliency::is_io_abort_error)]
    fn generic_retry_with_receiver(&self) -> HsmResult<()> {
        Ok(())
    }
}

#[resiliency_open_part(
    max_retries = 2,
    backoff_base_ms = 20,
    backoff_jitter_ms = 5,
    condition = "enabled"
)]
fn open_part_with_overrides(enabled: bool) -> HsmResult<()> {
    let _ = enabled;
    Ok(())
}

#[resiliency_init_part(max_retries = 2, backoff_base_ms = 20, backoff_jitter_ms = 5)]
fn init_part_with_overrides(resiliency_config: Option<&u8>) -> HsmResult<()> {
    let _ = resiliency_config;
    Ok(())
}

#[resiliency_key_gen(session = "session", max_retries = 2, backoff_base_ms = 20)]
fn key_gen_with_option_and_cloned_args(
    session: &HsmSession,
    payload: Payload,
    output: Option<&mut u8>,
) -> HsmResult<u8> {
    let _ = session;
    if let Some(output) = output {
        *output = payload.0;
    }
    Ok(payload.0)
}

#[resiliency_open_session(partition = "partition", max_retries = 2, backoff_base_ms = 20)]
fn open_session_with_overrides(partition: &HsmPartition, payload: Payload) -> HsmResult<u8> {
    let _ = partition;
    Ok(payload.0)
}

#[resiliency_cert_chain(
    partition = "partition",
    max_retries = 2,
    backoff_base_ms = 20,
    backoff_jitter_ms = 5
)]
fn cert_chain_with_overrides(partition: &HsmPartition) -> HsmResult<()> {
    let _ = partition;
    Ok(())
}

#[resiliency_key_op(key = "key", max_retries = 2, backoff_base_ms = 20)]
fn key_op_with_overrides(key: &HsmKey, payload: Payload) -> HsmResult<u8> {
    let _ = key;
    Ok(payload.0)
}

#[test]
fn tests() {
    if !cargo_is_available() {
        return;
    }

    compile_pass_macros_expand_and_run();
    check_case(
        "async_fn",
        Some("retry macros do not support async functions"),
    );
    check_case(
        "bad_condition",
        Some("failed to parse `condition` expression"),
    );
    check_case(
        "by_value_self",
        Some("retry macros do not support by-value `self`; use `&self` or `&mut self`."),
    );
    check_case("malformed_attribute", None);
    check_case("missing_required_arg", Some("Missing field `key`"));
    check_case("non_ident_pattern", None);
    check_case(
        "no_return",
        Some("retry macros require the function to return HsmResult<T>"),
    );
    check_case(
        "wrong_return",
        Some("retry macros require the function to return HsmResult<T>"),
    );
}

fn cargo_is_available() -> bool {
    Command::new(cargo_command())
        .arg("--version")
        .output()
        .is_ok()
}

fn cargo_command() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn compile_pass_macros_expand_and_run() {
    let mut methods = TestMethods;
    let session = HsmSession;
    let partition = HsmPartition;
    let key = HsmKey;
    let mut output = 0;

    methods
        .generic_retry_with_overrides(true)
        .expect("generic retry with overrides should succeed");
    methods
        .generic_retry_with_receiver()
        .expect("generic retry with receiver should succeed");
    open_part_with_overrides(true).expect("open partition retry macro should succeed");
    init_part_with_overrides(Some(&1)).expect("init partition retry macro should succeed");
    key_gen_with_option_and_cloned_args(&session, Payload(7), Some(&mut output))
        .expect("key generation retry macro should succeed");
    open_session_with_overrides(&partition, Payload(8))
        .expect("open session retry macro should succeed");
    cert_chain_with_overrides(&partition).expect("cert chain retry macro should succeed");
    key_op_with_overrides(&key, Payload(9)).expect("key operation retry macro should succeed");
    assert_eq!(output, 7);
}

fn check_case(case: &str, expected_error: Option<&str>) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest_dir
        .join("tests")
        .join("compile_tests")
        .join(format!("{case}.rs"));
    let case_dir = compile_test_dir(manifest_dir).join(case);
    let src_dir = case_dir.join("src");

    let _ = std::fs::remove_dir_all(&case_dir);
    std::fs::create_dir_all(&src_dir).expect("failed to create compile-test src directory");
    std::fs::copy(&fixture, src_dir.join("main.rs")).expect("failed to copy compile-test fixture");
    std::fs::write(
        case_dir.join("Cargo.toml"),
        format!(
            "[workspace]\n\n[package]\nname = \"resiliency_macro_compile_test_{case}\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\nresiliency_macro = {{ path = {:?} }}\n",
            manifest_dir
        ),
    )
    .expect("failed to write compile-test Cargo.toml");

    let target_dir = case_dir.join("target");
    let output = Command::new(cargo_command())
        .arg("check")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(case_dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .output()
        .expect("failed to run cargo check for compile-test case");

    let stderr = String::from_utf8_lossy(&output.stderr);
    match expected_error {
        Some(expected) => {
            assert!(
                !output.status.success(),
                "{case} unexpectedly compiled successfully"
            );
            assert!(
                stderr.contains(expected),
                "{case} stderr did not contain expected text `{expected}`:\n{stderr}"
            );
        }
        None => {
            assert!(
                !output.status.success(),
                "{case} unexpectedly compiled successfully"
            );
        }
    }
}

fn compile_test_dir(manifest_dir: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("..").join("..").join("target"))
        .join("resiliency_macro_compile_tests")
}
