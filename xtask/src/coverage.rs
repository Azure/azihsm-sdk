// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run code coverage

use clap::Parser;
use dirs::home_dir;
use xshell::cmd;
use llvm_tools::LlvmTools;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run code coverage
#[derive(Parser)]
#[clap(about = "Run code coverage using cargo llvm-cov")]
pub struct Coverage {}

impl Xtask for Coverage {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running code coverage");

        let sh = xshell::Shell::new()?;

        // Find llvm tool paths
        let llvm_tools = LlvmTools::new().expect("failed to find llvm-tools");
        let llvm_cov_path = llvm_tools.tool(&llvm_tools::exe("llvm-cov")).expect("llvm-cov not found in llvm-tools");
        let llvm_profdata_path = llvm_tools.tool(&llvm_tools::exe("llvm-profdata")).expect("llvm-profdata not found in llvm-tools");

        // Set environment variable for llvm-cov to generate .profraw files for native code
        sh.set_var("LLVM_COV", &llvm_cov_path);
        sh.set_var("LLVM_PROFDATA", &llvm_profdata_path);

        // sanity check
        cmd!(sh, "cargo llvm-cov show-env").quiet().run()?;

        // Check cargo-llvm-cov version
        cmd!(sh, "cargo llvm-cov --version").quiet().run()?;

        // Run tests with coverage
        // log::info!("Building all tests and running them with coverage");
        // cmd!(
        //     sh,
        //     "cargo llvm-cov nextest --no-report --include-ffi --no-fail-fast --features mock --profile ci-mock --workspace --exclude integration-tests"
        // )
        // .run()?;

        // Gather workspace members
        let json = String::from_utf8(cmd!(sh, "cargo metadata --format-version=1 --no-deps --manifest-path .\\Cargo.toml").output()?.stdout)?;
        let parsed = jzon::parse(&json)?;
        let workspace_members = parsed.get("workspace_members").and_then(|members| members.as_array()).ok_or(anyhow::anyhow!("failed to get workspace members from cargo metadata"))?;

        // Check for/create reports directory
        let reports_dir = ctx.root.join("target").join("reports");
        if !reports_dir.exists() {
            log::info!("Creating reports directory at {}", reports_dir.display());
            std::fs::create_dir_all(&reports_dir)?;
        }

        // Find cmake build directory
        let build_dir = ctx.root.join("target").join("llvm-cov-target").join("debug").join("build");
        let mut cmake_build_dir = None;
        for entry in std::fs::read_dir(&build_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.file_name().and_then(|s| s.to_str()).map(|s| s.starts_with("azihsm_api_tests-")).unwrap_or(false) {
                // check if directory contains 'out' subdirectory to see if it's the cmake build directory
                if path.join("out").is_dir() {
                    println!("Found cmake build directory: {}", path.display());
                    cmake_build_dir = Some(path.join("out").join("build"));
                    break;
                }
            }
        }

        if cmake_build_dir.is_none() {
            println!("CMake build directory not found, coverage for C++ code will be missing");
        }

        // Gather build objects
        let mut build_objects = Vec::new();
        let target_dirs = vec![ctx.root.join("target").join("llvm-cov-target").join("debug").join("deps"),
        cmake_build_dir.unwrap()];
        for target_dir in target_dirs {
            for entry in std::fs::read_dir(&target_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| Some(s.to_str() == Some("dll") || s.to_str() == Some("exe"))) == Some(true) {
                    log::info!("Found build object: {}", path.display());
                    build_objects.push(path);
                }
            }
        }

        // Filter build objects to include only workspace members
        let filtered_objects: Vec<_> = build_objects.into_iter().filter(|obj| {
            let obj_name = obj.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let crate_name = obj_name.split('-').next().unwrap_or(""); // Get the crate name part of the object file name
            workspace_members.iter().any(|member| {
                let member_str = member.as_str().unwrap_or("");
                member_str.contains(crate_name)
            })
        }).collect();

        // Print filtered build objects
        for obj in &filtered_objects {
            println!("Including build object: {}", obj.display());
        }

        // Build '-object' arguments for 'llvm show' command
        let mut command_args = Vec::new();
        for obj in &filtered_objects {
            command_args.push("-object");
            command_args.push(obj.as_os_str().to_str().unwrap());
        }

        // get home directory
        let ctx_root_str = format!("{}", ctx.root.display()).replace("\\", "\\\\").replace(".", "\\.").replace("-", "\\-");
        let home_dir = home_dir().ok_or(anyhow::anyhow!("failed to get home directory"))?;
        let cargo_dir = format!("{}", home_dir.join(".cargo").display()).replace("\\", "\\\\").replace(".", "\\.").replace("-", "\\-");
        let rustup_dir = format!("{}", home_dir.join(".rustup").display()).replace("\\", "\\\\").replace(".", "\\.").replace("-", "\\-");
        let ignore_regex = format!("\\\\rustc\\\\([0-9a-f]+|[0-9]+\\.[0-9]+\\.[0-9]+)\\\\|^{0}(\\\\.*)?\\\\(tests|examples|benches)\\\\|^{0}(\\\\.*)?\\\\(tests\\.rs|[0-9a-zA-Z_-]+[_-]tests\\.rs)$|^{0}\\\\target\\\\llvm\\-cov\\-target($|\\\\)|^{1}\\\\(registry|git)\\\\|^{2}\\\\toolchains($|\\\\)", ctx_root_str, cargo_dir, rustup_dir);
        println!("{}", &ignore_regex);

        // Build rest of arguments
        command_args.push("-ignore-filename-regex");
        command_args.push(&ignore_regex);
        command_args.push("-show-instantiations=false");
        command_args.push("-show-line-counts-or-regions");
        command_args.push("-show-expansions");
        command_args.push("-show-branches=count");
        command_args.push("-show-mcdc");
        command_args.push("-Xdemangler=C:\\Users\\v-davidz\\.cargo\\bin\\cargo-llvm-cov.exe");
        command_args.push("-Xdemangler=llvm-cov");
        command_args.push("-Xdemangler=demangle");
        command_args.push("-output-dir=./target/reports/sdk-cov/html");

        // Run 'llvm-profdata merge -sparse' command
        cmd!(sh, "{llvm_profdata_path} merge -sparse -f C:\\repo\\github\\azihsm-sdk\\target\\llvm-cov-target\\azihsm-sdk-profraw-list -o C:\\repo\\github\\azihsm-sdk\\target\\llvm-cov-target\\azihsm-sdk.profdata")
            .quiet()
            .run()?;

        // Run 'llvm show' command
        cmd!(sh, "{llvm_cov_path} show -format=html -instr-profile=C:\\repo\\github\\azihsm-sdk\\target\\llvm-cov-target\\azihsm-sdk.profdata {command_args...}")
            .quiet()
            .run()?;

        // Generate cobertura report
        // log::info!("Generating cobertura report");
        // cmd!(
        //     sh,
        //     "cargo llvm-cov -vv report --cobertura --output-path ./target/reports/cobertura_sdk.xml --include-ffi"
        // ).run()?;

        // // Generate json report
        // log::info!("Generating json report");
        // cmd!(
        //     sh,
        //     "cargo llvm-cov -vv report --json --summary-only --output-path ./target/reports/sdk-cov.json --include-ffi"
        // ).run()?;

        // // Generate HTML report
        // log::info!("Generating HTML report");
        // cmd!(sh, " cargo llvm-cov -vv report --html --output-dir ./target/reports/sdk-cov/ --include-ffi").run()?;

        // log::info!("Code coverage completed successfully");

        Ok(())
    }
}
